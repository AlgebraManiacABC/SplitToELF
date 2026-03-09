import math
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
from ctrtype import CRO, CTRBinary
from util import subp_run, BinaryWriter, EXIT_SUCCESS


def compile_sources(name: str, info, objcopy):
    # Compile
    to_compile = info.sources.get(name, [])
    compiled = []
    default = info.cc_info.get('default', None)
    ignore_list = info.cc_info.get(name, {}).get('ignored', [])
    errored = []
    num_to_compile = len(to_compile)
    compile_futures = []
    completed_count = 0
    lock = threading.Lock()

    def compile_source(c_path: Path, o_path: Path, cc: str,
                       flags: list[str], objcopy: str, ignore_compiler_errors: bool,
                       progress_reports: bool) -> tuple[bool, Path]:
        nonlocal completed_count
        cmd = [cc, *flags, str(c_path), '-c', '-o', str(o_path)]
        # print(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != EXIT_SUCCESS:
            if ignore_compiler_errors:
                print(f"Error compiling {c_path}! Skipping!")
                ret = False, c_path
            else:
                raise Exception(f"Compiler error!\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}")
        else:
            ret = True, o_path
        with lock:
            completed_count += 1
            if progress_reports and (completed_count % math.ceil(num_to_compile / 100)) == 0:
                print(f"[COMPILER PROGRESS] {completed_count / num_to_compile:.1f}%")
        return ret

    with ThreadPoolExecutor() as executor:
        (info.build_dir / name).mkdir(parents=True, exist_ok=True)
        for c in to_compile:
            if c.name in ignore_list:
                continue
            bld = info.build_dir / name / (c.stem + '.o')
            d = info.cc_info[name].get(c.name, None)
            if not d:
                d = default
            cc = info.tool_dir / d['cc']
            flags = d['flags']
            compile_futures.append(
                executor.submit(compile_source, c, bld, str(cc), flags, objcopy,
                                info.args['ignore_compiler_errors'],
                                info.args['progress_reports'])
            )

    for f in compile_futures:
        ok, path = f.result()
        if ok:
            # Since armcc doesn't globalize the symbol (and we might need it for linking), globalize with objcopy
            cmd = [objcopy, f'--globalize-symbol={path.stem}', str(path)]
            subp_run(cmd, False, f"Objcopy error on {path}!")
            compiled.append(path)
        else:
            errored.append(path)

    if info.args['progress_reports']:
        print("[COMPILER PROGRESS] 100%")

    if errored:
        print(f"Error compiling {len(errored)} functions!! First 10:")
        for e in errored[0:10]:
            print(e)

    return compiled


def generate_objdiff_unit(name: str, info: CTRPipelineInfo, compiled: list[Path],
                          targets: list[tuple[int, Path]], symbols: list[Symbol]) -> tuple[list, list[Path]]:
    # Generate objdiff json units
    objdiff_units = []
    target_dict: dict[int, Path] = {addr: path for addr, path in targets}
    compiled_dict = {path.stem: path for path in compiled}
    to_link = []
    for t_addr, t_path in sorted(target_dict.items()):
        base_path = compiled_dict.get(t_path.stem, None)
        if base_path:
            compiled_dict.pop(t_path.stem)
            to_link.append(base_path)
        else:
            to_link.append(t_path)
        objdiff_units.append({
            "name": f'{name}/{t_path.stem}',
            "target_path": str(t_path.relative_to(info.working_dir)),
            "base_path": str(base_path.relative_to(info.working_dir)) if base_path else None,
            "metadata": {
                "progress_categories": [name],
                "complete": False if base_path is None else None
            }
        })
    for base_path in compiled_dict.values():
        print(f"Mismatching filename not found in target: {base_path}")
    return objdiff_units, to_link


def link_by_seriatum(name: str, to_link: list[Path], out_dir: Path, ld: str, verbose: bool, info) -> Path:
    # Link (in groups of files, so we can see progress)
    link_by = 100
    response_file = out_dir / f'{name}.txt'
    link_bounds = [(i, i + link_by) for i in range(0, len(to_link), link_by)]
    temp_links: list[Path] = []
    for i, bounds in enumerate(link_bounds):
        linked = out_dir / f'{name}_linked_{bounds[0]}'
        response_file.write_text('\n'.join('"' + str(o).replace('\\', '/') + '"' for o in to_link[bounds[0]:bounds[1]]))
        cmd = [ld, '--entry=0', '--no-warn-mismatch', '-r', f'@{response_file}', '-o', str(linked)]
        if info.args['progress_reports']:
            print(f"[LINKER PROGRESS] {link_by * i / len(link_bounds):.1f}%")
        subp_run(cmd, verbose, "Linker error!")
        temp_links.append(linked)

    linked = out_dir / f'{name}_linked'
    if info.args['progress_reports']:
        print("[LINKER PROGRESS] Performing final link...")
    response_file.write_text('\n'.join(str(o).replace('\\', '/') for o in temp_links))
    cmd = [ld, '--entry=0', '--no-warn-mismatch',
           f'@{response_file}', '-o', str(linked)]
    subp_run(cmd, True, "Linker error!")
    for link in temp_links:
        link.unlink()
    response_file.unlink()
    return linked


def link_all(name: str, to_link: list[Path], out_dir: Path, ld: str, info) -> Path:
    response_file = out_dir / f'{name}.txt'
    linked = out_dir / f'{name}_linked'
    if info.args['progress_reports']:
        print("[LINKER PROGRESS] Performing final link...")
    response_file.write_text('\n'.join(str(o).replace('\\', '/') for o in to_link))
    cmd = [ld, '--entry=0', '--no-warn-mismatch',
           f'@{response_file}', '-o', str(linked)]
    subp_run(cmd, True, "Linker error!")
    response_file.unlink()
    return linked


def recreate_binary(name: str, out_dir: Path, objcopy: str, linked: Path, in_binary: CTRBinary):
    # Objcopy
    final_binary = out_dir / name
    if '.cro' in name:
        final_binary = out_dir / f'{name}.temp'
    cmd = [objcopy, str(linked), '-O', 'binary', str(final_binary)]
    subp_run(cmd, True, "Objcopy error!")

    # .cro modules need recreated
    if '.cro' in name:
        cro = CRO.from_cro(in_binary.binary, final_binary.read_bytes())
        final_cro = out_dir / name
        writer = BinaryWriter()
        cro.write(writer)
        writer.flush(final_cro)
        final_binary.unlink()
        final_binary = final_cro

    return final_binary