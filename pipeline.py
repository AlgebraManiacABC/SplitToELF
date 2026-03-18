import math
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
from ctrtype import CRO, CTRBinary
from elf import ELF
from files import CTRPipelineInfo
from util import subp_run, BinaryWriter, EXIT_SUCCESS, Symbol


def compile_sources(name: str, info, objcopy):
    # Compile
    build_dir = info.build_dir / name
    to_compile: list[Path] = info.sources.get(name, [])
    # Detect and prevent duplicates
    seen = {}
    duplicates = []
    for c in to_compile:
        if c.name in seen:
            duplicates.append(c)
            duplicates.append(seen[c.name])
        else:
            seen[c.name] = c
    if duplicates:
        dupes = '\n'.join([str(d) for d in duplicates])
        raise Exception(f"Error compiling: Cannot compile duplicate functions!:\n{dupes}")
    compiled = []
    default = info.cc_info.get('default', None)
    errored = []
    num_to_compile = len(to_compile)
    print(f"Compiling {num_to_compile} files!")
    compile_futures = []
    completed_count = 0
    lock = threading.Lock()

    def compile_source(c_path: Path, o_path: Path, cc: str,
                       flags: list[str], ignore_compiler_errors: bool,
                       progress_reports: bool, verbose: bool, force: bool) -> tuple[bool, Path]:
        nonlocal completed_count
        # Double check we even *need* to compile (is object file newer than .c?)
        if not force and o_path.exists() and o_path.stat().st_mtime > c_path.stat().st_mtime:
            return True, o_path
        cmd = [cc, *flags, str(c_path), '-c', '-o', str(o_path)]
        if verbose:
            with lock:
                print(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != EXIT_SUCCESS:
            if ignore_compiler_errors:
                with lock:
                    print(f"Error compiling {c_path}! Skipping!")
                ret = False, c_path
            else:
                raise Exception(f"Compiler error!\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}")
        else:
            ret = True, o_path
        with lock:
            completed_count += 1
            if progress_reports and (completed_count % math.ceil(num_to_compile / 100)) == 0:
                print(f"[COMPILER PROGRESS] {100 * completed_count / num_to_compile:.1f}%")
        return ret

    with ThreadPoolExecutor() as executor:
        build_dir.mkdir(parents=True, exist_ok=True)
        force = any([c.stat().st_mtime < (info.working_dir / 'cc.yaml').stat().st_mtime for c in to_compile])
        for c in to_compile:
            bld = info.build_dir / name / (c.stem + '.o')
            d = info.cc_info[name].get(c.name, None)
            if not d:
                d = default
            cc = info.tool_dir / d['cc']
            flags = d['flags']
            compile_futures.append(
                executor.submit(compile_source, c, bld, str(cc), flags,
                                info.args['ignore_compiler_errors'],
                                info.args['progress_reports'],
                                info.args['verbose_compilation'],
                                force)
            )

    for f in compile_futures:
        ok, path = f.result()
        if ok:
            # Globalize the symbol and set .text alignment to 1 byte
            cmd = [objcopy, f'--globalize-symbol={path.stem}',
                   '--set-section-alignment', '.text=1', str(path)]
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


def generate_module_objdiff_unit(name: str, to_link: list[Path], info: CTRPipelineInfo,
                                 compiled: list[Path]) -> tuple[dict, list[Path]]:
    objdiff_to_link = [obj for obj in to_link if obj in compiled]
    objdiff_dict = {
        "name": f'{name}',
        "target_path": str(info.out_dir / 'objdiff_target' / f'{name}'),
        "base_path": str(info.out_dir / 'objdiff_base' / f'{name}')
    }
    return objdiff_dict, objdiff_to_link


def generate_function_objdiff_units(name: str, info: CTRPipelineInfo, compiled: list[Path],
                          targets: list[tuple[int, Path]]) -> tuple[list, list[Path]]:
    # Generate objdiff json units
    objdiff_units = []
    target_dict: dict[int, Path] = {addr: path for addr, path in targets}
    compiled_dict = {path.stem: path for path in compiled}
    to_link = []
    sorted_targets = sorted(target_dict.items())
    t_addrs_merged = []
    for i, t_info in enumerate(sorted_targets):
        t_addr, t_path = t_info
        if t_addr in t_addrs_merged:
            continue
        base_path = compiled_dict.get(t_path.stem, None)
        if base_path:
            # Matching file exists. But only link if contents match
            o_file = compiled_dict.pop(t_path.stem)
            b_elf = ELF.from_path(o_file)
            t_elf = ELF.from_path(t_path)
            t_elf_original_size = len(t_elf.data)
            t_addrs_to_merge = []
            while len(b_elf.data) > len(t_elf.data) and len(t_elf.data) + t_addr < info.binaries[name].text_size:
                # Attempt to merge binaries
                t_addr_2, t_path_2 = sorted_targets[i+1]
                t_addrs_to_merge.append(t_addr_2)
                i += 1
                t_elf += ELF.from_path(t_path_2)
            if b_elf == t_elf:
                to_link.append(o_file)
                t_addrs_merged += t_addrs_to_merge
            elif t_addrs_to_merge:
                print(f"Object file {o_file} (.text size {len(b_elf.data)}) was larger than"
                      f"{t_path} (.text size {t_elf_original_size}) and was compared with:")
                for a in t_addrs_to_merge:
                    print(f" - {target_dict[a]}")
                print(f"In order to create a new ELF with .text size {len(t_elf.data)}...")
                print(f"And yet it was not equivalent! Using linked version instead.")
                to_link.append(t_path)
            else:
                print(f"Object file {o_file} did not match {t_path}! Using linked version instead.")
                to_link.append(t_path)
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

LD_FLAGS = ['--entry=0', '--no-warn-mismatch']

def link_by_seriatum(name: str, to_link: list[Path], out_dir: Path, ld: str, verbose: bool, info) -> Path:
    # Link (in groups of files, so we can see progress)
    link_by = 100
    response_file = out_dir / f'{name}.txt'
    link_bounds = [(i, i + link_by) for i in range(0, len(to_link), link_by)]
    temp_links: list[Path] = []
    for i, bounds in enumerate(link_bounds):
        linked = out_dir / f'{name}_linked_{bounds[0]}'
        response_file.write_text('\n'.join('"' + str(o).replace('\\', '/') + '"' for o in to_link[bounds[0]:bounds[1]]))
        cmd = [ld, *LD_FLAGS, '-r', f'@{response_file}', '-o', str(linked)]
        if info.args['progress_reports'] and (i % math.ceil(len(link_bounds)/100)) == 0:
            print(f"[LINKER PROGRESS] {link_by * i / len(link_bounds):.1f}%")
        subp_run(cmd, verbose, "Linker error!")
        temp_links.append(linked)

    linked = out_dir / f'{name}_linked'
    if info.args['progress_reports']:
        print("[LINKER PROGRESS] Performing final link...")
    response_file.write_text('\n'.join(str(o).replace('\\', '/') for o in temp_links))
    cmd = [ld, *LD_FLAGS, f'@{response_file}', '-o', str(linked), '-Map', str(linked) + ".map"]
    subp_run(cmd, True, "Linker error!")
    # for link in temp_links:
    #     link.unlink()
    response_file.unlink()
    return linked


def link_all(name: str, to_link: list[Path], out_dir: Path, ld: str, info) -> Path:
    response_file = out_dir / f'{name}.txt'
    linked = out_dir / f'{name}_linked'
    if info.args['progress_reports']:
        print("[LINKER PROGRESS] Performing final link...")
    response_file.write_text('\n'.join(str(o).replace('\\', '/') for o in to_link))
    cmd = [ld, *LD_FLAGS, f'@{response_file}', '-o', str(linked), '-Map', str(linked) + '.map']
    subp_run(cmd, True, "Linker error!")
    # response_file.unlink()
    return linked


def link_all_keep_relocatable(name: str, to_link: list[Path], out_dir: Path, ld: str) -> Path | None:
    if not to_link:
        return None
    response_file = out_dir / f'{name}.txt'
    linked = out_dir / f'{name}'
    response_file.write_text('\n'.join(str(o).replace('\\','/') for o in to_link))
    cmd = [ld, '--entry=0', '--no-warn-mismatch', '-r',
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