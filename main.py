import hashlib
import sys
import subprocess
import json
from pathlib import Path

from ctrtype import CRO
from files import gather_bearings
from split import split
from util import BinaryWriter

EXIT_SUCCESS=0
EXIT_FAILURE=1

def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    info = gather_bearings(argv)
    print(f"Source file count: {len(info.sources)}")
    print(f"Binaries to split:")
    for binary in info.binaries:
        print(f"\t{binary}")
    print(f"Symbol files loaded:")
    for sym_file, sym_list in info.symbols.items():
        print(f"\t{sym_file} ({len(sym_list)} symbols)")
    print(f"Build directory: {info.build_dir}")
    print(f"Final output directory: {info.out_dir}")

    objdiff_units = []

    for name in info.binaries.keys():
        # Compile
        to_compile = info.sources.get(name,[])
        compiled = []
        default = info.cc_info.get('default', None)
        for c in to_compile:
            bld = info.build_dir / name / (c.stem + '.o')
            bld.parent.mkdir(parents=True, exist_ok=True)
            d = info.cc_info[name].get(c.name, None)
            if not d:
                d = default
            cc = d['cc']
            flags = d['flags']
            cmd = [str(info.tool_dir / cc), *flags, str(c), '-c', '-o', str(bld)]
            print(" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != EXIT_SUCCESS:
                raise Exception(f"Compiler error!\nstdout: {result.stdout}\nstderr: {result.stderr}")
            compiled.append(bld)

        # Split
        splat, compiled = split(info.binaries[name], compiled, info.build_dir / name, info.symbols.get(name,[]))

        # Generate objdiff json units
        compiled_dict: dict [int, Path] = {addr: path for addr, path in compiled}
        target_dict: dict[int, Path] = {addr: path for addr, path in splat}
        to_link = []
        for t_addr, t_path in target_dict.items():
            base_path = compiled_dict.get(t_addr, None)
            if base_path:
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

        # Link
        linked = info.out_dir / f'{name}_linked'
        linked.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str((info.tool_dir / 'ld').resolve()), '--entry=0', '--no-warn-mismatch',
                                 *[str(o) for o in to_link], '-o', str(linked)]
        print(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != EXIT_SUCCESS:
            raise Exception(f"Linker error!\nstdout: {result.stdout}\nstderr: {result.stderr}")

        # Objcopy
        final_binary = info.out_dir / name
        if '.cro' in name:
            final_binary = info.out_dir / f'{name}.temp'
        cmd = [str((info.tool_dir / 'objcopy').resolve()), str(linked), '-O', 'binary', str(final_binary)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != EXIT_SUCCESS:
            raise Exception(f"Objcopy error!\nstdout: {result.stdout}\nstderr: {result.stderr}")
        linked.unlink()

        # .cro modules need recreated
        if '.cro' in name:
            cro = CRO.from_cro(info.binaries[name].binary, final_binary.read_bytes())
            final_cro = info.out_dir / name
            writer = BinaryWriter()
            cro.write(writer)
            writer.flush(final_cro)
            final_binary.unlink()
            final_binary = final_cro

        # Hash check - did we create an identical binary?
        de_novo = hashlib.sha256(final_binary.read_bytes()).digest()
        original_file = next(p for p in info.originals if p.name == name)
        existing = hashlib.sha256(original_file.read_bytes()).digest()
        if de_novo != existing:
            raise Exception(f"Binary {name} was created, but does not match original!")

        print(f"ROUND TRIP DECOMP COMPLETE FOR {name.upper()}!!")

    objdiff = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "build_target": False,
        "build_base": False,
        "units": objdiff_units,
        "progress_categories": [{"id": n, "name": n} for n in info.binaries.keys()]
    }
    objdiff_path = info.working_dir / 'objdiff.json'
    objdiff_path.write_text(json.dumps(objdiff, indent=2))

    return EXIT_SUCCESS


if __name__ == '__main__':
    # try:
    sys.exit(main(sys.argv))
    # except Exception as e:
    #     print(f"An issue occurred while running {sys.argv[0]}:")
    #     print(e)
    #     print("Program aborted.")
    #     sys.exit(EXIT_FAILURE)
