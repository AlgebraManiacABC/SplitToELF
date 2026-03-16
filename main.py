import hashlib
import sys
import json
from files import gather_bearings
from pipeline import *
from split import split_by_symbols, gather_splits
from util import EXIT_SUCCESS, EXIT_FAILURE


def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    info = gather_bearings(argv)
    print(f"Source file count: {sum([len(info.sources[name]) for name in info.binaries if name in info.sources.keys()])}")
    print(f"Binaries loaded (and their symbol counts):")
    for binary, sym_dict in zip(sorted(info.binaries), sorted(info.symbols.items())):
        print(f"   * {binary}: {len(sym_dict[1])} symbols")
    print(f"Final output directory: {info.out_dir}")

    ld = str((info.tool_dir / 'ld').resolve())
    objcopy = str((info.tool_dir / 'objcopy').resolve())

    objdiff_units = []

    for name in info.binaries.keys():
        if not info.args['compile_only'] and not info.args['skip_split']:
            print(f"Splitting {name}!")
            (info.split_dir / name).mkdir(parents=True, exist_ok=True)
            targets = split_by_symbols(info.binaries[name], info.split_dir / name, info.symbols.get(name, []), info)
        else:
            print(f"Gathering split objects for {name}...")
            targets = gather_splits(info.binaries[name], info.split_dir / name, info.symbols.get(name, []))

        if not info.args['skip_compile'] and not info.args['use_splits_only']:
            print(f"Compiling {name}!")
            (info.build_dir / name).mkdir(parents=True, exist_ok=True)
            compiled = compile_sources(name, info, objcopy)

            if info.args['compile_only']:
                if info.args['progress_reports']:
                    print(f"COMPILATION OF {name.upper()} COMPLETE!")
                continue
        elif info.args['use_splits_only']:
            print(f"Will not compile! (--use-splits-only set)")
        else:
            print(f"Gathering compiled objects from {info.build_dir / name}...")
            compiled = list((info.build_dir / name).rglob('*.o'))

        # Generate objdiff json units
        print("Preparing to link!")
        if not info.args['use_splits_only']:
            _, to_link = generate_function_objdiff_units(name, info, compiled, targets)
        else:
            to_link = [t[1] for t in targets]

        # Disregard function-wise units and instead use module units:
        unit, objdiff_to_link = generate_module_objdiff_unit(name, to_link, info, compiled)
        objdiff_units += unit

        if info.args['recreate_binaries']:
            # Link
            # linked = link_by_seriatum(name, to_link, info.out_dir, ld, False, info)
            linked = link_all(name, to_link, info.out_dir, ld, info)
            objdiff_dir = info.out_dir / 'objdiff'
            objdiff_dir.mkdir(parents=True, exist_ok=True)
            objdiff_linked = link_all_keep_relocatable(name, objdiff_to_link, objdiff_dir, ld)

            # Objcopy
            final_binary = recreate_binary(name, info.out_dir, objcopy, linked, info.binaries[name])

            # Hash check - did we create an identical binary?
            de_novo = hashlib.sha256(final_binary.read_bytes()).digest()
            original_file = next(p for p in info.originals if p.name == name)
            existing = hashlib.sha256(original_file.read_bytes()).digest()
            if de_novo != existing:
                raise Exception(f"Binary {name} was created, but does not match original!")

            if info.args['progress_reports']:
                print(f"ROUND TRIP DECOMP COMPLETE FOR {name.upper()}!!")
        else:
            if info.args['progress_reports']:
                print(f"OBJECT CREATION COMPLETE FOR {name.upper()}!!")

    if info.args['recreate_binaries']:
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
