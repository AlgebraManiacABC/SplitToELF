import sys
from shutil import copy

from files import gather_bearings
from split import split

EXIT_SUCCESS=0
EXIT_FAILURE=1

def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    info = gather_bearings(argv)
    print(f"Compiled object count: {len(info.compiled_objects)}")
    print(f"Binaries to split:")
    for binary in info.binaries:
        print(f"\t{binary}")
    print(f"Symbol files loaded:")
    for sym_file, sym_list in info.symbols.items():
        print(f"\t{sym_file} ({len(sym_list)} symbols)")
    print(f"Build directory: {info.build_dir}")
    print(f"Final output directory: {info.out_dir}")

    built_binaries = dict()
    for name, binary in info.binaries.items():
        # Split
        created = split(binary, info.compiled_objects[name], info.build_dir / name, info.symbols[name])
        created += info.compiled_objects[name]
        built_binaries[name] = created

    return EXIT_SUCCESS


if __name__ == '__main__':
    # try:
    sys.exit(main(sys.argv))
    # except Exception as e:
    #     print(f"An issue occurred while running {sys.argv[0]}:")
    #     print(e)
    #     print("Program aborted.")
    #     sys.exit(EXIT_FAILURE)
