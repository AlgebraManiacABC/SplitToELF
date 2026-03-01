import sys
from files import gather_bearings

EXIT_SUCCESS=0
EXIT_FAILURE=1

def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    (compiled_objects,
     binary_file,
     symbol_file,
     split_dir) = gather_bearings()
    print(f"Compiled objects located in: {compiled_objects[0].parent}")
    print(f"Binary to split: {binary_file}")
    print(f"Symbol file: {symbol_file}")
    print(f"Directory to output split objects: {split_dir}")

    # Locations of matching binaries within the main binary
    address_matches = []
    # Symbols imported by compiled binaries
    #  (must be exported by a split binary)
    undefined_symbols = []

    # TODO: For each valid .o file in user-compiled object directory,
    #   1. Get list of relocations (for masking during the search)
    #   2. Find text/data/etc. in main binary (will be a list of matches in case multiple found)
    #   3. Add imported symbols to list to find later

    # TODO: Create address tuples (start, end) for interstitial space (bytes not matched to a compiled object)

    # TODO: Create object files from interstitial space, exporting symbols which are imported by user-compiled objects

    return EXIT_SUCCESS


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        print(f"An issue occurred while running {sys.argv[0]}:")
        print(e)
        print("Program aborted.")
        sys.exit(EXIT_FAILURE)
