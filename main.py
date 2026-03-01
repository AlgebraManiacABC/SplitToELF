import sys

def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    # TODO: Get directory with user-compiled objects

    # TODO: Get binary to split

    # TODO: Get symbol list file

    # TODO: Select or create directory where split objects should go

    # TODO: Create list tuple of Address (start, end) which match a binary
    # TODO: Also keep a list of str which are symbols defined in these binaries and
    #  which need to be found in the symbol list file to be exported by the split binary

    # TODO: For each valid .o file in user-compiled object directory,
    #   1. Get list of relocations (for masking during the search)
    #   2. Find text/data/etc. in main binary (will be a list of matches in case multiple found)
    #   3. Add imported symbols to list to find later

    # TODO: Create address tuples (start, end) for interstitial space (bytes not matched to a compiled object)

    # TODO: Create object files from interstitial space, exporting symbols which are imported by user-compiled objects

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
