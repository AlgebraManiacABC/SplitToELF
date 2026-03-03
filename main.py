import sys
from files import gather_bearings
from ELF import *

EXIT_SUCCESS=0
EXIT_FAILURE=1

def main(argv: list[str]) -> int:
    """
    Main function
    :param argv: sys.argv
    :return: exit code
    """

    (compiled_objects,
     ctr_binary,
     symbols,
     split_dir) = gather_bearings(argv)
    print(f"Compiled objects located in: {compiled_objects[0].parent}")
    print(f"Binary to split: {ctr_binary.name}")
    print(f"Symbol count from symbol file: {len(symbols)}")
    print(f"Directory to output split objects: {split_dir}")

    # Locations of matching binaries within the main binary
    address_matches = []
    # Symbols imported by compiled binaries
    #  (must be exported by a split binary)
    undefined_symbols = []

    binary_bytes = ctr_binary.binary
    for o_file in compiled_objects:
        o = ELF.from_path(o_file)
        if o.data == b'\x00':
            # Not a valid .o file
            continue
        found = find_all_bytes(binary_bytes, o.data, o.mask)
        undefined_symbols += o.imported_symbols
        if not found:
            raise Exception(f"Binary file {o_file} was not found in {ctr_binary.name}!")

        print(f"Found {len(found)} {'matches' if len(found) > 1 else 'match'} for {o_file}!")
        for start_addr in found:
            end_addr = start_addr + len(o.data) - 1
            print(f"  -> {start_addr:#x} to {end_addr:#x}")
            address_matches.append((start_addr, end_addr))

    # Calculate interstitial space (bytes which were not user-compiled)
    to_objectify = []
    address_matches.sort(key=lambda a: a[0])
    start_addr = 0
    while address_matches:
        next_obj = address_matches.pop(0)
        if next_obj[0] > start_addr:
            # Plan new object ending just before next start
            to_objectify.append((start_addr, next_obj[0]-1))
        start_addr = next_obj[1] + 1
    # Plan trailing bytes as final object
    if start_addr < len(binary_bytes):
        to_objectify.append((start_addr, len(binary_bytes)-1))

    # Create an object file for each interstice
    for start_end in to_objectify:
        o_file = split_dir / f'{start_end[0]:08x}.o'
        counter = 1
        while o_file.exists():
            o_file = split_dir / f'{start_end[0]:08x}_{counter}.o'
            counter += 1
        symbols_in_range = [Symbol(sym.addr - start_end[0], sym.name)
                     for sym in symbols if start_end[0] <= sym.addr <= start_end[1]]
        o = ELF.from_bytes(binary_bytes[start_end[0]:start_end[1]+1], start_end[0],
                           undefined_symbols, symbols_in_range, o_file)
        o.write(o_file)

    if undefined_symbols:
        print("Not all symbols could be defined! Remaining:")
        for sym in undefined_symbols:
            print(f"\t{sym}")

    return EXIT_SUCCESS


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        print(f"An issue occurred while running {sys.argv[0]}:")
        print(e)
        print("Program aborted.")
        sys.exit(EXIT_FAILURE)
