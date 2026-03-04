from pathlib import Path
from elf import ELF
from ctrtype import CTRBinary
from util import find_all_bytes, Symbol


def split(binary: CTRBinary, compiled_objects: list[Path], build_dir: Path, symbols: list[Symbol]):
    """
    Creates object files in the space between compiled objects for the given binary.
    Writes created object files to the build directory.
    :param binary: The binary to split
    :param compiled_objects: A list of objects already compiled, with which to split the binary
    :param build_dir: The build (sub)directory to write created object files
    :param symbols: A symbol list for proper linking of objects later
    :return: The list of new objects
    """
    # Locations of matching binaries within the main binary
    address_matches = []
    # Symbols imported by compiled binaries
    #  (must be exported by a split binary)
    undefined_symbols = []

    binary_bytes = binary.data
    compiled = []
    for o_file in compiled_objects:
        o = ELF.from_path(o_file)
        if o.data == b'\x00':
            # Not a valid .o file
            continue
        found = find_all_bytes(binary_bytes, o.data, o.mask)
        undefined_symbols += o.imported_symbols
        if not found:
            raise Exception(f"Binary file {o_file} was not found in {binary.name}!")

        print(f"Found {len(found)} {'matches' if len(found) > 1 else 'match'} for {o_file}!")
        for start_addr in found:
            compiled.append((start_addr, o_file))
            end_addr = start_addr + len(o.data) - 1
            print(f"  -> {start_addr:#x} to {end_addr:#x}")
            address_matches.append((start_addr, end_addr))

    # Calculate interstitial space (bytes which were not user-compiled)
    to_objectify = address_matches.copy()
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

    # Create an object file for each split
    splat = []
    for start_end in to_objectify:
        base_name = f'{start_end[0] + binary.base_addr:08x}'
        o_file = build_dir / f'{base_name}.o'
        symbols_in_range = [Symbol(sym.addr - start_end[0], sym.name, sym.mode)
                     for sym in symbols if start_end[0] <= sym.addr <= start_end[1]]
        o = ELF.from_bytes(binary_bytes[start_end[0]:start_end[1]+1], start_end[0],
                           undefined_symbols, symbols_in_range)
        o_file.parent.mkdir(parents=True, exist_ok=True)
        o.write(o_file)
        splat.append((start_end[0],o_file))

    if undefined_symbols:
        print("Not all symbols could be defined! Remaining:")
        for sym in undefined_symbols:
            print(f"\t{sym}")

    splat.sort(key=lambda s: s[0])
    compiled.sort(key=lambda c: c[0])

    return splat, compiled