from pathlib import Path

from typing_extensions import deprecated

from elf import ELF
from ctrtype import CTRBinary
from util import find_all_bytes, Symbol, sanitize


def split_by_symbols(binary: CTRBinary, split_dir: Path, symbols: list[Symbol], info):
    """
    Creates object files for all symbols in the list,
     using the provided binary.
    :param binary: The binary to split
    :param split_dir: The output directory for the new objects
    :param symbols: The list of symbols by which to split the binary
    :return: A list of new objects as (address_in_binary, path)
    """

    bin_data = binary.data
    bin_size = len(bin_data)
    print(f'Total binary size: {bin_size} (0x{bin_size:x})')
    symbol_dict = {sym.addr: sym for sym in symbols}
    addrs = sorted([sym.addr for sym in symbols])
    addrs_to_log = set(addrs[i] for i in range(0, len(addrs), 100))
    splat = []
    all_o = []
    cur_addr = 0
    while cur_addr < len(bin_data):
        if info.args['progress_reports'] and cur_addr in addrs_to_log:
            print(f"[SPLIT PROGRESS] {100 * cur_addr / len(bin_data):.2f}%")
        next_addr = addrs[0] if addrs else len(bin_data)
        while cur_addr > next_addr:
            # print(f"Symbol at {next_addr} was overlapped by a preceding symbol! Ignoring")
            addrs.pop(0)
            next_addr = addrs[0] if addrs else len(bin_data)
        if cur_addr == next_addr:
            addrs.pop(0)
            sym = symbol_dict[cur_addr]
            sym_name = sym.name.replace('::', '__')
            symbol_bytes = bin_data[sym.addr:sym.addr + sym.size]
            cur_addr += sym.size
            sym = Symbol(sym.addr, sym_name, sym.mode, sym.size)
        else:
            symbol_bytes = bin_data[cur_addr:next_addr]
            name = f'{cur_addr:08x}'
            sym = Symbol(cur_addr, name, '$d', next_addr - cur_addr)
            cur_addr = next_addr

        o = ELF.from_bytes_single(symbol_bytes, sym)
        all_o.append(o)
        o_file = split_dir / f'{sanitize(sym.name)}.o'
        o.write(o_file)
        splat.append((sym.addr, o_file))

    total_bin_data = sum([len(o.data) for o in all_o])
    if total_bin_data != bin_size:
        raise Exception(f"Mismatch in binary data! Expected {bin_size}, got {total_bin_data}!")

    if info.args['progress_reports']:
        print("[SPLIT PROGRESS] 100.00%")
    return splat



@deprecated("Use split_by_symbols instead")
def split(binary: CTRBinary, compiled_objects: list[Path], build_dir: Path, symbols: list[Symbol]):
    """
    Creates object files in the space between compiled objects for the given binary.
    Writes created object files to the build directory.
    :param binary: The binary to split
    :param compiled_objects: A list of objects already compiled, with which to split the binary
    :param build_dir: The build (sub)directory to write created object files
    :param symbols: A symbol list for proper linking of objects later
    :return:
    """
    # Locations of matching binaries within the main binary
    address_matches = []

    binary_bytes = binary.data
    compiled = []
    for o_file in compiled_objects:
        o = ELF.from_path(o_file)
        if o.data == b'\x00':
            # Not a valid .o file
            continue
        found = find_all_bytes(binary_bytes, o.data, o.mask)
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
        symbols_in_range = [Symbol(sym.addr - start_end[0], sym.name, sym.mode, sym.size)
                     for sym in symbols if start_end[0] <= sym.addr < start_end[1]]
        o = ELF.from_bytes_multi(binary_bytes[start_end[0]:start_end[1]+1], start_end[0],
                           symbols_in_range)
        o_file.parent.mkdir(parents=True, exist_ok=True)
        o.write(o_file)
        splat.append((start_end[0],o_file))

    splat.sort(key=lambda s: s[0])
    compiled.sort(key=lambda c: c[0])

    return splat, compiled