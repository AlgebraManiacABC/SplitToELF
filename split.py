from pathlib import Path

from typing_extensions import deprecated

from elf import ELF
from ctrtype import CTRBinary
from util import find_all_bytes, Symbol, sanitize


def gather_splits(binary: CTRBinary, split_dir: Path, symbols: list[Symbol]):
    bin_size = len(binary.data)
    symbol_dict = {sym.addr: sym for sym in symbols}
    addrs = sorted([sym.addr for sym in symbols if sym.addr >= 0])
    splat = []
    cur_addr = 0
    while addrs or cur_addr < bin_size:
        if not addrs:
            # Fully finished, yet there are still trailing bytes
            sym_name = f'{cur_addr:08x}'
            sym_size = bin_size - cur_addr
            start_addr = cur_addr
            cur_addr += sym_size
        elif cur_addr == addrs[0]:
            # We reached a symbol definition; split it!
            start_addr = cur_addr
            sym = symbol_dict[cur_addr]
            sym_name = sanitize(sym.name)
            sym_size = sym.size
            next_addr = addrs[1] if len(addrs) > 1 else bin_size
            if cur_addr + sym_size > next_addr:
                sym_size = next_addr - cur_addr
            cur_addr += sym_size
            addrs.pop(0)  # Remove the address after processing
        elif cur_addr < addrs[0]:
            # Current address needs to keep up! This is safe to treat as data.
            sym_name = f'{cur_addr:08x}'
            start_addr = cur_addr
            cur_addr = addrs[0]
        else: # cur_addr > addrs[0]
            # This should be impossible!!
            raise RuntimeError(f"cur_addr ({cur_addr:08x}) grew beyond the next symbol (at {addrs[0]:08x})! Contact the developer!")

        o_file = split_dir / f'{sanitize(sym_name)}.o'
        if not o_file.exists():
            raise Exception(f"Skipped splitting object files, yet {o_file} does not exist (it should)!")
        splat.append((start_addr, o_file))
    return splat


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
    addrs = sorted([sym.addr for sym in symbols if sym.addr >= 0])
    addrs_to_log = set(addrs[i] for i in range(0, len(addrs), 100))
    splat = []
    all_o = []
    total_symbol_size = {'inter': 0, 'named': 0}
    cur_addr = 0
    last_segment = '.text'

    while addrs or cur_addr < bin_size:

        if info.args['progress_reports'] and cur_addr in addrs_to_log:
            print(f"[SPLIT PROGRESS] {100 * cur_addr / bin_size:.2f}%")

        if not addrs:
            # Fully finished, yet there are still trailing bytes
            sym_name = f'{cur_addr:08x}'
            symbol_bytes = bin_data[cur_addr:]
            sym = Symbol(cur_addr, sym_name, '$d', bin_size - cur_addr, last_segment)
            total_symbol_size['inter'] += sym.size
            cur_addr += sym.size
        elif cur_addr == addrs[0]:
            # We reached a symbol definition; split it!
            sym = symbol_dict[cur_addr]
            sym_name = sanitize(sym.name)
            sym_size = sym.size
            next_addr = addrs[1] if len(addrs) > 1 else bin_size
            if cur_addr + sym_size > next_addr:
                sym_size = next_addr - cur_addr
            symbol_bytes = bin_data[sym.addr:sym.addr+sym_size]
            sym = Symbol(cur_addr, sym_name, sym.mode, sym_size, sym.segment)
            last_segment = sym.segment
            cur_addr += sym.size
            total_symbol_size['named'] += sym.size
            addrs.pop(0)  # Remove the address after processing
        elif cur_addr < addrs[0]:
            # Current address needs to keep up! This is safe to treat as data.
            sym_name = f'{cur_addr:08x}'
            symbol_bytes = bin_data[cur_addr:addrs[0]]
            sym = Symbol(cur_addr, sym_name, "$d", addrs[0] - cur_addr, last_segment)
            cur_addr = addrs[0]
            total_symbol_size['inter'] += sym.size
        else: # cur_addr > addrs[0]
            # This should be impossible!!
            raise RuntimeError(f"cur_addr ({cur_addr:08x}) grew beyond the next symbol (at {addrs[0]:08x})! Contact the developer!")

        o = ELF.from_bytes_single(symbol_bytes, sym)
        all_o.append(o)
        o_file = split_dir / f'{sanitize(sym.name)}.o'
        o.write(o_file)
        splat.append((sym.addr, o_file))


    # print(f'Total binary size: {bin_size} (0x{bin_size:x})')
    total_bin_data = sum([len(o.data) for o in all_o])
    # print(f'Total binary size from split objects: {total_bin_data} (0x{total_bin_data:x})')
    # print(f'Total binary size from symbols (named): {total_symbol_size["named"]} (0x{total_symbol_size["named"]:x})')
    # print(f'Total binary size from symbols (gaps): {total_symbol_size["inter"]} (0x{total_symbol_size["inter"]:x})')
    total_symbol_size = total_symbol_size['named'] + total_symbol_size['inter']
    # print(f'Total binary size from symbols (all): {total_symbol_size} (0x{total_symbol_size:x})')
    if total_bin_data != bin_size or bin_size != total_symbol_size:
        raise Exception(f"Mismatch in binary data! Expected {bin_size}, got {total_bin_data} and {total_symbol_size}!")

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
        symbols_in_range = [Symbol(sym.addr - start_end[0], sym.name, sym.mode, sym.size, sym.segment)
                     for sym in symbols if start_end[0] <= sym.addr < start_end[1]]
        o = ELF.from_bytes_multi(binary_bytes[start_end[0]:start_end[1]+1], start_end[0],
                           symbols_in_range)
        o_file.parent.mkdir(parents=True, exist_ok=True)
        o.write(o_file)
        splat.append((start_end[0],o_file))

    splat.sort(key=lambda s: s[0])
    compiled.sort(key=lambda c: c[0])

    return splat, compiled