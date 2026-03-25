"""Splits original binaries into per-symbol ELF relocatable objects."""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from pipeline.ctr import CTRBinary, SectionType
from pipeline.elf_util import create_split_object
from pipeline.symbols import Symbol, SymbolSegment, SymbolTable

logger = logging.getLogger(__name__)

SEGMENT_TO_SECTION = {
    SymbolSegment.TEXT: ".text",
    SymbolSegment.RODATA: ".rodata",
    SymbolSegment.DATA: ".data",
    SymbolSegment.BSS: ".bss",
}

SEGMENT_TO_SECTYPE = {
    SymbolSegment.TEXT: SectionType.TEXT,
    SymbolSegment.RODATA: SectionType.RODATA,
    SymbolSegment.DATA: SectionType.DATA,
    SymbolSegment.BSS: SectionType.BSS,
}


def _get_section_end(binary: CTRBinary, segment: SymbolSegment) -> int:
    """Get the end address of the section corresponding to a segment."""
    sec_type = SEGMENT_TO_SECTYPE[segment]
    for sec in binary.sections:
        if sec.type == sec_type:
            return sec.offset + sec.size if binary.is_module else sec.end
    # Fallback: use binary data length + base
    return binary.base_address + len(binary.raw_data)


def split_object_name(sym: Symbol) -> str:
    """Canonical object filename for a split symbol."""
    return f"{sym.name}.o"


def split_binary(binary: CTRBinary, sym_table: SymbolTable,
                 output_dir: Path, lazy_skip: Optional[Set[str]] = None) -> Dict[str, Path]:
    """Split a binary into per-symbol ELF relocatable objects.

    Parameters
    ----------
    binary : CTRBinary
        The original binary to split.
    sym_table : SymbolTable
        Symbol table (from CSV) for this binary.
    output_dir : Path
        Directory to write split objects into.
    lazy_skip : set of str, optional
        Symbol names to skip (for lazy splitting when compiled objects exist).

    Returns
    -------
    dict mapping symbol name -> path to the split .o file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {}

    for segment in SymbolSegment:
        seg_symbols = sym_table.symbols_in_segment(segment)
        if not seg_symbols:
            continue

        section_name = SEGMENT_TO_SECTION[segment]
        section_end = _get_section_end(binary, segment)

        for i, sym in enumerate(seg_symbols):
            if lazy_skip and sym.name in lazy_skip:
                logger.debug("Lazy skip: %s", sym.name)
                continue

            # Compute byte range: from this symbol to the next in the same segment
            if i + 1 < len(seg_symbols):
                next_addr = seg_symbols[i + 1].address
            else:
                next_addr = section_end

            byte_count = next_addr - sym.address
            if byte_count <= 0:
                logger.warning("Symbol %s at 0x%x has zero or negative size, skipping",
                               sym.name, sym.address)
                continue

            if segment == SymbolSegment.BSS:
                # BSS has no file data
                section_data = b"\x00" * byte_count
            else:
                section_data = binary.read_bytes_at(sym.address, byte_count)

            obj_data = create_split_object(
                section_name=section_name,
                section_data=section_data,
                symbol_name=sym.name,
                is_code=sym.is_code,
                is_thumb=sym.is_thumb,
            )

            obj_path = output_dir / split_object_name(sym)
            obj_path.write_bytes(obj_data)
            result[sym.name] = obj_path
            logger.debug("Split: %s -> %s (%d bytes)", sym.name, obj_path, byte_count)

    logger.info("Split %s: %d objects written to %s", binary.name, len(result), output_dir)
    return result


def split_binary_chunked(binary: CTRBinary, sym_table: SymbolTable,
                        output_dir: Path, compiled_symbols: Optional[Set[str]] = None) -> Dict[str, Path]:
    """Split a binary into chunk objects covering full section ranges.

    Creates chunk .o files for contiguous ranges of non-compiled address space,
    including any gaps before the first symbol, between sections, and after the
    last symbol in each section.

    Parameters
    ----------
    binary : CTRBinary
        The original binary to split.
    sym_table : SymbolTable
        Symbol table (from CSV) for this binary.
    output_dir : Path
        Directory to write chunk objects into.
    compiled_symbols : set of str, optional
        Symbol names that have compiled replacements.

    Returns
    -------
    dict mapping symbol name -> path to the chunk .o file.
    All symbols within a chunk point to the same file. Synthetic filler
    symbols are created for uncovered ranges.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    chunk_counter = 0

    if compiled_symbols is None:
        compiled_symbols = set()

    for sec in binary.sections:
        sec_type_val = sec.type
        # Map section type to segment
        segment = None
        for seg, st in SEGMENT_TO_SECTYPE.items():
            if st == sec_type_val:
                segment = seg
                break
        if segment is None or segment == SymbolSegment.BSS:
            continue
        if segment not in SEGMENT_TO_SECTION:
            continue
        if sec.size == 0:
            continue

        section_name = SEGMENT_TO_SECTION[segment]
        sec_start = sec.offset
        sec_end = sec.offset + sec.size

        all_seg_symbols = sym_table.symbols_in_segment(segment)

        # Filter symbols to only those within the section boundaries
        seg_symbols = [s for s in all_seg_symbols
                       if sec_start <= s.address < sec_end]
        if len(seg_symbols) != len(all_seg_symbols):
            skipped = len(all_seg_symbols) - len(seg_symbols)
            logger.debug("Skipped %d out-of-range %s symbols for section 0x%x-0x%x",
                        skipped, section_name, sec_start, sec_end)

        # Build an ordered list of "events" within this section:
        # Each event is (address, is_compiled, symbol_or_none)
        # We walk through the section linearly, creating chunks for non-compiled ranges

        # Create ranges: list of (start_addr, end_addr, is_compiled, symbols_in_range)
        ranges = []

        # Add a filler for the gap before the first symbol (if any)
        if seg_symbols and seg_symbols[0].address > sec_start:
            ranges.append((sec_start, seg_symbols[0].address, False, []))

        for i, sym in enumerate(seg_symbols):
            # End of this symbol's range (clamped to section end)
            if i + 1 < len(seg_symbols):
                sym_end = min(seg_symbols[i + 1].address, sec_end)
            else:
                sym_end = sec_end

            is_compiled = sym.name in compiled_symbols
            ranges.append((sym.address, sym_end, is_compiled, [sym]))

        # If no symbols at all, the entire section is one filler chunk
        if not seg_symbols:
            ranges.append((sec_start, sec_end, False, []))

        # Merge consecutive non-compiled ranges into chunks
        chunks = []  # list of (start, end, symbols)
        current_start = None
        current_end = None
        current_syms = []

        for rng_start, rng_end, is_compiled, syms in ranges:
            if is_compiled:
                # Flush current non-compiled chunk
                if current_start is not None:
                    chunks.append((current_start, current_end, current_syms))
                    current_start = None
                    current_end = None
                    current_syms = []
            else:
                if current_start is None:
                    current_start = rng_start
                current_end = rng_end
                current_syms.extend(syms)

        # Flush final chunk
        if current_start is not None:
            chunks.append((current_start, current_end, current_syms))

        # Create one object per chunk
        for chunk_start, chunk_end, chunk_syms in chunks:
            byte_count = chunk_end - chunk_start
            if byte_count <= 0:
                continue

            section_data = binary.read_bytes_at(chunk_start, byte_count)

            # Use the first symbol name if available, otherwise a synthetic name
            if chunk_syms:
                export_name = chunk_syms[0].name
                is_code = chunk_syms[0].is_code
                is_thumb = chunk_syms[0].is_thumb
            else:
                export_name = f"__filler_0x{chunk_start:08x}"
                is_code = (section_name == ".text")
                is_thumb = False

            obj_data = create_split_object(
                section_name=section_name,
                section_data=section_data,
                symbol_name=export_name,
                is_code=is_code,
                is_thumb=is_thumb,
            )

            chunk_obj_name = f"chunk_0x{chunk_start:08x}.o"
            obj_path = output_dir / chunk_obj_name
            obj_path.write_bytes(obj_data)
            chunk_counter += 1

            # Map all symbols in the chunk to this path
            for sym in chunk_syms:
                result[sym.name] = obj_path
            # Also map filler name if no symbols
            if not chunk_syms:
                result[export_name] = obj_path

            logger.debug("Chunk: %d syms at 0x%x-0x%x -> %s (%d bytes)",
                        len(chunk_syms), chunk_start, chunk_end, obj_path.name, byte_count)

    logger.info("Split %s (chunked): %d chunks written to %s",
                binary.name, chunk_counter, output_dir)
    return result
