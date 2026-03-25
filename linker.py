"""Linker script generation, linking, and final binary production."""

import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pipeline.ctr import CTRBinary, SectionInfo, SectionType
from pipeline.elf_util import (
    create_target_elf,
    read_elf_section,
    read_elf_symbols,
)
from pipeline.symbols import Symbol, SymbolSegment, SymbolTable

logger = logging.getLogger(__name__)

SEGMENT_ORDER = [SymbolSegment.TEXT, SymbolSegment.RODATA, SymbolSegment.DATA, SymbolSegment.BSS]

SEGMENT_TO_SECTION_NAME = {
    SymbolSegment.TEXT: ".text",
    SymbolSegment.RODATA: ".rodata",
    SymbolSegment.DATA: ".data",
    SymbolSegment.BSS: ".bss",
}

SECTYPE_TO_SEGMENT = {
    SectionType.TEXT: SymbolSegment.TEXT,
    SectionType.RODATA: SymbolSegment.RODATA,
    SectionType.DATA: SymbolSegment.DATA,
    SectionType.BSS: SymbolSegment.BSS,
}


def _section_vma(binary: CTRBinary, segment: SymbolSegment) -> Optional[int]:
    """Get the VMA for a section in the binary."""
    sec_type = {
        SymbolSegment.TEXT: SectionType.TEXT,
        SymbolSegment.RODATA: SectionType.RODATA,
        SymbolSegment.DATA: SectionType.DATA,
        SymbolSegment.BSS: SectionType.BSS,
    }[segment]
    for sec in binary.sections:
        if sec.type == sec_type:
            return sec.offset
    return None


def generate_linker_script(binary: CTRBinary, sym_table: SymbolTable,
                           object_map: Dict[str, Path],
                           output_path: Path,
                           mangled_to_csv: Optional[Dict[str, str]] = None,
                           discard_constdata: bool = False) -> Path:
    """Generate a linker script that places objects at the correct addresses.

    Parameters
    ----------
    binary : CTRBinary
        The target binary (for section VMAs).
    sym_table : SymbolTable
        Full symbol table for ordering.
    object_map : dict
        Maps symbol name -> object file path to use (compiled or split/chunked).
        For chunked objects, the key is the first symbol name in the chunk.
        For compiled objects, the key is a symbol name they export.
    output_path : Path
        Where to write the linker script.

    Returns the path to the generated linker script.
    """
    lines = []
    lines.append('OUTPUT_FORMAT("elf32-littlearm")')
    lines.append("OUTPUT_ARCH(arm)")
    lines.append(f"ENTRY({sym_table.symbols[0].name})" if sym_table.symbols else "")
    lines.append("")
    lines.append("SECTIONS")
    lines.append("{")

    # Track all objects added across all sections (to detect orphans)
    all_added_objects: Dict[Path, str] = {}

    for segment in SEGMENT_ORDER:
        seg_symbols = sym_table.symbols_in_segment(segment)

        section_name = SEGMENT_TO_SECTION_NAME[segment]
        vma = _section_vma(binary, segment)
        if vma is None:
            continue

        if segment == SymbolSegment.BSS:
            lines.append(f"    {section_name} 0x{vma:08X} (NOLOAD) : SUBALIGN(1)")
        else:
            lines.append(f"    {section_name} 0x{vma:08X} : SUBALIGN(1)")
        lines.append("    {")

        # Track which objects we've already added (compiled objects may cover multiple symbols)
        added_objects: Dict[Path, str] = {}  # object path -> first symbol that added it

        for sym in seg_symbols:
            obj_path = object_map.get(sym.name)
            if obj_path is None:
                logger.warning("No object for symbol %s, leaving gap", sym.name)
                continue

            # Only add each unique object file once
            if obj_path in added_objects:
                logger.debug("Object %s already added for symbol %s, skipping duplicate for %s",
                           obj_path, added_objects[obj_path], sym.name)
                continue

            added_objects[obj_path] = sym.name
            # Use the object file, pulling the correct section
            lines.append(f"        KEEP({obj_path}({section_name}));")

        # Place filler objects for this section that aren't tied to CSV symbols.
        # This handles sections that have no symbols at all (e.g. .rodata when
        # the CSV only contains .text symbols) — without this, filler chunks
        # become orphan sections and the linker places them at wrong addresses.
        sec_type = {
            SymbolSegment.TEXT: SectionType.TEXT,
            SymbolSegment.RODATA: SectionType.RODATA,
            SymbolSegment.DATA: SectionType.DATA,
            SymbolSegment.BSS: SectionType.BSS,
        }[segment]
        for filler_name, obj_path in object_map.items():
            if not filler_name.startswith("__filler_"):
                continue
            if obj_path in added_objects:
                continue
            # Check if the filler address falls within this section
            try:
                filler_addr = int(filler_name.split("_0x")[1], 16)
            except (IndexError, ValueError):
                continue
            for sec in binary.sections:
                if sec.type == sec_type and sec.offset <= filler_addr < sec.end:
                    added_objects[obj_path] = filler_name
                    lines.append(f"        KEEP({obj_path}({section_name}));")
                    break

        # In mod mode, collect plain .constdata into .rodata for compiled objects
        if not discard_constdata and segment == SymbolSegment.RODATA:
            lines.append("        *(.constdata)")

        lines.append("    }")
        lines.append("")

        all_added_objects.update(added_objects)

    # Discard unwanted sections
    lines.append("    /DISCARD/ :")
    lines.append("    {")
    lines.append("        *(.comment)")
    lines.append("        *(.ARM.attributes)")
    lines.append("        *(.ARM.exidx)")
    lines.append("        *(.ARM.exidx.*)")
    lines.append("        *(.note*)")
    if discard_constdata:
        # Match mode: discard ALL constdata (split chunks have correct data)
        lines.append("        *(.constdata*)")
        lines.append("        *(.conststring*)")
    else:
        # Mod mode: discard only COMDAT vtable/typeinfo/conststring sections.
        # Vtable symbols are resolved via direct linker script assignments.
        # Keep plain .constdata (user-defined const data like ScriptTable).
        lines.append("        *(.constdata__*)")
        lines.append("        *(.conststring*)")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # Provide absolute address definitions for all symbols so that compiled
    # objects can resolve cross-references to other symbols in the binary.
    # Skip symbols with characters invalid in linker script identifiers.
    import re
    _valid_ld_sym = re.compile(r'^[A-Za-z_.$][A-Za-z0-9_.$]*$')
    lines.append("/* Symbol address definitions */")
    for sym in sym_table:
        if _valid_ld_sym.match(sym.name):
            lines.append(f"PROVIDE({sym.name} = 0x{sym.address:08X});")

    # Also emit address definitions for mangled C++ names that map to CSV symbols.
    # For vtable/typeinfo symbols (_ZTV*, _ZTI*, _ZTS*), use direct assignment
    # instead of PROVIDE so they override COMDAT section definitions.
    # For other symbols, use PROVIDE (weaker, doesn't override).
    if mangled_to_csv:
        lines.append("")
        lines.append("/* Mangled C++ name aliases */")
        for mangled, csv_name in mangled_to_csv.items():
            csv_sym = sym_table.get_by_name(csv_name)
            if csv_sym and _valid_ld_sym.match(mangled):
                if mangled.startswith(("_ZTV", "_ZTI", "_ZTS")):
                    # Direct assignment overrides COMDAT vtable/typeinfo definitions
                    lines.append(f"{mangled} = 0x{csv_sym.address:08X};")
                else:
                    lines.append(f"PROVIDE({mangled} = 0x{csv_sym.address:08X});")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
    logger.debug("Linker script written to %s", output_path)
    return output_path


def link_objects(object_files: List[Path], linker_script: Path,
                 output_elf: Path, ld_path: Path,
                 search_dirs: Optional[List[Path]] = None,
                 allow_unresolved: bool = False) -> Tuple[bool, str]:
    """Link object files into an ELF using the user's ld.

    Returns (success, message).
    """
    output_elf.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(ld_path), "--no-warn-mismatch"]
    if allow_unresolved:
        cmd.extend(["--unresolved-symbols=ignore-all", "--noinhibit-exec"])
    cmd.extend(["-T", str(linker_script)])
    if search_dirs:
        for d in search_dirs:
            cmd.extend(["-L", str(d)])
    cmd.extend(["-o", str(output_elf)])
    cmd.extend(str(p) for p in object_files)

    logger.debug("Link: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            msg = f"Linking failed:\n{result.stderr}"
            logger.error(msg)
            return False, msg
        return True, f"Linked: {output_elf}"
    except FileNotFoundError:
        return False, f"Linker not found: {ld_path}"
    except subprocess.TimeoutExpired:
        return False, "Linking timed out"


def elf_to_binary(elf_path: Path, bin_path: Path,
                  objcopy_path: Path) -> Tuple[bool, str]:
    """Convert a linked ELF to a flat binary using objcopy.

    Returns (success, message).
    """
    bin_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(objcopy_path), "-O", "binary", str(elf_path), str(bin_path)]
    logger.debug("objcopy: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            msg = f"objcopy failed:\n{result.stderr}"
            logger.error(msg)
            return False, msg
        return True, f"Binary: {bin_path}"
    except FileNotFoundError:
        return False, f"objcopy not found: {objcopy_path}"


def extract_elf_sections(elf_path: Path) -> Dict[str, bytes]:
    """Read all loadable sections from a linked ELF using pyelftools."""
    from elftools.elf.elffile import ELFFile

    sections = {}
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name in (".text", ".rodata", ".data"):
                sections[sec.name] = sec.data()
    return sections


# ── Comparison ─────────────────────────────────────────────────────────────

def compare_objects(compiled_path: Path, binary: CTRBinary,
                    sym: Symbol, sym_table: SymbolTable) -> Tuple[bool, str]:
    """Compare a compiled object's section bytes against the original binary.

    Reads the compiled .o's section (e.g. .text) and compares it against the
    expected byte range in the original binary for the given symbol.

    Returns (matches, detail_message).
    """
    section_name = sym.section_name
    compiled_data = read_elf_section(str(compiled_path), section_name)
    if compiled_data is None:
        # Try alternate: some compilers put everything in .text
        compiled_data = read_elf_section(str(compiled_path), ".text")
        if compiled_data is None:
            return False, f"No {section_name} section in compiled object"

    # Get expected bytes from original binary
    sec_type = {
        SymbolSegment.TEXT: SectionType.TEXT,
        SymbolSegment.RODATA: SectionType.RODATA,
        SymbolSegment.DATA: SectionType.DATA,
        SymbolSegment.BSS: SectionType.BSS,
    }[sym.segment]

    section_end = 0
    for sec in binary.sections:
        if sec.type == sec_type:
            section_end = sec.end if not binary.is_module else sec.offset + sec.size
            break

    expected_size = sym_table.get_split_range(sym, section_end)
    expected_data = binary.read_bytes_at(sym.address, expected_size)

    if compiled_data == expected_data:
        return True, f"MATCH: {sym.name}"

    # Partial comparison: check declared size
    if len(compiled_data) == expected_size:
        # Same size but different content
        diff_count = sum(1 for a, b in zip(compiled_data, expected_data) if a != b)
        return False, f"MISMATCH: {sym.name} ({diff_count} byte(s) differ)"
    else:
        return False, (f"SIZE MISMATCH: {sym.name} "
                       f"(compiled={len(compiled_data)}, expected={expected_size})")


# ── Objdiff target creation ──────────────────────────────────────────────

def create_objdiff_target(binary: CTRBinary, sym_table: SymbolTable,
                          output_path: Path) -> Path:
    """Convert an original binary into an ELF with all symbols exported.

    This is used as the objdiff 'target' — the reference against which
    decompiled (base) objects are compared.
    """
    sections = []
    for sec in binary.sections:
        if sec.type == SectionType.BSS:
            continue
        sec_name = {
            SectionType.TEXT: ".text",
            SectionType.RODATA: ".rodata",
            SectionType.DATA: ".data",
        }.get(sec.type)
        if sec_name is None:
            continue
        sec_data = binary.section_bytes(sec)
        if sec_data:
            sections.append((sec_name, sec.offset, sec_data))

    symbols = [
        (sym.name, sym.address, sym.size, sym.is_code, sym.is_thumb)
        for sym in sym_table
    ]

    # Collect ARM mapping symbols ($a, $t, $d) for the disassembler
    from pipeline.symbols import SymbolMode
    mapping_symbols = []
    for sym in sym_table:
        if sym.mode == SymbolMode.ARM:
            mapping_symbols.append(("$a", sym.address))
        elif sym.mode == SymbolMode.THUMB:
            mapping_symbols.append(("$t", sym.address))
        elif sym.mode == SymbolMode.DATA:
            mapping_symbols.append(("$d", sym.address))

    elf_data = create_target_elf(sections, symbols, binary.base_address,
                                 mapping_symbols=mapping_symbols)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(elf_data)
    logger.info("Objdiff target: %s", output_path)
    return output_path


def create_objdiff_base(compiled_objects: Dict[str, Path],
                        sym_table: SymbolTable, binary: CTRBinary,
                        output_elf: Path, ld_path: Path,
                        work_dir: Path) -> Optional[Path]:
    """Link only compiled objects into a base ELF for objdiff.

    Symbols not covered by compiled objects are omitted (base is partial).
    """
    if not compiled_objects:
        logger.warning("No compiled objects for objdiff base")
        return None

    # Build object map: only compiled objects
    object_map = {}
    for sym_name, obj_path in compiled_objects.items():
        object_map[sym_name] = obj_path

    # Generate a linker script with only the compiled symbols
    linker_script = work_dir / "base_link.ld"
    generate_linker_script(binary, sym_table, object_map, linker_script)

    # Collect unique object files
    obj_files = list(set(compiled_objects.values()))

    ok, msg = link_objects(obj_files, linker_script, output_elf, ld_path,
                           search_dirs=[work_dir], allow_unresolved=True)
    if not ok:
        logger.error("Objdiff base linking failed: %s", msg)
        return None

    return output_elf


# ── SHA256 verification ──────────────────────────────────────────────────

def verify_sha256(original_path: Path, output_path: Path) -> Tuple[bool, str]:
    """Verify that the output binary matches the original via SHA256."""
    orig_hash = hashlib.sha256(original_path.read_bytes()).hexdigest()
    out_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()

    if orig_hash == out_hash:
        return True, f"SHA256 OK: {orig_hash}"
    else:
        return False, (f"SHA256 MISMATCH!\n"
                       f"  Original: {orig_hash}\n"
                       f"  Output:   {out_hash}")
