"""Compiles user-provided C/C++ source files using settings from cc.yaml."""

import logging
import struct
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pipeline.config import ProjectConfig, CompileSettings
from pipeline.elf_util import create_split_object, read_elf_symbols, read_elf_section

logger = logging.getLogger(__name__)

SOURCE_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".s", ".asm"}


def fix_elf_symbol_visibility(obj_path: Path) -> None:
    """Patch HIDDEN symbols to DEFAULT visibility in an ARM ELF .o file.

    armcc produces all symbols with STV_HIDDEN visibility, which prevents
    the linker from resolving cross-object references. This function patches
    the st_other field of all GLOBAL/WEAK symbols from HIDDEN (2) to DEFAULT (0).
    """
    data = bytearray(obj_path.read_bytes())

    # Parse ELF header to find .symtab
    if data[:4] != b"\x7fELF":
        return
    if data[4] != 1:  # 32-bit only
        return

    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]

    # Find .symtab section
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from("<I", data, sh_off + 4)[0]
        if sh_type == 2:  # SHT_SYMTAB
            sym_offset = struct.unpack_from("<I", data, sh_off + 16)[0]
            sym_size = struct.unpack_from("<I", data, sh_off + 20)[0]
            sym_entsize = struct.unpack_from("<I", data, sh_off + 36)[0]
            if sym_entsize == 0:
                sym_entsize = 16

            # Iterate symbols and fix visibility
            num_syms = sym_size // sym_entsize
            for j in range(num_syms):
                sym_off = sym_offset + j * sym_entsize
                st_info = data[sym_off + 12]
                st_other = data[sym_off + 13]
                bind = st_info >> 4
                vis = st_other & 0x3
                # Fix GLOBAL or WEAK symbols with HIDDEN visibility
                if bind in (1, 2) and vis == 2:  # STB_GLOBAL=1, STB_WEAK=2, STV_HIDDEN=2
                    data[sym_off + 13] = st_other & ~0x3  # Set to STV_DEFAULT (0)

            obj_path.write_bytes(bytes(data))
            logger.debug("Fixed symbol visibility in %s", obj_path.name)
            return


def strip_comdat_vtable_sections(obj_path: Path) -> None:
    """Remove .constdata__ZTV* COMDAT sections from a compiled .o file.

    armcc emits vtable data in COMDAT sections named .constdata__ZTV<class>.
    These sections cause 'defined in discarded section' errors during linking
    because the linker script discards them but other compiled objects reference
    the vtable symbols. By stripping these sections from the objects, the vtable
    symbols become truly undefined and are resolved by PROVIDE directives.
    """
    data = bytearray(obj_path.read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != 1:
        return

    import struct as st
    e_shoff = st.unpack_from("<I", data, 0x20)[0]
    e_shentsize = st.unpack_from("<H", data, 0x2E)[0]
    e_shnum = st.unpack_from("<H", data, 0x30)[0]
    e_shstrndx = st.unpack_from("<H", data, 0x32)[0]

    if e_shoff == 0 or e_shnum == 0:
        return

    # Read section header string table
    shstr_offset = st.unpack_from("<I", data, e_shoff + e_shstrndx * e_shentsize + 0x10)[0]
    shstr_size = st.unpack_from("<I", data, e_shoff + e_shstrndx * e_shentsize + 0x14)[0]
    shstrtab = bytes(data[shstr_offset:shstr_offset + shstr_size])

    def get_section_name(sh_name_idx: int) -> str:
        end = shstrtab.index(b'\0', sh_name_idx)
        return shstrtab[sh_name_idx:end].decode('ascii', errors='replace')

    # Find and zero out COMDAT vtable sections
    modified = False
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = st.unpack_from("<I", data, sh_off)[0]
        sec_name = get_section_name(sh_name_idx)

        if sec_name.startswith(".constdata__ZTV") or sec_name.startswith(".conststring__"):
            # Zero out the section content (set sh_size = 0, sh_type = SHT_NULL)
            st.pack_into("<I", data, sh_off + 0x04, 0)  # sh_type = SHT_NULL
            # Also zero the section's symbol table entries
            modified = True
            logger.debug("Stripped COMDAT section %s from %s", sec_name, obj_path.name)

    if modified:
        obj_path.write_bytes(bytes(data))


def discover_sources(src_dir: Path) -> List[Path]:
    """Recursively find all C/C++/asm source files under a directory."""
    sources = []
    if not src_dir.exists():
        return sources
    for p in sorted(src_dir.rglob("*")):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS:
            sources.append(p)
    return sources


def compile_source(source: Path, output: Path, settings: CompileSettings,
                   tools_dir: Path, include_dir: Optional[Path] = None,
                   extra_flags: Optional[List[str]] = None,
                   cwd: Optional[Path] = None) -> Tuple[bool, str]:
    """Compile a single source file into a relocatable object.

    Returns (success, output_message).
    """
    cc_path = tools_dir / settings.cc
    if not cc_path.exists():
        return False, f"Compiler not found: {cc_path}"

    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(cc_path)]
    cmd.extend(settings.flags)
    if include_dir and include_dir.exists():
        cmd.extend(["-I", str(include_dir)])
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.extend(["-c", str(source), "-o", str(output)])

    logger.debug("Compile: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                cwd=str(cwd) if cwd else None)
        if result.returncode != 0:
            msg = f"Compilation failed for {source.name}:\n{result.stderr}"
            logger.error(msg)
            return False, msg
        return True, f"OK: {source.name} -> {output.name}"
    except FileNotFoundError:
        msg = f"Compiler executable not found: {cc_path}"
        logger.error(msg)
        return False, msg
    except subprocess.TimeoutExpired:
        msg = f"Compilation timed out for {source.name}"
        logger.error(msg)
        return False, msg


def compile_binary_sources(binary_name: str, src_dir: Path, build_dir: Path,
                           config: ProjectConfig, tools_dir: Path,
                           include_dir: Optional[Path] = None,
                           project_root: Optional[Path] = None) -> Dict[str, Path]:
    """Compile all source files for a binary.

    Returns dict mapping source relative path -> compiled .o path.
    """
    sources = discover_sources(src_dir)
    if not sources:
        logger.info("No sources found for %s in %s", binary_name, src_dir)
        return {}

    build_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    for src in sources:
        # Relative path from the binary's source dir
        rel = src.relative_to(src_dir)
        rel_str = str(rel).replace("\\", "/")

        # Check ignore list
        if config.is_ignored(binary_name, rel_str):
            logger.debug("Ignored: %s/%s", binary_name, rel_str)
            continue

        # Resolve compile settings
        settings = config.get_compile_settings(binary_name, rel_str)

        # Output path: mirror source structure in build dir
        out_path = build_dir / rel.with_suffix(".o")

        ok, msg = compile_source(src, out_path, settings, tools_dir, include_dir,
                                 cwd=project_root)
        if ok:
            # Fix armcc's STV_HIDDEN symbol visibility
            fix_elf_symbol_visibility(out_path)
            results[rel_str] = out_path
            logger.debug(msg)
        else:
            logger.warning(msg)

    logger.info("Compiled %s: %d/%d sources succeeded",
                binary_name, len(results), len(sources))
    return results


def expand_multi_symbol_objects(compiled_symbol_map: Dict[str, Path],
                                 sym_table: "SymbolTable") -> Dict[str, Path]:
    """Split multi-function compiled .o files into per-function .o files.

    When a single source file defines multiple functions (e.g. Item.c contains
    Item_Clear, Item_Copy, etc.), the compiler produces one .o with all of them
    in a single .text section. The linker can only place that .o at one address,
    but each function needs to go to a different address.

    This function:
    1. Groups symbols by their compiled .o path
    2. For .o files with multiple symbols: reads the .o, extracts each function's
       bytes based on its offset/size in the symbol table, creates individual .o files
    3. Returns an updated symbol_name -> .o path mapping

    Parameters
    ----------
    compiled_symbol_map : dict
        Maps symbol name -> compiled .o path (may have multiple names pointing
        to the same .o).
    sym_table : SymbolTable
        The full symbol table for address/size info.

    Returns
    -------
    dict
        Updated mapping with multi-function objects split into per-function objects.
    """
    from pipeline.symbols import SymbolMode

    # Group symbols by .o path
    obj_to_syms: Dict[Path, List[str]] = defaultdict(list)
    for sym_name, obj_path in compiled_symbol_map.items():
        obj_to_syms[obj_path].append(sym_name)

    result = {}
    for obj_path, sym_names in obj_to_syms.items():
        if len(sym_names) <= 1:
            # Single-function .o, no splitting needed
            for sn in sym_names:
                result[sn] = obj_path
            continue

        # Multi-function .o — need to split
        logger.info("Splitting multi-function object %s (%d symbols)",
                    obj_path.name, len(sym_names))

        # Read the compiled .o's symbols and section data
        try:
            elf_syms = read_elf_symbols(str(obj_path))
            text_data = read_elf_section(str(obj_path), ".text")
        except Exception as e:
            logger.warning("Could not read %s for splitting: %s", obj_path, e)
            for sn in sym_names:
                result[sn] = obj_path
            continue

        if text_data is None:
            logger.warning("No .text section in %s, keeping as-is", obj_path)
            for sn in sym_names:
                result[sn] = obj_path
            continue

        # Build map of symbol name -> (offset_in_text, size) from the ELF
        elf_sym_info = {}
        for name, value, size, sec_name in elf_syms:
            if sec_name == ".text" and name in sym_names:
                # value is the offset within .text (for .o files, value is section-relative)
                # Mask off thumb bit if present
                offset = value & ~1
                elf_sym_info[name] = (offset, size)

        # Sort by offset to determine boundaries
        sorted_syms = sorted(elf_sym_info.items(), key=lambda x: x[1][0])

        # For symbols with size=0, infer size from gap to next symbol
        resolved_syms = []
        for i, (name, (offset, size)) in enumerate(sorted_syms):
            if size == 0:
                if i + 1 < len(sorted_syms):
                    size = sorted_syms[i + 1][1][0] - offset
                else:
                    size = len(text_data) - offset
            resolved_syms.append((name, offset, size))

        # Create per-function .o files
        split_dir = obj_path.parent
        for name, offset, size in resolved_syms:
            if size <= 0:
                logger.warning("Skipping symbol %s with size %d", name, size)
                result[name] = obj_path  # Fallback to original
                continue

            func_bytes = text_data[offset:offset + size]

            # Determine if this is thumb code
            sym_info = sym_table.get_by_name(name)
            is_thumb = False
            if sym_info and sym_info.mode == SymbolMode.THUMB:
                is_thumb = True
            # Also check ELF symbol value for thumb bit
            for ename, evalue, esize, esec in elf_syms:
                if ename == name and (evalue & 1):
                    is_thumb = True
                    break

            split_o = create_split_object(".text", func_bytes, name,
                                          is_code=True, is_thumb=is_thumb)
            out_path = split_dir / f"{name}.o"
            out_path.write_bytes(split_o)
            result[name] = out_path
            logger.debug("Split %s from %s (%d bytes at offset %#x)",
                        name, obj_path.name, size, offset)

        # Handle any sym_names that weren't in the ELF .text (e.g. data symbols)
        for sn in sym_names:
            if sn not in result:
                logger.warning("Symbol %s not found in .text of %s, keeping original",
                              sn, obj_path.name)
                result[sn] = obj_path

    return result
