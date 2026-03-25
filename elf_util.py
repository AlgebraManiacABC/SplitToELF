"""ELF object creation for ARM 32-bit targets.

Creates relocatable objects (.o) for split symbols and full ELF executables
for objdiff targets.
"""

import struct
from typing import Dict, List, Optional, Tuple

# ── ELF constants ──────────────────────────────────────────────────────────

ELFMAG = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2LSB = 1
EV_CURRENT = 1
ELFOSABI_NONE = 0

ET_REL = 1
ET_EXEC = 2
EM_ARM = 40
EF_ARM_EABI_VER5 = 0x05000000

# Section header types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_ARM_ATTRIBUTES = 0x70000003

# Section header flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Symbol binding / type
STB_LOCAL = 0
STB_GLOBAL = 1
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

# Special section indices
SHN_UNDEF = 0
SHN_ABS = 0xFFF1

# Program header types
PT_LOAD = 1
PF_R = 4
PF_W = 2
PF_X = 1

ELF_HDR_SIZE = 52
SHDR_SIZE = 40
PHDR_SIZE = 32
SYM_SIZE = 16

SECTION_FLAGS = {
    ".text":   SHF_ALLOC | SHF_EXECINSTR,
    ".rodata": SHF_ALLOC,
    ".data":   SHF_ALLOC | SHF_WRITE,
    ".bss":    SHF_ALLOC | SHF_WRITE,
}


def _align(val: int, alignment: int) -> int:
    return (val + alignment - 1) & ~(alignment - 1)


# ── Low-level packing ─────────────────────────────────────────────────────

def _pack_elf_header(e_type: int, e_shoff: int, e_shnum: int, e_shstrndx: int,
                     e_entry: int = 0, e_phoff: int = 0, e_phnum: int = 0,
                     e_flags: int = EF_ARM_EABI_VER5) -> bytes:
    ident = struct.pack("4sBBBB8x", ELFMAG, ELFCLASS32, ELFDATA2LSB,
                        EV_CURRENT, ELFOSABI_NONE)
    rest = struct.pack("<HHIIIIIHHHHHH",
                       e_type, EM_ARM, EV_CURRENT, e_entry, e_phoff, e_shoff,
                       e_flags, ELF_HDR_SIZE,
                       PHDR_SIZE if e_phnum > 0 else 0, e_phnum,
                       SHDR_SIZE, e_shnum, e_shstrndx)
    return ident + rest


def _pack_shdr(sh_name: int, sh_type: int, sh_flags: int, sh_addr: int,
               sh_offset: int, sh_size: int, sh_link: int = 0,
               sh_info: int = 0, sh_addralign: int = 1,
               sh_entsize: int = 0) -> bytes:
    return struct.pack("<IIIIIIIIII",
                       sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                       sh_size, sh_link, sh_info, sh_addralign, sh_entsize)


def _pack_sym(st_name: int, st_value: int, st_size: int,
              st_info: int, st_other: int, st_shndx: int) -> bytes:
    return struct.pack("<IIIBBH", st_name, st_value, st_size,
                       st_info, st_other, st_shndx)


def _pack_phdr(p_type: int, p_offset: int, p_vaddr: int, p_paddr: int,
               p_filesz: int, p_memsz: int, p_flags: int,
               p_align: int) -> bytes:
    return struct.pack("<IIIIIIII",
                       p_type, p_offset, p_vaddr, p_paddr,
                       p_filesz, p_memsz, p_flags, p_align)


class StringTable:
    """Helper to build an ELF string table."""

    def __init__(self):
        self._data = bytearray(b"\x00")
        self._index: Dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s in self._index:
            return self._index[s]
        off = len(self._data)
        self._data.extend(s.encode("utf-8"))
        self._data.append(0)
        self._index[s] = off
        return off

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    def __len__(self):
        return len(self._data)


# ── Relocatable object creation ───────────────────────────────────────────

def create_split_object(section_name: str, section_data: bytes,
                        symbol_name: str, is_code: bool = True,
                        is_thumb: bool = False) -> bytes:
    """Create a minimal ARM ELF relocatable object (.o) with one section
    and one exported global symbol.

    Parameters
    ----------
    section_name : str
        One of '.text', '.rodata', '.data'.
    section_data : bytes
        Raw bytes for the section.
    symbol_name : str
        Name of the global symbol to export.
    is_code : bool
        True for code (STT_FUNC), False for data (STT_OBJECT).
    is_thumb : bool
        If True, symbol value gets bit 0 set (THUMB interwork).
    """
    sh_flags = SECTION_FLAGS.get(section_name, SHF_ALLOC)
    sh_type = SHT_NOBITS if section_name == ".bss" else SHT_PROGBITS

    # ── Build string tables ──
    shstrtab = StringTable()
    sec_name_idx = shstrtab.add(section_name)
    symtab_name_idx = shstrtab.add(".symtab")
    strtab_name_idx = shstrtab.add(".strtab")
    shstrtab_name_idx = shstrtab.add(".shstrtab")

    strtab = StringTable()
    sym_name_off = strtab.add(symbol_name)

    # ── Build symbol table ──
    #   [0] NULL symbol
    #   [1] Section symbol (LOCAL)
    #   [2] Global symbol
    sym_type = STT_FUNC if is_code else STT_OBJECT
    sym_value = 1 if is_thumb else 0

    symtab = b""
    symtab += _pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)                     # NULL
    symtab += _pack_sym(0, 0, 0, (STB_LOCAL << 4) | STT_SECTION, 0, 1) # section
    symtab += _pack_sym(sym_name_off, sym_value, len(section_data),
                        (STB_GLOBAL << 4) | sym_type, 0, 1)            # global

    # ── Compute layout ──
    content_offset = ELF_HDR_SIZE
    content_size = len(section_data) if sh_type != SHT_NOBITS else 0

    symtab_offset = _align(content_offset + content_size, 4)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shdr_offset = _align(shstrtab_offset + len(shstrtab), 4)

    # 5 section headers: NULL, content, .symtab, .strtab, .shstrtab
    num_sections = 5

    # ── Section headers ──
    shdrs = b""
    # [0] NULL
    shdrs += _pack_shdr(0, SHT_NULL, 0, 0, 0, 0)
    # [1] content section
    shdrs += _pack_shdr(sec_name_idx, sh_type, sh_flags, 0,
                        content_offset, len(section_data),
                        sh_addralign=4)
    # [2] .symtab  (link -> strtab idx 3, info -> first global idx 2)
    shdrs += _pack_shdr(symtab_name_idx, SHT_SYMTAB, 0, 0,
                        symtab_offset, len(symtab),
                        sh_link=3, sh_info=2, sh_addralign=4,
                        sh_entsize=SYM_SIZE)
    # [3] .strtab
    shdrs += _pack_shdr(strtab_name_idx, SHT_STRTAB, 0, 0,
                        strtab_offset, len(strtab))
    # [4] .shstrtab
    shdrs += _pack_shdr(shstrtab_name_idx, SHT_STRTAB, 0, 0,
                        shstrtab_offset, len(shstrtab))

    # ── Assemble ──
    ehdr = _pack_elf_header(ET_REL, shdr_offset, num_sections, 4)

    buf = bytearray(ehdr)
    buf.extend(section_data if sh_type != SHT_NOBITS else b"")
    buf.extend(b"\x00" * (symtab_offset - len(buf)))
    buf.extend(symtab)
    buf.extend(strtab.data)
    buf.extend(shstrtab.data)
    buf.extend(b"\x00" * (shdr_offset - len(buf)))
    buf.extend(shdrs)

    return bytes(buf)


# ── Full ELF creation (for objdiff target) ────────────────────────────────

def create_target_elf(sections: List[Tuple[str, int, bytes]],
                      symbols: List[Tuple[str, int, int, bool, bool]],
                      base_address: int,
                      mapping_symbols: Optional[List[Tuple[str, int]]] = None) -> bytes:
    """Create a relocatable ELF representing the full original binary,
    with all symbols exported using section-relative addresses.

    objdiff expects ET_REL objects with symbol values relative to
    their containing section (not absolute VMAs).

    Parameters
    ----------
    sections : list of (name, vma, data)
        Each loaded section with its virtual address and raw content.
    symbols : list of (name, address, size, is_code, is_thumb)
        All symbols to export.
    base_address : int
        Entry point / base address of the binary (unused for ET_REL).
    mapping_symbols : list of (name, address), optional
        ARM mapping symbols ($a, $t, $d) for the disassembler.
    """
    # ── Prepare string tables ──
    shstrtab = StringTable()
    strtab = StringTable()

    section_name_indices = {}
    for sec_name, _, _ in sections:
        section_name_indices[sec_name] = shstrtab.add(sec_name)
    symtab_shname = shstrtab.add(".symtab")
    strtab_shname = shstrtab.add(".strtab")
    shstrtab_shname = shstrtab.add(".shstrtab")

    # Build a map of section name -> section header index (1-based, after NULL)
    sec_hdr_indices = {}
    for i, (sec_name, _, _) in enumerate(sections):
        sec_hdr_indices[sec_name] = i + 1

    # ── Build symbols ──
    # [0] NULL
    symtab_data = _pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)
    # [1..N] Section symbols (LOCAL)
    for sec_name, _, sec_data in sections:
        symtab_data += _pack_sym(0, 0, 0, (STB_LOCAL << 4) | STT_SECTION,
                                 0, sec_hdr_indices[sec_name])
    # ARM mapping symbols ($a, $t, $d) — LOCAL, tell disassembler about code regions
    num_mapping = 0
    if mapping_symbols:
        for map_name, map_addr in mapping_symbols:
            map_name_off = strtab.add(map_name)
            # Find containing section
            map_shndx = SHN_ABS
            map_val = map_addr
            for sec_name, sec_vma, sec_data in sections:
                if sec_vma <= map_addr < sec_vma + len(sec_data):
                    map_shndx = sec_hdr_indices[sec_name]
                    map_val = map_addr - sec_vma
                    break
            symtab_data += _pack_sym(map_name_off, map_val, 0,
                                     (STB_LOCAL << 4) | STT_NOTYPE, 0, map_shndx)
            num_mapping += 1
    first_global = 1 + len(sections) + num_mapping
    # [N+1..] Global symbols — values are section-relative for ET_REL
    for sym_name, sym_addr, sym_size, is_code, is_thumb in symbols:
        name_off = strtab.add(sym_name)
        sym_type = STT_FUNC if is_code else STT_OBJECT

        # Determine which section this symbol belongs to and compute relative offset
        shndx = SHN_ABS
        val = sym_addr  # fallback: absolute
        for sec_name, sec_vma, sec_data in sections:
            if sec_vma <= sym_addr < sec_vma + len(sec_data):
                shndx = sec_hdr_indices[sec_name]
                val = sym_addr - sec_vma  # section-relative
                break

        if is_thumb:
            val = val | 1

        symtab_data += _pack_sym(name_off, val, sym_size,
                                 (STB_GLOBAL << 4) | sym_type, 0, shndx)

    # ── Layout (no program headers for ET_REL) ──
    first_section_file_offset = _align(ELF_HDR_SIZE, 0x10)

    # Compute file offsets for each section's data
    sec_file_offsets = []
    cur_offset = first_section_file_offset
    for _, _, sec_data in sections:
        sec_file_offsets.append(cur_offset)
        cur_offset = _align(cur_offset + len(sec_data), 4)

    # Metadata sections after loaded sections
    symtab_offset = _align(cur_offset, 4)
    strtab_offset = symtab_offset + len(symtab_data)
    shstrtab_offset = strtab_offset + len(strtab)
    shdr_offset = _align(shstrtab_offset + len(shstrtab), 4)

    # Total section headers: NULL + loaded sections + .symtab + .strtab + .shstrtab
    num_shdrs = 1 + len(sections) + 3
    shstrtab_idx = num_shdrs - 1  # last section header

    # ── Section headers (VMA=0 for ET_REL) ──
    shdrs = _pack_shdr(0, SHT_NULL, 0, 0, 0, 0)  # [0] NULL
    for i, (sec_name, sec_vma, sec_data) in enumerate(sections):
        sh_flags = SECTION_FLAGS.get(sec_name, SHF_ALLOC)
        shdrs += _pack_shdr(section_name_indices[sec_name], SHT_PROGBITS,
                            sh_flags, 0, sec_file_offsets[i],
                            len(sec_data), sh_addralign=4)
    # .symtab
    symtab_shdr_idx = 1 + len(sections)
    strtab_shdr_idx = symtab_shdr_idx + 1
    shdrs += _pack_shdr(symtab_shname, SHT_SYMTAB, 0, 0,
                        symtab_offset, len(symtab_data),
                        sh_link=strtab_shdr_idx, sh_info=first_global,
                        sh_addralign=4, sh_entsize=SYM_SIZE)
    # .strtab
    shdrs += _pack_shdr(strtab_shname, SHT_STRTAB, 0, 0,
                        strtab_offset, len(strtab))
    # .shstrtab
    shdrs += _pack_shdr(shstrtab_shname, SHT_STRTAB, 0, 0,
                        shstrtab_offset, len(shstrtab))

    # ── ELF header (ET_REL, no program headers) ──
    ehdr = _pack_elf_header(ET_REL, shdr_offset, num_shdrs, shstrtab_idx)

    # ── Assemble ──
    buf = bytearray(ehdr)
    # Pad to first section
    buf.extend(b"\x00" * (first_section_file_offset - len(buf)))
    for i, (_, _, sec_data) in enumerate(sections):
        buf.extend(b"\x00" * (sec_file_offsets[i] - len(buf)))
        buf.extend(sec_data)
    # Pad and write metadata
    buf.extend(b"\x00" * (symtab_offset - len(buf)))
    buf.extend(symtab_data)
    buf.extend(strtab.data)
    buf.extend(shstrtab.data)
    buf.extend(b"\x00" * (shdr_offset - len(buf)))
    buf.extend(shdrs)

    return bytes(buf)


# ── ELF reading helpers (using pyelftools) ────────────────────────────────

def read_elf_symbols(elf_path: str) -> List[Tuple[str, int, int, str]]:
    """Read global symbols from an ELF file.

    Returns list of (name, value, size, section_name).
    """
    from elftools.elf.elffile import ELFFile

    results = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return results
        for sym in symtab.iter_symbols():
            if sym["st_info"]["bind"] == "STB_GLOBAL" and sym.name:
                sec_idx = sym["st_shndx"]
                if isinstance(sec_idx, int) and sec_idx > 0:
                    sec = elf.get_section(sec_idx)
                    sec_name = sec.name if sec else ""
                else:
                    sec_name = ""
                results.append((sym.name, sym["st_value"], sym["st_size"], sec_name))
    return results


def read_elf_section(elf_path: str, section_name: str) -> Optional[bytes]:
    """Read the raw bytes of a named section from an ELF file."""
    from elftools.elf.elffile import ELFFile

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(section_name)
        if sec is None:
            return None
        return sec.data()
