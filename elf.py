from util import *


class ELFHeader:
    IDENT = b'\x7fELF\x01\x01\x01' + b'\x00' * 9
    T_M_V = struct.pack('<HHI', 1, 0x28, 1)
    EHSIZE = 0x34
    SHENTSIZE = 0x28
    FLAGS = 0x05000000

    def __init__(self, shoff: int, shnum: int, shstrndx: int, valid: bool):
        self.shoff = shoff
        self.shnum = shnum
        self.shstrndx = shstrndx
        self.valid = valid
        return

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ELFHeader":
        reader.seek(0)
        check = reader.read_bytes(4)
        if check != b'\x7fELF':
            return cls(0, 0, 0, False)
        reader.seek(0x20)
        shoff = reader.read_u32()
        reader.seek(0x30)
        shnum = reader.read_u16()
        shstrndx = reader.read_u16()
        return cls(shoff, shnum, shstrndx, True)

    def write_standalone(self, path: Path):
        writer = BinaryWriter()
        self.write(writer)
        writer.flush(path)

    def write(self, writer: BinaryWriter):
        writer.write_bytes(self.IDENT)
        writer.write_bytes(self.T_M_V)
        writer.write_u32(0)  # e_entry
        writer.write_u32(0)  # e_phoff
        writer.write_u32(self.shoff)
        writer.write_u32(self.FLAGS)
        writer.write_u16(self.EHSIZE)
        writer.write_u16(0)  # e_phentsize
        writer.write_u16(0)  # e_phnum
        writer.write_u16(self.SHENTSIZE)
        writer.write_u16(self.shnum)
        writer.write_u16(self.shstrndx)


class SectionHeaderEntry:
    def __init__(self, name_off: int, type: int, flags: int, addr: int, off: int,
                 size: int, link: int = 0, info: int = 0,
                 entsize: int = 0, addralign: int = 0x4):
        self.name_off = name_off
        self.type = type
        self.flags = flags
        self.addr = addr
        self.off = off
        self.size = size
        self.link = link
        self.info = info
        self.entsize = entsize
        self.addralign = addralign

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SectionHeaderEntry":
        name_off = reader.read_u32()
        type = reader.read_u32()
        flags = reader.read_u32()
        addr = reader.read_u32()
        off = reader.read_u32()
        size = reader.read_u32()
        link = reader.read_u32()
        info = reader.read_u32()
        addralign = reader.read_u32()
        entsize = reader.read_u32()
        return cls(name_off, type, flags, addr, off, size, link, info, entsize, addralign)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name_off)
        writer.write_u32(self.type)
        writer.write_u32(self.flags)
        writer.write_u32(self.addr)
        writer.write_u32(self.off)
        writer.write_u32(self.size)
        writer.write_u32(self.link)
        writer.write_u32(self.info)
        writer.write_u32(0 if self.name_off == 0 else self.addralign)
        writer.write_u32(self.entsize)

    def __str__(self):
        return (f"name offset {self.name_off:08x} | type {self.type} | "
                f"flags {self.flags:08x} | addr {self.addr:08x} | "
                f"off {self.off:08x} | size {self.size:08x}")


class SymbolTableEntry:
    def __init__(self, name_off: int, value: int, size: int, info: int, other: int, shndx: int):
        self.name_off = name_off
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SymbolTableEntry":
        name_off = reader.read_u32()
        value = reader.read_u32()
        size = reader.read_u32()
        info = reader.read_u8()
        other = reader.read_u8()
        shndx = reader.read_u16()
        return cls(name_off, value, size, info, other, shndx)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name_off)
        writer.write_u32(self.value)
        writer.write_u32(self.size)
        writer.write_u8(self.info)
        writer.write_u8(self.other)
        writer.write_u16(self.shndx)

    def __str__(self):
        return f"name offset {self.name_off:08x} ({self.size} bytes) [wip] -> section header #{self.shndx}"


class SectionHeaderType(IntEnum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11


class ELF:
    def __init__(self, header: ELFHeader, data: bytes, data_off: int, mask: Bitmask,
                 imported: list[str], strtab_bytes: bytes,
                 local_syms: list[SymbolTableEntry], global_syms: list[SymbolTableEntry]):
        self.header = header
        self.data = data
        self.data_off = data_off
        self.mask = mask
        self.imported_symbols = imported
        self.strtab_bytes = strtab_bytes
        self.local_syms = local_syms
        self.global_syms = global_syms
        return

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ELF":
        header = ELFHeader.from_reader(reader)
        if not header.valid:
            return cls(header, b'\x00', 0, Bitmask(0), [], b'\x00', [], [])
        sh_entries = []
        text_data = []
        data_off = 0
        text_name_offsets = []
        local_syms = []
        global_syms = []
        strtab_index = 0
        rel_indices = []
        for i in range(header.shnum):
            # Seek to and read in section header entry
            reader.seek(header.shoff + header.SHENTSIZE * i)
            sh_entry = SectionHeaderEntry.from_reader(reader)
            sh_entries.append(sh_entry)
            match sh_entry.type:
                case 1:
                    # .text, .rodata, .data, etc.
                    reader.seek(sh_entry.off)
                    text_data.append(reader.read_bytes(sh_entry.size))
                    text_name_offsets.append(sh_entry.name_off)
                    data_off = sh_entry.addr
                case 2:
                    # .symtab
                    strtab_index = sh_entry.link
                    reader.seek(sh_entry.off)
                    num_symbols = int(sh_entry.size / 0x10)
                    for j in range(num_symbols):
                        sym = SymbolTableEntry.from_reader(reader)
                        if j >= sh_entry.info:
                            global_syms.append(sym)
                        else:
                            local_syms.append(sym)
                case 9:
                    # .rel.xyz (e.g., .rel.debug, .rel.text)
                    rel_indices.append(i)
                case _:
                    pass

        # Acquire strings from string table, if it exists
        strings = []
        if strtab_index > 0:
            sh_str = sh_entries[strtab_index]
            reader.seek(sh_str.off)
            strings = reader.read_bytes(sh_str.size)

        # Only keep .text
        sh_shstrtab = sh_entries[header.shstrndx]
        reader.seek(sh_shstrtab.off)
        shstrs = reader.read_bytes(sh_shstrtab.size)
        bin_bytes = None
        for off in text_name_offsets:
            name = get_name(shstrs, off)
            if name == '.text':
                bin_bytes = text_data[text_name_offsets.index(off)]
                break
        if not bin_bytes:
            raise Exception(f"No .text section in this object!")

        # Handle relocations
        mask = Bitmask(len(bin_bytes))
        undefined_symbols = []
        for i in rel_indices:
            sh_rel = sh_entries[i]
            sh_rel_name = get_name(shstrs, sh_rel.name_off)
            if sh_rel_name == '.rel.text':
                reader.seek(sh_rel.off)
                num_relocs = int(sh_rel.size / sh_rel.entsize)
                for j in range(num_relocs):
                    rel_entry = RelocationEntry.from_reader(reader)
                    sym = (local_syms + global_syms)[rel_entry.symbol_index]
                    # strings should NOT be None here
                    rel_name = get_name(strings, sym.name_off)
                    print(f"Name to relocate: {rel_name}")
                    undefined_symbols.append(rel_name)
                    mask.add_relocation(rel_entry)

        return cls(header, bin_bytes, data_off, mask, undefined_symbols, strings, local_syms, global_syms)

    @classmethod
    def from_path(cls, path: Path) -> "ELF":
        return cls.from_reader(BinaryReader.from_path(path))

    @classmethod
    def from_bytes_multi(cls, b: bytes, data_off: int, sym_list: list[Symbol]) -> "ELF":
        header = ELFHeader(0, 0, 0, True)
        mask = Bitmask(len(b))
        local_strtab = bytearray(b'\x00')
        global_strtab = bytearray()
        local_syms = []
        global_syms: list[SymbolTableEntry] = []
        for sym in sym_list:
            if sym.addr < data_off or sym.addr >= data_off + len(b):
                continue
            local_syms.append(SymbolTableEntry(len(local_strtab),
                sym.addr - data_off, 0, 0x0, 0x0, 1))
            local_strtab += sym.mode.encode('utf-8') + b'\x00'
            global_syms.append(SymbolTableEntry(len(global_strtab),
                sym.addr - data_off, sym.size, 0x12, 0, 1))
            global_strtab += sym.name.encode('utf-8') + b'\x00'
        for g_sym in global_syms:
            g_sym.name_off += len(local_strtab)
        strtab_bytes = local_strtab + global_strtab
        return cls(header, b, data_off, mask, [], strtab_bytes, local_syms, global_syms)

    @classmethod
    def from_bytes_single(cls, b: bytes, symbol: Symbol) -> "ELF":
        header = ELFHeader(0, 0, 0, True)
        local_strtab = bytearray(b'\x00')
        global_strtab = bytearray()
        local_syms = [SymbolTableEntry(len(local_strtab),
                0, 0, 0x0, 0x0, 1)]
        local_strtab += symbol.mode.encode('utf-8') + b'\x00'
        global_syms: list[SymbolTableEntry] = [SymbolTableEntry(len(global_strtab) + len(local_strtab),
                0, len(b), 0x12, 0, 1)]
        global_strtab += symbol.name.encode('utf-8') + b'\x00'
        strtab_bytes = local_strtab + global_strtab
        return cls(header, b, symbol.addr, Bitmask(len(b)), [], strtab_bytes, local_syms, global_syms)

    def write(self, o_file: Path):
        writer = BinaryWriter()
        self.header.write(writer)
        # .text
        text_off = writer.tell()
        writer.write_bytes(self.data)
        pad_to_4(writer)
        # .symtab
        symtab_off = writer.tell()
        writer.write_bytes(b'\x00' * 0x10) # 0th entry is null
        for st_entry in self.local_syms:
            st_entry.write(writer)
        for st_entry in self.global_syms:
            st_entry.write(writer)
        # .strtab
        strtab_off = writer.tell()
        writer.write_bytes(self.strtab_bytes)
        # .shstrtab
        shstrtab_off = writer.tell()
        writer.write_u8(0)
        text_name_off = writer.tell() - shstrtab_off
        writer.write_str('.text')
        symtab_name_off = writer.tell() - shstrtab_off
        if self.global_syms or self.local_syms:
            writer.write_str('.symtab')
        strtab_name_off = writer.tell() - shstrtab_off
        if self.global_syms or self.local_syms:
            writer.write_str('.strtab')
        shstrtab_name_off = writer.tell() - shstrtab_off
        writer.write_str('.shstrtab')
        pad_to_4(writer)
        # Section header entries
        sh_off = writer.tell()
        SectionHeaderEntry(0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0).write(writer)
        SectionHeaderEntry(text_name_off, SectionHeaderType.SHT_PROGBITS, 0x6, 0, text_off,
                           symtab_off - text_off, 0, 0, 0).write(writer)
        if self.global_syms or self.local_syms:
            SectionHeaderEntry(symtab_name_off, SectionHeaderType.SHT_SYMTAB, 0, 0, symtab_off,
                           strtab_off - symtab_off, 3, len(self.local_syms) + 1, 0x10).write(writer)
            SectionHeaderEntry(strtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, strtab_off,
                           len(self.strtab_bytes), 0, 0, 0).write(writer)
        SectionHeaderEntry(shstrtab_name_off, SectionHeaderType.SHT_STRTAB, 0, 0, shstrtab_off,
                           sh_off - shstrtab_off, 0, 0, 0, 0).write(writer)

        # Fix header
        writer.seek(0x20)
        writer.write_u32(sh_off)
        writer.seek(0x30)
        writer.write_u16(5 if self.global_syms or self.local_syms else 3) # shnum
        writer.write_u16(4 if self.global_syms or self.local_syms else 2) # shstrndx

        writer.flush(o_file)
