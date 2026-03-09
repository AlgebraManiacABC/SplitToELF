import hashlib
from typing import TypeVar, Generic
from typing_extensions import override

from util import *


class CTRSectionType(IntEnum):
    TEXT = 0
    RODATA = 1
    DATA = 2
    BSS = 3


INDEXED_IMPORT_ENTRY_SIZE = 0x8
ANON_IMPORT_ENTRY_SIZE = 0x8
EXPORT_TRIE_ENTRY_SIZE = 0x8


class OffSize:
    def __init__(self, off: int, size: int):
        self.off = off
        self.size = size

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "OffSize":
        off = reader.read_u32()
        size = reader.read_u32()
        return cls(off,size)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32(self.size)


T = TypeVar("T", bound=Writable)


class OffObject(Generic[T]):
    def __init__(self, off: int, obj: T | list[T]):
        self.off = off
        self.obj = obj

    def write(self, writer: BinaryWriter):
        ret = writer.tell()
        to_write = self.obj if isinstance(self.obj, list) else [self.obj]
        writer.seek(self.off)
        for obj in to_write:
            obj.write(writer)
        writer.seek(ret)

    def get_size(self, elem_size: int):
        if elem_size == 1 and self.obj and isinstance(self.obj[0], WritableStr):
            return sum(len(s) + 1 for s in self.obj)
        return len(self.obj) * elem_size

    def as_OffSize(self, elem_size: int = 1) -> OffSize:
        return OffSize(self.off, self.get_size(elem_size))


class CTRSectionInfo(OffSize):
    def __init__(self, addr: int, size: int, type: CTRSectionType):
        super().__init__(addr, size)
        self.type = type

    @classmethod
    def from_reader_with_type(cls, reader: BinaryReader, type: CTRSectionType) -> "CTRSectionInfo":
        addr = reader.read_u32()
        reader.read_u32()
        size = reader.read_u32()
        reader.read_u32()
        return cls(addr,size, type)

    @classmethod
    def from_cro_reader(cls, reader: BinaryReader) -> "CTRSectionInfo":
        addr = reader.read_u32()
        size = reader.read_u32()
        type = CTRSectionType(reader.read_u32())
        return cls(addr, size, type)

    @override
    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        writer.write_u32(self.size)
        writer.write_u32(self.type.value)


class ExHeader:
    def __init__(self, text, rodata, data, bss):
        self.text: CTRSectionInfo = text
        self.rodata: CTRSectionInfo = rodata
        self.data: CTRSectionInfo = data
        self.bss: CTRSectionInfo = bss

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExHeader":
        reader.seek(0x10)
        text = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.TEXT)
        rodata = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.RODATA)
        data = CTRSectionInfo.from_reader_with_type(reader, CTRSectionType.DATA)
        bss = CTRSectionInfo(data.off + data.size, reader.read_u32(), CTRSectionType.BSS)
        return cls(text, rodata, data, bss)


class SegmentOffset:
    def __init__(self, seg_idx: int, seg_off: int):
        self.index = seg_idx
        self.off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SegmentOffset":
        tmp = reader.read_u32()
        return cls(tmp & 0x0F, tmp >> 4)

    def write(self, writer: BinaryWriter):
        tmp = (self.off << 4) | self.index
        writer.write_u32(tmp)


class NamedExportTableEntry:
    def __init__(self, name: OffObject, seg_off: SegmentOffset):
        self.name = name
        self.seg_off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "NamedExportTableEntry":
        name_off = reader.read_u32()
        ret = reader.tell()
        reader.seek(name_off)
        name = reader.read_str()
        reader.seek(ret)
        seg_off = SegmentOffset.from_reader(reader)
        return cls(OffObject(name_off, name), seg_off)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name.off)
        self.seg_off.write(writer)


class ExportTrieEntry:
    def __init__(self, flags: int, left: int, right: int, index: int):
        self.flags = flags
        self.left = left
        self.right = right
        self.index = index

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExportTrieEntry":
        flags = reader.read_u16()
        left = reader.read_u16()
        right = reader.read_u16()
        index = reader.read_u16()
        return cls(flags, left, right, index)

    def write(self, writer: BinaryWriter):
        writer.write_u16(self.flags)
        writer.write_u16(self.left)
        writer.write_u16(self.right)
        writer.write_u16(self.index)


class ImportModuleTableEntry:
    def __init__(self, name: OffObject, indexed: OffSize, anon: OffSize):
        self.name = name
        self.indexed = indexed
        self.anon = anon

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ImportModuleTableEntry":
        name_off = reader.read_u32()
        indexed = OffSize.from_reader(reader)
        anon = OffSize.from_reader(reader)
        ret = reader.tell()
        reader.seek(name_off)
        name = reader.read_str()
        reader.seek(ret)
        return cls(OffObject(name_off, name), indexed, anon)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.name.off)
        self.indexed.write(writer)
        self.anon.write(writer)


class CRORelocationEntry:
    def __init__(self, seg_off: SegmentOffset, type: RelocationType, misc):
        self.seg_off = seg_off
        self.type = type
        self.misc = misc

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRORelocationEntry":
        seg_off = SegmentOffset.from_reader(reader)
        type = RelocationType(reader.read_u8())
        misc = reader.read_bytes(7)
        return cls(seg_off, type, misc)

    def write(self, writer: BinaryWriter):
        self.seg_off.write(writer)
        writer.write_u8(self.type.value)
        writer.write_bytes(self.misc)


class NamedImportTableEntry:
    def __init__(self, name: OffObject, off: int):
        self.name = name
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "NamedImportTableEntry":
        name_off = reader.read_u32()
        off = reader.read_u32()
        ret = reader.tell()
        reader.seek(name_off)
        name = OffObject(name_off, reader.read_str())
        reader.seek(ret)
        return cls(name, off)

    def write(self, writer : BinaryWriter):
        writer.write_u32(self.name.off)
        writer.write_u32(self.off)


class IndexedImportTableEntry:
    def __init__(self, index: int, off: int):
        self.index = index
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "IndexedImportTableEntry":
        index = reader.read_u32()
        off = reader.read_u32()
        return cls(index, off)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.index)
        writer.write_u32(self.off)


class AnonImportTableEntry:
    def __init__(self, seg_off: SegmentOffset, off: int):
        self.seg_off = seg_off
        self.off = off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "AnonImportTableEntry":
        seg_off = SegmentOffset.from_reader(reader)
        off = reader.read_u32()
        return cls(seg_off, off)

    def write(self, writer: BinaryWriter):
        self.seg_off.write(writer)
        writer.write_u32(self.off)


class UnknownRelocationInfo:
    def __init__(self, off: int, seg_off: SegmentOffset):
        self.off = off
        self.seg_off = seg_off

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "UnknownRelocationInfo":
        off = reader.read_u32()
        seg_off = SegmentOffset.from_reader(reader)
        return cls(off, seg_off)

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        self.seg_off.write(writer)


class CRO:
    def __init__(self, misc_info, cro_size, bss_size, misc_info_2,
                 nnroCO: SegmentOffset, OnLoad: SegmentOffset, OnExit: SegmentOffset,
                 OnUnresolved: SegmentOffset, text: OffObject, data: OffObject,
                 module_name: OffObject, segment_table: OffObject, named_export_table: OffObject,
                 indexed_export_table: OffObject, export_strings: OffObject,
                 export_trie: OffObject, import_module_table: OffObject,
                 import_relocations: OffObject, named_import_table: OffObject,
                 indexed_import_table: OffObject, anon_import_table: OffObject,
                 import_strings: OffObject, unk_reloc_base: OffObject,
                 internal_relocs: OffObject, unk_relocs: OffObject):
        self.misc_info = misc_info
        self.cro_size = cro_size
        self.bss_size = bss_size
        self.misc_info_2 = misc_info_2
        self.nnroCO = nnroCO
        self.OnLoad = OnLoad
        self.OnExit = OnExit
        self.OnUnresolved = OnUnresolved
        self.text = text
        self.data = data
        self.module_name = module_name
        self.segment_table = segment_table
        self.named_export_table = named_export_table
        self.indexed_export_table = indexed_export_table
        self.export_strings = export_strings
        self.export_trie = export_trie
        self.import_module_table = import_module_table
        self.import_relocations = import_relocations
        self.named_import_table = named_import_table
        self.indexed_import_table = indexed_import_table
        self.anon_import_table = anon_import_table
        self.import_strings = import_strings
        self.unk_reloc_base = unk_reloc_base
        self.internal_relocs = internal_relocs
        self.unk_relocs = unk_relocs

    def get_text_bytes(self) -> bytes:
        return self.text.obj
    
    def get_data_bytes(self) -> bytes:
        return self.data.obj

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "CRO":
        reader.seek(0x80) # Ignore hashes while reading
        magic = reader.read_bytes(4)
        if magic != b'CRO0':
            raise Exception("Invalid CRO0 format!")
        misc_info = reader.read_bytes(0xC)
        cro_size = reader.read_u32()
        bss_size = reader.read_u32()
        misc_info_2 = reader.read_bytes(0x8)
        nnroCO = SegmentOffset.from_reader(reader)
        OnLoad = SegmentOffset.from_reader(reader)
        OnExit = SegmentOffset.from_reader(reader)
        OnUnresolved = SegmentOffset.from_reader(reader)
        text_info = OffSize.from_reader(reader)
        data_info = OffSize.from_reader(reader)
        module_name_info = OffSize.from_reader(reader)
        segment_table_info = OffSize.from_reader(reader)
        named_export_table_info = OffSize.from_reader(reader)
        indexed_export_table_info = OffSize.from_reader(reader)
        export_strings_info = OffSize.from_reader(reader)
        export_trie_info = OffSize.from_reader(reader)
        import_module_table_info = OffSize.from_reader(reader)
        import_relocations_info = OffSize.from_reader(reader)
        named_import_table_info = OffSize.from_reader(reader)
        indexed_import_table_info = OffSize.from_reader(reader)
        anon_import_table_info = OffSize.from_reader(reader)
        import_strings_info = OffSize.from_reader(reader)
        unk_reloc_base_info = OffSize.from_reader(reader)
        internal_reloc_info = OffSize.from_reader(reader)
        unk_reloc_info = OffSize.from_reader(reader)

        reader.seek(text_info.off)
        text_bytes = reader.read_bytes(text_info.size)
        text = OffObject(text_info.off, WritableBytes(text_bytes))

        reader.seek(data_info.off)
        data_bytes = reader.read_bytes(data_info.size)
        data = OffObject(data_info.off, WritableBytes(data_bytes))

        reader.seek(module_name_info.off)
        module_name = OffObject(module_name_info.off,
                WritableStr(reader.read_bytes(module_name_info.size).decode('utf-8')))

        reader.seek(segment_table_info.off)
        segment_table = OffObject(segment_table_info.off, [])
        for i in range(segment_table_info.size):
            segment_table.obj.append(CTRSectionInfo.from_cro_reader(reader))

        reader.seek(named_export_table_info.off)
        named_export_table = OffObject(named_export_table_info.off, [])
        for i in range(named_export_table_info.size):
            named_export_table.obj.append(NamedExportTableEntry.from_reader(reader))

        reader.seek(indexed_export_table_info.off)
        indexed_export_table = OffObject(indexed_export_table_info.off, [])
        for i in range(indexed_export_table_info.size):
            indexed_export_table.obj.append(SegmentOffset.from_reader(reader))

        reader.seek(export_strings_info.off)
        ii = export_strings_info.size
        export_strings = OffObject(export_strings_info.off, [])
        while ii > 0:
            next_str = reader.read_str()
            ii -= len(next_str) + 1
            export_strings.obj.append(WritableStr(next_str))

        reader.seek(export_trie_info.off)
        export_trie = OffObject(export_trie_info.off, [])
        for i in range(export_trie_info.size):
            export_trie.obj.append(ExportTrieEntry.from_reader(reader))

        reader.seek(import_module_table_info.off)
        import_module_table = OffObject(import_module_table_info.off, [])
        for i in range(import_module_table_info.size):
            import_module_table.obj.append(ImportModuleTableEntry.from_reader(reader))

        reader.seek(import_relocations_info.off)
        import_relocations = OffObject(import_relocations_info.off, [])
        for i in range(import_relocations_info.size):
            import_relocations.obj.append(CRORelocationEntry.from_reader(reader))

        reader.seek(named_import_table_info.off)
        named_import_table = OffObject(named_import_table_info.off, [])
        for i in range(named_import_table_info.size):
            named_import_table.obj.append(NamedImportTableEntry.from_reader(reader))

        reader.seek(indexed_import_table_info.off)
        indexed_import_table = OffObject(indexed_import_table_info.off, [])
        for i in range(indexed_import_table_info.size):
            indexed_import_table.obj.append(IndexedImportTableEntry.from_reader(reader))

        reader.seek(anon_import_table_info.off)
        anon_import_table = OffObject(anon_import_table_info.off, [])
        for i in range(anon_import_table_info.size):
            anon_import_table.obj.append(AnonImportTableEntry.from_reader(reader))

        reader.seek(import_strings_info.off)
        ii = import_strings_info.size
        import_strings = OffObject(import_strings_info.off, [])
        while ii > 0:
            next_str = reader.read_str()
            ii -= len(next_str) + 1
            import_strings.obj.append(WritableStr(next_str))

        reader.seek(unk_reloc_base_info.off)
        unk_reloc_base = OffObject(unk_reloc_base_info.off, [])
        for i in range(unk_reloc_base_info.size):
            unk_reloc_base.obj.append(UnknownRelocationInfo.from_reader(reader))

        reader.seek(internal_reloc_info.off)
        internal_relocs = OffObject(internal_reloc_info.off, [])
        for i in range(internal_reloc_info.size):
            internal_relocs.obj.append(CRORelocationEntry.from_reader(reader))

        reader.seek(unk_reloc_info.off)
        unk_relocs = OffObject(unk_reloc_info.off, [])
        for i in range(unk_reloc_info.size):
            unk_relocs.obj.append(CRORelocationEntry.from_reader(reader))

        return cls(misc_info, cro_size, bss_size, misc_info_2,
                 nnroCO, OnLoad, OnExit, OnUnresolved, text, data,
                 module_name, segment_table, named_export_table, indexed_export_table,
                 export_strings, export_trie, import_module_table, import_relocations,
                 named_import_table, indexed_import_table, anon_import_table,
                 import_strings, unk_reloc_base, internal_relocs, unk_relocs)

    def write(self, writer: BinaryWriter):
        writer.seek(0x80)
        writer.write_bytes(b'CRO0')
        writer.write_bytes(self.misc_info)
        writer.write_u32(self.cro_size)
        writer.write_u32(self.bss_size)
        writer.write_bytes(self.misc_info_2)
        self.nnroCO.write(writer)
        self.OnLoad.write(writer)
        self.OnExit.write(writer)
        self.OnUnresolved.write(writer)
        self.text.as_OffSize().write(writer)
        self.data.as_OffSize().write(writer)
        self.module_name.as_OffSize().write(writer)
        self.segment_table.as_OffSize().write(writer)
        self.named_export_table.as_OffSize().write(writer)
        self.indexed_export_table.as_OffSize().write(writer)
        self.export_strings.as_OffSize().write(writer)
        self.export_trie.as_OffSize().write(writer)
        self.import_module_table.as_OffSize().write(writer)
        self.import_relocations.as_OffSize().write(writer)
        self.named_import_table.as_OffSize().write(writer)
        self.indexed_import_table.as_OffSize().write(writer)
        self.anon_import_table.as_OffSize().write(writer)
        self.import_strings.as_OffSize().write(writer)
        self.unk_reloc_base.as_OffSize().write(writer)
        self.internal_relocs.as_OffSize().write(writer)
        self.unk_relocs.as_OffSize().write(writer)

        self.text.write(writer)
        self.data.write(writer)
        self.module_name.write(writer)
        self.segment_table.write(writer)
        self.named_export_table.write(writer)
        self.indexed_export_table.write(writer)
        self.export_strings.write(writer)
        self.export_trie.write(writer)
        self.import_module_table.write(writer)
        self.import_relocations.write(writer)
        self.named_import_table.write(writer)
        self.indexed_import_table.write(writer)
        self.anon_import_table.write(writer)
        self.import_strings.write(writer)
        self.unk_reloc_base.write(writer)
        self.internal_relocs.write(writer)
        self.unk_relocs.write(writer)

        cur_size = len(writer.getvalue())
        padding = b'\xCC' * (self.cro_size - cur_size)
        writer.seek(cur_size)
        writer.write_bytes(padding)

        writer.seek(0)
        for hash_bounds in [(0x80, self.text.off),
                            (self.text.off, self.module_name.off),
                            (self.module_name.off, self.data.off),
                            (self.data.off, self.data.off + self.data.as_OffSize().size)]:
            bytes_to_hash = writer.getvalue()[hash_bounds[0]:hash_bounds[1]]
            sha256 = hashlib.sha256(bytes_to_hash).digest()
            writer.write_bytes(sha256)

    @classmethod
    def from_cro(cls, cro: "CRO", data: bytes) -> "CRO":
        data = bytearray(data)[:len(cro.text.obj)]
        text_section = OffObject(cro.text.off, WritableBytes(data))
        return cls(cro.misc_info, cro.cro_size, cro.bss_size, cro.misc_info_2,
                   cro.nnroCO, cro.OnLoad, cro.OnExit, cro.OnUnresolved,
                   text_section, cro.data, cro.module_name, cro.segment_table,
                   cro.named_export_table, cro.indexed_export_table,
                   cro.export_strings, cro.export_trie, cro.import_module_table,
                   cro.import_relocations, cro.named_import_table,
                   cro.indexed_import_table, cro.anon_import_table,
                   cro.import_strings, cro.unk_reloc_base,
                   cro.internal_relocs, cro.unk_relocs)


class CTRBinary:
    def __init__(self, name: str, binary: bytes | CRO, exh: ExHeader = None):
        self.name = name
        self.binary = binary
        # Ensure real bytes are kept
        if isinstance(binary, CRO):
            self.data = self.binary.get_text_bytes() + self.binary.get_data_bytes()
            self.base_addr = self.binary.text.off
            self.text_size = len(self.binary.text.obj)
        else:
            self.data = self.binary
            self.base_addr = 0x100000
            self.text_size = exh.text.size

    @classmethod
    def from_path(cls, path: Path, exh: ExHeader = None) -> "CTRBinary":
        if '.cro' in path.name:
            reader = BinaryReader.from_path(path)
            cro = CRO.from_reader(reader)
            return cls(path.name, cro)
        else:
            code = path.read_bytes()
            return cls(path.name, code, exh)
