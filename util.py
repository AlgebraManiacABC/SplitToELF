import struct
from enum import IntEnum
from io import BytesIO
from pathlib import Path


class CTRSectionType(IntEnum):
    TEXT = 0
    RODATA = 1
    DATA = 2
    BSS = 3


class Symbol:
    def __init__(self, addr: int, name: str):
        self.addr = addr
        self.name = name


class BinaryReader:
    def __init__(self, data: bytes):
        self._stream = BytesIO(data)

    @classmethod
    def from_path(cls, path: Path) -> "BinaryReader":
        return cls(path.read_bytes())

    def seek(self, offset: int):
        self._stream.seek(offset)

    def tell(self) -> int:
        return self._stream.tell()

    def read_bytes(self, size: int) -> bytes:
        return self._stream.read(size)

    def read_u8(self) -> int:
        return struct.unpack("<B", self._stream.read(1))[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self._stream.read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self._stream.read(4))[0]

    def read_s32(self) -> int:
        return struct.unpack("<i", self._stream.read(4))[0]


class BinaryWriter:
    def __init__(self):
        self._stream = BytesIO()

    def seek(self, offset: int):
        self._stream.seek(offset)

    def tell(self) -> int:
        return self._stream.tell()

    def write_bytes(self, data: bytes):
        self._stream.write(data)

    def write_u8(self, value: int):
        self._stream.write(struct.pack("<B", value))

    def write_u16(self, value: int):
        self._stream.write(struct.pack("<H", value))

    def write_u32(self, value: int):
        self._stream.write(struct.pack("<I", value))

    def write_s32(self, value: int):
        self._stream.write(struct.pack("<i", value))

    def flush(self, path: Path):
        path.write_bytes(self._stream.getvalue())

    def getvalue(self) -> bytes:
        return self._stream.getvalue()

    def write_str(self, s: str):
        self._stream.write(s.encode('utf-8') + b'\x00')


class RelocationType(IntEnum):
    R_ARM_NONE = 0
    R_ARM_ABS32 = 2
    R_ARM_REL32 = 3
    R_ARM_THM_PC22 = 10
    R_ARM_CALL = 28
    R_ARM_JUMP24 = 29
    R_ARM_TARGET1 = 38
    R_ARM_PREL31 = 42


class RelocationEntry:
    def __init__(self, off: int, symbol_index: int, type: RelocationType):
        self.off = off
        self.symbol_index = symbol_index
        self.type = type

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "RelocationEntry":
        off = reader.read_u32()
        tmp = reader.read_u32()
        return cls(off, tmp >> 8, RelocationType(tmp & 0xFF))

    def write(self, writer: BinaryWriter):
        writer.write_u32(self.off)
        tmp = self.symbol_index << 8
        tmp |= self.type & 0xFF
        writer.write_u32(tmp)

    def __str__(self):
        return f"offset {self.off:08x} | symbol #{self.symbol_index} | type {self.type.name}"


class Bitmask:
    def __init__(self, length: int):
        self.mask = bytearray(b'\xFF' * length)

    def add_relocation(self, rel_entry: RelocationEntry):
        match rel_entry.type:
            case RelocationType.R_ARM_CALL:
                self.mask[rel_entry.off: rel_entry.off + 3] = b'\x00' * 3
            case _:
                print(f"Found {rel_entry.type.name}, but this is unimplemented!")


class CTRSectionInfo:
    def __init__(self, addr: int, size: int, type: CTRSectionType):
        self.addr = addr
        self.size = size
        self.type = type
        pass

    @classmethod
    def from_reader(cls, reader: BinaryReader, type: CTRSectionType) -> "CTRSectionInfo":
        addr = reader.read_u32()
        reader.read_u32()
        size = reader.read_u32()
        reader.read_u32()
        return cls(addr,size, type)


class ExHeader:
    def __init__(self, text, rodata, data, bss):
        self.text = text
        self.rodata = rodata
        self.data = data
        self.bss = bss

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "ExHeader":
        reader.seek(0x10)
        text = CTRSectionInfo.from_reader(reader, CTRSectionType.TEXT)
        rodata = CTRSectionInfo.from_reader(reader, CTRSectionType.RODATA)
        data = CTRSectionInfo.from_reader(reader, CTRSectionType.DATA)
        bss = CTRSectionInfo(data.addr + data.size, reader.read_u32())
        return cls(text, rodata, data, bss)


def get_name(data: bytes, off: int) -> str:
    end = data.index(b'\x00', off)
    return data[off:end].decode('utf-8')


def find_bytes(data: bytes, pattern: bytes, mask: bytes, start: int = 0) -> int:
    length = len(pattern)
    for i in range(start, len(data) - length + 1):
        if all((data[i + j] & mask[j]) == (pattern[j] & mask[j]) for j in range(length)):
            return i
    return -1


def find_all_bytes(data: bytes, pattern: bytes, mask: Bitmask):
    found = []
    start = 0
    while start >= 0:
        start = find_bytes(data, pattern, mask.mask, start)
        if start >= 0:
            found.append(start)
            start += 1
    return found
