"""Binary I/O utilities and common types for 3DS binary handling."""

import io
import struct
from enum import IntEnum
from pathlib import Path
from typing import Protocol


class RelocationType(IntEnum):
    R_ARM_ABS32 = 2
    R_ARM_REL32 = 3
    R_ARM_THM_CALL = 10
    R_ARM_CALL = 28
    R_ARM_JUMP24 = 29
    R_ARM_THM_JUMP24 = 30
    R_ARM_TARGET1 = 38
    R_ARM_THM_JUMP11 = 102
    R_ARM_THM_JUMP8 = 103


class Writable(Protocol):
    def write(self, writer: "BinaryWriter") -> None: ...


class WritableBytes:
    def __init__(self, data: bytes):
        self.data = data

    def write(self, writer: "BinaryWriter"):
        writer.write_bytes(self.data)

    def __len__(self):
        return len(self.data)


class WritableStr:
    def __init__(self, s: str):
        self.s = s

    def write(self, writer: "BinaryWriter"):
        writer.write_bytes(self.s.encode("utf-8"))
        writer.write_u8(0)

    def __len__(self):
        return len(self.s)


class BinaryReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    @classmethod
    def from_path(cls, path: Path) -> "BinaryReader":
        return cls(path.read_bytes())

    def seek(self, pos: int):
        self._pos = pos

    def tell(self) -> int:
        return self._pos

    def read_bytes(self, n: int) -> bytes:
        result = self._data[self._pos : self._pos + n]
        self._pos += n
        return result

    def read_u8(self) -> int:
        val = self._data[self._pos]
        self._pos += 1
        return val

    def read_u16(self) -> int:
        val = struct.unpack_from("<H", self._data, self._pos)[0]
        self._pos += 2
        return val

    def read_u32(self) -> int:
        val = struct.unpack_from("<I", self._data, self._pos)[0]
        self._pos += 4
        return val

    def read_str(self) -> str:
        end = self._data.index(0, self._pos)
        s = self._data[self._pos : end].decode("utf-8")
        self._pos = end + 1
        return s

    def __len__(self):
        return len(self._data)


class BinaryWriter:
    def __init__(self):
        self._buf = io.BytesIO()

    def seek(self, pos: int):
        self._buf.seek(pos)

    def tell(self) -> int:
        return self._buf.tell()

    def write_bytes(self, data: bytes):
        self._buf.write(data)

    def write_u8(self, val: int):
        self._buf.write(struct.pack("<B", val))

    def write_u16(self, val: int):
        self._buf.write(struct.pack("<H", val))

    def write_u32(self, val: int):
        self._buf.write(struct.pack("<I", val))

    def getvalue(self) -> bytes:
        return self._buf.getvalue()
