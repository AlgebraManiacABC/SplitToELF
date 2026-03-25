"""3DS binary format parsing: ExHeader, CRO modules, and CTRBinary."""

import hashlib
from enum import IntEnum
from pathlib import Path
from typing import List, Optional, Tuple

from pipeline.util import BinaryReader, BinaryWriter, WritableBytes


class SectionType(IntEnum):
    TEXT = 0
    RODATA = 1
    DATA = 2
    BSS = 3


SECTION_NAMES = {
    SectionType.TEXT: ".text",
    SectionType.RODATA: ".rodata",
    SectionType.DATA: ".data",
    SectionType.BSS: ".bss",
}


class SectionInfo:
    """Describes a section's location and size within a binary."""

    def __init__(self, offset: int, size: int, sec_type: SectionType):
        self.offset = offset
        self.size = size
        self.type = sec_type

    @property
    def name(self) -> str:
        return SECTION_NAMES[self.type]

    @property
    def end(self) -> int:
        return self.offset + self.size

    def contains(self, addr: int) -> bool:
        return self.offset <= addr < self.end


class ExHeader:
    """Parses the 3DS exheader.bin to extract section layout for code.bin."""

    def __init__(self, text: SectionInfo, rodata: SectionInfo,
                 data: SectionInfo, bss: SectionInfo):
        self.text = text
        self.rodata = rodata
        self.data = data
        self.bss = bss
        self.sections = [text, rodata, data, bss]

    @classmethod
    def from_bytes(cls, data: bytes) -> "ExHeader":
        reader = BinaryReader(data)
        reader.seek(0x10)

        # .text: address, num_pages, size, num_pages
        text_addr = reader.read_u32()
        reader.read_u32()  # num pages
        text_size = reader.read_u32()
        reader.read_u32()  # num pages

        # .rodata
        rodata_addr = reader.read_u32()
        reader.read_u32()
        rodata_size = reader.read_u32()
        reader.read_u32()

        # .data
        data_addr = reader.read_u32()
        reader.read_u32()
        data_size = reader.read_u32()
        reader.read_u32()

        # .bss size
        bss_size = reader.read_u32()

        text = SectionInfo(text_addr, text_size, SectionType.TEXT)
        rodata = SectionInfo(rodata_addr, rodata_size, SectionType.RODATA)
        data = SectionInfo(data_addr, data_size, SectionType.DATA)
        bss = SectionInfo(data_addr + data_size, bss_size, SectionType.BSS)

        return cls(text, rodata, data, bss)

    @classmethod
    def from_path(cls, path: Path) -> "ExHeader":
        return cls.from_bytes(path.read_bytes())

    @property
    def base_address(self) -> int:
        return self.text.offset

    def section_for_address(self, addr: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.contains(addr):
                return sec
        return None


class CROHeader:
    """Parsed CRO module header with section info and metadata."""

    MAGIC = b"CRO0"
    HASH_REGION_SIZE = 0x80

    def __init__(self, raw_header: bytes, sections: List[SectionInfo],
                 text_off: int, text_size: int,
                 data_off: int, data_size: int,
                 module_name: str, cro_size: int, bss_size: int):
        self.raw_header = raw_header  # Full header bytes for reconstruction
        self.sections = sections
        self.text_off = text_off
        self.text_size = text_size
        self.data_off = data_off
        self.data_size = data_size
        self.module_name = module_name
        self.cro_size = cro_size
        self.bss_size = bss_size

    @classmethod
    def from_bytes(cls, data: bytes) -> "CROHeader":
        reader = BinaryReader(data)

        # Skip hash area, read magic
        reader.seek(0x80)
        magic = reader.read_bytes(4)
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid CRO magic: {magic!r}, expected {cls.MAGIC!r}")

        reader.read_bytes(0xC)  # misc_info
        cro_size = reader.read_u32()
        bss_size = reader.read_u32()
        reader.read_bytes(0x8)  # misc_info_2

        # Skip SegmentOffset fields (nnroCO, OnLoad, OnExit, OnUnresolved)
        for _ in range(4):
            reader.read_u32()

        # Read OffSize pairs for text, data
        text_off = reader.read_u32()
        text_size = reader.read_u32()
        data_off = reader.read_u32()
        data_size = reader.read_u32()

        # Module name
        mod_name_off = reader.read_u32()
        mod_name_size = reader.read_u32()

        # Segment table
        seg_table_off = reader.read_u32()
        seg_table_count = reader.read_u32()

        # Read module name
        reader.seek(mod_name_off)
        module_name = reader.read_bytes(mod_name_size).decode("utf-8").rstrip("\x00")

        # Read segment table
        reader.seek(seg_table_off)
        sections = []
        for _ in range(seg_table_count):
            sec_off = reader.read_u32()
            sec_size = reader.read_u32()
            sec_type = SectionType(reader.read_u32())
            sections.append(SectionInfo(sec_off, sec_size, sec_type))

        return cls(
            raw_header=data,
            sections=sections,
            text_off=text_off,
            text_size=text_size,
            data_off=data_off,
            data_size=data_size,
            module_name=module_name,
            cro_size=cro_size,
            bss_size=bss_size,
        )

    @classmethod
    def from_path(cls, path: Path) -> "CROHeader":
        return cls.from_bytes(path.read_bytes())

    @property
    def base_address(self) -> int:
        """Base address for CRO: the text section offset in the file."""
        return self.text_off

    def section_for_address(self, addr: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.contains(addr):
                return sec
        return None


class CTRBinary:
    """Represents a 3DS binary (code.bin or .cro module) with its section layout."""

    def __init__(self, name: str, raw_data: bytes, base_address: int,
                 sections: List[SectionInfo],
                 cro_header: Optional[CROHeader] = None):
        self.name = name
        self.raw_data = raw_data
        self.base_address = base_address
        self.sections = sections
        self.cro_header = cro_header
        self.is_module = cro_header is not None

    @classmethod
    def from_code_bin(cls, path: Path, exheader: ExHeader) -> "CTRBinary":
        data = path.read_bytes()
        return cls(
            name=path.name,
            raw_data=data,
            base_address=exheader.base_address,
            sections=exheader.sections,
        )

    @classmethod
    def from_cro(cls, path: Path) -> "CTRBinary":
        data = path.read_bytes()
        header = CROHeader.from_bytes(data)
        return cls(
            name=path.name,
            raw_data=data,
            base_address=header.base_address,
            sections=header.sections,
            cro_header=header,
        )

    @classmethod
    def from_path(cls, path: Path, exheader: Optional[ExHeader] = None) -> "CTRBinary":
        if path.suffix == ".cro" or ".cro" in path.name:
            return cls.from_cro(path)
        else:
            if exheader is None:
                raise ValueError(f"ExHeader required for code.bin: {path}")
            return cls.from_code_bin(path, exheader)

    def addr_to_file_offset(self, addr: int) -> int:
        """Convert a virtual/CSV address to a file offset."""
        if self.is_module:
            # For CRO modules, CSV addresses are file offsets directly
            return addr
        else:
            # For code.bin, CSV addresses are VMA-based
            return addr - self.base_address

    def read_bytes_at(self, addr: int, size: int) -> bytes:
        """Read bytes from the binary at a given address."""
        offset = self.addr_to_file_offset(addr)
        return self.raw_data[offset : offset + size]

    def section_for_address(self, addr: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.contains(addr):
                return sec
        return None

    def section_bytes(self, sec: SectionInfo) -> bytes:
        """Get the raw bytes for a section."""
        if self.is_module:
            return self.raw_data[sec.offset : sec.offset + sec.size]
        else:
            file_off = sec.offset - self.base_address
            return self.raw_data[file_off : file_off + sec.size]

    def get_text_bytes(self) -> bytes:
        for sec in self.sections:
            if sec.type == SectionType.TEXT:
                return self.section_bytes(sec)
        return b""

    def get_rodata_bytes(self) -> bytes:
        for sec in self.sections:
            if sec.type == SectionType.RODATA:
                return self.section_bytes(sec)
        return b""

    def get_data_bytes(self) -> bytes:
        for sec in self.sections:
            if sec.type == SectionType.DATA:
                return self.section_bytes(sec)
        return b""

    def reconstruct_cro(self, section_bytes_map: dict) -> bytes:
        """Reconstruct a CRO module with new section bytes.

        Parameters
        ----------
        section_bytes_map : dict
            Maps section name (e.g. ".text", ".rodata", ".data") to bytes.
            Only the segment table section ranges are replaced; the rest of the
            CRO file (headers, tables, module name, etc.) is preserved.
        """
        if not self.is_module or self.cro_header is None:
            raise ValueError("Can only reconstruct CRO modules")

        hdr = self.cro_header
        buf = bytearray(self.raw_data)

        # Replace only the segment-table-defined section ranges
        for sec in hdr.sections:
            if sec.type == SectionType.BSS:
                continue  # BSS has no file data
            sec_name = SECTION_NAMES.get(sec.type)
            if sec_name and sec_name in section_bytes_map:
                replacement = section_bytes_map[sec_name]
                # Only replace up to the segment table's section size
                replace_len = min(len(replacement), sec.size)
                buf[sec.offset : sec.offset + replace_len] = replacement[:replace_len]

        # Recompute SHA256 hashes (4 regions)
        # Find actual module_name offset from the header
        reader = BinaryReader(bytes(buf))
        reader.seek(0x80 + 4 + 0xC + 4 + 4 + 0x8 + 4 * 4 + 4 * 2 + 4 * 2)
        mod_name_off_actual = reader.read_u32()

        hash_regions = [
            (0x80, hdr.text_off),
            (hdr.text_off, mod_name_off_actual),
            (mod_name_off_actual, hdr.data_off),
            (hdr.data_off, hdr.data_off + hdr.data_size),
        ]

        hash_offset = 0
        for start, end in hash_regions:
            region_bytes = bytes(buf[start:end])
            sha = hashlib.sha256(region_bytes).digest()
            buf[hash_offset : hash_offset + 32] = sha
            hash_offset += 32

        # Pad to cro_size
        if len(buf) < hdr.cro_size:
            buf.extend(b"\xCC" * (hdr.cro_size - len(buf)))
        elif len(buf) > hdr.cro_size:
            buf = buf[: hdr.cro_size]

        return bytes(buf)

    def sha256(self) -> str:
        """SHA256 hash of the original binary data."""
        return hashlib.sha256(self.raw_data).hexdigest()
