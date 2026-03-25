"""Symbol table parsing from CSV files."""

import csv
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SymbolMode(Enum):
    ARM = "ARM"
    THUMB = "THUMB"
    DATA = "DATA"

    @classmethod
    def from_str(cls, s: str) -> "SymbolMode":
        s = s.strip().strip('"').strip()
        s_upper = s.upper()
        if s_upper in ("ARM", "A", "CODE32") or s == "$a":
            return cls.ARM
        elif s_upper in ("THUMB", "T", "CODE16") or s == "$t":
            return cls.THUMB
        elif s_upper in ("DATA", "D", "OBJECT") or s == "$d":
            return cls.DATA
        else:
            raise ValueError(f"Unknown symbol mode: {s!r}")


class SymbolSegment(Enum):
    TEXT = "text"
    RODATA = "rodata"
    DATA = "data"
    BSS = "bss"
    RAM = "ram"  # External RAM symbols — outside the binary, skipped by pipeline

    @classmethod
    def from_str(cls, s: str) -> "SymbolSegment":
        s = s.strip().strip('"').strip().lower().lstrip(".")
        if s in ("text", "0"):
            return cls.TEXT
        elif s in ("rodata", "1"):
            return cls.RODATA
        elif s in ("data", "2"):
            return cls.DATA
        elif s in ("bss", "3"):
            return cls.BSS
        elif s == "ram":
            return cls.RAM
        else:
            raise ValueError(f"Unknown segment: {s!r}")

    @property
    def section_name(self) -> str:
        if self == SymbolSegment.RAM:
            return ".bss"  # fallback, but RAM symbols should be filtered
        return f".{self.value}"


@dataclass
class Symbol:
    address: int
    name: str
    mode: SymbolMode
    size: int
    segment: SymbolSegment

    @property
    def is_code(self) -> bool:
        return self.mode in (SymbolMode.ARM, SymbolMode.THUMB)

    @property
    def is_thumb(self) -> bool:
        return self.mode == SymbolMode.THUMB

    @property
    def section_name(self) -> str:
        return self.segment.section_name


class SymbolTable:
    """Collection of symbols for a single binary, sorted by address."""

    def __init__(self, binary_name: str, symbols: List[Symbol]):
        self.binary_name = binary_name
        # Filter out RAM symbols (addresses outside the binary)
        filtered = [s for s in symbols if s.segment != SymbolSegment.RAM]
        self.symbols = sorted(filtered, key=lambda s: s.address)
        self._by_name: Dict[str, Symbol] = {s.name: s for s in self.symbols}
        self._by_address: Dict[int, Symbol] = {s.address: s for s in self.symbols}

    @classmethod
    def from_csv(cls, path: Path, binary_name: str) -> "SymbolTable":
        symbols = []
        with open(path, "r", newline="") as f:
            reader = csv.DictReader(f)
            has_segment = "Segment" in (reader.fieldnames or [])
            for row_num, row in enumerate(reader, start=2):
                # Skip malformed/truncated rows
                if row.get("Mode") is None or row.get("Size") is None:
                    logger.warning("Skipping malformed row %d in %s", row_num, path)
                    continue
                addr_str = row["Location"].strip().strip('"')
                # Always parse as hex (with or without 0x prefix)
                addr = int(addr_str, 16)
                name = row["Name"].strip().strip('"')
                mode = SymbolMode.from_str(row["Mode"])
                size_str = row["Size"].strip().strip('"')
                size = int(size_str, 16) if size_str else 0
                if has_segment:
                    segment = SymbolSegment.from_str(row["Segment"])
                else:
                    # Default: infer from mode — code symbols go to .text,
                    # data symbols go to .text as well for CRO modules
                    # (the splitter will clamp to actual section boundaries)
                    segment = SymbolSegment.TEXT
                symbols.append(Symbol(addr, name, mode, size, segment))
        return cls(binary_name, symbols)

    def get_by_name(self, name: str) -> Optional[Symbol]:
        return self._by_name.get(name)

    def get_by_address(self, addr: int) -> Optional[Symbol]:
        return self._by_address.get(addr)

    def symbols_in_segment(self, segment: SymbolSegment) -> List[Symbol]:
        return [s for s in self.symbols if s.segment == segment]

    def get_split_range(self, sym: Symbol, section_end: int) -> int:
        """Get the byte range for a symbol's split: from its address to the
        next symbol in the same segment, or to the section end."""
        seg_syms = self.symbols_in_segment(sym.segment)
        idx = next(i for i, s in enumerate(seg_syms) if s.address == sym.address)
        if idx + 1 < len(seg_syms):
            return seg_syms[idx + 1].address - sym.address
        else:
            return section_end - sym.address

    def __len__(self):
        return len(self.symbols)

    def __iter__(self):
        return iter(self.symbols)
