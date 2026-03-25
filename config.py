"""cc.yaml configuration parser for compiler settings."""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml


@dataclass
class CompileSettings:
    """Compiler and flags for a single source file."""
    cc: str
    flags: List[str] = field(default_factory=list)


@dataclass
class BinaryConfig:
    """Configuration for a single binary (code.bin or a .cro module)."""
    name: str
    ignored: List[str] = field(default_factory=list)
    presets: Dict[str, List[str]] = field(default_factory=dict)
    per_file: Dict[str, CompileSettings] = field(default_factory=dict)


class ProjectConfig:
    """Full project configuration parsed from cc.yaml."""

    def __init__(self, default: CompileSettings,
                 presets: Dict[str, CompileSettings],
                 binaries: Dict[str, BinaryConfig]):
        self.default = default
        self.presets = presets
        self.binaries = binaries

    @classmethod
    def from_yaml(cls, path: Path) -> "ProjectConfig":
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        # Parse default
        default_data = data.get("default", {})
        default = CompileSettings(
            cc=default_data.get("cc", ""),
            flags=list(default_data.get("flags", [])),
        )

        # Parse presets
        presets = {}
        for name, preset_data in data.get("presets", {}).items():
            presets[name] = CompileSettings(
                cc=preset_data.get("cc", default.cc),
                flags=list(preset_data.get("flags", default.flags)),
            )

        # Parse per-binary configs
        reserved_keys = {"default", "presets"}
        binaries = {}
        for key, value in data.items():
            if key in reserved_keys:
                continue
            if not isinstance(value, dict):
                continue

            bin_config = BinaryConfig(name=key)

            # Ignored files
            bin_config.ignored = list(value.get("ignored", []))

            # Preset assignments (preset_name -> list of file patterns)
            bin_presets = value.get("presets", {})
            if isinstance(bin_presets, dict):
                for preset_name, file_list in bin_presets.items():
                    if isinstance(file_list, list):
                        bin_config.presets[preset_name] = file_list

            # Per-file overrides: any key that looks like a source file
            for file_key, file_val in value.items():
                if file_key in ("ignored", "presets"):
                    continue
                if isinstance(file_val, dict) and "cc" in file_val:
                    bin_config.per_file[file_key] = CompileSettings(
                        cc=file_val["cc"],
                        flags=list(file_val.get("flags", [])),
                    )

            binaries[key] = bin_config

        return cls(default, presets, binaries)

    def is_ignored(self, binary_name: str, src_relative: str) -> bool:
        """Check if a source file is in the ignore list for a binary.
        Explicit per-file or preset entries do NOT override wildcard ignores.
        Wildcards in the ignore list always take precedence."""
        bin_cfg = self.binaries.get(binary_name)
        if bin_cfg is None:
            return False
        for pattern in bin_cfg.ignored:
            if fnmatch.fnmatch(src_relative, pattern):
                return True
        return False

    def get_compile_settings(self, binary_name: str, src_relative: str) -> CompileSettings:
        """Resolve compiler settings for a source file.

        Priority (highest to lowest):
          1. Explicit per-file entry (exact filename match)
          2. Preset assignment (by filename or wildcard)
          3. Default settings
        """
        bin_cfg = self.binaries.get(binary_name)

        # 1. Per-file override (exact match on filename)
        if bin_cfg:
            src_basename = Path(src_relative).name
            if src_basename in bin_cfg.per_file:
                return bin_cfg.per_file[src_basename]
            if src_relative in bin_cfg.per_file:
                return bin_cfg.per_file[src_relative]

        # 2. Preset match
        if bin_cfg:
            for preset_name, file_patterns in bin_cfg.presets.items():
                for pattern in file_patterns:
                    if fnmatch.fnmatch(src_relative, pattern) or \
                       fnmatch.fnmatch(Path(src_relative).name, pattern):
                        if preset_name in self.presets:
                            return self.presets[preset_name]

        # 3. Default
        return self.default

    def get_binary_config(self, binary_name: str) -> Optional[BinaryConfig]:
        return self.binaries.get(binary_name)
