# 3DS-Decomp-Pipeline

A Python-based build pipeline for decompiling Nintendo 3DS titles.
Handles binary splitting, compilation, object comparison, linking,
and binary recreation — with progress tracking via
[objdiff](https://github.com/encounter/objdiff) and
[decomp.dev](https://decomp.dev).

## Usage

```
python main.py <working_dir> [options]
```
See below for complete information

## Overview

The pipeline takes original `code.bin` and `.cro` module binaries,
together with the `exheader.bin`, splits them into individual
ELF `.o` files based on Ghidra-exported symbol lists, compiles
decompiled source files, compares them against the split originals,
and optionally links everything back into a byte-identical binary.

The high-level flow of this program is:

1. **Split** — Divide each original binary into per-symbol ELF object
    files using exported symbol `csv` files.
2. **Compile** — Build decompiled `.c`/`.cpp` sources with compatible compiler.
3. **Compare** — Match compiled objects against their split counterparts
    (byte-level comparison with relocation masking).
4. **Link** (optional) — Combine matching compiled objects and unmatched
    split objects via `ld` (or compatible linker).
5. **Recreate** (optional) — Produce the final binary with `objcopy`;
    for CRO modules, reconstruct the full CRO container including SHA-256 hashes.
6. **Verify** (optional) — SHA-256 hash check against the original binary.

An `objdiff.json` configuration is generated for decomp.dev progress tracking.

## Directory Structure

The pipeline expects the following layout relative to the working directory:

```
working_dir/
├── orig/           # Original binaries (code.bin, *.cro, exheader)
├── src/            # Decompiled source files
│   ├── code.bin/   #  Sources for the main executable
│   └── *.cro/      #  Sources for each CRO module
├── symbols/        # Ghidra-exported symbol CSVs (one per binary, named to match - e.g. code.bin.csv)
├── tools/          # Build tools
│   ├── *cc         #   Necessary compilers (see cc.yaml)
│   ├── ld          #   arm-none-eabi-ld
│   └── objcopy     #   arm-none-eabi-objcopy
├── cc.yaml         # Compiler configuration (see below)
├── build/          # (generated) Compiled object files
├── split/          # (generated) Split object files from originals
└── out/            # (generated) Final linked/recreated binaries
```

## Symbol CSV Format

Symbol files in `symbols/` are Ghidra-style CSVs with the following columns:

| Column     | Description                                      |
|------------|--------------------------------------------------|
| `Name`     | Fully qualified symbol name                      |
| `Location` | Hex address in the original binary               |
| `Mode`     | ARM/Thumb mapping symbol (`$a`, `$t`, or `$d`)   |
| `Size`     | Hex size of the symbol                           |

It may be helpful to use my [Ghidra Script](https://github.com/AlgebraManiacABC/3ds-Ghidra-Scripts-Java/blob/main/ExportSymbols.java)
for exporting these files. It was custom-built for this purpose.

Symbol addresses are stored as absolute addresses; the pipeline subtracts
each binary's base address automatically. For `code.bin`, the base address
is `0x100000`; for CRO modules, it is the text section offset within the
CRO file (most often `0x180`).

## Compiler Configuration (`cc.yaml`)

A YAML file that maps source filenames to compiler settings. A `default` key provides fallback settings. Per-binary sections can override on a per-file basis and specify an `ignored` glob list.

```yaml
default:
  cc: gcc  # Path relative to tools/
  flags:
    - --cpu=MPCore
    - -O2
    # ... etc.

code.bin:
  ignored: # Won't compile or link these
    - todo/*.c # Will rglob match within code.bin/src/*
    - whatsthis.c # Also works with individual files

  some_special_file.cpp:
    cc: g++
    flags: # Note that these flags replace those from default
      - --cpu=MPCore
      - -O3

ModuleX.cro:
  # ... etc.
```

### Options

| Flag | Description                                                          |
|------|----------------------------------------------------------------------|
| `--recreate-binaries` | Link objects and recreate original binaries (with hash verification) |
| `--compile-only` | Only compile sources, skip linking                                   |
| `--skip-split` | Skip regenerating split `.o` files (use existing ones)               |
| `--skip-compile` | Skip compilation, use existing `.o` files from `build/`              |
| `--use-splits-only` | Skip compilation entirely; link only from split binaries             |
| `--ignore-compiler-errors` | Continue past compiler failures (will tell you what errored)         |
| `--verbose-compilation` | Print full compiler commands                                         |
| `--progress-reports` / `--no-progress-reports` | Toggle progress output (default: on)                                 |
**NOTE:** No "cleaning" occurs between runs, so be sure to clean out
your directories if you are having issues.

### Typical Workflows

**First run (generate splits + compile + compare):**
```
python main.py ./project
```

**Iterate on source code (splits already exist):**
```
python main.py ./project --skip-split
```

**Full round-trip verification:**
```
python main.py ./project --skip-split --recreate-binaries
```

## Module Architecture

| File | Role |
|------|------|
| `main.py` | Entry point; orchestrates the full pipeline |
| `files.py` | Gathers binaries, symbols, sources, and compiler config; defines `CTRPipelineInfo` |
| `split.py` | Splits original binaries into per-symbol ELF `.o` files |
| `pipeline.py` | Compilation, objdiff unit generation, linking, and binary recreation |
| `elf.py` | ELF reading/writing; constructs minimal ARM ELF objects with `.text`, `.symtab`, `.strtab` |
| `ctrtype.py` | 3DS-specific types: CRO parsing/writing, ExHeader, segment offsets, import/export tables |
| `util.py` | Binary reader/writer, relocation types, bitmask comparison, helpers |

## CRO Module Handling

CRO (CTR Relocatable Object) files are the 3DS equivalent of shared libraries
(think `.dll`, `.so`). The pipeline:

- Parses the full CRO structure (header, text/data sections,
    import/export tables, relocations, segment tables).
- Extracts text + data sections for splitting and comparison.
- On recreation, replaces the text section with linked output and
    recomputes the four SHA-256 region hashes that the CRO format requires.
- Preserves all non-code sections (import/export tables, relocations,
module metadata) from the original.

## Object Comparison

Compiled objects are compared against split originals at the byte level.
A `Bitmask` system masks out bytes affected by relocations (e.g., `R_ARM_CALL`
branch targets) so that only instruction encodings and non-relocated data
are compared. If a compiled object's `.text` is larger than the corresponding
split, the pipeline attempts to merge consecutive split objects to form
an equivalent comparison unit.

## Dependencies

- Python 3.10+ (`match` statements, `typing_extensions`)
- PyYAML
- A compatible compiler collection of your choosing
- devkitARM (`arm-none-eabi-ld`, `arm-none-eabi-objcopy`) - alternatively,
any `ld` and `objcopy` should work

## Legal

This project is based on clean-room reverse engineering of legally
obtained retail cartridges. No original binaries or assembly files
are committed to the repository, nor should any user commit such
file to any public repository.

This software pipeline comes AS IS, with NO WARRANTY, express or implied.
