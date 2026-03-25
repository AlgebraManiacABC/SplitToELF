# 3DS Decompilation Pipeline

A Python-based pipeline for decompiling Nintendo 3DS binaries (`code.bin` and `.cro` modules). It splits original binaries into per-symbol ELF objects, compiles user-provided C/C++ source files, and links them together to recreate the original binaries or produce modded versions.

## Requirements

- Python 3.10+
- `pyelftools` (`pip install pyelftools`)
- `pyyaml` (`pip install pyyaml`)
- ARM cross-compilation toolchain (compilers, `ld`, `objcopy`) provided in `/tools/`

## Project Structure

```
project_root/
├── orig/               # Original binaries (read-only, never modified)
│   ├── code.bin        # Main ARM executable
│   ├── exheader.bin    # Section layout for code.bin
│   └── *.cro           # Optional modules (may be nested in subdirectories)
├── src/                # User-provided C/C++ source files
│   ├── code.bin/       # Sources for the main binary
│   │   ├── func1.c
│   │   └── subdir/func2.c
│   └── ModuleName.cro/ # Sources for a specific module
│       └── func3.c
├── include/            # Optional shared include directory
├── symbols/            # Symbol CSVs (one per binary)
│   ├── code.bin.csv
│   └── ModuleName.cro.csv
├── tools/              # Cross-compilation tools
│   ├── armcc_4.1_1049  # Compiler(s) referenced in cc.yaml
│   ├── ld              # ARM linker
│   └── objcopy         # ARM objcopy
├── cc.yaml             # Compilation configuration
├── main.py             # Pipeline entry point
└── pipeline/           # Pipeline implementation
```

### Directory Naming

Source subdirectories under `/src/` must match the binary filenames found in `/orig/` exactly (e.g., `src/code.bin/`, `src/ModuleName.cro/`). The internal structure within each subdirectory is flexible.

## Usage

```bash
python main.py <project_dir> [options]
```

### Modes

At least one mode must be specified. If none is given, `--match` is used by default.

| Flag | Description |
|------|-------------|
| `--match` | Recreate exact binary matches. Compiled objects must match their split counterparts. SHA256 verification against originals. |
| `--mod` | Create modded binaries. Compiled objects are used regardless of whether they match. |
| `--objdiff` | Create base/target ELF pairs for use with [objdiff](https://github.com/encounter/objdiff). |

Multiple modes can be combined (e.g., `--match --objdiff`).

### Options

| Flag | Description |
|------|-------------|
| `--binary <name>`, `-b` | Process only one binary (e.g., `code.bin` or `ModuleName.cro`) |
| `--strict` | In match mode, abort immediately on any object mismatch |
| `--lazy` | Skip splitting symbols that have compiled equivalents (faster builds) |
| `--verbose`, `-v` | Enable debug-level logging |
| `--quiet`, `-q` | Suppress all output except errors |

### Examples

```bash
# Full match build for all binaries
python main.py ./myproject --match

# Objdiff mode for just code.bin
python main.py ./myproject --objdiff --binary code.bin

# Strict match + lazy splitting
python main.py ./myproject --match --strict --lazy

# Modded build with verbose output
python main.py ./myproject --mod -v

# Combined match + objdiff
python main.py ./myproject --match --objdiff
```

## Output Directories

| Directory | Contents |
|-----------|----------|
| `split/<binary>/` | Per-symbol ELF objects split from originals |
| `build/<binary>/` | Compiled user source objects |
| `out/<binary>` | Final output binaries (match/mod modes) |
| `out/base/<binary>` | Objdiff base: linked compiled objects only |
| `out/target/<binary>` | Objdiff target: original binary as ELF |

## cc.yaml Configuration

The `cc.yaml` file controls how each source file is compiled. It has four levels of configuration:

### Structure

```yaml
# Default compiler settings (applied when no override matches)
default:
  cc: armcc_4.1_1049
  flags: []

# Named presets (reusable flag sets)
presets:
  thumb:
    cc: armcc_4.1_1049
    flags: [--thumb]
  heavy:
    cc: armcc_4.1_1049
    flags: [-O3]

# Per-binary configuration
code.bin:
  # Files to exclude from compilation (supports glob wildcards)
  ignored:
    - ghidra/*
    - wip/*
    - broken_file.c

  # Assign presets to files (supports glob wildcards)
  presets:
    thumb:
      - FUN_00100794.c
      - subdir/*.c
    heavy:
      - Item_GetID.c

  # Per-file explicit overrides (highest priority)
  Item_Clear.c:
    cc: armcc_4.1_1049
    flags: [-O3, --cpu=MPCore]

ModuleName.cro:
  # Same structure as code.bin section
  ...
```

### Priority Order (highest to lowest)

1. **Per-file explicit override** — exact filename match in the binary's section
2. **Preset assignment** — filename or wildcard match in a preset's file list
3. **Default settings** — the `default:` block

### Ignore List Behavior

Wildcard patterns in the `ignored` list always take precedence. If a file matches any ignore pattern, it is excluded from compilation regardless of whether it also appears in a preset or per-file override. This is by design: the ignore list is intended as a hard exclusion mechanism.

## Symbol CSV Format

Each binary needs a CSV file in `/symbols/` named `<binary_name>.csv`:

```csv
Location,Name,Mode,Size,Segment
0x00100000,_start,ARM,64,text
0x00100040,main,ARM,256,text
0x00200000,string_table,DATA,1024,rodata
0x00300000,global_var,DATA,4,data
```

| Column | Description |
|--------|-------------|
| `Location` | Hex address of the symbol. For `code.bin`: VMA-based (typically 0x100000+). For `.cro` modules: file offset within the module. |
| `Name` | Symbol name (must be unique within a binary) |
| `Mode` | `ARM`, `THUMB`, or `DATA` |
| `Size` | Declared symbol size in bytes (hex or decimal) |
| `Segment` | Section: `text`, `rodata`, `data`, or `bss` |

### Address Bases

- **code.bin**: Addresses are virtual memory addresses. The base address comes from `exheader.bin` (typically `0x100000`).
- **.cro modules**: Addresses are file offsets within the `.cro` file. The base comes from the module's own header (typically the text section starts around `0x180`).

## Pipeline Stages

### 1. Split (`/orig/` → `/split/`)

The original binary is divided into one ELF relocatable object (`.o`) per symbol, based on the symbol CSV. Each split object contains the raw bytes from the symbol's address to the next symbol (or section end), ensuring complete coverage without gaps.

With `--lazy`, symbols that have a compiled equivalent are skipped during splitting.

### 2. Compile (`/src/` → `/build/`)

User C/C++ files are compiled using the settings from `cc.yaml`. The compiler executable must be present in `/tools/`. Include files from `/include/` are automatically added to the include path.

### 3. Compare (match mode only)

Each compiled object is compared byte-for-byte against the corresponding region in the original binary. Mismatched objects fall back to their split counterparts. With `--strict`, any mismatch aborts the build.

### 4. Link (`/split/` + `/build/` → `/out/`)

A linker script is generated that places all symbols at their correct virtual addresses. Objects are linked using the user's `/tools/ld`, then converted to a flat binary with `/tools/objcopy`.

For `.cro` modules, the pipeline extracts linked section bytes and reconstructs the CRO format (including hash recomputation) using the original header as a template.

### 5. Verify (match mode only)

The output binary is compared against the original via SHA256. A hash mismatch here indicates a pipeline bug (not a source code issue), since mismatched compiled objects are already handled in stage 3.

### Objdiff Mode

When `--objdiff` is used, the pipeline produces:

- **Target**: The original binary converted to a single ELF executable with all sections and symbols exported. No splitting is needed.
- **Base**: Only the compiled objects, linked together. This will be smaller than the target while decompilation is in progress.
- **objdiff.json**: Configuration file pointing to base/target paths for each binary.

## CRO Module Handling

`.cro` modules contain a CRO header with hash regions, segment tables, import/export tables, and relocation information. The pipeline only recreates the executable sections (`.text`, `.data`); all header metadata is copied from the original module. SHA256 hashes for the four header regions are recomputed automatically.

Creating CRO header information from scratch (import/export tables, relocations, etc.) is out of scope for this pipeline. For full module reconstruction, a dedicated CRO builder would be needed.

## Modded Binary Caveats

When using `--mod`, compiled objects that differ from the original are linked in regardless. This can cause issues because split objects may contain hardcoded addresses or branch targets that become invalid when surrounding code shifts. Use modded builds with caution — they are best suited for small, isolated changes that don't affect the binary's layout.
