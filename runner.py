"""Pipeline orchestration: discovers project structure and runs all stages."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pipeline.compiler import compile_binary_sources, discover_sources, expand_multi_symbol_objects
from pipeline.config import ProjectConfig
from pipeline.ctr import CTRBinary, ExHeader, SectionType
from pipeline.elf_util import read_elf_symbols
from pipeline.linker import (
    compare_objects,
    create_objdiff_base,
    create_objdiff_target,
    elf_to_binary,
    extract_elf_sections,
    generate_linker_script,
    link_objects,
    verify_sha256,
)
from pipeline.splitter import split_binary, split_binary_chunked, split_object_name
from pipeline.symbols import SymbolTable

logger = logging.getLogger(__name__)


class PipelineMode:
    MATCH = "match"
    MOD = "mod"
    OBJDIFF = "objdiff"


class Project:
    """Represents the full decomp project directory structure."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.orig_dir = self.root / "orig"
        self.src_dir = self.root / "src"
        self.include_dir = self.root / "include"
        self.symbols_dir = self.root / "symbols"
        self.tools_dir = self.root / "tools"
        self.split_dir = self.root / "split"
        self.build_dir = self.root / "build"
        self.out_dir = self.root / "out"
        self.cc_yaml = self.root / "cc.yaml"

    @property
    def ld_path(self) -> Path:
        return self.tools_dir / "ld"

    @property
    def objcopy_path(self) -> Path:
        return self.tools_dir / "objcopy"

    def validate(self) -> List[str]:
        """Check that required directories and files exist. Returns errors."""
        errors = []
        if not self.orig_dir.exists():
            errors.append(f"Missing: {self.orig_dir}")
        if not self.cc_yaml.exists():
            errors.append(f"Missing: {self.cc_yaml}")
        if not self.symbols_dir.exists():
            errors.append(f"Missing: {self.symbols_dir}")
        if not self.tools_dir.exists():
            errors.append(f"Missing: {self.tools_dir}")
        if not self.ld_path.exists():
            errors.append(f"Missing linker: {self.ld_path}")
        if not self.objcopy_path.exists():
            errors.append(f"Missing objcopy: {self.objcopy_path}")
        return errors


def _find_binaries(orig_dir: Path) -> Tuple[Optional[Path], Optional[Path], List[Path]]:
    """Find code.bin, exheader.bin, and .cro modules in /orig/ (recursive)."""
    code_bin = None
    exheader = None
    modules = []

    for p in orig_dir.rglob("*"):
        if not p.is_file():
            continue
        name_lower = p.name.lower()
        if name_lower in ("code.bin", ".code"):
            code_bin = p
        elif name_lower in ("exheader.bin", "extheader.bin"):
            exheader = p
        elif name_lower.endswith(".cro"):
            modules.append(p)

    return code_bin, exheader, sorted(modules)


def _find_symbol_csv(symbols_dir: Path, binary_name: str) -> Optional[Path]:
    """Find the CSV file for a binary in /symbols/.

    Tries multiple naming conventions:
      binary_name.csv         (e.g. code.bin.csv, ModuleFoo.cro.csv)
      stem_only.csv           (e.g. BootMenu.csv for BootMenu.cro)
    """
    # Try exact match: binary_name.csv (e.g., code.bin.csv)
    csv_path = symbols_dir / f"{binary_name}.csv"
    if csv_path.exists():
        return csv_path

    # Try without the binary extension (e.g. BootMenu.csv for BootMenu.cro)
    stem = Path(binary_name).stem
    csv_path = symbols_dir / f"{stem}.csv"
    if csv_path.exists():
        return csv_path

    # Case-insensitive search
    name_lower = binary_name.lower()
    stem_lower = stem.lower()
    for p in symbols_dir.iterdir():
        pname = p.name.lower()
        if pname == f"{name_lower}.csv" or pname == f"{stem_lower}.csv":
            return p
    return None


def _demangle_symbols(mangled_names: List[str]) -> Dict[str, str]:
    """Batch-demangle C++ symbol names using c++filt.

    Returns a dict mapping mangled name -> demangled name.
    """
    import subprocess

    if not mangled_names:
        return {}

    try:
        input_text = "\n".join(mangled_names)
        result = subprocess.run(["c++filt"], input=input_text, capture_output=True,
                                text=True, timeout=10)
        if result.returncode == 0:
            demangled = result.stdout.strip().split("\n")
            return dict(zip(mangled_names, demangled))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return {}


def _strip_params(demangled: str) -> str:
    """Strip parameter list from a demangled C++ symbol name.

    'Boot::LoadSave()' -> 'Boot::LoadSave'
    'GameWork::addCoin(GameWork*, int)' -> 'GameWork::addCoin'
    'operator delete(void*)' -> 'operator delete'
    """
    # Find the first '(' that isn't part of the name
    paren = demangled.find("(")
    if paren > 0:
        return demangled[:paren]
    return demangled


def _demangled_to_csv_name(demangled: str) -> List[str]:
    """Generate candidate CSV names from a demangled C++ symbol.

    Returns a list of possible CSV names to try matching against, most specific first.
    Handles special cases like vtables, typeinfo, etc.
    """
    candidates = []

    # 'vtable for ClassName' -> 'ClassName::vtable'
    if demangled.startswith("vtable for "):
        cls_name = demangled[len("vtable for "):]
        candidates.append(f"{cls_name}::vtable")
    # 'typeinfo for ClassName' -> 'ClassName::typeinfo'
    elif demangled.startswith("typeinfo for "):
        cls_name = demangled[len("typeinfo for "):]
        candidates.append(f"{cls_name}::typeinfo")
    # 'typeinfo name for ClassName' -> 'ClassName::typeinfo_name'
    elif demangled.startswith("typeinfo name for "):
        cls_name = demangled[len("typeinfo name for "):]
        candidates.append(f"{cls_name}::typeinfo_name")
    # 'guard variable for ...' -> skip
    elif demangled.startswith("guard variable for "):
        pass
    # 'construction vtable for ...' -> skip
    elif demangled.startswith("construction vtable for "):
        pass
    # C++ operators: 'operator delete(void*)' -> 'operator.delete', etc.
    elif demangled.startswith("operator "):
        stripped = _strip_params(demangled)  # 'operator delete'
        # CSV convention: 'operator.delete', 'operator.new', 'operator.delete[]'
        op_name = stripped[len("operator "):]  # 'delete', 'new', 'delete[]'
        candidates.append(f"operator.{op_name}")
        # Also try with underscore: 'operator_delete'
        candidates.append(f"operator_{op_name}")
        # Original forms too
        candidates.append(stripped)
    else:
        # Standard function: strip params
        stripped = _strip_params(demangled)
        candidates.append(stripped)
        # Also try the full demangled form
        if demangled != stripped:
            candidates.append(demangled)

    return candidates


def _map_compiled_to_symbols(compiled_objects: Dict[str, Path],
                             sym_table: SymbolTable) -> Tuple[Dict[str, Path], Dict[str, str]]:
    """Map symbol names to compiled object paths by reading ELF exports.

    Only includes symbols that are *defined* in the object (have a non-empty
    section name), not undefined extern references. Supports C++ name demangling
    to match against demangled names in the symbol CSV.

    Also scans *undefined* references from compiled objects and builds
    mangled->CSV mappings for them (vtables, typeinfo, etc.) so that
    PROVIDE directives in the linker script resolve cross-references.

    Returns
    -------
    compiled_symbol_map : dict
        Maps CSV symbol name -> compiled .o path.
    mangled_to_csv : dict
        Maps mangled C++ name -> CSV symbol name (for PROVIDE directives).
    """
    # First pass: collect all ELF symbols (both defined and undefined)
    elf_defined: List[tuple] = []  # (mangled_name, sec_name, obj_path)
    all_undefined: Set[str] = set()  # mangled names referenced but not defined
    for src_rel, obj_path in compiled_objects.items():
        try:
            symbols = read_elf_symbols(str(obj_path))
            for sym_name, _, _, sec_name in symbols:
                if sec_name:
                    elf_defined.append((sym_name, sec_name, obj_path))
                else:
                    # Undefined reference (extern)
                    all_undefined.add(sym_name)
        except Exception as e:
            logger.warning("Could not read symbols from %s: %s", obj_path, e)

    # Try direct match first for defined symbols
    result = {}
    mangled_to_csv: Dict[str, str] = {}
    unmatched = []
    for mangled, sec_name, obj_path in elf_defined:
        if sym_table.get_by_name(mangled) is not None:
            result[mangled] = obj_path
            # No mangling involved — mangled == csv name
        else:
            unmatched.append((mangled, sec_name, obj_path))

    # Demangle unmatched defined symbols and try matching
    if unmatched:
        mangled_names = [m for m, _, _ in unmatched]
        demangled_map = _demangle_symbols(mangled_names)

        for mangled, sec_name, obj_path in unmatched:
            demangled = demangled_map.get(mangled, mangled)
            stripped = _strip_params(demangled)

            matched_csv = None
            if sym_table.get_by_name(stripped) is not None:
                matched_csv = stripped
            elif sym_table.get_by_name(demangled) is not None:
                matched_csv = demangled
            else:
                # Try _demangled_to_csv_name for vtable/typeinfo/operator patterns
                candidates = _demangled_to_csv_name(demangled)
                for candidate in candidates:
                    if sym_table.get_by_name(candidate) is not None:
                        matched_csv = candidate
                        break

            if matched_csv is not None:
                result[matched_csv] = obj_path
                mangled_to_csv[mangled] = matched_csv

    # Second pass: resolve undefined references (extern symbols from compiled objects)
    # These need PROVIDE directives so the linker can resolve them against the binary.
    # Filter to only those not already in mangled_to_csv and not directly in CSV.
    undef_to_resolve = [
        name for name in all_undefined
        if name not in mangled_to_csv and sym_table.get_by_name(name) is None
    ]

    if undef_to_resolve:
        undef_demangled = _demangle_symbols(undef_to_resolve)

        for mangled in undef_to_resolve:
            demangled = undef_demangled.get(mangled, mangled)
            if demangled == mangled:
                continue  # Not a C++ symbol, skip

            # Use _demangled_to_csv_name to generate candidate CSV names
            candidates = _demangled_to_csv_name(demangled)
            for candidate in candidates:
                if sym_table.get_by_name(candidate) is not None:
                    mangled_to_csv[mangled] = candidate
                    logger.debug("Resolved extern %s -> %s (CSV: %s)",
                                mangled, demangled, candidate)
                    break

    return result, mangled_to_csv


def run_pipeline(project: Project, modes: List[str],
                 target_binary: Optional[str] = None,
                 strict: bool = False,
                 lazy: bool = False,
                 verbose: bool = False) -> bool:
    """Run the full decomp pipeline.

    Parameters
    ----------
    project : Project
        The project directory structure.
    modes : list of str
        Pipeline modes to run: 'match', 'mod', 'objdiff'.
    target_binary : str, optional
        If specified, only process this binary (e.g., 'code.bin' or 'Module.cro').
    strict : bool
        If True, abort on any mismatch in match mode.
    lazy : bool
        If True, skip splitting symbols that have compiled equivalents.
    verbose : bool
        Enable verbose output.

    Returns True if all operations succeeded.
    """
    # ── Validate project ──
    errors = project.validate()
    if errors:
        for e in errors:
            logger.error(e)
        return False

    # ── Load config ──
    config = ProjectConfig.from_yaml(project.cc_yaml)

    # ── Discover binaries ──
    code_bin_path, exheader_path, module_paths = _find_binaries(project.orig_dir)

    if code_bin_path is None:
        logger.error("code.bin not found in %s", project.orig_dir)
        return False
    if exheader_path is None:
        logger.error("exheader.bin not found in %s", project.orig_dir)
        return False

    exheader = ExHeader.from_path(exheader_path)

    # ── Build binary list ──
    binaries_to_process: List[Tuple[str, CTRBinary, Path]] = []

    # code.bin
    code_binary = CTRBinary.from_code_bin(code_bin_path, exheader)
    binaries_to_process.append((code_binary.name, code_binary, code_bin_path))

    # .cro modules
    for mod_path in module_paths:
        try:
            mod_binary = CTRBinary.from_cro(mod_path)
            binaries_to_process.append((mod_binary.name, mod_binary, mod_path))
        except Exception as e:
            logger.warning("Failed to parse module %s: %s", mod_path, e)

    # Filter to target binary if specified
    if target_binary:
        binaries_to_process = [
            (name, binary, path) for name, binary, path in binaries_to_process
            if name.lower() == target_binary.lower()
        ]
        if not binaries_to_process:
            logger.error("Binary '%s' not found in project", target_binary)
            return False

    # ── Process each binary ──
    all_ok = True
    objdiff_units = []
    progress_categories = []

    for bin_name, binary, orig_path in binaries_to_process:
        logger.info("=" * 60)
        logger.info("Processing: %s", bin_name)
        logger.info("=" * 60)

        # Find symbol CSV
        csv_path = _find_symbol_csv(project.symbols_dir, bin_name)
        if csv_path is None:
            logger.warning("No symbol CSV for %s, skipping", bin_name)
            continue

        sym_table = SymbolTable.from_csv(csv_path, bin_name)
        logger.info("Loaded %d symbols from %s", len(sym_table), csv_path)

        # ── Compile sources ──
        src_subdir = project.src_dir / bin_name
        build_subdir = project.build_dir / bin_name
        compiled_objects: Dict[str, Path] = {}

        if src_subdir.exists():
            compiled_objects = compile_binary_sources(
                bin_name, src_subdir, build_subdir,
                config, project.tools_dir,
                project.include_dir if project.include_dir.exists() else None,
                project_root=project.root,
            )
        else:
            logger.info("No source directory for %s", bin_name)

        # Map compiled symbols
        compiled_symbol_map, mangled_to_csv = _map_compiled_to_symbols(compiled_objects, sym_table)
        logger.info("Compiled objects cover %d/%d symbols",
                     len(compiled_symbol_map), len(sym_table))

        # Split multi-function .o files into per-function .o files
        compiled_symbol_map = expand_multi_symbol_objects(compiled_symbol_map, sym_table)

        # ── Mode: objdiff ──
        if PipelineMode.OBJDIFF in modes:
            _run_objdiff(project, binary, sym_table, compiled_symbol_map,
                         bin_name, objdiff_units, progress_categories)

        # ── Mode: match / mod ──
        if PipelineMode.MATCH in modes or PipelineMode.MOD in modes:
            is_match = PipelineMode.MATCH in modes
            ok = _run_build(project, binary, sym_table, compiled_symbol_map,
                            bin_name, orig_path, is_match, strict, lazy,
                            mangled_to_csv=mangled_to_csv)
            if not ok:
                all_ok = False

    # ── Write objdiff.json ──
    if PipelineMode.OBJDIFF in modes and objdiff_units:
        objdiff_json = {
            "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
            "build_target": False,
            "build_base": False,
            "units": objdiff_units,
            "progress_categories": progress_categories,
        }
        json_path = project.root / "objdiff.json"
        json_path.write_text(json.dumps(objdiff_json, indent=2))
        logger.info("Wrote %s", json_path)

    return all_ok


def _run_objdiff(project: Project, binary: CTRBinary, sym_table: SymbolTable,
                 compiled_symbol_map: Dict[str, Path], bin_name: str,
                 objdiff_units: list, progress_categories: list):
    """Run the objdiff mode for a single binary."""
    logger.info("--- Objdiff mode for %s ---", bin_name)

    # Target: convert original binary to ELF
    target_path = project.out_dir / "target" / bin_name
    create_objdiff_target(binary, sym_table, target_path)

    # Base: link only compiled objects
    base_path = project.out_dir / "base" / bin_name
    work_dir = project.build_dir / bin_name

    if compiled_symbol_map:
        result = create_objdiff_base(
            compiled_symbol_map, sym_table, binary,
            base_path, project.ld_path, work_dir,
        )
        if result is None:
            # Create empty placeholder
            base_path.parent.mkdir(parents=True, exist_ok=True)
            base_path.write_bytes(b"")
    else:
        base_path.parent.mkdir(parents=True, exist_ok=True)
        base_path.write_bytes(b"")

    # Use forward slashes for JSON paths, relative to project root
    target_rel = str(target_path.relative_to(project.root)).replace("\\", "/")
    base_rel = str(base_path.relative_to(project.root)).replace("\\", "/")

    objdiff_units.append({
        "name": bin_name,
        "target_path": target_rel,
        "base_path": base_rel,
    })
    progress_categories.append({
        "id": bin_name,
        "name": bin_name,
    })


def _run_build(project: Project, binary: CTRBinary, sym_table: SymbolTable,
               compiled_symbol_map: Dict[str, Path], bin_name: str,
               orig_path: Path, is_match: bool, strict: bool,
               lazy: bool, mangled_to_csv: Optional[Dict[str, str]] = None) -> bool:
    """Run match or mod build for a single binary."""
    mode_name = "match" if is_match else "mod"
    logger.info("--- %s mode for %s ---", mode_name.capitalize(), bin_name)

    # ── Comparison (match mode) ──
    mismatches = []
    if is_match:
        for sym_name, obj_path in compiled_symbol_map.items():
            sym = sym_table.get_by_name(sym_name)
            if sym is None:
                continue
            matches, detail = compare_objects(obj_path, binary, sym, sym_table)
            if matches:
                logger.info("  %s", detail)
            else:
                logger.warning("  %s", detail)
                mismatches.append(sym_name)

        if mismatches and strict:
            logger.error("Strict mode: %d mismatches, aborting", len(mismatches))
            return False

        if mismatches:
            logger.warning("%d mismatches found; using split objects for those symbols",
                           len(mismatches))

    # ── Split original (chunked) ──
    split_dir = project.split_dir / bin_name

    # Determine which symbols have valid compiled replacements
    # (use compiled for symbols that match, use split for mismatches and uncompiled)
    compiled_with_match: Set[str] = set()
    if is_match:
        # In match mode, use compiled only for symbols that don't mismatch
        compiled_with_match = set(compiled_symbol_map.keys()) - set(mismatches)
    else:
        # In mod mode, use all compiled objects
        compiled_with_match = set(compiled_symbol_map.keys())

    # Use chunked splitting: pass the set of symbols with valid compiled replacements
    # to avoid creating chunks for those symbols
    split_map = split_binary_chunked(binary, sym_table, split_dir, compiled_with_match)

    # ── Build object map ──
    # For chunked objects: map chunk's first symbol name to chunk .o path
    # For compiled objects: map any exported symbol name to compiled .o path
    object_map: Dict[str, Path] = {}

    # First pass: add all chunk objects (keys are first symbol names in chunks)
    for first_sym_name, chunk_path in split_map.items():
        object_map[first_sym_name] = chunk_path

    # Second pass: add compiled objects (they override chunk entries)
    for sym_name in compiled_with_match:
        object_map[sym_name] = compiled_symbol_map[sym_name]

    if len(object_map) < len(sym_table):
        logger.warning("Object map incomplete: %d/%d symbols covered",
                       len(object_map), len(sym_table))

    # ── Generate linker script ──
    work_dir = project.build_dir / bin_name
    work_dir.mkdir(parents=True, exist_ok=True)
    linker_script = work_dir / f"{bin_name}_link.ld"
    generate_linker_script(binary, sym_table, object_map, linker_script,
                           mangled_to_csv=mangled_to_csv,
                           discard_constdata=is_match)

    # ── Link ──
    linked_elf = work_dir / f"{bin_name}.elf"
    all_objects = list(set(object_map.values()))
    search_dirs = [split_dir, work_dir]

    ok, msg = link_objects(all_objects, linker_script, linked_elf,
                           project.ld_path, search_dirs)
    if not ok:
        logger.error("Link failed for %s: %s", bin_name, msg)
        return False
    logger.info("Linked: %s", linked_elf)

    # ── Produce output binary ──
    out_path = project.out_dir / bin_name

    if binary.is_module:
        # CRO: extract sections from ELF and reconstruct
        elf_sections = extract_elf_sections(linked_elf)
        cro_data = binary.reconstruct_cro(elf_sections)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(cro_data)
        logger.info("CRO output: %s", out_path)
    else:
        # code.bin: objcopy to flat binary
        ok, msg = elf_to_binary(linked_elf, out_path, project.objcopy_path)
        if not ok:
            logger.error("objcopy failed for %s: %s", bin_name, msg)
            return False
        # Pad to match original size (code.bin is typically page-aligned)
        out_size = out_path.stat().st_size
        orig_size = len(binary.raw_data)
        if out_size < orig_size:
            with open(out_path, "ab") as f:
                f.write(b"\x00" * (orig_size - out_size))
            logger.debug("Padded output from %d to %d bytes", out_size, orig_size)
        logger.info("Binary output: %s", out_path)

    # ── Verify (match mode) ──
    if is_match:
        ok, detail = verify_sha256(orig_path, out_path)
        if ok:
            logger.info("VERIFIED: %s", detail)
        else:
            logger.error("VERIFICATION FAILED: %s", detail)
            logger.error(
                "This indicates a pipeline bug, not a source code issue. "
                "The linking or reconstruction process produced incorrect output."
            )
            return False

    return True
