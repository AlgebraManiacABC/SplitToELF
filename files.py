import csv
from pathlib import Path
import yaml
from ctrtype import CTRBinary, CRO
from util import Symbol, BinaryReader

try:
    HAS_TKINTER = True
    from tkinter import filedialog, messagebox
except ImportError:
    filedialog = None
    messagebox = None
    HAS_TKINTER = False


def gather_binaries(path: Path) -> dict[str, CTRBinary]:
    binaries = dict()
    for f in path.rglob('*'):
        if '.cro' in f.name:
            cro = CRO.from_reader(BinaryReader.from_path(f))
            binaries[f.name] = CTRBinary(f.name, cro)
        if 'code' in f.name:
            binaries[f.name] = CTRBinary(f.name, f.read_bytes())
    return binaries


def gather_compiled_object_files(path: Path) -> dict[str, list[Path]]:
    """
    :param path: Directory path containing all user-compiled objects
    :return: A dict of paths for all compiled objects ({module: o_files_list})
    """
    objects = dict()
    for sub_dir in path.iterdir():
        if sub_dir.is_dir():
            objects[sub_dir.name] = list(sub_dir.rglob('*.o'))
    return objects


def gather_symbols(sym_path: Path) -> list[Symbol]:
    """
    :param sym_path: Path of exported symbol list (Ghidra style)
    :return: List of symbols
    """
    symbols = []
    reader = csv.DictReader(sym_path.read_text().splitlines())
    for line in reader:
        try:
            symbols.append(Symbol(int(line["Location"], 16), line["Name"], line["Mode"], int(line["Size"], 16)))
        except ValueError:
            pass

    return symbols


def gather_sources(src_path: Path) -> dict[str,list[Path]]:
    objects = dict()
    for sub_dir in src_path.iterdir():
        if sub_dir.is_dir():
            objects[sub_dir.name] = list(sub_dir.rglob('*.c*'))
    return objects



class CTRPipelineInfo:
    def __init__(self, working_dir: Path, originals: list[Path],
                 binaries: dict[str,CTRBinary],
                 sources: dict[str, list[Path]],
                 build_dir: Path, split_dir: Path,
                 out_dir: Path, tool_dir: Path,
                 symbols: dict[str, list[Symbol]],
                 cc_info: dict[str, dict[str, dict]],
                 recreating_binaries: bool,
                 compile_only: bool):
        self.working_dir = working_dir
        self.originals = originals
        self.binaries = binaries
        self.sources = sources
        self.build_dir = build_dir
        self.split_dir = split_dir
        self.out_dir = out_dir
        self.tool_dir = tool_dir
        self.symbols = symbols
        self.cc_info = cc_info
        self.recreating_binaries = recreating_binaries
        self.compile_only = compile_only

    @classmethod
    def from_path(cls, working_dir: Path, recreating_binaries: bool, compile_only: bool) -> "CTRPipelineInfo":
        orig_dir = working_dir / 'orig'
        originals = list(orig_dir.rglob('*'))
        source_dir = working_dir / 'src'
        build_dir = working_dir / 'build'
        build_dir.mkdir(parents=True, exist_ok=True)
        split_dir = working_dir / 'split'
        out_dir = working_dir / 'out'
        out_dir.mkdir(parents=True, exist_ok=True)
        tool_dir = working_dir / 'tools'
        sym_dir = working_dir / 'symbols'
        cc_info_path = working_dir / 'cc.yaml'
        missing = []
        if not orig_dir.exists():
            missing.append('directory "orig"')
        if not tool_dir.exists():
            missing.append('directory "tools"')
        else:
            if not (tool_dir / 'ld').exists():
                missing.append('tool "ld"')
            if not (tool_dir / 'objcopy').exists():
                missing.append('tool "objcopy"')
        if not sym_dir.exists():
            missing.append('directory "symbols"')
        if not cc_info_path.exists():
            missing.append('compiler configuration "cc.yaml"')
        if missing:
            e = f"Pipeline incomplete for working dir {working_dir} (current dir {Path.cwd()})!"
            e += "".join(f"\nMissing {m}!" for m in missing)
            raise Exception(e)
        binaries = gather_binaries(orig_dir)
        sources = gather_sources(source_dir)
        symbols: dict[str, list[Symbol]] = dict()
        for f in sym_dir.iterdir():
            sym_list = gather_symbols(f)
            for sym in sym_list:
                sym.addr -= binaries[f.stem].base_addr
            symbols[f.stem] = sym_list
        cc_info = yaml.safe_load(cc_info_path.read_text())
        return cls(working_dir, originals, binaries, sources, build_dir, split_dir,
                   out_dir, tool_dir, symbols, cc_info, recreating_binaries, compile_only)


def gather_bearings(argv: list[str]) -> CTRPipelineInfo:
    """
    :return:
    """

    if not HAS_TKINTER and len(argv) < 2:
        raise Exception(
            f"""
            Usage: python {Path(argv[0]).name} <dir>
            
                --recreateBinaries=[True/False]          If the program should attempt to link (key work being attempt)
            
            === OR ===
            (if tkinter installed)
            
            Usage: python {Path(argv[0]).name}
            """
        )

    if HAS_TKINTER and len(argv) < 2:
        working_dir = filedialog.askdirectory(
            mustexist=True,
            title="Choose working directory"
        )
        if working_dir:
            recreating_binaries = messagebox.askyesno("Recreate originals?",
                    "Should this program attempt to link the created"
                            "objects and recreate the original binaries?")
    else:
        working_dir = argv[1]
        recreating_binaries = False
        compile_only = False
        if len(argv) == 3:
            test_rb = argv[2].startswith('--recreateBinaries')
            test_co = argv[2].startswith('--compileOnly')
            if test_rb:
                recreating_binaries = argv[2] == '--recreateBinaries=True'
            if test_co:
                compile_only = argv[2] == '--compileOnly=True'
        elif len(argv) == 4:
            test_rb = argv[2] if argv[2].startswith('--recreatingBinaries') else argv[3]
            test_co = argv[2] if argv[2].startswith('compileOnly') else argv[3]
            recreating_binaries = test_rb == '--recreateBinaries=True'
            compile_only = test_co == '--compileOnly=True'
    if not working_dir:
        raise Exception("Did not pick a working directory!")

    return CTRPipelineInfo.from_path(Path(working_dir), recreating_binaries, compile_only)
