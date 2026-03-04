import csv
from pathlib import Path
import yaml

from ctrtype import CTRBinary, CRO
from util import Symbol, BinaryReader

try:
    HAS_TKINTER = True
    from tkinter import filedialog
except ImportError:
    filedialog = None
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
            symbols.append(Symbol(int(line["Location"], 16), line["Name"]))
        except ValueError:
            pass

    return symbols


class CTRPipelineInfo:
    def __init__(self, working_dir: Path, binaries: dict[str,CTRBinary],
                 compiled_objects: dict[str, list[Path]],
                 build_dir: Path, out_dir: Path, tool_dir: Path,
                 symbols: dict[str, list[Symbol]],
                 cc_info: dict[str, dict[str, dict]]):
        self.working_dir = working_dir
        self.binaries = binaries
        self.compiled_objects = compiled_objects
        self.build_dir = build_dir
        self.out_dir = out_dir
        self.tool_dir = tool_dir
        self.symbols = symbols
        self.cc_info = cc_info

    @classmethod
    def from_path(cls, working_dir: Path) -> "CTRPipelineInfo":
        orig_dir = working_dir / 'orig'
        build_dir = working_dir / 'build'
        out_dir = working_dir / 'out'
        tool_dir = working_dir / 'tools'
        sym_dir = working_dir / 'symbols'
        cc_info_path = working_dir / 'cc.yaml'
        missing = []
        if not orig_dir.exists():
            missing.append('directory "orig"')
        if not tool_dir.exists():
            missing.append('directory "tools"')
        if not sym_dir.exists():
            missing.append('directory "symbols"')
        if not cc_info_path.exists():
            missing.append('compiler configuration "cc.yaml"')
        if missing:
            e = f"Pipeline incomplete for working dir {working_dir}!"
            e += "".join(f"\nMissing {m}!" for m in missing)
            raise Exception(e)
        binaries = gather_binaries(orig_dir)
        compiled_objects = gather_compiled_object_files(build_dir)
        symbols: dict[str, list[Symbol]] = dict()
        for f in sym_dir.iterdir():
            sym_list = gather_symbols(f)
            for sym in sym_list:
                sym.addr -= binaries[f.stem].base_addr
            symbols[f.stem] = sym_list
        cc_info = yaml.safe_load(cc_info_path.read_text())
        return cls(working_dir, binaries, compiled_objects, build_dir, out_dir, tool_dir, symbols, cc_info)


def gather_bearings(argv: list[str]) -> CTRPipelineInfo:
    """
    :return:
    """

    if not HAS_TKINTER and len(argv) < 2:
        raise Exception(
            f"""
            Usage: python {Path(argv[0]).name} <dir>
            
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
    else:
        working_dir = argv[1]
    if not working_dir:
        raise Exception("Did not pick a working directory!")

    return CTRPipelineInfo.from_path(Path(working_dir))
