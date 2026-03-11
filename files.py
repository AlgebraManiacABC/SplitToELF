import csv
from pathlib import Path
import argparse
import yaml
from ctrtype import CTRBinary, CRO, ExHeader
from util import Symbol, BinaryReader

try:
    HAS_TKINTER = True
    from tkinter import filedialog, messagebox
except ImportError:
    filedialog = None
    messagebox = None
    HAS_TKINTER = False


def gather_binaries(path: Path, module: str=None) -> tuple[ExHeader, dict[str, CTRBinary]]:
    binaries = dict()
    exh = None
    code_path = None
    for f in path.rglob('*'):
        if 'header' in f.name or 'Header' in f.name:
            exh = ExHeader.from_reader(BinaryReader.from_path(f))
        if module and module not in f.name:
            continue
        if '.cro' in f.name:
            cro = CRO.from_reader(BinaryReader.from_path(f))
            binaries[f.name] = CTRBinary(f.name, cro)
        if 'code' in f.name:
            # Wait to load until exheader is found
            code_path = f
    if code_path:
        binaries[code_path.name] = CTRBinary(code_path.name, code_path.read_bytes(), exh)
    return exh, binaries


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


def gather_sources(src_path: Path, cc_info: "CTRPipelineInfo", module: str = None) -> dict[str, list[Path]]:
    objects = {}
    for sub_dir in src_path.iterdir():
        if not sub_dir.is_dir() or (module and sub_dir.name != module):
            continue
        d_info = cc_info.get(sub_dir.name)
        ignored = {p for path in (d_info.get('ignored', []) if d_info else []) for p in sub_dir.rglob(path)}
        objects[sub_dir.name] = [p for p in sub_dir.rglob('*') if p.suffix in {'.c', '.cpp'} and p not in ignored]
    return objects


class CTRPipelineInfo:
    def __init__(self, working_dir: Path, originals: list[Path],
                 exheader: ExHeader,
                 binaries: dict[str,CTRBinary],
                 sources: dict[str, list[Path]],
                 build_dir: Path, split_dir: Path,
                 out_dir: Path, tool_dir: Path,
                 symbols: dict[str, list[Symbol]],
                 cc_info: dict[str, dict[str, dict]],
                 args):
        self.working_dir = working_dir
        self.originals = originals
        self.exheader = exheader
        self.binaries = binaries
        self.sources = sources
        self.build_dir = build_dir
        self.split_dir = split_dir
        self.out_dir = out_dir
        self.tool_dir = tool_dir
        self.symbols = symbols
        self.cc_info = cc_info
        self.args = args

    @classmethod
    def from_path(cls, working_dir: Path, args) -> "CTRPipelineInfo":
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
        exh, binaries = gather_binaries(orig_dir, args['single_binary'])
        sources = gather_sources(source_dir, args['single_binary'])
        symbols: dict[str, list[Symbol]] = dict()
        for f in sym_dir.iterdir():
            if args['single_binary'] and args['single_binary'] not in f.name:
                continue
            sym_list = gather_symbols(f)
            for sym in sym_list:
                sym.addr -= binaries[f.stem].base_addr
            symbols[f.stem] = sym_list
        cc_info = yaml.safe_load(cc_info_path.read_text())
        return cls(working_dir, originals, exh, binaries, sources, build_dir, split_dir,
                   out_dir, tool_dir, symbols, cc_info, args)


def gather_bearings(argv: list[str]) -> CTRPipelineInfo:
    """
    :return:
    """

    parser = argparse.ArgumentParser(
        prog="3DS-Decomp-Pipeline",
        description="CTR decompilation pipeline tool"
    )
    parser.add_argument(
        "dir",
        nargs="?",
        help="Working directory"
    )
    parser.add_argument(
        "--recreate-binaries",
        action="store_true",
        default=False,
        help="Attempt to link objects and recreate original binaries"
    )
    parser.add_argument(
        "--compile-only",
        action="store_true",
        default=False,
        help="Only compile, do not link"
    )
    parser.add_argument(
        "--ignore-compiler-errors",
        action="store_true",
        default=False,
        help="When the compiler fails, do not exit (will not report)"
    )
    parser.add_argument(
        "--progress-reports",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether to report [PROGRESS] __._% during compiling, splitting, and linking"
    )
    parser.add_argument(
        "--skip-split",
        action="store_true",
        default=False,
        help="Skip generating the split `.o` files - a good idea to use"
             "if there are no symbol changes and they were already generated"
    )
    parser.add_argument(
        "--skip-compile",
        action="store_true",
        default=False,
        help="Skip compilation and use all `.o` files as-is from the build directory"
    )
    parser.add_argument(
        "--use-splits-only",
        action="store_true",
        default=False,
        help="Skip compilation and only rely on the splat binaries"
    )
    parser.add_argument(
        "--verbose-compilation",
        action="store_true",
        default=False,
        help="Output compiler commands"
    )
    parser.add_argument(
        "--single-binary",
        metavar="BINARY_NAME",
        help="If provided, will operate on only the single binary provided"
    )

    args = parser.parse_args(argv[1:])

    working_dir = args.dir
    if not working_dir:
        if HAS_TKINTER:
            working_dir = filedialog.askdirectory(mustexist=True, title="Choose working directory")
    if not working_dir:
        raise Exception("Did not pick a working directory!")

    args = vars(args)

    return CTRPipelineInfo.from_path(Path(args['dir']), args)
