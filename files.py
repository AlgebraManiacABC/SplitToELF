import csv
from pathlib import Path

from ctrtype import CTRBinary
from util import Symbol
try:
    HAS_TKINTER = True
    from tkinter import filedialog
except ImportError:
    filedialog = None
    HAS_TKINTER = False


def gather_compiled_object_files(dirname: str) -> list[Path]:
    """
    :param dirname: Name of the directory containing all user-compiled objects
    :return: A list of Paths for all compiled objects
    """
    objects = []
    for o in Path(dirname).iterdir():
        if o.suffix == '.o':
            objects.append(o)
    return objects


def gather_symbols(sym_file: str) -> list[Symbol]:
    """
    :param sym_file: Filename of exported symbol list (Ghidra style)
    :return: List of symbols
    """
    symbols = []
    reader = csv.DictReader(Path(sym_file).read_text().splitlines())
    for line in reader:
        try:
            symbols.append(Symbol(int(line["Location"], 16), line["Name"]))
        except ValueError:
            pass

    return symbols


def gather_bearings(argv: list[str]):
    """
    :return:
    """

    if not HAS_TKINTER and len(argv) < 5:
        raise Exception(
            f"""
            Usage: python {Path(argv[0]).name} <compiled_dir> <3ds_binary> <symbol_file> <split_output_dir>
            
            === OR ===
            (if tkinter installed)
            
            Usage: python {Path(argv[0]).name}
            """
        )

    if HAS_TKINTER and len(argv) < 5:
        compiled_dir = filedialog.askdirectory(
            initialdir='.',
            mustexist=True,
            title="User-compiled objects directory"
        )
    else:
        compiled_dir = argv[1]
    if not compiled_dir:
        raise Exception("Did not pick a user-compiled object directory!")
    compiled_objects = gather_compiled_object_files(compiled_dir)
    if len(compiled_objects) == 0:
        raise Exception(f"No object files found in {compiled_dir}!")

    if HAS_TKINTER and len(argv) < 5:
        binary_file = filedialog.askopenfilename(
            filetypes=[("3DS Executable Binary", ".cro code.bin .code"), ("All files", "*")],
            title="Binary to Split"
        )
    else:
        binary_file = argv[2]
    if not binary_file:
        raise Exception("Did not pick the binary to split!")

    ctr_binary = CTRBinary.from_path(Path(binary_file))

    if HAS_TKINTER and len(argv) < 5:
        symbol_file = filedialog.askopenfilename(
            filetypes=[("CSV Files",".csv"), ("All files", "*")],
            title="Symbol file"
        )
    else:
        symbol_file = argv[3]
    if not symbol_file:
        raise Exception("Did not pick the symbol file!")
    symbols = gather_symbols(symbol_file)
    for sym in symbols:
        sym.addr -= ctr_binary.base_addr

    if HAS_TKINTER and len(argv) < 5:
        split_dir = filedialog.askdirectory(
            mustexist=False,
            title="Split object output directory"
        )
    else:
        split_dir = argv[4]
    if not split_dir:
        raise Exception("Did not pick the output directory!")

    return compiled_objects, ctr_binary, symbols, Path(split_dir)
