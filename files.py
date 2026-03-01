from pathlib import Path
from tkinter import filedialog


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


def gather_bearings():
    """
    :return:
    """

    compiled_dir = filedialog.askdirectory(
        initialdir='.',
        mustexist=True,
        title="User-compiled objects directory"
    )
    if not compiled_dir:
        raise Exception("Did not pick a user-compiled object directory!")
    compiled_objects = gather_compiled_object_files(compiled_dir)
    if len(compiled_objects) == 0:
        raise Exception(f"No object files found in {compiled_dir}!")

    binary_file = filedialog.askopenfilename(
        filetypes=[("3DS Executable Binary", "*.cro code.bin"), ("All files", "*")],
        title="Binary to Split"
    )
    if not binary_file:
        raise Exception("Did not pick the binary to split!")

    symbol_file = filedialog.askopenfilename(
        filetypes=[("All files", "*")],
        title="Symbol file"
    )
    if not symbol_file:
        raise Exception("Did not pick the symbol file!")

    split_dir = filedialog.askdirectory(
        mustexist=False,
        title="Split object output directory"
    )
    if not split_dir:
        raise Exception("Did not pick the output directory!")

    return compiled_objects, Path(binary_file), Path(symbol_file), Path(split_dir)
