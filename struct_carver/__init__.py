"""Struct Carver package.

A semantic, non-sequential file carver for digital forensics.
"""

import sys
import multiprocessing

def _init_excepthook(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        try:
            is_main = multiprocessing.current_process().name == "MainProcess"
        except Exception:
            is_main = True
        if is_main:
            sys.stderr.write("\n[-] Operation aborted by user. Exiting...\n")
        sys.exit(130)
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = _init_excepthook
