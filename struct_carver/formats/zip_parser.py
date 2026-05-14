from typing import List, Tuple
from .base import BaseFormatParser


class ZIPParser(BaseFormatParser):
    """
    Phase 3 Parser: Handles hierarchical binary ZIP formats (and DOCX/XLSX).
    ZIP files contain multiple Local File Headers ('PK\\x03\\x04').
    To remain compatible with the StackEngine, this parser tracks an internal
    state and only pushes an opening tag on the first Local File Header,
    and closes it when it encounters the End of Central Directory ('PK\\x05\\x06').
    """
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.found_central_dir = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'PK\x05\x06']

    def analyze_binary(self, data: bytes) -> Tuple[bool, bool, int]:
        if not self.is_open:
            if b'PK\x03\x04' in data:
                self.is_open = True
            else:
                # if not opened and no header found in the first chunk, corrupt
                return True, False, 0

        if b'PK\x05\x06' in data:
            self.found_central_dir = True

        if self.found_central_dir:
            end_idx = data.find(b'PK\x05\x06')
            if end_idx != -1 and len(data) >= end_idx + 22:
                # 22 bytes is the minimum size of the End of Central Directory record
                return False, True, end_idx + 22

        return False, False, len(data)
