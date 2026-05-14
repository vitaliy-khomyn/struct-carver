from typing import List, Tuple
from .base import BaseFormatParser


class PDFParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'%pdf-']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'%%eof']

    def analyze_binary(self, data: bytes) -> Tuple[bool, bool, int]:
        if not self.is_open:
            if b'%pdf-' in data.lower():
                self.is_open = True
            else:
                return True, False, 0

        end_idx = data.lower().find(b'%%eof')
        if end_idx != -1:
            return False, True, end_idx + 5

        return False, False, len(data)
