from typing import List, Tuple
from .base import BaseFormatParser


class DynamicBinaryParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self, ext: str, header: bytes, footer: bytes):
        self.ext = ext
        self._header = header
        self._footer = footer
        self.is_open = False

    def clone(self) -> 'DynamicBinaryParser':
        new_parser = DynamicBinaryParser(self.ext, self._header, self._footer)
        new_parser.is_open = self.is_open
        return new_parser

    def reset(self):
        self.is_open = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [self._header]

    @property
    def footer_signatures(self) -> List[bytes]:
        return [self._footer]

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        if not self.is_open:
            start_idx = data.find(self._header)
            if start_idx != -1:
                self.is_open = True
                data = data[start_idx:]
            else:
                return True, False, 0, 0

        end_idx = data.find(self._footer)
        if end_idx != -1:
            return False, True, end_idx + len(self._footer), 0

        return False, False, len(data), 0
