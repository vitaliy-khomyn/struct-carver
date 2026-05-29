from typing import List, Tuple
from ..base import BaseFormatParser


class MPGParser(BaseFormatParser):
    engine_type = "binary"
    ext = "mpg"

    def __init__(self):
        self.is_open = False

    def clone(self) -> 'MPGParser':
        new_parser = MPGParser()
        new_parser.is_open = self.is_open
        return new_parser

    def reset(self):
        self.is_open = False

    def state_tuple(self) -> tuple:
        return (self.is_open,)

    @property
    def header_signatures(self) -> List[bytes]:
        # MPEG sequence or pack headers
        return [b'\x00\x00\x01\xBA', b'\x00\x00\x01\xB3']

    @property
    def footer_signatures(self) -> List[bytes]:
        # MPEG End Code
        return [b'\x00\x00\x01\xB9']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Find sequence header or pack header
            sig_ba = data.find(b'\x00\x00\x01\xBA')
            sig_b3 = data.find(b'\x00\x00\x01\xB3')
            valid_indices = [p for p in [sig_ba, sig_b3] if p != -1]
            if not valid_indices:
                return True, False, 0, 0

            start_idx = min(valid_indices)
            self.is_open = True
            idx = start_idx

        # Search for MPEG End Code (b'\x00\x00\x01\xB9')
        end_idx = data.find(b'\x00\x00\x01\xB9', idx)
        if end_idx != -1:
            return False, True, end_idx + 4, 0

        # Wait for more data
        return False, False, n, 0
