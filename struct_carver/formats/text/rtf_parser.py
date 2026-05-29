from typing import List, Tuple
from ..base import BaseFormatParser


class RTFParser(BaseFormatParser):
    def __init__(self):
        self.escape = False
        self.is_corrupted = False

    def clone(self) -> 'RTFParser':
        new_parser = RTFParser()
        new_parser.escape = self.escape
        new_parser.is_corrupted = self.is_corrupted
        return new_parser

    def reset(self):
        self.escape = False
        self.is_corrupted = False

    def state_tuple(self) -> tuple:
        return (self.escape, self.is_corrupted)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        tags = []
        
        # Check for binary control bytes (strictly illegal in RTF)
        for b in data:
            if b < 32 and b not in (9, 10, 13):
                self.is_corrupted = True
                return [], 0
        last_offset = 0
        for i, byte_val in enumerate(data):
            if self.escape:
                self.escape = False
                continue
            if byte_val == ord('\\'):
                self.escape = True
            elif byte_val == ord('{'):
                tags.append(('{', False))
                last_offset = i + 1
            elif byte_val == ord('}'):
                tags.append(('{', True))
                last_offset = i + 1
        return tags, last_offset
