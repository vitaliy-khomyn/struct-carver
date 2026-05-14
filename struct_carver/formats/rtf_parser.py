from typing import List, Tuple
from .base import BaseFormatParser


class RTFParser(BaseFormatParser):
    def __init__(self):
        self.escape = False

    def clone(self) -> 'RTFParser':
        new_parser = RTFParser()
        new_parser.escape = self.escape
        return new_parser

    def reset(self):
        self.escape = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        tags = []
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
