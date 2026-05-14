from typing import List, Tuple
from .base import BaseFormatParser


class RTFParser(BaseFormatParser):
    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        tags = []
        escape = False
        last_offset = 0
        for i, byte_val in enumerate(data):
            if escape:
                escape = False
                continue
            if byte_val == ord('\\'):
                escape = True
            elif byte_val == ord('{'):
                tags.append(('{', False))
                last_offset = i + 1
            elif byte_val == ord('}'):
                tags.append(('{', True))
                last_offset = i + 1
        return tags, last_offset
