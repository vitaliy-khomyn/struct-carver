from typing import List, Tuple
from .base import BaseFormatParser


class RTFParser(BaseFormatParser):
    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: bytes) -> List[Tuple[str, bool]]:
        tags = []
        escape = False
        for byte_val in data:
            if escape:
                escape = False
                continue
            if byte_val == ord('\\'):
                escape = True
            elif byte_val == ord('{'):
                tags.append(('{', False))
            elif byte_val == ord('}'):
                tags.append(('{', True))
        return tags
