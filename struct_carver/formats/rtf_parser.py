from typing import List, Tuple
from .base import BaseFormatParser


class RTFParser(BaseFormatParser):
    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        tags = []
        escape = False
        for char in data:
            if escape:
                escape = False
                continue
            if char == '\\':
                escape = True
            elif char == '{':
                tags.append(('{', False))
            elif char == '}':
                tags.append(('{', True))
        return tags
