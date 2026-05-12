import re
from typing import List, Tuple
from .base import BaseFormatParser


class RTFParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(r'([{}])')

        self.tag_map = {
            '{': ('{', False),
            '}': ('{', True)
        }

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        return [self.tag_map[m.group(1)] for m in self.tag_pattern.finditer(data) if m.group(1) in self.tag_map]
