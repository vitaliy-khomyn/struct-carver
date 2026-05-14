import re
from typing import List, Tuple
from .base import BaseFormatParser


class JSONParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(rb'([\{\}\[\]])')

        self.tag_map = {
            b'{': ('{', False),
            b'}': ('{', True),
            b'[': ('[', False),
            b']': ('[', True)
        }

    @property
    def header_signatures(self) -> List[bytes]:
        # Simple heuristic headers for JSON objects or arrays
        return [b'{"', b'[{']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}', b']']

    def extract_tags(self, data: bytes) -> List[Tuple[str, bool]]:
        return [self.tag_map[m.group(1)] for m in self.tag_pattern.finditer(data) if m.group(1) in self.tag_map]
