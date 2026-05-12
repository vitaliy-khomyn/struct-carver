import re
from typing import List, Tuple
from .base import BaseFormatParser


class PDFParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(r'\b(obj|endobj|stream|endstream)\b|(<<|>>|\[|\])')

        self.tag_map = {
            'obj': ('obj', False),
            'endobj': ('obj', True),
            'stream': ('stream', False),
            'endstream': ('stream', True),
            '<<': ('<<', False),
            '>>': ('<<', True),
            '[': ('[', False),
            ']': ('[', True)
        }

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'%pdf-']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'%%eof']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        return [self.tag_map[m.group(0)] for m in self.tag_pattern.finditer(data) if m.group(0) in self.tag_map]
