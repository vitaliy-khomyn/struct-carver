import re
from typing import List, Tuple
from .base import BaseFormatParser


class XMLParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(r'<(/?)(\w+)([^>]*)>')

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'<?xml', b'<html']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'</root>', b'</html>']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        tags = []
        for match in self.tag_pattern.finditer(data):
            is_closing = bool(match.group(1))
            tag_name = match.group(2).lower()
            rest = match.group(3)

            if not (rest.strip().endswith('/') or rest.strip().endswith('?')):
                tags.append((tag_name, is_closing))
        return tags
