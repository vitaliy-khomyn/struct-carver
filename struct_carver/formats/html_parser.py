import re
from typing import List, Tuple
from .base import BaseFormatParser


class HTMLParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')

        # HTML void elements that never have closing tags
        self.void_elements = {
            'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
            'link', 'meta', 'param', 'source', 'track', 'wbr', '!doctype'
        }

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'<html', b'<!doctype html']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'</html>']

    def extract_tags(self, data: bytes) -> List[Tuple[str, bool]]:
        tags = []
        for match in self.tag_pattern.finditer(data):
            is_closing = bool(match.group(1))
            tag_name = match.group(2).decode('ascii', errors='ignore').lower()
            rest = match.group(3)

            if tag_name not in self.void_elements and not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                tags.append((tag_name, is_closing))
        return tags
