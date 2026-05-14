import re
from typing import List, Tuple
from .base import BaseFormatParser


class HTMLParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')

        # HTML void elements that never have closing tags
        self.void_elements = {
            b'area', b'base', b'br', b'col', b'embed', b'hr', b'img', b'input',
            b'link', b'meta', b'param', b'source', b'track', b'wbr', b'!doctype'
        }

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'<html', b'<!doctype html']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'</html>']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        tags = []
        last_offset = 0
        for match in self.tag_pattern.finditer(data):
            is_closing = bool(match.group(1))
            tag_name = match.group(2).lower()
            rest = match.group(3)

            if tag_name not in self.void_elements and not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                tags.append((tag_name.decode('ascii', errors='ignore'), is_closing))
                last_offset = match.end()
        return tags, last_offset
