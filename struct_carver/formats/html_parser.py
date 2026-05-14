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
        in_comment = False
        i = 0
        last_offset = 0
        n = len(data)

        while i < n:
            if in_comment:
                end_comment = data.find(b'-->', i)
                if end_comment != -1:
                    in_comment = False
                    i = end_comment + 3
                else:
                    break
            else:
                next_comment = data.find(b'<!--', i)
                next_tag = data.find(b'<', i)

                if next_tag == -1:
                    break

                if next_comment != -1 and next_comment <= next_tag:
                    in_comment = True
                    i = next_comment + 4
                else:
                    end_tag = data.find(b'>', next_tag)
                    if end_tag == -1:
                        break

                    tag_str = data[next_tag:end_tag + 1]
                    match = self.tag_pattern.match(tag_str)
                    if match:
                        is_closing = bool(match.group(1))
                        tag_name = match.group(2).lower()
                        rest = match.group(3)

                        if tag_name not in self.void_elements and not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                            tags.append((tag_name.decode('ascii', errors='ignore'), is_closing))
                            last_offset = end_tag + 1

                    i = end_tag + 1

        return tags, last_offset
