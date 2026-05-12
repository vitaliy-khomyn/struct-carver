import re
from typing import List, Tuple
from .base import BaseFormatParser


class HTMLParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(r'<(/?)(\w+)([^>]*)>')

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

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        tags = []
        in_comment = False
        i = 0
        n = len(data)

        while i < n:
            if in_comment:
                # if comment, look for the closing comment tag
                end_comment = data.find('-->', i)
                if end_comment != -1:
                    in_comment = False
                    i = end_comment + 3
                else:
                    break  # comment spans past this chunk
            else:
                # look for the next comment start or regular tag start
                next_comment = data.find('<!--', i)
                next_tag = data.find('<', i)

                if next_tag == -1:
                    break  # no more tags or comments in this chunk

                if next_comment != -1 and next_comment <= next_tag:
                    in_comment = True
                    i = next_comment + 4
                else:
                    # Process a regular HTML tag
                    end_tag = data.find('>', next_tag)
                    if end_tag == -1:
                        break  # incomplete tag at the end of chunk

                    tag_str = data[next_tag:end_tag + 1]
                    match = self.tag_pattern.match(tag_str)
                    if match:
                        is_closing = bool(match.group(1))
                        tag_name = match.group(2).lower()
                        rest = match.group(3)

                        if tag_name not in self.void_elements and not (rest.strip().endswith('/') or rest.strip().endswith('?')):
                            tags.append((tag_name, is_closing))

                    i = end_tag + 1

        return tags
