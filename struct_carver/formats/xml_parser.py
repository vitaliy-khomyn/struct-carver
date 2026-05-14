import re
from typing import List, Tuple
from .base import BaseFormatParser


class XMLParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'<?xml', b'<html']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'</root>', b'</html>']

    def extract_tags(self, data: bytes) -> List[Tuple[str, bool]]:
        tags = []
        in_cdata = False
        in_comment = False
        i = 0
        n = len(data)

        while i < n:
            if in_cdata:
                end_cdata = data.find(b']]>', i)
                if end_cdata != -1:
                    in_cdata = False
                    i = end_cdata + 3
                else:
                    break
            elif in_comment:
                end_comment = data.find(b'-->', i)
                if end_comment != -1:
                    in_comment = False
                    i = end_comment + 3
                else:
                    break
            else:
                next_tag = data.find(b'<', i)
                if next_tag == -1:
                    break

                if data.startswith(b'<![CDATA[', next_tag):
                    in_cdata = True
                    i = next_tag + 9
                elif data.startswith(b'<!--', next_tag):
                    in_comment = True
                    i = next_tag + 4
                else:
                    end_tag = data.find(b'>', next_tag)
                    if end_tag == -1:
                        break

                    tag_str = data[next_tag:end_tag + 1]
                    match = self.tag_pattern.match(tag_str)
                    if match:
                        is_closing = bool(match.group(1))
                        tag_name = match.group(2).decode('ascii', errors='ignore').lower()
                        rest = match.group(3)

                        if not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                            tags.append((tag_name, is_closing))

                    i = end_tag + 1

        return tags
