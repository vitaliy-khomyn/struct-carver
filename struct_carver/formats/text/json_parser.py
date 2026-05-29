import re
from typing import List, Tuple
from ..base import BaseFormatParser


class JSONParser(BaseFormatParser):
    def __init__(self):
        self.tag_pattern = re.compile(rb'([\{\}\[\]])')

        self.tag_map = {
            b'{': ('{', False),
            b'}': ('{', True),
            b'[': ('[', False),
            b']': ('[', True)
        }

        self.in_string = False
        self.escape_next = False
        self.is_corrupted = False

    def clone(self) -> 'JSONParser':
        new_parser = JSONParser()
        new_parser.in_string = self.in_string
        new_parser.escape_next = self.escape_next
        new_parser.is_corrupted = self.is_corrupted
        return new_parser

    def reset(self):
        self.in_string = False
        self.escape_next = False
        self.is_corrupted = False

    def state_tuple(self) -> tuple:
        return (self.in_string, self.escape_next, self.is_corrupted)

    @property
    def header_signatures(self) -> List[bytes]:
        # Simple heuristic headers for JSON objects or arrays
        return [b'{"', b'[{']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}', b']']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        tags = []
        last_offset = 0
        allowed_outside = b' \t\r\n{}[]:,-+0123456789.eEtruesfaln'

        for i, byte_val in enumerate(data):
            # Control characters (except tab, LF, CR) are strictly illegal in JSON
            if byte_val < 32 and byte_val not in (9, 10, 13):
                self.is_corrupted = True
                break

            if self.in_string:
                if self.escape_next:
                    self.escape_next = False
                elif byte_val == ord('\\'):
                    self.escape_next = True
                elif byte_val == ord('"'):
                    self.in_string = False
            else:
                if byte_val == ord('"'):
                    self.in_string = True
                elif byte_val not in allowed_outside:
                    self.is_corrupted = True
                    break
                elif byte_val == ord('{'):
                    tags.append(('{', False))
                    last_offset = i + 1
                elif byte_val == ord('}'):
                    tags.append(('{', True))
                    last_offset = i + 1
                elif byte_val == ord('['):
                    tags.append(('[', False))
                    last_offset = i + 1
                elif byte_val == ord(']'):
                    tags.append(('[', True))
                    last_offset = i + 1

        return tags, last_offset
