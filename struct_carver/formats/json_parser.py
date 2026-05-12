from typing import List, Tuple
from .base import BaseFormatParser


class JSONParser(BaseFormatParser):
    @property
    def header_signatures(self) -> List[bytes]:
        # Simple heuristic headers for JSON objects or arrays
        return [b'{"', b'[{']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'}', b']']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        tags = []
        in_string = False
        escape_next = False

        for char in data:
            if in_string:
                if escape_next:
                    escape_next = False
                elif char == '\\':
                    escape_next = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '{':
                    tags.append(('{', False))
                elif char == '}':
                    tags.append(('{', True))
                elif char == '[':
                    tags.append(('[', False))
                elif char == ']':
                    tags.append(('[', True))

        return tags
