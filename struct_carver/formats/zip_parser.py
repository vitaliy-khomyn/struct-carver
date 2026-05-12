from typing import List, Tuple
from .base import BaseFormatParser


class ZIPParser(BaseFormatParser):
    """
    Phase 3 Parser: Handles hierarchical binary ZIP formats (and DOCX/XLSX).
    ZIP files contain multiple Local File Headers ('PK\\x03\\x04').
    To remain compatible with the StackEngine, this parser tracks an internal
    state and only pushes an opening tag on the first Local File Header,
    and closes it when it encounters the End of Central Directory ('PK\\x05\\x06').
    """
    def __init__(self):
        self.is_open = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'PK\x05\x06']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        tags = []
        i = 0
        n = len(data)

        while i < n:
            next_start = data.find('PK\x03\x04', i)
            next_end = data.find('PK\x05\x06', i)

            if next_start != -1 and (next_end == -1 or next_start < next_end):
                if not self.is_open:
                    tags.append(('zip', False))
                    self.is_open = True
                i = next_start + 4
            elif next_end != -1:
                if self.is_open:
                    tags.append(('zip', True))
                    self.is_open = False
                i = next_end + 4
            else:
                break

        return tags
