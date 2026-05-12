from typing import List, Tuple
from .base import BaseFormatParser


class ZIPParser(BaseFormatParser):
    """
    Prototype parser for Phase 3.
    ZIPs (and DOCX/XLSX) are hierarchical binary formats. We can use signatures
    like 'PK\\x03\\x04' (Local File Header) as opening tags and 'PK\\x05\\x06'
    (End of Central Directory) as closing logic.
    """

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'PK\x05\x06']

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        return []
