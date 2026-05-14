from abc import ABC, abstractmethod
from typing import List, Tuple


class BaseFormatParser(ABC):
    engine_type = "semantic"  # Can be "semantic" or "binary"

    @property
    @abstractmethod
    def header_signatures(self) -> List[bytes]:
        """List of bytes that indicate the start of this file format."""
        pass

    @property
    @abstractmethod
    def footer_signatures(self) -> List[bytes]:
        pass

    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        """Returns a list of tuples: (tag_name, is_closing)"""
        return []

    def analyze_binary(self, data: bytes) -> Tuple[bool, bool, int]:
        """
        Used by the BinaryOffsetEngine.
        Returns a tuple: (is_corrupted, is_complete, bytes_to_advance)
        """
        return False, False, 0
