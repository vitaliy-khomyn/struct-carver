from abc import ABC, abstractmethod
from typing import List, Tuple


class BaseFormatParser(ABC):
    @property
    @abstractmethod
    def header_signatures(self) -> List[bytes]:
        """List of bytes that indicate the start of this file format."""
        pass

    @property
    @abstractmethod
    def footer_signatures(self) -> List[bytes]:
        pass

    @abstractmethod
    def extract_tags(self, data: bytes) -> List[Tuple[str, bool]]:
        """Returns a list of tuples: (tag_name, is_closing)"""
        pass
