"""Base interface for format parsers in Struct Carver!

This module defines the abstract base class BaseFormatParser, which all file
format parsers (text-based and binary) must inherit and implement.
"""

from abc import ABC, abstractmethod
from typing import List, Tuple


class BaseFormatParser(ABC):
    """Abstract base class for all file format parsers.

    Provides the common interface for extracting signatures, parsing chunks,
    and managing parser state.
    """

    @property
    @abstractmethod
    def header_signatures(self) -> List[bytes]:
        """Returns a list of byte sequences that mark the start of this format.

        Returns:
            List[bytes]: A list of header signature bytes.
        """
        pass

    @property
    @abstractmethod
    def footer_signatures(self) -> List[bytes]:
        """Returns a list of byte sequences that mark the end of this format.

        Returns:
            List[bytes]: A list of footer signature bytes.
        """
        pass

    @abstractmethod
    def extract_tags(self, data: str) -> List[Tuple[str, bool]]:
        """Extracts markup/logical tags from the given textual data chunk.

        Args:
            data (str): The textual data block to parse.

        Returns:
            List[Tuple[str, bool]]: A list of parsed tags, where each tag is
                represented as a tuple of (tag_name, is_closing).
        """
        pass

    @abstractmethod
    def clone(self) -> 'BaseFormatParser':
        """Creates a deep copy of the parser in its current state.

        Returns:
            BaseFormatParser: A cloned instance of this parser.
        """
        pass

    @abstractmethod
    def reset(self):
        """Resets the internal parser state back to initial clear values."""
        pass

    def state_tuple(self) -> tuple:
        """Returns a hashable tuple of the internal parser state for caching.

        Returns:
            tuple: A hashable representation of the parser state.
        """
        return ()
