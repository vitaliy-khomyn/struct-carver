"""Base interface for format parsers.

This module defines the abstract class hierarchy for file format parsers:
- BaseFormatParser: Root class defining common lifecycle, signatures, and gap-jumping hooks.
- TextFormatParser: Specialization for hierarchical/markup text formats (XML, HTML, JSON, RTF).
- BaseBinaryParser: Specialization for binary formats (ZIP, PDF, SQLite, PNG, etc.).
"""

from abc import ABC, abstractmethod
from typing import List, Tuple


class BaseFormatParser(ABC):
    """Abstract base class for all file format parsers.

    Provides the common interface for extracting signatures, managing state,
    and evaluating cluster continuation during gap jumping.
    """

    engine_type: str = "semantic"
    header_offset: int = 0

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

    def prepare_for_gap_jump(self) -> None:
        """Hook called prior to evaluating candidate clusters during a gap jump.

        Override to reset transient mid-stream wait state (e.g. PDF endstream search)
        so that candidate continuation clusters are tested from a clean structural boundary.
        """
        pass

    def has_continuation_markers(self, candidate_cluster: bytes) -> bool:
        """Checks if a candidate cluster contains format-specific continuation tokens.

        Args:
            candidate_cluster (bytes): Raw disk cluster bytes being inspected.

        Returns:
            bool: True if the cluster contains characteristic syntax for this format.
        """
        return False

    def validate_header(self, data: bytes, offset: int = 0) -> bool:
        """Validates candidate header at given offset in buffer.

        Args:
            data (bytes): Buffer containing candidate header.
            offset (int, optional): Starting offset of the file in data (default: 0).

        Returns:
            bool: True if candidate header appears valid, False otherwise.
        """
        return True

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Default stub for tag extraction. Text parsers override this method.

        Args:
            data (bytes): Input cluster payload.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: Parsed tags and last offset.
        """
        return [], 0


class TextFormatParser(BaseFormatParser):
    """Base class for text and markup format parsers (e.g. XML, HTML, JSON, RTF)."""

    engine_type: str = "semantic"

    @staticmethod
    def is_illegal_control_byte(b: int) -> bool:
        """Checks whether a single byte is an illegal control character in text streams.

        Bytes < 32 except tab (9), line feed (10), and carriage return (13) are illegal.

        Args:
            b (int): Byte integer value (0-255).

        Returns:
            bool: True if the byte is an illegal control character.
        """
        return b < 32 and b not in (9, 10, 13)

    @classmethod
    def has_illegal_control_bytes(cls, data: bytes) -> bool:
        """Checks if the byte sequence contains any illegal control characters.

        Args:
            data (bytes): Input byte buffer.

        Returns:
            bool: True if any illegal control byte is found.
        """
        return any(b < 32 and b not in (9, 10, 13) for b in data)

    @abstractmethod
    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Extracts structural tags or bracket tokens from textual data chunks.

        Args:
            data (bytes): Input cluster payload.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: List of parsed (tag_name, is_closing) tuples
                and the last processed byte offset.
        """
        pass


class BaseMarkupParser(TextFormatParser):
    """Base class for tag-based markup formats (HTML and XML)."""

    def __init__(self):
        """Initializes markup parser common state."""
        import re
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')
        self.in_comment = False
        self.is_corrupted = False

    def has_continuation_markers(self, candidate_cluster: bytes) -> bool:
        """Checks if a candidate cluster contains tag opening brackets.

        Args:
            candidate_cluster (bytes): Raw candidate cluster.

        Returns:
            bool: True if an opening bracket is present.
        """
        return b'<' in candidate_cluster


class BaseBinaryParser(BaseFormatParser):
    """Base class for binary format parsers (e.g. ZIP, PDF, SQLite, PNG, images, audio)."""

    engine_type: str = "binary"

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Binary formats operate on offset engines and do not produce text tags."""
        return [], 0

    @abstractmethod
    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary cluster and checks structural integrity.

        Args:
            data (bytes): Cluster payload bytes.
            bytes_remaining (int, optional): Bytes remaining from previous block/stream.

        Returns:
            Tuple[bool, bool, int, int]:
                - is_corrupted (bool): True if structure is invalid.
                - is_complete (bool): True if end-of-file reached.
                - bytes_to_advance (int): Valid bytes in this cluster.
                - expected_remaining (int): Expected bytes in current payload block.
        """
        pass
