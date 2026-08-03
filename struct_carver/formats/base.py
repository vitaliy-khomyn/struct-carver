"""Base interface for format parsers in Struct Carver!

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
