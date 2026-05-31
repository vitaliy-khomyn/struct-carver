"""Binary parsing state engine for Struct Carver!

This module implements the BinaryOffsetEngine, which tracks the integrity
and completion state of files that rely on size structure offsets.
"""


class BinaryOffsetEngine:
    """Engine that tracks parsing state of binary format parsers.

    Attributes:
        is_corrupted (bool): True if current state is corrupted.
        is_complete (bool): True if parsing successfully reached the file boundary.
        bytes_remaining (int): Expected remaining bytes to read.
    """

    def __init__(self):
        """Initializes the binary offset engine state."""
        self.is_corrupted = False
        self.is_complete = False
        self.bytes_remaining = 0

    def process_binary(self, is_corrupted: bool, is_complete: bool, bytes_remaining: int = 0) -> bool:
        """Processes a new parsing block state update.

        Args:
            is_corrupted (bool): True if the block indicates corruption.
            is_complete (bool): True if the block signals file completion.
            bytes_remaining (int, optional): Number of bytes expected in subsequent reads.

        Returns:
            bool: True if the file has not encountered corruption, otherwise False.
        """
        self.is_corrupted = is_corrupted
        self.is_complete = is_complete
        self.bytes_remaining = bytes_remaining
        return not self.is_corrupted

    def is_empty(self) -> bool:
        """Checks if the parse session has completed.

        Returns:
            bool: True if the file parser is completed, otherwise False.
        """
        # for the binary engine, "empty stack" conceptually translates to "file is complete"
        return self.is_complete

    def clone(self) -> 'BinaryOffsetEngine':
        """Clones the engine state into a new instance.

        Returns:
            BinaryOffsetEngine: A copy of this engine instance.
        """
        new_engine = BinaryOffsetEngine()
        new_engine.is_corrupted = self.is_corrupted
        new_engine.is_complete = self.is_complete
        new_engine.bytes_remaining = self.bytes_remaining
        return new_engine

    def reset(self):
        """Resets the parser state back to clean initial values."""
        self.is_corrupted = False
        self.is_complete = False
        self.bytes_remaining = 0
