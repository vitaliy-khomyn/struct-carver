"""Tag tracking stack engine for Struct Carver!

This module implements the StackEngine, which tracks opening and closing tags
for hierarchical textual formats (such as HTML, XML) to verify balance and integrity.
"""

from collections import deque
from typing import List, Tuple


class StackEngine:
    """Engine that manages semantic tags using an internal stack.

    Attributes:
        stack (deque): Stack storing tag names as they are parsed.
        is_corrupted (bool): True if tag mismatches or underflows are detected.
    """

    def __init__(self):
        """Initializes the stack engine state."""
        self.stack = deque()
        self.is_corrupted = False

    def process_tags(self, tags: List[Tuple[str, bool]]) -> bool:
        """Processes a list of tags to update the stack state.

        Args:
            tags (List[Tuple[str, bool]]): List of parsed tags, where each tag
                is represented as a tuple of (tag_name, is_closing).

        Returns:
            bool: True if the tags are balanced/valid so far, otherwise False.
        """
        for tag_name, is_closing in tags:
            if not is_closing:
                self.stack.append(tag_name)
            else:
                if not self.stack:
                    self.is_corrupted = True
                    return False

                expected_tag = self.stack.pop()
                if expected_tag != tag_name:
                    self.is_corrupted = True
                    return False
        return True

    def is_empty(self) -> bool:
        """Checks if the stack is currently empty.

        Returns:
            bool: True if empty, otherwise False.
        """
        return len(self.stack) == 0

    def reset(self):
        """Resets the tag stack and corruption flag to clear initial state."""
        self.stack.clear()
        self.is_corrupted = False

    def clone(self) -> 'StackEngine':
        """Clones the engine state into a new instance.

        Returns:
            StackEngine: A copy of this engine instance.
        """
        new_engine = StackEngine()
        new_engine.stack = self.stack.copy()
        new_engine.is_corrupted = self.is_corrupted
        return new_engine
