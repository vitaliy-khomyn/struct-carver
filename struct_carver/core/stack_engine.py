from collections import deque
from typing import List, Tuple


class StackEngine:
    def __init__(self):
        self.stack = deque()
        self.is_corrupted = False

    def process_tags(self, tags: List[Tuple[str, bool]]) -> bool:
        """
        Processes a list of tags.
        Returns True if the file seems balanced/valid so far.
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
        return len(self.stack) == 0

    def reset(self):
        self.stack = []
        self.is_corrupted = False

    def clone(self) -> 'StackEngine':
        new_engine = StackEngine()
        new_engine.stack = self.stack.copy()
        new_engine.is_corrupted = self.is_corrupted
        return new_engine
