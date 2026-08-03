"""Unit tests for StackEngine in Struct Carver!

Verifies tag stack pushing, popping, corruption detection for mismatched tags,
and deep copy isolation.
"""

import unittest
from struct_carver.core.stack_engine import StackEngine


class TestStackEngine(unittest.TestCase):
    """Test suite verifying hierarchical tag matching in StackEngine."""

    def setUp(self):
        self.engine = StackEngine()

    def test_balanced_tags(self):
        """Verifies that symmetrically balanced opening and closing tags leave the stack empty and uncorrupted."""
        tags = [("div", False), ("span", False), ("span", True), ("div", True)]
        self.assertTrue(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_empty())
        self.assertFalse(self.engine.is_corrupted)

    def test_mismatched_tags(self):
        """Verifies that closing a different tag than the top of stack marks corruption."""
        tags = [("div", False), ("span", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_empty_stack_pop(self):
        """Verifies that encountering a closing tag on an empty stack triggers corruption."""
        tags = [("div", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_clone_isolation(self):
        """Verifies that mutating a cloned stack does not affect the original engine."""
        self.engine.process_tags([("div", False)])
        clone = self.engine.clone()

        clone.process_tags([("div", True)])
        self.assertTrue(clone.is_empty())

        self.assertFalse(self.engine.is_empty())
        self.assertSequenceEqual(self.engine.stack, ["div"])

    def test_valid_nesting(self):
        """Verifies multi-level valid document nesting (e.g. html/body)."""
        tags = [("html", False), ("body", False), ("body", True), ("html", True)]
        self.engine.process_tags(tags)
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_empty())

    def test_invalid_nesting_corrupts(self):
        """Verifies out-of-order closing tags mark the document corrupted."""
        tags = [("html", False), ("body", False), ("html", True)]
        self.engine.process_tags(tags)
        self.assertTrue(self.engine.is_corrupted)

    def test_extraneous_closing_corrupts(self):
        """Verifies closing a tag without an antecedent opening tag flags corruption."""
        tags = [("body", True)]
        self.engine.process_tags(tags)
        self.assertTrue(self.engine.is_corrupted)

    def test_incomplete_stack(self):
        """Verifies unclosed tags leave the engine non-empty without marking corruption."""
        tags = [("html", False), ("body", False)]
        self.engine.process_tags(tags)
        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_empty())

    def test_clone_independence(self):
        """Verifies deep copy independence across multiple subsequent push/pop operations."""
        tags = [("html", False)]
        self.engine.process_tags(tags)

        cloned = self.engine.clone()
        cloned.process_tags([("body", False), ("body", True), ("html", True)])

        self.assertFalse(cloned.is_corrupted)
        self.assertTrue(cloned.is_empty())

        # original should remain unchanged and incomplete
        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_empty())

    def test_reset(self):
        """Verifies reset() clears all stacked tags and corruption flags."""
        self.engine.process_tags([("html", False), ("html", True), ("extraneous", True)])
        self.engine.reset()
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_empty())


if __name__ == '__main__':
    unittest.main()
