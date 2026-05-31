"""Unit tests for the STACK_ENGINE component."""
import unittest
from struct_carver.core.stack_engine import StackEngine


class TestStackEngine(unittest.TestCase):
    """Test suite for StackEngine parsing and carving."""
    def setUp(self):
        self.engine = StackEngine()

    def test_balanced_tags(self):
        """Tests that balanced tags."""
        tags = [("div", False), ("span", False), ("span", True), ("div", True)]
        self.assertTrue(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_empty())
        self.assertFalse(self.engine.is_corrupted)

    def test_mismatched_tags(self):
        """Tests that mismatched tags."""
        tags = [("div", False), ("span", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_empty_stack_pop(self):
        """Tests that empty stack pop."""
        tags = [("div", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_clone_isolation(self):
        """Tests that clone isolation."""
        self.engine.process_tags([("div", False)])
        clone = self.engine.clone()

        clone.process_tags([("div", True)])
        self.assertTrue(clone.is_empty())

        self.assertFalse(self.engine.is_empty())
        self.assertSequenceEqual(self.engine.stack, ["div"])

    def test_valid_nesting(self):
        """Tests that valid nesting."""
        # properly nested structure: <html><body></body></html>
        tags = [("html", False), ("body", False), ("body", True), ("html", True)]
        self.engine.process_tags(tags)
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_empty())

    def test_invalid_nesting_corrupts(self):
        """Tests that invalid nesting corrupts."""
        # mismatched tags: <html><body></html>
        tags = [("html", False), ("body", False), ("html", True)]
        self.engine.process_tags(tags)
        self.assertTrue(self.engine.is_corrupted)

    def test_extraneous_closing_corrupts(self):
        """Tests that extraneous closing corrupts."""
        # trying to close a tag when the stack is empty
        tags = [("body", True)]
        self.engine.process_tags(tags)
        self.assertTrue(self.engine.is_corrupted)

    def test_incomplete_stack(self):
        """Tests that incomplete stack."""
        # left open: <html><body>
        tags = [("html", False), ("body", False)]
        self.engine.process_tags(tags)
        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_empty())  # stack is not empty

    def test_clone_independence(self):
        """Tests that clone independence."""
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
        """Tests that reset."""
        self.engine.process_tags([("html", False), ("html", True), ("extraneous", True)])
        self.engine.reset()
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_empty())
