import unittest
from struct_carver.core.stack_engine import StackEngine


class TestStackEngine(unittest.TestCase):
    def setUp(self):
        self.engine = StackEngine()

    def test_balanced_tags(self):
        tags = [("div", False), ("span", False), ("span", True), ("div", True)]
        self.assertTrue(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_empty())
        self.assertFalse(self.engine.is_corrupted)

    def test_mismatched_tags(self):
        tags = [("div", False), ("span", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_empty_stack_pop(self):
        tags = [("div", True)]
        self.assertFalse(self.engine.process_tags(tags))
        self.assertTrue(self.engine.is_corrupted)

    def test_clone_isolation(self):
        self.engine.process_tags([("div", False)])
        clone = self.engine.clone()

        clone.process_tags([("div", True)])
        self.assertTrue(clone.is_empty())

        self.assertFalse(self.engine.is_empty())
        self.assertSequenceEqual(self.engine.stack, ["div"])
