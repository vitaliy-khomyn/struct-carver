"""Unit tests for BinaryOffsetEngine in Struct Carver!

Verifies state tracking, corruption flags, cloning isolation, and reset behavior.
"""

import unittest
from struct_carver.core.binary_engine import BinaryOffsetEngine


class TestBinaryOffsetEngine(unittest.TestCase):
    """Test suite verifying BinaryOffsetEngine functionality."""

    def setUp(self):
        self.engine = BinaryOffsetEngine()

    def test_initial_state(self):
        """Verifies initial defaults for corruption, completion, and remaining byte count."""
        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_empty())  # for binary engine, empty == complete
        self.assertEqual(self.engine.bytes_remaining, 0)

    def test_process_binary_valid(self):
        """Verifies state transition when processing a clean completed binary block."""
        result = self.engine.process_binary(is_corrupted=False, is_complete=True, bytes_remaining=15)
        self.assertTrue(result)
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_complete)
        self.assertTrue(self.engine.is_empty())
        self.assertEqual(self.engine.bytes_remaining, 15)

    def test_process_binary_corrupted(self):
        """Verifies corruption flag is raised when parsing invalid binary data."""
        result = self.engine.process_binary(is_corrupted=True, is_complete=False)
        self.assertFalse(result)
        self.assertTrue(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_complete)

    def test_clone(self):
        """Verifies that clone() creates an independent deep copy with matching state."""
        self.engine.process_binary(is_corrupted=False, is_complete=True, bytes_remaining=42)
        cloned = self.engine.clone()

        self.assertEqual(cloned.is_corrupted, self.engine.is_corrupted)
        self.assertEqual(cloned.is_complete, self.engine.is_complete)
        self.assertEqual(cloned.bytes_remaining, self.engine.bytes_remaining)
        self.assertIsNot(cloned, self.engine)  # ensure it is a completely separate instance

    def test_reset(self):
        """Verifies that reset() restores initial state after processing blocks."""
        self.engine.process_binary(is_corrupted=True, is_complete=True, bytes_remaining=99)
        self.engine.reset()

        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_complete)
        self.assertEqual(self.engine.bytes_remaining, 0)


if __name__ == '__main__':
    unittest.main()
