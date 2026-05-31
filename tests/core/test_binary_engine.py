"""Unit tests for the BINARY_ENGINE component."""
import unittest
from struct_carver.core.binary_engine import BinaryOffsetEngine


class TestBinaryOffsetEngine(unittest.TestCase):
    """Test suite for BinaryOffsetEngine parsing and carving."""
    def setUp(self):
        self.engine = BinaryOffsetEngine()

    def test_initial_state(self):
        """Tests that initial state."""
        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_empty())  # for binary engine, empty == complete
        self.assertEqual(self.engine.bytes_remaining, 0)

    def test_process_binary_valid(self):
        """Tests that process binary valid."""
        result = self.engine.process_binary(is_corrupted=False, is_complete=True, bytes_remaining=15)
        self.assertTrue(result)
        self.assertFalse(self.engine.is_corrupted)
        self.assertTrue(self.engine.is_complete)
        self.assertTrue(self.engine.is_empty())
        self.assertEqual(self.engine.bytes_remaining, 15)

    def test_process_binary_corrupted(self):
        """Tests that process binary corrupted."""
        result = self.engine.process_binary(is_corrupted=True, is_complete=False)
        self.assertFalse(result)
        self.assertTrue(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_complete)

    def test_clone(self):
        """Tests that clone."""
        self.engine.process_binary(is_corrupted=False, is_complete=True, bytes_remaining=42)
        cloned = self.engine.clone()

        self.assertEqual(cloned.is_corrupted, self.engine.is_corrupted)
        self.assertEqual(cloned.is_complete, self.engine.is_complete)
        self.assertEqual(cloned.bytes_remaining, self.engine.bytes_remaining)
        self.assertIsNot(cloned, self.engine)  # ensure it is a completely separate instance

    def test_reset(self):
        """Tests that reset."""
        self.engine.process_binary(is_corrupted=True, is_complete=True, bytes_remaining=99)
        self.engine.reset()

        self.assertFalse(self.engine.is_corrupted)
        self.assertFalse(self.engine.is_complete)
        self.assertEqual(self.engine.bytes_remaining, 0)
