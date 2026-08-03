"""Unit tests for SQLiteParser in Struct Carver!

Verifies SQLite header decoding, page size calculations (including the 65536 edge case),
spillover handling across multiple clusters, and corruption detection.
"""

import unittest
import struct
from struct_carver.formats.binary.sqlite_parser import SQLiteParser


class TestSQLiteParser(unittest.TestCase):
    """Test suite verifying SQLite binary header analysis."""

    def setUp(self):
        self.parser = SQLiteParser()

    def _build_mock_header(self, page_size: int, num_pages: int) -> bytes:
        """Helper to build a 32-byte SQLite header with specific page sizes and counts."""
        sig = b'SQLite format 3\x00'
        ps_bytes = struct.pack('>H', page_size)
        np_bytes = struct.pack('>I', num_pages)
        # SQLite format: signature(16) + page_size(2) + padding(10) + num_pages(4) = 32 bytes
        return sig + ps_bytes + (b'\x00' * 10) + np_bytes

    def test_sqlite_complete_flow(self):
        """Verifies successful completion when entire page payload is present."""
        # 4096 bytes per page, 2 pages = 8192 bytes total
        header = self._build_mock_header(4096, 2)
        data = header + (b'\xAA' * (8192 - 32))

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)
        self.assertEqual(advance, 8192)

    def test_sqlite_spillover_calculation(self):
        """Verifies remaining byte calculations when data spans beyond the current cluster."""
        # 1024 bytes per page, 5 pages = 5120 bytes total
        header = self._build_mock_header(1024, 5)
        chunk1 = header + (b'\xAA' * (1024 - 32))  # provide exactly 1024 bytes (1 cluster)

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 4096)  # should correctly expect exactly 4096 more bytes

    def test_sqlite_page_size_1_edge_case(self):
        """Verifies the SQLite specification edge case where page_size=1 represents 65536 bytes."""
        header = self._build_mock_header(1, 2)  # total should be 131,072 bytes

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(header)
        self.assertFalse(is_corrupted)
        self.assertEqual(remaining, 131072 - 32)

    def test_sqlite_corrupted_header(self):
        """Verifies that an illegal page_size (0) flags the header as corrupted."""
        header = self._build_mock_header(0, 10)  # invalid page size of 0
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(header)
        self.assertTrue(is_corrupted)


if __name__ == '__main__':
    unittest.main()
