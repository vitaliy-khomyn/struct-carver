"""Unit tests for the ZIP component."""
import unittest
import struct
from struct_carver.formats.binary.zip_parser import ZIPParser


class TestZIPParser(unittest.TestCase):
    """Test suite for ZIPParser parsing and carving."""
    def setUp(self):
        self.parser = ZIPParser()

    def test_zip_complete_flow(self):
        """Tests that zip complete flow."""
        # mock Local File Header (30 bytes + 4 byte name + 5 byte data)
        local = b"PK\x03\x04" + (b"\x00" * 14) + struct.pack('<I', 5) + (b"\x00" * 4) + struct.pack('<HH', 4, 0) + b"test" + b"abcde"

        # mock Central Directory (46 bytes + 4 byte name)
        central = b"PK\x01\x02" + (b"\x00" * 24) + struct.pack('<HHH', 4, 0, 0) + (b"\x00" * 12) + b"test"

        # mock End of Central Directory (22 bytes)
        end_record = b"PK\x05\x06" + (b"\x00" * 18)

        data = local + central + end_record
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)

        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_zip_spillover_edge_case(self):
        """Tests that zip spillover edge case."""
        # 30 byte header + 4 byte name + 10 bytes expected compressed data
        local_chunk = b"PK\x03\x04" + (b"\x00" * 14) + struct.pack('<I', 10) + (b"\x00" * 4) + struct.pack('<HH', 4, 0) + b"test" + b"abc"

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(local_chunk)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 7)  # expected 10 data bytes, got 3 -> 7 remaining

    def test_zip_invalid_header(self):
        """Tests that zip invalid header."""
        data = b"Random binary noise before the header"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertTrue(is_corrupted)

    def test_zip_split_local_header_signature(self):
        """Tests that zip split local header signature."""
        self.parser.is_open = True
        rest_of_header = (b"\x00" * 14) + struct.pack('<I', 5) + (b"\x00" * 4) + struct.pack('<HH', 4, 0) + b"test" + b"abcde"
        
        chunk1 = b"PK\x03"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        
        chunk2 = b"\x04" + rest_of_header
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk2)
        self.assertFalse(is_corrupted)
        self.assertTrue(self.parser.header_verified)

    def test_zip_split_data_descriptor(self):
        """Tests that zip split data descriptor."""
        local = b"PK\x03\x04" + (b"\x00" * 2) + struct.pack('<H', 0x0008) + (b"\x00" * 10) + struct.pack('<I', 0) + (b"\x00" * 4) + struct.pack('<HH', 4, 0) + b"test"
        
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(local)
        self.assertFalse(is_corrupted)
        self.assertTrue(self.parser.in_data_descriptor)
        
        payload = b"compresseddata"
        chunk1 = payload + b"PK\x07"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertTrue(self.parser.in_data_descriptor)
        
        chunk2 = b"\x08" + b"CRCC" + struct.pack('<I', len(payload)) + b"UNCP"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk2)
        self.assertFalse(is_corrupted)
        self.assertFalse(self.parser.in_data_descriptor)
