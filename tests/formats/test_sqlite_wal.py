import unittest
import struct
from struct_carver.formats.binary.sqlite_wal_parser import SQLiteWALParser


class TestSQLiteWALParser(unittest.TestCase):
    def setUp(self):
        self.parser = SQLiteWALParser()

    def _build_mock_wal(self, endian_char: str, magic: bytes, page_size: int, salt1: int, salt2: int, valid_frame: bool = True) -> bytes:
        """Helper to build a 32-byte WAL Header and a 24-byte Frame Header with given endianness."""
        # file Header (32 bytes): Magic (4s) + Format (I) + PageSize (I) + Checkpoint (I) + Salt1 (I) + Salt2 (I) + Chk1 (I) + Chk2 (I)
        file_header = struct.pack(f'{endian_char}4sIIIIIII', magic, 3007000, page_size, 0, salt1, salt2, 0, 0)

        # frame Header (24 bytes): PageNum (I) + Commit (I) + Salt1 (I) + Salt2 (I) + Chk1 (I) + Chk2 (I)
        frame_salt1 = salt1 if valid_frame else salt1 + 1
        frame_header = struct.pack(f'{endian_char}IIIIII', 1, 1, frame_salt1, salt2, 0, 0)

        # frame Data (page_size bytes)
        frame_data = b'\xAA' * page_size

        return file_header + frame_header + frame_data

    def test_little_endian_wal(self):
        # 0x377f0682 triggers Little-Endian parsing ('<')
        data = self._build_mock_wal('<', b'\x37\x7f\x06\x82', 4096, 12345, 67890)

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)

        self.assertFalse(is_corrupted)
        self.assertEqual(self.parser.endian, '<', "Parser failed to switch to Little-Endian mode.")
        self.assertEqual(self.parser.page_size, 4096)
        self.assertEqual(self.parser.salt1, 12345)
        self.assertEqual(self.parser.salt2, 67890)

    def test_big_endian_wal(self):
        # 0x377f0683 triggers Big-Endian parsing ('>')
        data = self._build_mock_wal('>', b'\x37\x7f\x06\x83', 1024, 54321, 9876)

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)

        self.assertFalse(is_corrupted)
        self.assertEqual(self.parser.endian, '>', "Parser failed to switch to Big-Endian mode.")
        self.assertEqual(self.parser.page_size, 1024)
        self.assertEqual(self.parser.salt1, 54321)
        self.assertEqual(self.parser.salt2, 9876)

    def test_wal_frame_mismatch_eof_completion(self):
        # inject an invalid frame salt to simulate a broken frame/fragmentation boundary, which should act as EOF
        data = self._build_mock_wal('<', b'\x37\x7f\x06\x82', 4096, 1111, 2222, valid_frame=False)
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted, "WAL EOF should not be flagged as corruption.")
        self.assertTrue(is_complete, "WAL salt mismatch should mark completion (EOF).")
        self.assertEqual(advance, 32, "WAL completion should advance exactly up to the last valid frame (32 bytes header).")

    def test_wal_spillover_in_frame_data(self):
        # Frame data split across chunks
        data = self._build_mock_wal('<', b'\x37\x7f\x06\x82', 4096, 111, 222)

        # 32 (file header) + 24 (frame header) + 100 (partial data) = 156
        chunk1 = data[:156]

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 3996)  # 4096 - 100

    def test_wal_spillover_in_frame_header(self):
        # Frame header split across chunks
        data = self._build_mock_wal('>', b'\x37\x7f\x06\x83', 1024, 333, 444)

        # 32 (file header) + 10 (partial frame header) = 42
        chunk1 = data[:42]

        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 14)  # 24 - 10
