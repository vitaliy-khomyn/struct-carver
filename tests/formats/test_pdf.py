"""Unit tests for the PDF format parser."""
import unittest
from struct_carver.formats.binary.pdf_parser import PDFParser


class TestPDFParser(unittest.TestCase):
    """Test suite for PDFParser parsing and carving."""
    def setUp(self):
        self.parser = PDFParser()

    def test_pdf_basic_completion(self):
        """Verify standard PDF structure detects completion upon matching EOF marker."""
        data = b"%pdf-1.4\n1 0 obj << /Type /Catalog >> endobj stream data endstream [ ] %%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)

    def test_pdf_stream_length_parsing(self):
        """Verify stream length parsing from PDF dictionary object."""
        data = b"%pdf-1.4\n1 0 obj << /Length 4 >> endobj stream\n1234\nendstream\n%%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_pdf_stream_spillover(self):
        """Verify remaining byte tracking when stream payload spans multiple chunks."""
        chunk1 = b"%pdf-1.4\n1 0 obj << /Length 100 >> endobj stream\n1234567890"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 90)

    def test_pdf_corrupted_stream(self):
        """Verify corruption detection when stream does not terminate with endstream."""
        data = b"%pdf-1.4\n1 0 obj << /Length 4 >> endobj stream\n1234\nbadstream\n%%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertTrue(is_corrupted)

    def test_pdf_uppercase_header(self):
        """Verify support for both uppercase %PDF- and lowercase %pdf- signatures."""
        self.assertIn(b'%PDF-', self.parser.header_signatures)
        self.assertIn(b'%pdf-', self.parser.header_signatures)
        data = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj stream data endstream [ ] %%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)

    def test_pdf_indirect_stream_length(self):
        """Verify indirect stream length references (e.g. /Length 12 0 R) are parsed via delimiter scanning."""
        data = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /XObject /Subtype /Image /Width 10 /Height 10 /Length 12 0 R >>\n"
            b"stream\n"
            b"Binary image stream data that is much longer than 12 bytes\n"
            b"endstream\n"
            b"endobj\n"
            b"%%EOF\n"
        )
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_pdf_multi_object_mixed_lengths(self):
        """Verify earlier direct length tags do not leak into subsequent indirect stream dictionaries."""
        data = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Length 4 >>\n"
            b"stream\n"
            b"1234\n"
            b"endstream\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /XObject /Length 25 0 R >>\n"
            b"stream\n"
            b"Second stream with indirect length reference\n"
            b"endstream\n"
            b"endobj\n"
            b"%%EOF\n"
        )
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_pdf_indirect_stream_spillover(self):
        """Verify indirect stream spanning multiple chunks tracks continuation with remaining=-1."""
        chunk1 = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Length 12 0 R >>\n"
            b"stream\n"
            b"First part of indirect stream payload without terminating marker"
        )
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, -1)

        chunk2 = b"Second part of indirect stream payload\nendstream\nendobj\n%%EOF"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk2, bytes_remaining=remaining)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_pdf_direct_length_discrepancy_fallback(self):
        """Verify direct length discrepancy falls back to scanning for endstream rather than aborting."""
        # /Length claims 6 bytes, but payload is actually 10 bytes
        data = b"%PDF-1.4\n1 0 obj << /Length 6 >> stream\n0123456789\nendstream\n%%EOF"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)

    def test_pdf_gap_jump_verify_zero_filler(self):
        """Verify gap_jump_verify rejects unallocated zero-filler blocks and accepts valid data."""
        # 4096 zero bytes (unallocated disk fill) must be rejected
        self.assertFalse(self.parser.gap_jump_verify(b'\x00' * 4096))
        # valid non-zero PDF continuation data must be accepted
        self.assertTrue(self.parser.gap_jump_verify(b'1 0 obj << /Type /Pages >> endobj'))
        # conflicting signature (e.g. JPEG) must be rejected
        self.assertFalse(self.parser.gap_jump_verify(b'\xFF\xD8\xFF\xE0\x00\x10JFIF'))

