"""Unit tests for the PDF component."""
import unittest
from struct_carver.formats.binary.pdf_parser import PDFParser


class TestPDFParser(unittest.TestCase):
    """Test suite for PDFParser parsing and carving."""
    def setUp(self):
        self.parser = PDFParser()

    def test_pdf_basic_completion(self):
        """Tests that pdf basic completion."""
        data = b"%pdf-1.4\n1 0 obj << /Type /Catalog >> endobj stream data endstream [ ] %%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)

    def test_pdf_stream_length_parsing(self):
        """Tests that pdf stream length parsing."""
        data = b"%pdf-1.4\n1 0 obj << /Length 4 >> endobj stream\n1234\nendstream\n%%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        self.assertEqual(remaining, 0)

    def test_pdf_stream_spillover(self):
        """Tests that pdf stream spillover."""
        chunk1 = b"%pdf-1.4\n1 0 obj << /Length 100 >> endobj stream\n1234567890"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(chunk1)
        self.assertFalse(is_corrupted)
        self.assertFalse(is_complete)
        self.assertEqual(remaining, 90)

    def test_pdf_corrupted_stream(self):
        """Tests that pdf corrupted stream."""
        data = b"%pdf-1.4\n1 0 obj << /Length 4 >> endobj stream\n1234\nbadstream\n%%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertTrue(is_corrupted)

    def test_pdf_uppercase_header(self):
        """Tests that pdf uppercase header."""
        self.assertIn(b'%PDF-', self.parser.header_signatures)
        self.assertIn(b'%pdf-', self.parser.header_signatures)
        data = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj stream data endstream [ ] %%eof"
        is_corrupted, is_complete, advance, remaining = self.parser.analyze_binary(data)
        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
