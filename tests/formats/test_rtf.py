"""Unit tests for the RTF component."""
import unittest
from struct_carver.formats.text.rtf_parser import RTFParser


class TestRTFParser(unittest.TestCase):
    """Test suite for RTFParser parsing and carving."""
    def setUp(self):
        self.parser = RTFParser()

    def test_escaped_braces(self):
        """Tests that escaped braces."""
        data = rb"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Hello \{ World! \}}"
        tags, _ = self.parser.extract_tags(data)
        expected = [("{", False), ("{", False), ("{", True), ("{", True)]
        self.assertEqual(tags, expected)
