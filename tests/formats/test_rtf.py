"""Unit tests for RTFParser.

Verifies RTF brace structure extraction and escaped character handling.
"""

import unittest
from struct_carver.formats.text.rtf_parser import RTFParser


class TestRTFParser(unittest.TestCase):
    """Test suite verifying RTF brace matching."""

    def setUp(self):
        self.parser = RTFParser()

    def test_escaped_braces(self):
        """Verifies escaped literal braces (\\{ and \\}) are not treated as document scope boundaries."""
        data = rb"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Hello \{ World! \}}"
        tags, _ = self.parser.extract_tags(data)
        expected = [("{", False), ("{", False), ("{", True), ("{", True)]
        self.assertEqual(tags, expected)


if __name__ == '__main__':
    unittest.main()
