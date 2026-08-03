"""Unit tests for XMLParser in Struct Carver!

Verifies tag extraction, CDATA and comment filtering, self-closing tag handling,
and cross-chunk CDATA parsing state.
"""

import unittest
from struct_carver.formats.text.xml_parser import XMLParser


class TestXMLParser(unittest.TestCase):
    """Test suite verifying XML structural tag extraction."""

    def setUp(self):
        self.parser = XMLParser()

    def test_basic_tags(self):
        """Verifies matched tag extraction while ignoring self-closing elements."""
        data = b"<root><node>text</node><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_cdata_and_comments(self):
        """Verifies pseudo-tags embedded inside CDATA sections and comments are ignored."""
        data = b"<root><node>text</node><![CDATA[<fake>data</fake>]]><!-- <ignored></ignored> --><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_cross_chunk_cdata_state(self):
        """Verifies unclosed CDATA sections spanning chunk boundaries preserve suppression state."""
        chunk1 = b"<root><node>text</node><![CDATA[<fake>"
        chunk2 = b"data</fake>]]><empty/></root>"
        tags1, _ = self.parser.extract_tags(chunk1)
        tags2, _ = self.parser.extract_tags(chunk2)
        self.assertEqual(tags1, [("root", False), ("node", False), ("node", True)])
        self.assertEqual(tags2, [("root", True)])


if __name__ == '__main__':
    unittest.main()
