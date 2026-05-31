"""Unit tests for the XML component."""
import unittest
from struct_carver.formats.text.xml_parser import XMLParser


class TestXMLParser(unittest.TestCase):
    """Test suite for XMLParser parsing and carving."""
    def setUp(self):
        self.parser = XMLParser()

    def test_basic_tags(self):
        """Tests that basic tags."""
        data = b"<root><node>text</node><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_cdata_and_comments(self):
        """Tests that cdata and comments."""
        data = b"<root><node>text</node><![CDATA[<fake>data</fake>]]><!-- <ignored></ignored> --><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_cross_chunk_cdata_state(self):
        """Tests that cross chunk cdata state."""
        chunk1 = b"<root><node>text</node><![CDATA[<fake>"
        chunk2 = b"data</fake>]]><empty/></root>"
        tags1, _ = self.parser.extract_tags(chunk1)
        tags2, _ = self.parser.extract_tags(chunk2)
        self.assertEqual(tags1, [("root", False), ("node", False), ("node", True)])
        self.assertEqual(tags2, [("root", True)])
