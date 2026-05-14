import unittest
from struct_carver.formats.xml_parser import XMLParser


class TestXMLParser(unittest.TestCase):
    def setUp(self):
        self.parser = XMLParser()

    def test_basic_tags(self):
        data = b"<root><node>text</node><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_cdata_and_comments(self):
        data = b"<root><node>text</node><![CDATA[<fake>data</fake>]]><!-- <ignored></ignored> --><empty/></root>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)
