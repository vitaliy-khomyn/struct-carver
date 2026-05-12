import unittest
from struct_carver.formats.xml_parser import XMLParser
from struct_carver.formats.html_parser import HTMLParser
from struct_carver.formats.pdf_parser import PDFParser
from struct_carver.formats.json_parser import JSONParser
from struct_carver.formats.rtf_parser import RTFParser
from struct_carver.formats.zip_parser import ZIPParser


class TestFormats(unittest.TestCase):
    def test_xml_parser(self):
        parser = XMLParser()
        data = "<root><node>text</node><![CDATA[<fake>data</fake>]]><!-- <ignored></ignored> --><empty/></root>"
        tags = parser.extract_tags(data)
        expected = [("root", False), ("node", False), ("node", True), ("root", True)]
        self.assertEqual(tags, expected)

    def test_html_parser(self):
        parser = HTMLParser()
        data = "<html><body><!-- <div class='fake'> </div> --><img src='test.jpg'><br><p>text</p></body></html>"
        tags = parser.extract_tags(data)
        expected = [("html", False), ("body", False), ("p", False), ("p", True), ("body", True), ("html", True)]
        self.assertEqual(tags, expected)

    def test_pdf_parser(self):
        parser = PDFParser()
        data = "1 0 obj << /Type /Catalog >> endobj stream data endstream [ ]"
        tags = parser.extract_tags(data)
        expected = [
            ("obj", False), ("<<", False), ("<<", True), ("obj", True),
            ("stream", False), ("stream", True), ("[", False), ("[", True)
        ]
        self.assertEqual(tags, expected)

    def test_json_parser(self):
        parser = JSONParser()
        data = '{"k{e}y": ["[\\"escaped\\"]", "value2"]}'
        tags = parser.extract_tags(data)
        expected = [("{", False), ("[", False), ("[", True), ("{", True)]
        self.assertEqual(tags, expected)

    def test_rtf_parser(self):
        parser = RTFParser()
        data = r"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Hello World!}"
        tags = parser.extract_tags(data)
        expected = [("{", False), ("{", False), ("{", True), ("{", True)]
        self.assertEqual(tags, expected)

    def test_zip_parser(self):
        parser = ZIPParser()
        # Simulate ZIP with two local headers and one end of central directory
        data = "PK\x03\x04_file1_PK\x03\x04_file2_PK\x01\x02_dir_PK\x05\x06_end_"
        tags = parser.extract_tags(data)
        expected = [("zip", False), ("zip", True)]
        self.assertEqual(tags, expected)
