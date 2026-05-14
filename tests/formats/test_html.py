import unittest
from struct_carver.formats.html_parser import HTMLParser


class TestHTMLParser(unittest.TestCase):
    def setUp(self):
        self.parser = HTMLParser()

    def test_basic_and_void_tags(self):
        data = b"<html><body><img src='test.jpg'><br><p>text</p></body></html>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("html", False), ("body", False), ("p", False), ("p", True), ("body", True), ("html", True)]
        self.assertEqual(tags, expected)

    def test_ignore_comments(self):
        data = b"<html><body><!-- <div class='fake'> </div> --></body></html>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("html", False), ("body", False), ("body", True), ("html", True)]
        self.assertEqual(tags, expected)
