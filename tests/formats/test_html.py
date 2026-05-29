import unittest
from struct_carver.formats.text.html_parser import HTMLParser


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

    def test_cross_chunk_comment_state(self):
        chunk1 = b"<html><body><!-- comment started"
        chunk2 = b" still comment --> <p>text</p> </body></html>"
        tags1, _ = self.parser.extract_tags(chunk1)
        tags2, _ = self.parser.extract_tags(chunk2)
        self.assertEqual(tags1, [("html", False), ("body", False)])
        self.assertEqual(tags2, [("p", False), ("p", True), ("body", True), ("html", True)])
