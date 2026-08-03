"""Unit tests for HTMLParser.

Verifies tag extraction, void element suppression, comment skipping, and cross-chunk comment state.
"""

import unittest
from struct_carver.formats.text.html_parser import HTMLParser


class TestHTMLParser(unittest.TestCase):
    """Test suite verifying HTML tag extraction and parser state tracking."""

    def setUp(self):
        self.parser = HTMLParser()

    def test_basic_and_void_tags(self):
        """Verifies paired tags are extracted while void elements (img, br) are ignored."""
        data = b"<html><body><img src='test.jpg'><br><p>text</p></body></html>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("html", False), ("body", False), ("p", False), ("p", True), ("body", True), ("html", True)]
        self.assertEqual(tags, expected)

    def test_ignore_comments(self):
        """Verifies fake tags inside HTML comments are ignored."""
        data = b"<html><body><!-- <div class='fake'> </div> --></body></html>"
        tags, _ = self.parser.extract_tags(data)
        expected = [("html", False), ("body", False), ("body", True), ("html", True)]
        self.assertEqual(tags, expected)

    def test_cross_chunk_comment_state(self):
        """Verifies that an unclosed comment in chunk 1 suppresses tags in chunk 2 until closed."""
        chunk1 = b"<html><body><!-- comment started"
        chunk2 = b" still comment --> <p>text</p> </body></html>"
        tags1, _ = self.parser.extract_tags(chunk1)
        tags2, _ = self.parser.extract_tags(chunk2)
        self.assertEqual(tags1, [("html", False), ("body", False)])
        self.assertEqual(tags2, [("p", False), ("p", True), ("body", True), ("html", True)])


if __name__ == '__main__':
    unittest.main()
