import unittest
from struct_carver.formats.rtf_parser import RTFParser


class TestRTFParser(unittest.TestCase):
    def setUp(self):
        self.parser = RTFParser()

    def test_escaped_braces(self):
        data = rb"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Hello \{ World! \}}"
        tags, _ = self.parser.extract_tags(data)
        expected = [("{", False), ("{", False), ("{", True), ("{", True)]
        self.assertEqual(tags, expected)
