import unittest
from struct_carver.formats.json_parser import JSONParser


class TestJSONParser(unittest.TestCase):
    def setUp(self):
        self.parser = JSONParser()

    def test_escaped_strings(self):
        data = b'{"k{e}y": ["[\\"escaped\\"]", "value2"]}'
        tags, _ = self.parser.extract_tags(data)
        expected = [("{", False), ("[", False), ("[", True), ("{", True)]
        self.assertEqual(tags, expected)
