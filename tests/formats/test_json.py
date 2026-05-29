import unittest
from struct_carver.formats.text.json_parser import JSONParser


class TestJSONParser(unittest.TestCase):
    def setUp(self):
        self.parser = JSONParser()

    def test_escaped_strings(self):
        data = b'{"k{e}y": ["[\\"escaped\\"]", "value2"]}'
        tags, _ = self.parser.extract_tags(data)
        expected = [("{", False), ("[", False), ("[", True), ("{", True)]
        self.assertEqual(tags, expected)

    def test_cross_chunk_string_state(self):
        chunk1 = b'{"k{e}y": ["started string ['
        chunk2 = b'] ended string", "value2"]}'
        tags1, _ = self.parser.extract_tags(chunk1)
        tags2, _ = self.parser.extract_tags(chunk2)
        self.assertEqual(tags1, [("{", False), ("[", False)])
        self.assertEqual(tags2, [("[", True), ("{", True)])
