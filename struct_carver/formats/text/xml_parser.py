"""XML format parser for Struct Carver!

This module provides the XMLParser class, which parses XML document streams,
extracting tags while handling comments and CDATA sections.
"""

import re
from typing import List, Tuple
from ..base import BaseFormatParser


class XMLParser(BaseFormatParser):
    """Parser for XML documents that validates structure using nested tags.

    Attributes:
        in_cdata (bool): True if parsing is currently inside a CDATA block.
        in_comment (bool): True if parsing is currently inside an XML comment.
        is_corrupted (bool): True if illegal control bytes are detected.
    """

    def __init__(self):
        """Initializes the XML parser state and tag pattern."""
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')

        self.in_cdata = False
        self.in_comment = False
        self.is_corrupted = False

    def clone(self) -> 'XMLParser':
        """Creates a clone of the parser with the current state.

        Returns:
            XMLParser: The cloned parser instance.
        """
        new_parser = XMLParser()
        new_parser.in_cdata = self.in_cdata
        new_parser.in_comment = self.in_comment
        new_parser.is_corrupted = self.is_corrupted
        return new_parser

    def reset(self):
        """Resets the parser state back to initial default values."""
        self.in_cdata = False
        self.in_comment = False
        self.is_corrupted = False

    def state_tuple(self) -> tuple:
        """Returns a hashable tuple representing the internal parser state.

        Returns:
            tuple: representation of parser state.
        """
        return (self.in_cdata, self.in_comment, self.is_corrupted)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [b'<?xml', b'<html']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'</root>', b'</html>']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Extracts XML tag elements, skipping CDATA and comments.

        Args:
            data (bytes): Input data block cluster to parse.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: List of parsed tags and the
                last processed byte offset.
        """
        tags = []
        
        # check for binary control bytes (strictly illegal in XML)
        for b in data:
            if b < 32 and b not in (9, 10, 13):
                self.is_corrupted = True
                return [], 0

        i = 0
        last_offset = 0
        n = len(data)

        while i < n:
            if self.in_cdata:
                end_cdata = data.find(b']]>', i)
                if end_cdata != -1:
                    self.in_cdata = False
                    i = end_cdata + 3
                else:
                    break
            elif self.in_comment:
                end_comment = data.find(b'-->', i)
                if end_comment != -1:
                    self.in_comment = False
                    i = end_comment + 3
                else:
                    break
            else:
                next_tag = data.find(b'<', i)
                if next_tag == -1:
                    break

                if data.startswith(b'<![CDATA[', next_tag):
                    self.in_cdata = True
                    i = next_tag + 9
                elif data.startswith(b'<!--', next_tag):
                    self.in_comment = True
                    i = next_tag + 4
                else:
                    end_tag = data.find(b'>', next_tag)
                    if end_tag == -1:
                        break

                    tag_str = data[next_tag:end_tag + 1]
                    match = self.tag_pattern.match(tag_str)
                    if match:
                        is_closing = bool(match.group(1))
                        tag_name = match.group(2).decode('ascii', errors='ignore').lower()
                        rest = match.group(3)

                        if not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                            tags.append((tag_name, is_closing))
                            last_offset = end_tag + 1

                    i = end_tag + 1

        return tags, last_offset
