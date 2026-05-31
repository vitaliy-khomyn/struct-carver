"""HTML format parser for Struct Carver!

This module provides the HTMLParser class, which parses HTML document streams,
extracting semantic tag structures while ignoring void elements and comments.
"""

import re
from typing import List, Tuple
from ..base import BaseFormatParser


class HTMLParser(BaseFormatParser):
    """Parser for HTML documents that checks tag balancing using a tag stack.

    Attributes:
        void_elements (set): Set of void element tag names.
        in_comment (bool): True if parsing is currently inside an HTML comment.
        is_corrupted (bool): True if illegal control bytes are detected.
    """

    def __init__(self):
        """Initializes the HTML parser state and signature patterns."""
        self.tag_pattern = re.compile(rb'<(/?)(\w+)([^>]*)>')

        # html void elements that never have closing tags
        self.void_elements = {
            b'area', b'base', b'br', b'col', b'embed', b'hr', b'img', b'input',
            b'link', b'meta', b'param', b'source', b'track', b'wbr', b'!doctype'
        }

        self.in_comment = False
        self.is_corrupted = False

    def clone(self) -> 'HTMLParser':
        """Creates a clone of the parser with the current state.

        Returns:
            HTMLParser: The cloned parser instance.
        """
        new_parser = HTMLParser()
        new_parser.in_comment = self.in_comment
        new_parser.is_corrupted = self.is_corrupted
        return new_parser

    def reset(self):
        """Resets the parser state back to initial default values."""
        self.in_comment = False
        self.is_corrupted = False

    def state_tuple(self) -> tuple:
        """Returns a hashable tuple representing the internal parser state.

        Returns:
            tuple: representation of parser state.
        """
        return (self.in_comment, self.is_corrupted)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [b'<html', b'<!doctype html']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'</html>']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Extracts HTML tags from the data, skipping void elements and comments.

        Args:
            data (bytes): Input data block cluster to parse.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: List of parsed tags and the
                last processed byte offset in the block.
        """
        tags = []
        
        # check for binary control bytes (strictly illegal in HTML text contexts)
        for b in data:
            if b < 32 and b not in (9, 10, 13):
                self.is_corrupted = True
                return [], 0

        i = 0
        last_offset = 0
        n = len(data)

        while i < n:
            if self.in_comment:
                end_comment = data.find(b'-->', i)
                if end_comment != -1:
                    self.in_comment = False
                    i = end_comment + 3
                else:
                    break
            else:
                next_comment = data.find(b'<!--', i)
                next_tag = data.find(b'<', i)

                if next_tag == -1:
                    break

                if next_comment != -1 and next_comment <= next_tag:
                    self.in_comment = True
                    i = next_comment + 4
                else:
                    end_tag = data.find(b'>', next_tag)
                    if end_tag == -1:
                        break

                    tag_str = data[next_tag:end_tag + 1]
                    match = self.tag_pattern.match(tag_str)
                    if match:
                        is_closing = bool(match.group(1))
                        tag_name = match.group(2).lower()
                        rest = match.group(3)

                        if tag_name not in self.void_elements and not (rest.strip().endswith(b'/') or rest.strip().endswith(b'?')):
                            tags.append((tag_name.decode('ascii', errors='ignore'), is_closing))
                            last_offset = end_tag + 1

                    i = end_tag + 1

        return tags, last_offset
