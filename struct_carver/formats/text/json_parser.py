"""JSON format parser for Struct Carver!

This module provides the JSONParser class, which parses JSON documents
by extracting structural braces and brackets while safely skipping escaped strings.
"""

from typing import List, Tuple
from ..base import TextFormatParser


class JSONParser(TextFormatParser):
    """Parser for JSON documents that tracks bracket and brace balancing.

    Attributes:
        in_string (bool): True if parser is currently inside a JSON string.
        escape_next (bool): True if the previous character was a backslash.
        is_corrupted (bool): True if illegal characters or control bytes are found.
    """

    def __init__(self):
        """Initializes the JSON parser state."""
        self.in_string = False
        self.escape_next = False
        self.is_corrupted = False
        self.depth = 0
        self.has_opened = False

    def clone(self) -> 'JSONParser':
        """Creates a clone of the parser with the current state.

        Returns:
            JSONParser: The cloned parser instance.
        """
        new_parser = JSONParser()
        new_parser.in_string = self.in_string
        new_parser.escape_next = self.escape_next
        new_parser.is_corrupted = self.is_corrupted
        new_parser.depth = self.depth
        new_parser.has_opened = self.has_opened
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.in_string = False
        self.escape_next = False
        self.is_corrupted = False
        self.depth = 0
        self.has_opened = False

    def state_tuple(self) -> tuple:
        """Returns a hashable representation of the parser state.

        Returns:
            tuple: representation of parser state.
        """
        return (self.in_string, self.escape_next, self.is_corrupted, self.depth, self.has_opened)

    def has_continuation_markers(self, candidate_cluster: bytes) -> bool:
        """Checks if a candidate cluster contains JSON structure delimiter characters.

        Args:
            candidate_cluster (bytes): Raw candidate cluster.

        Returns:
            bool: True if JSON structure characters are detected.
        """
        return any(c in candidate_cluster for c in [b'{', b'}', b'[', b']', b'\\'])

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        # simple heuristic headers for JSON objects or arrays
        return [b'{"', b'[{']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'}', b']']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Extracts brace and bracket tags, handling string and escape sequences.

        Args:
            data (bytes): Input data block cluster to parse.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: List of parsed brackets/braces
                and the last processed byte offset.
        """
        tags = []
        last_offset = 0
        allowed_outside = b' \t\r\n{}[]:,-+0123456789.eEtruesfaln'

        for i, byte_val in enumerate(data):
            # control characters (except tab, LF, CR) are strictly illegal in JSON
            if self.is_illegal_control_byte(byte_val):
                self.is_corrupted = True
                break

            if self.in_string:
                if self.escape_next:
                    self.escape_next = False
                elif byte_val == ord('\\'):
                    self.escape_next = True
                elif byte_val == ord('"'):
                    self.in_string = False
            else:
                # if root object or array has already closed, inspect trailing bytes
                if self.has_opened and self.depth == 0:
                    if byte_val in (ord(' '), ord('\t'), ord('\r'), ord('\n')):
                        continue
                    elif byte_val in (ord('{'), ord('[')):
                        # start of a new root document; complete current document here
                        break
                    else:
                        self.is_corrupted = True
                        break

                if byte_val == ord('"'):
                    self.in_string = True
                elif byte_val not in allowed_outside:
                    self.is_corrupted = True
                    break
                elif byte_val == ord('{'):
                    tags.append(('{', False))
                    self.depth += 1
                    self.has_opened = True
                    last_offset = i + 1
                elif byte_val == ord('}'):
                    tags.append(('{', True))
                    self.depth -= 1
                    last_offset = i + 1
                elif byte_val == ord('['):
                    tags.append(('[', False))
                    self.depth += 1
                    self.has_opened = True
                    last_offset = i + 1
                elif byte_val == ord(']'):
                    tags.append(('[', True))
                    self.depth -= 1
                    last_offset = i + 1

        return tags, last_offset
