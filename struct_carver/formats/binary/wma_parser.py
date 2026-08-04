"""WMA format parser.

This module implements the parser for WMA binary format.
"""

from .asf_parser import BaseASFParser


class WMAParser(BaseASFParser):
    """Parser for WMA format files."""

    ext = "wma"

    def _verify_header_payload(self, header_data: bytes) -> bool:
        """WMA must not contain a Video Stream Header GUID.

        If a Video Stream Header GUID is present, this is WMV, not WMA.
        ASF_Video_Media GUID (little-endian): BC19EFC0-5B4D-11CF-A8FD-00805F5C442B.

        Args:
            header_data (bytes): Accumulated full ASF header payload.

        Returns:
            bool: True if ASF_Video_Media GUID is absent from the header.
        """
        video_stream_guid = b'\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B'
        return video_stream_guid not in header_data
