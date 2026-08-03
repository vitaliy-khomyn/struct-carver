"""Format parser registry.

This module manages format parser discovery, initialization, custom parser
registration, and extension lookups.
"""

from typing import List, Dict, Type, Optional, Any
from struct_carver.formats.base import BaseFormatParser
from struct_carver.formats.text.xml_parser import XMLParser
from struct_carver.formats.text.html_parser import HTMLParser
from struct_carver.formats.binary.pdf_parser import PDFParser
from struct_carver.formats.text.json_parser import JSONParser
from struct_carver.formats.text.rtf_parser import RTFParser
from struct_carver.formats.binary.zip_parser import ZIPParser
from struct_carver.formats.binary.sqlite_parser import SQLiteParser
from struct_carver.formats.binary.sqlite_wal_parser import SQLiteWALParser
from struct_carver.formats.binary.jpg_parser import JPGParser
from struct_carver.formats.binary.png_parser import PNGParser
from struct_carver.formats.binary.gif_parser import GIFParser
from struct_carver.formats.binary.bmp_parser import BMPParser
from struct_carver.formats.binary.tiff_parser import TIFFParser
from struct_carver.formats.binary.pcx_parser import PCXParser
from struct_carver.formats.binary.wav_parser import WAVParser
from struct_carver.formats.binary.mp3_parser import MP3Parser
from struct_carver.formats.binary.au_parser import AUParser
from struct_carver.formats.binary.wma_parser import WMAParser
from struct_carver.formats.binary.wmv_parser import WMVParser
from struct_carver.formats.binary.avi_parser import AVIParser
from struct_carver.formats.binary.mp4_parser import MP4Parser
from struct_carver.formats.binary.mov_parser import MOVParser
from struct_carver.formats.binary.flv_parser import FLVParser
from struct_carver.formats.binary.mpg_parser import MPGParser
from struct_carver.formats.binary.seven_z_parser import SevenZParser
from struct_carver.formats.binary.rar_parser import RARParser
from struct_carver.formats.binary.gz_parser import GZParser
from struct_carver.formats.binary.bz2_parser import BZ2Parser
from struct_carver.formats.binary.tar_parser import TARParser
from struct_carver.formats.binary.wim_parser import WIMParser


AVAILABLE_PARSERS: Dict[str, Type[BaseFormatParser]] = {
    'xml': XMLParser,
    'html': HTMLParser,
    'pdf': PDFParser,
    'json': JSONParser,
    'rtf': RTFParser,
    'zip': ZIPParser,
    'sqlite': SQLiteParser,
    'sqlitewal': SQLiteWALParser,
    'jpg': JPGParser,
    'png': PNGParser,
    'gif': GIFParser,
    'bmp': BMPParser,
    'tiff': TIFFParser,
    'pcx': PCXParser,
    'wav': WAVParser,
    'mp3': MP3Parser,
    'au': AUParser,
    'wma': WMAParser,
    'wmv': WMVParser,
    'avi': AVIParser,
    'mp4': MP4Parser,
    'mov': MOVParser,
    'flv': FLVParser,
    'mpg': MPGParser,
    '7z': SevenZParser,
    'rar': RARParser,
    'gz': GZParser,
    'bz2': BZ2Parser,
    'tar': TARParser,
    'wim': WIMParser,
    'docx': ZIPParser,
    'xlsx': ZIPParser,
    'pptx': ZIPParser,
    'tif': TIFFParser,
}


class ParserRegistry:
    """Registry managing available format parsers and instances for carving sessions.

    Attributes:
        parsers (List[BaseFormatParser]): List of active parser instances.
        ext_map (Dict[Type, str]): Reverse lookup dictionary mapping parser classes to extensions.
    """

    @classmethod
    def get_supported_formats(cls) -> List[str]:
        """Returns a list of all built-in supported format extensions.

        Returns:
            List[str]: List of format extensions.
        """
        return list(AVAILABLE_PARSERS.keys())

    def __init__(self, formats: Optional[List[str]] = None, custom_parsers: Optional[List[Any]] = None):
        """Initializes the parser registry.

        Args:
            formats (List[str], optional): List of format extensions to enable.
            custom_parsers (List[Any], optional): List of custom parser instances.
        """
        self.parsers: List[BaseFormatParser] = []
        self.ext_map: Dict[Type, str] = {cls: fmt for fmt, cls in AVAILABLE_PARSERS.items()}
        self.ext_map[ZIPParser] = "zip"
        self.ext_map[TIFFParser] = "tiff"

        if formats is None:
            formats = list(AVAILABLE_PARSERS.keys())

        for fmt in formats:
            parser_class = AVAILABLE_PARSERS.get(fmt.lower())
            if parser_class:
                self.parsers.append(parser_class())

        if custom_parsers:
            self.parsers.extend(custom_parsers)

    def get_extension(self, parser: Any) -> str:
        """Gets the default extension for a given parser instance.

        Args:
            parser (Any): Parser object.

        Returns:
            str: File extension string.
        """
        return getattr(parser, 'ext', self.ext_map.get(type(parser), "bin"))
