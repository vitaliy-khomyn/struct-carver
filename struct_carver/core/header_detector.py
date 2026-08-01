"""Header detector module for Struct Carver!

This module handles file signature scanning across buffer boundaries,
control byte validation for textual parsers, and engine state initialization.
"""

import os
from typing import List, Tuple, Optional, Any
from struct_carver.core.stack_engine import StackEngine
from struct_carver.core.binary_engine import BinaryOffsetEngine
from struct_carver.formats.registry import ParserRegistry


class HeaderDetector:
    """Detects file header signatures in cluster streams and initializes carving engines.

    Attributes:
        registry (ParserRegistry): Parser registry instance.
    """

    def __init__(self, registry: ParserRegistry):
        """Initializes the header detector.

        Args:
            registry (ParserRegistry): Registry containing active parsers.
        """
        self.registry = registry

    def detect_header(
        self,
        cluster: bytes,
        prev_overlap: bytes,
        file_id: int,
        output_dir: str,
        worker_id: int
    ) -> Tuple[bool, Optional[Any], Optional[Any], Optional[Any], bytes, int]:
        """Scans data buffer for file header signature matches.

        Args:
            cluster (bytes): The current disk cluster payload.
            prev_overlap (bytes): Overlap bytes saved from the previous cluster.
            file_id (int): Numerical file index identifier.
            output_dir (str): Output directory path.
            worker_id (int): Parallel worker ID thread index.

        Returns:
            Tuple[bool, Optional[Any], Optional[Any], Optional[Any], bytes, int]: Match status,
                matched parser instance, initialized state engine, opened output file handle,
                sliced search buffer starting at signature, and matching signature index offset.
        """
        search_buffer = prev_overlap + cluster
        cluster_lower = search_buffer.lower()

        best_idx = None
        best_parser = None
        best_is_binary = None
        best_sig_len = 0

        for parser in self.registry.parsers:
            is_binary = getattr(parser, 'engine_type', 'semantic') == 'binary'
            # if it's a text parser, ensure the cluster is actually text data to avoid false matches in binary streams
            if not is_binary:
                stripped_cluster = cluster.rstrip(b'\x00')
                if len(stripped_cluster) == 0:
                    continue
                control_count = sum(1 for b in stripped_cluster if b < 32 and b not in (9, 10, 13)) + stripped_cluster.count(127)
                if (1.0 - (control_count / len(stripped_cluster))) < 0.95:
                    continue

            target_buffer = search_buffer if is_binary else cluster_lower
            for sig in parser.header_signatures:
                sig_to_search = sig if is_binary else sig.lower()
                idx = target_buffer.find(sig_to_search)
                if idx != -1:
                    if best_idx is None or idx < best_idx:
                        best_idx = idx
                        best_parser = parser
                        best_is_binary = is_binary
                        best_sig_len = len(sig)
                    elif idx == best_idx:
                        if len(sig) > best_sig_len:
                            best_parser = parser
                            best_is_binary = is_binary
                            best_sig_len = len(sig)

        if best_idx is not None:
            best_parser.reset()
            if best_is_binary:
                engine = BinaryOffsetEngine()
            else:
                engine = StackEngine()

            # slice the search buffer to begin exactly at the matching signature
            search_buffer = search_buffer[best_idx:]

            ext = self.registry.get_extension(best_parser)
            out_path = os.path.join(output_dir, f"carved_w{worker_id}_{file_id}.{ext}")
            handle = open(out_path, 'wb')
            return True, best_parser, engine, handle, search_buffer, best_idx

        return False, None, None, None, cluster, -1
