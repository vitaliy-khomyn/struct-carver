"""Core carving logic and utilities for Struct Carver!

This module provides the main Carver class and BufferedClusterReader, which
together handle binary stream buffering, signature detection, gap-jumping,
false-positive correction, and reassembly of fragmented files.
"""

import os
import json
import zipfile
from typing import List, Dict, Tuple, Optional, Any
from tqdm import tqdm
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
from struct_carver.core.stack_engine import StackEngine
from struct_carver.core.binary_engine import BinaryOffsetEngine
from struct_carver.logger import setup_logger


class BufferedClusterReader:
    """A custom buffered disk reader for large raw forensic images.

    Pulls large chunks of data into memory to reduce the system call overhead
    of reading cluster-by-cluster, while supporting the seek() and tell() methods
    required for gap-jumping heuristics.
    """

    def __init__(self, file_path: str, buffer_size: int = 16 * 1024 * 1024, lookbehind: int = 4 * 1024 * 1024):
        """Initializes the buffered cluster reader.

        Args:
            file_path (str): Path to the image file to read.
            buffer_size (int, optional): Buffer cache size in bytes (default: 16MB).
            lookbehind (int, optional): Buffer rewind lookbehind size in bytes (default: 4MB).
        """
        self.file = open(file_path, 'rb')
        self.buffer_size = buffer_size
        self.buffer = memoryview(b"")
        self.buffer_start_pos = 0
        self.current_pos = 0
        self.eof_pos = -1
        self.lookbehind = lookbehind

    def read(self, size: int) -> bytes:
        """Reads a chunk of bytes from the buffered file.

        Args:
            size (int): Number of bytes to read.

        Returns:
            bytes: The requested data chunk, or empty bytes if EOF is reached.
        """
        if self.eof_pos != -1 and self.current_pos >= self.eof_pos:
            return b""

        buffer_end = self.buffer_start_pos + len(self.buffer)

        # if the read falls outside the cached buffer (either rewinding past start or reading past end)
        if self.current_pos < self.buffer_start_pos or self.current_pos + size > buffer_end:
            # smart alignment: load the buffer so that current_pos is near the beginning,
            # but explicitly preserve a lookbehind window to accommodate f.seek() rewinds.
            read_start = max(0, self.current_pos - self.lookbehind)
            read_size = max(self.buffer_size, size + (self.current_pos - read_start))

            self.file.seek(read_start)
            raw_bytes = self.file.read(read_size)

            # check if the absolute end of the disk image
            if not raw_bytes and self.current_pos >= read_start + len(raw_bytes):
                self.eof_pos = self.current_pos
                return b""

            self.buffer = memoryview(raw_bytes)
            self.buffer_start_pos = read_start
            buffer_end = self.buffer_start_pos + len(self.buffer)

        # handle EOF clipping if the file ends before fulfilling the full requested 'size'
        available_bytes = min(size, buffer_end - self.current_pos)
        if available_bytes <= 0:
            self.eof_pos = self.current_pos
            return b""

        offset = self.current_pos - self.buffer_start_pos
        chunk = self.buffer[offset:offset + available_bytes].tobytes()
        self.current_pos += len(chunk)
        return chunk

    def seek(self, pos: int):
        """Sets the current file cursor position.

        Args:
            pos (int): File offset in bytes.
        """
        self.current_pos = pos

    def tell(self) -> int:
        """Gets the current file cursor position.

        Returns:
            int: The current file offset in bytes.
        """
        return self.current_pos

    def close(self):
        """Closes the underlying raw file stream."""
        self.file.close()

    def __enter__(self):
        """Enters the context manager block."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exits the context manager block, closing the stream."""
        self.close()


class Carver:
    """Manages the semantic and non-sequential carving process.

    Uses a dual-engine parser structure to handle textual and binary files
    and reconstruct fragmented files using gap-jumping heuristic sweeps.
    """

    def __init__(self, cluster_size=4096, formats=None, custom_parsers=None, max_search_clusters=1000, text_density_threshold=0.8):
        """Initializes the carver instance with active parsers and search limits.

        Args:
            cluster_size (int, optional): Disk cluster block size in bytes (default: 4096).
            formats (list, optional): List of format extension strings to carve.
            custom_parsers (list, optional): List of custom parser objects to include.
            max_search_clusters (int, optional): Max clusters to look ahead during a gap jump.
            text_density_threshold (float, optional): Text ratio to validate non-tag text clusters.
        """
        self.cluster_size = cluster_size
        self.parsers = []
        self.max_search_clusters = max_search_clusters
        self.text_density_threshold = text_density_threshold
        self.cluster_cache = {}

        AVAILABLE_PARSERS = {
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

        if formats is None:
            formats = list(AVAILABLE_PARSERS.keys())

        for fmt in formats:
            parser_class = AVAILABLE_PARSERS.get(fmt.lower())
            if parser_class:
                self.parsers.append(parser_class())

        if custom_parsers:
            self.parsers.extend(custom_parsers)

        # dynamically build the reverse lookup map for file extensions
        self.ext_map = {cls: fmt for fmt, cls in AVAILABLE_PARSERS.items()}
        self.ext_map[ZIPParser] = "zip"
        self.ext_map[TIFFParser] = "tiff"

    def _detect_header(self, cluster: bytes, prev_overlap: bytes, file_id: int, output_dir: str, worker_id: int) -> Tuple[bool, Optional[Any], Optional[Any], Optional[Any], bytes, int]:
        """Scans the buffer for signature matches to identify file starts.

        Args:
            cluster (bytes): The current disk cluster.
            prev_overlap (bytes): Overlap bytes saved from the previous cluster.
            file_id (int): ID of the file to be created.
            output_dir (str): Directory where output carved files are written.
            worker_id (int): Worker thread index identifier.

        Returns:
            Tuple[bool, Optional[Any], Optional[Any], Optional[Any], bytes, int]: Match status,
                parser, engine, file handle, search buffer slice, and best signature match index.
        """
        search_buffer = prev_overlap + cluster
        cluster_lower = search_buffer.lower()

        best_idx = None
        best_parser = None
        best_is_binary = None
        best_sig_len = 0

        for parser in self.parsers:
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

            ext = getattr(best_parser, 'ext', self.ext_map.get(type(best_parser), "bin"))
            out_path = os.path.join(output_dir, f"carved_w{worker_id}_{file_id}.{ext}")
            handle = open(out_path, 'wb')
            return True, best_parser, engine, handle, search_buffer, best_idx

        return False, None, None, None, cluster, -1

    def _process_cluster(self, cluster: bytes, parser: Any, engine: Any, text_overlap: bytes = b"") -> Tuple[List[Any], bytes, int]:
        """Feeds cluster data into the designated parser/engine and updates state.

        Args:
            cluster (bytes): Cluster payload to process.
            parser (Any): Parser instance to handle the decoding/analysis.
            engine (Any): State tracking engine.
            text_overlap (bytes, optional): Retained tags/escape characters from previous cluster.

        Returns:
            Tuple[List[Any], bytes, int]: Parsed tags or chunks list, updated text overlap,
                and total bytes of progress to advance within the block.
        """
        is_binary = getattr(parser, 'engine_type', 'semantic') == 'binary'
        if is_binary:
            is_corr, is_comp, bytes_to_advance, expected_remaining = parser.analyze_binary(cluster, engine.bytes_remaining)
            engine.process_binary(is_corr, is_comp, expected_remaining)
            return ["binary_chunk"], b"", bytes_to_advance
        else:
            cluster = cluster.rstrip(b'\x00')
            search_buffer = text_overlap + cluster
            byte_data = search_buffer

            # overlap: hold back incomplete XML/HTML tags or escape sequences
            last_open = byte_data.rfind(b'<')
            last_close = byte_data.rfind(b'>')

            held_back_bytes = b""
            if last_open > last_close:
                held_back_bytes = byte_data[last_open:]
                byte_data = byte_data[:last_open]
            elif byte_data.endswith(b'\\'):
                held_back_bytes = byte_data[-1:]
                byte_data = byte_data[:-1]

            tags, last_offset = parser.extract_tags(byte_data)
            engine.process_tags(tags)
            if getattr(parser, 'is_corrupted', False):
                engine.is_corrupted = True
            bytes_to_advance = last_offset - len(text_overlap)
            return tags, held_back_bytes, bytes_to_advance

    def _attempt_gap_jump(self, f: Any, snapshot: Any, parser_snapshot: Any, file_id: int, current_text_overlap: bytes, logger: Any) -> Tuple[bool, Any, Any, List[Any], bytes, int, bytes, int, int]:
        """Scans ahead in the raw image to bypass gaps and locate matching continuation structures.

        Args:
            f (Any): Open file reader source.
            snapshot (Any): Clone of the engine's last clean state.
            parser_snapshot (Any): Clone of the parser's last clean state.
            file_id (int): File ID being processed.
            current_text_overlap (bytes): Inter-cluster overlap buffer.
            logger (Any): Active worker logger.

        Returns:
            Tuple[bool, Any, Any, List[Any], bytes, int, bytes, int, int]: Search status,
                updated engine, updated parser, candidate tags, new overlap, advance offset,
                matched continuation block bytes, match start offset, and match end offset.
        """
        parser_name = type(parser_snapshot).__name__
        logger.warning(f"Fragmentation detected in file {file_id} ({parser_name}) at offset {f.tell()}. Initiating gap-jumping search...")
        global_limit = getattr(self, 'max_search_clusters', 1000)
        parser_limit = getattr(type(parser_snapshot), 'max_gap_clusters', 0)
        max_search_clusters = max(global_limit, parser_limit)
        search_count = 0
        original_pos = f.tell()
        is_binary = getattr(parser_snapshot, 'engine_type', 'semantic') == 'binary'

        while search_count < max_search_clusters:
            cand_start = f.tell()
            candidate_cluster = f.read(self.cluster_size)
            cand_end = f.tell()
            if not candidate_cluster:
                logger.info(f"Gap-jumping reached EOF at offset {cand_start} after checking {search_count} clusters.")
                break

            # cache key can now be used for both binary and text parsers
            cache_key = (cand_start, type(parser_snapshot), parser_snapshot.state_tuple(), current_text_overlap)

            if cache_key in self.cluster_cache:
                candidate_tags, new_overlap, bytes_to_advance, is_text_heavy, cached_parser, engine_state = self.cluster_cache[cache_key]
                test_engine = snapshot.clone()
                test_parser = cached_parser.clone()
                if is_binary:
                    test_engine.process_binary(*engine_state)
                else:
                    test_engine.process_tags(candidate_tags)
            else:
                is_text_heavy = False
                if not is_binary:
                    # performance optimization: lazy check for text parsers to avoid cloning and regex matching
                    is_text_heavy = (len(candidate_cluster) - candidate_cluster.count(b'\x00')) >= (self.cluster_size * self.text_density_threshold)
                    has_interesting_chars = False
                    if isinstance(parser_snapshot, (XMLParser, HTMLParser)):
                        has_interesting_chars = b'<' in candidate_cluster
                    elif isinstance(parser_snapshot, (JSONParser, RTFParser)):
                        has_interesting_chars = any(c in candidate_cluster for c in [b'{', b'}', b'[', b']', b'\\'])
                    
                    if not is_text_heavy and not has_interesting_chars:
                        search_count += 1
                        continue

                test_engine = snapshot.clone()
                test_parser = parser_snapshot.clone()

                # prepare the parser and engine for gap-jump testing.
                # mid-stream state (pending_endstream, bytes_remaining) would
                # cause parsers like PDFParser to expect the cluster to continue
                # a specific byte sequence from the fragmentation point — but
                # candidate clusters are independent disk fragments, so we must
                # test them from a clean object-boundary perspective.
                if is_binary:
                    # reset any "waiting for endstream / next N bytes" flags.
                    if hasattr(test_parser, 'pending_endstream'):
                        test_parser.pending_endstream = False
                        test_parser.pending_bytes_needed = 0
                    # bytes_remaining=-1 is PDF's "search for endstream" mode;
                    # 0 means "look for next object/stream keyword".
                    # reset to 0 so the parser scans for structure from scratch.
                    test_engine.bytes_remaining = 0
                    # start with a clean corruption flag so process_binary
                    # reflects the candidate result, not the snapshot state.
                    test_engine.is_corrupted = False

                candidate_tags, new_overlap, bytes_to_advance = self._process_cluster(candidate_cluster, test_parser, test_engine, current_text_overlap)

                if len(self.cluster_cache) > 100000:
                    self.cluster_cache.clear()
                
                engine_state = (test_engine.is_corrupted, test_engine.is_complete, test_engine.bytes_remaining) if is_binary else None
                self.cluster_cache[cache_key] = (candidate_tags, new_overlap, bytes_to_advance, is_text_heavy, test_parser.clone(), engine_state)

            if not test_engine.is_corrupted and (len(candidate_tags) > 0 or is_text_heavy or is_binary):
                # allow parsers to enforce stronger content checks on candidate clusters via optional verify method
                verify_fn = getattr(test_parser, 'gap_jump_verify', None)
                if verify_fn is not None and not verify_fn(candidate_cluster):
                    search_count += 1
                    continue
                logger.info(f"Found valid continuation for file {file_id} after {search_count + 1} clusters at offset {cand_start}!")
                return True, test_engine, test_parser, candidate_tags, new_overlap, bytes_to_advance, candidate_cluster, cand_start, cand_end

            search_count += 1

         # search failed
        logger.error(f"Search failed for file {file_id} ({parser_name}) after checking {search_count} clusters. Aborting recovery.")
        f.seek(original_pos)
        return False, snapshot, parser_snapshot, [], b"", 0, b"", -1, -1

    def _record_fragment(self, current_fragments: List[Dict[str, int]], phys_start: int, phys_end: int):
        """Helper to append or extend contiguous file fragments for the carve report."""
        if not current_fragments:
            current_fragments.append({"start_offset": phys_start, "end_offset": phys_end, "size": phys_end - phys_start})
            return

        if current_fragments[-1]["end_offset"] == phys_start:
            current_fragments[-1]["end_offset"] = phys_end
            current_fragments[-1]["size"] += (phys_end - phys_start)
        else:
            current_fragments.append({"start_offset": phys_start, "end_offset": phys_end, "size": phys_end - phys_start})

    def _post_process_file(self, file_path: str, ext: str, output_dir: str, filename: str, logger: Any) -> Tuple[str, str]:
        """Handles format-specific post-processing after a file is successfully carved to disk."""
        if ext == "zip":
            detected_ext = "zip"
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    namelist = zf.namelist()
                    if "word/document.xml" in namelist:
                        detected_ext = "docx"
                    elif "xl/workbook.xml" in namelist:
                        detected_ext = "xlsx"
                    elif "ppt/presentation.xml" in namelist:
                        detected_ext = "pptx"
            except Exception as e:
                logger.error(f"Failed to read ZIP structure for Office detection: {e}")
                return ext, filename

            if detected_ext != "zip":
                new_filename = filename.rsplit('.', 1)[0] + f".{detected_ext}"
                new_path = os.path.join(output_dir, new_filename)
                try:
                    if os.path.exists(file_path):
                        os.rename(file_path, new_path)
                    logger.info(f"Detected Office document. Renamed {filename} to {new_filename}")
                    return detected_ext, new_filename
                except Exception as e:
                    logger.error(f"Failed to rename Office document: {e}")
            else:
                zip_out_dir = f"{file_path}_extracted"
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        zf.extractall(zip_out_dir)
                    logger.info(f"Extracted ZIP contents to {zip_out_dir}")
                except Exception as e:
                    logger.error(f"Recovered ZIP extraction failed: {e}")
        return ext, filename

    def carve(self, image_path: str, output_dir: str, start_offset: int = 0, end_offset: int = None, worker_id: int = 0):
        """Carves supported files out of the raw forensic image file stream.

        Args:
            image_path (str): Absolute or relative path to the image file.
            output_dir (str): Output folder to write output directories and records.
            start_offset (int, optional): Disk block scan starting point (default: 0).
            end_offset (int, optional): Disk block scan end boundary point.
            worker_id (int, optional): Context worker process ID thread.
        """
        os.makedirs(output_dir, exist_ok=True)

        logger = setup_logger(f"Worker-{worker_id}", os.path.join(output_dir, f"audit_w{worker_id}.log"))
        logger.info(f"Starting carving process for worker {worker_id} from offset {start_offset} to {end_offset or 'EOF'}")

        try:
            total_size = os.path.getsize(image_path)
            end_boundary = end_offset if end_offset else total_size

            with BufferedClusterReader(image_path) as f:
                if start_offset > 0:
                    f.seek(start_offset)

                file_id = 0
                carving = False
                current_file_handle = None
                engine = None
                active_parser = None
                carve_text_overlap = b""
                report = {"files": []}

                max_sig_len = max([len(sig) for parser in self.parsers for sig in parser.header_signatures], default=0)
                overlap_size = max(0, max_sig_len - 1)
                prev_overlap = b""
                if start_offset > 0 and overlap_size > 0:
                    f.seek(start_offset - overlap_size)
                    prev_overlap = f.read(overlap_size)
                    f.seek(start_offset)

                pbar = tqdm(total=end_boundary - start_offset, unit='B', unit_scale=True, desc=f"Worker {worker_id}", leave=True, position=worker_id)
                try:
                    while True:
                        if not carving and f.tell() >= end_boundary:
                            break

                        # dynamically update progress bar to current position, supporting gap jump rewinds
                        pbar.n = f.tell() - start_offset
                        pbar.refresh()

                        # 1. read the disk cluster by cluster
                        phys_start = f.tell()
                        cluster = f.read(self.cluster_size)
                        phys_end = f.tell()
                        if not cluster:
                            break

                        just_started = False
                        raw_cluster = cluster  # save original before potential slicing
                        if not carving:
                            # 2. search for the beginning of a file
                            carving, active_parser, engine, current_file_handle, search_buffer, best_idx = self._detect_header(
                                cluster, prev_overlap, file_id, output_dir, worker_id
                            )
                            if carving:
                                overlap_len = len(search_buffer) - (phys_end - phys_start)
                                adj_start = phys_start - overlap_len

                                cluster = search_buffer
                                carve_text_overlap = b""

                                current_fragments = [{"start_offset": adj_start, "end_offset": phys_end, "size": phys_end - adj_start}]
                                current_ext = getattr(active_parser, 'ext', self.ext_map.get(type(active_parser), "bin"))
                                current_filename = f"carved_w{worker_id}_{file_id}.{current_ext}"
                                just_started = True
                            else:
                                prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""

                        if carving:
                            if not just_started:
                                self._record_fragment(current_fragments, phys_start, phys_end)

                            # 3. process cluster data
                            snapshot = engine.clone()
                            parser_snapshot = active_parser.clone()
                            tags, carve_text_overlap, bytes_to_advance = self._process_cluster(cluster, active_parser, engine, carve_text_overlap)

                            cluster_to_write = cluster
                            # 4. determine state
                            if engine.is_corrupted:
                                if not getattr(active_parser, 'header_verified', True):
                                    # discard false positive signature match immediately
                                    carving = False
                                    active_parser = None
                                    if current_file_handle:
                                        current_file_handle.close()
                                        current_file_handle = None
                                        old_path = os.path.join(output_dir, current_filename)
                                        if os.path.exists(old_path):
                                            os.remove(old_path)

                                    # seek to the byte right after the false signature's position
                                    # in the current cluster so the bytes that follow it are still
                                    # scanned for real headers.  best_idx is relative to
                                    # (orig_prev_overlap + raw_cluster), so we subtract the
                                    # overlap length to find the offset within raw_cluster.
                                    overlap_len_orig = len(prev_overlap)
                                    sig_in_cluster = best_idx - overlap_len_orig
                                    if sig_in_cluster >= 0:
                                        # false sig is inside the current cluster; seek past it.
                                        next_scan = phys_start + sig_in_cluster + 1
                                        f.seek(next_scan)
                                        # prev_overlap covers the bytes just before the false sig
                                        # so any header straddling the new read boundary is caught.
                                        pre_sig = raw_cluster[:sig_in_cluster]
                                        prev_overlap = pre_sig[-overlap_size:] if overlap_size > 0 else b""
                                    else:
                                        # false sig was in the previous-cluster overlap area;
                                        # just continue from the next full cluster naturally.
                                        prev_overlap = raw_cluster[-overlap_size:] if overlap_size > 0 else b""
                                    continue

                                found, new_engine, new_parser, tags, new_overlap, bytes_to_advance, candidate_cluster, cand_start, cand_end = self._attempt_gap_jump(
                                    f, snapshot, parser_snapshot, file_id, carve_text_overlap, logger
                                )
                                if found:
                                    engine = new_engine
                                    active_parser = new_parser
                                    carve_text_overlap = new_overlap
                                    cluster_to_write = candidate_cluster
                                    parser_is_binary = getattr(active_parser, 'engine_type', 'semantic') == 'binary'
                                    if parser_is_binary:
                                        # for binary formats the corrupted cluster is part of the
                                        # file (e.g. last stream bytes of Fragment 1).  writing it
                                        # preserves internal byte offsets (PDF xref tables, etc.).
                                        if current_file_handle:
                                            current_file_handle.write(cluster)
                                        # zero-fill the true inter-fragment gap so that subsequent
                                        # byte offsets in the carved file remain correct.
                                        gap_bytes = cand_start - phys_end
                                        if gap_bytes > 0 and current_file_handle:
                                            current_file_handle.write(b'\x00' * gap_bytes)
                                    current_fragments.append({"start_offset": cand_start, "end_offset": cand_end, "size": cand_end - cand_start})
                                else:
                                    carving = False
                                    active_parser = None
                                    if current_file_handle:
                                        current_file_handle.close()
                                        current_file_handle = None

                                        # rename the file to explicitly mark it as a partial recovery
                                        old_path = os.path.join(output_dir, current_filename)
                                        current_filename = f"carved_w{worker_id}_{file_id}_partial.{current_ext}"
                                        new_path = os.path.join(output_dir, current_filename)
                                        if os.path.exists(old_path):
                                            os.rename(old_path, new_path)

                                    report["files"].append({
                                        "file_id": file_id,
                                        "filename": current_filename,
                                        "format": current_ext,
                                        "status": "partial",
                                        "fragments": current_fragments,
                                        "total_size": sum(f["size"] for f in current_fragments)
                                    })
                                    file_id += 1
                                    prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""
                                    continue

                            # check for completion
                            if carving and engine.is_empty() and len(tags) > 0:
                                logger.info(f"Successfully carved file {file_id}!")
                                write_len = max(0, bytes_to_advance)

                                discarded_bytes = len(cluster_to_write) - write_len
                                current_fragments[-1]["end_offset"] -= discarded_bytes
                                current_fragments[-1]["size"] -= discarded_bytes

                                current_file_handle.write(cluster_to_write[:write_len])
                                if current_file_handle:
                                    current_file_handle.close()
                                    current_file_handle = None

                                report["files"].append({
                                    "file_id": file_id,
                                    "filename": current_filename,
                                    "format": current_ext,
                                    "status": "complete",
                                    "fragments": current_fragments,
                                    "total_size": sum(f["size"] for f in current_fragments)
                                })

                                # trigger post-processing routines
                                carved_file_path = os.path.join(output_dir, current_filename)
                                new_ext, new_filename = self._post_process_file(carved_file_path, current_ext, output_dir, current_filename, logger)
                                if new_ext != current_ext:
                                    report["files"][-1]["filename"] = new_filename
                                    report["files"][-1]["format"] = new_ext

                                file_id += 1
                                carving = False
                                active_parser = None
                                prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""
                            else:
                                current_file_handle.write(cluster_to_write)
                except Exception as e:
                    logger.error(f"Worker {worker_id} crashed during carving: {e}", exc_info=True)
                    report["error"] = str(e)
                    raise
                finally:
                    pbar.close()
                    # ensure final file handle is closed if the image ends prematurely or an exception occurs
                    if current_file_handle and not current_file_handle.closed:
                        current_file_handle.close()

                        old_path = os.path.join(output_dir, current_filename)
                        current_filename = f"carved_w{worker_id}_{file_id}_partial.{current_ext}"
                        new_path = os.path.join(output_dir, current_filename)
                        if os.path.exists(old_path):
                            os.rename(old_path, new_path)

                        report["files"].append({
                            "file_id": file_id,
                            "filename": current_filename,
                            "format": current_ext,
                            "status": "incomplete_eof",
                            "fragments": current_fragments,
                            "total_size": sum(f["size"] for f in current_fragments)
                        })

                    report_path = os.path.join(output_dir, f"carve_report_w{worker_id}.json")
                    try:
                        with open(report_path, "w") as f_report:
                            json.dump(report, f_report, indent=4)
                        logger.info(f"Forensic carve report saved to {report_path}")
                    except Exception as save_err:
                        logger.error(f"Failed to save report: {save_err}", exc_info=True)
        finally:
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
