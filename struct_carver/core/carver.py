"""Core carving logic and orchestrator.

This module provides the main Carver class, which orchestrates disk image buffering,
signature detection, gap-jumping heuristics, and post-carving processing.
"""

import os
import json
from typing import List, Dict, Tuple, Optional, Any
from tqdm import tqdm
from struct_carver.core.buffered_reader import BufferedClusterReader, get_image_size, discover_segments
from struct_carver.core.header_detector import HeaderDetector
from struct_carver.core.gap_jumper import GapJumper
from struct_carver.core.post_processor import PostProcessor
from struct_carver.core.hasher import CryptoHasher
from struct_carver.core.validator import FileValidator
from struct_carver.core.checkpoint import CheckpointManager
from struct_carver.core.entropy import calculate_file_entropy
from struct_carver.core.metadata import MetadataExtractor
from struct_carver.formats.registry import ParserRegistry
from struct_carver.logger import setup_logger

# re-export BufferedClusterReader and segment utilities for backwards compatibility
__all__ = ['Carver', 'BufferedClusterReader', 'get_image_size', 'discover_segments']


class Carver:
    """Orchestrates non-sequential file carving from raw forensic image streams.

    Delegates format handling to ParserRegistry, header detection to HeaderDetector,
    gap-jumping sweeps to GapJumper, and post-carving hooks to PostProcessor.
    """

    def __init__(
        self,
        cluster_size: int = 4096,
        formats: Optional[List[str]] = None,
        custom_parsers: Optional[List[Any]] = None,
        max_search_clusters: int = 1000,
        text_density_threshold: float = 0.8,
        max_gap_fill_bytes: int = 100 * 1024 * 1024,
        hasher: Optional[Any] = None,
        validator: Optional[Any] = None,
        checkpoint_mgr: Optional[Any] = None,
        max_file_size: int = 2 * 1024 * 1024 * 1024,
        extract_archives: bool = False,
        quiet: bool = False,
    ):
        """Initializes the carver orchestrator and underlying components.

        Args:
            cluster_size (int, optional): Disk cluster block size in bytes (default: 4096).
            formats (List[str], optional): List of format extension strings to carve.
            custom_parsers (List[Any], optional): List of custom parser objects to include.
            max_search_clusters (int, optional): Max clusters to look ahead during a gap jump.
            text_density_threshold (float, optional): Text ratio to validate non-tag text clusters.
            max_gap_fill_bytes (int, optional): Maximum bytes to zero-fill across a gap (default: 100MB).
            hasher (Optional[Any], optional): CryptoHasher instance or algorithm name (default: None).
            validator (Optional[Any], optional): FileValidator instance or bool (default: None).
            checkpoint_mgr (Optional[Any], optional): CheckpointManager instance for resuming (default: None).
            max_file_size (int, optional): Maximum carved file size before truncation (default: 2GB).
            extract_archives (bool, optional): Whether to extract carved archives safely (default: False).
            quiet (bool, optional): Suppress progress indicators and non-essential logs (default: False).
        """
        self.cluster_size = cluster_size
        self.max_search_clusters = max_search_clusters
        self.text_density_threshold = text_density_threshold
        self.max_gap_fill_bytes = max_gap_fill_bytes
        self.max_file_size = max_file_size
        self.quiet = quiet

        if isinstance(hasher, str):
            self.hasher: Optional[CryptoHasher] = CryptoHasher(hasher)
        else:
            self.hasher = hasher

        if validator is True:
            self.validator: Optional[FileValidator] = FileValidator()
        elif validator is False:
            self.validator = None
        else:
            self.validator = validator

        self.checkpoint_mgr: Optional[CheckpointManager] = checkpoint_mgr

        self.registry = ParserRegistry(formats=formats, custom_parsers=custom_parsers)
        self.header_detector = HeaderDetector(self.registry)
        self.gap_jumper = GapJumper(
            cluster_size=cluster_size,
            max_search_clusters=max_search_clusters,
            text_density_threshold=text_density_threshold
        )
        self.post_processor = PostProcessor(extract_archives=extract_archives)

    @property
    def parsers(self) -> List[Any]:
        """Backwards-compatible access to registry parsers."""
        return self.registry.parsers

    @property
    def ext_map(self) -> Dict[Any, str]:
        """Backwards-compatible access to registry extension mapping."""
        return self.registry.ext_map

    @property
    def cluster_cache(self) -> Dict[tuple, tuple]:
        """Backwards-compatible access to gap jumper cluster cache."""
        return self.gap_jumper.cluster_cache

    def _detect_header(
        self,
        cluster: bytes,
        prev_overlap: bytes,
        file_id: int,
        output_dir: str,
        worker_id: int
    ) -> Tuple[bool, Optional[Any], Optional[Any], Optional[Any], bytes, int]:
        """Delegates header detection to HeaderDetector."""
        return self.header_detector.detect_header(cluster, prev_overlap, file_id, output_dir, worker_id)

    def _process_cluster(
        self,
        cluster: bytes,
        parser: Any,
        engine: Any,
        text_overlap: bytes = b""
    ) -> Tuple[List[Any], bytes, int]:
        """Delegates cluster processing to GapJumper."""
        return self.gap_jumper.process_cluster(cluster, parser, engine, text_overlap)

    def _attempt_gap_jump(
        self,
        f: Any,
        snapshot: Any,
        parser_snapshot: Any,
        file_id: int,
        current_text_overlap: bytes,
        logger: Any
    ) -> Tuple[bool, Any, Any, List[Any], bytes, int, bytes, int, int]:
        """Delegates gap-jumping search to GapJumper."""
        return self.gap_jumper.attempt_gap_jump(f, snapshot, parser_snapshot, file_id, current_text_overlap, logger)

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
        """Delegates post-processing to PostProcessor."""
        return self.post_processor.post_process(file_path, ext, output_dir, filename, logger)

    def _hash_fragments(self, image_path: str, fragments: List[Dict[str, Any]]) -> None:
        """Computes fragment-level cryptographic hashes streamingly if a hasher is configured."""
        if not self.hasher or not os.path.exists(image_path):
            return
        try:
            for frag in fragments:
                frag["fragment_hash"] = self.hasher.hash_file_range(
                    image_path, frag["start_offset"], frag["size"]
                )
        except (OSError, ValueError):
            pass

    def _finalize_file_record(
        self,
        image_path: str,
        file_path: str,
        file_id: int,
        filename: str,
        fmt: str,
        status: str,
        fragments: List[Dict[str, Any]],
        worker_id: int,
        current_offset: int,
    ) -> Dict[str, Any]:
        """Builds a forensic file record with hashes, fragment hashes, LBA, slack, entropy, and metadata."""
        self._hash_fragments(image_path, fragments)
        total_size = sum(f["size"] for f in fragments)
        first_offset = fragments[0]["start_offset"] if fragments else 0
        start_lba = first_offset // 512
        slack_bytes = (self.cluster_size - (total_size % self.cluster_size)) % self.cluster_size

        record: Dict[str, Any] = {
            "file_id": file_id,
            "filename": filename,
            "format": fmt,
            "status": status,
            "fragments": fragments,
            "total_size": total_size,
            "size": total_size,
            "start_lba": start_lba,
            "slack_bytes": slack_bytes,
        }

        if os.path.exists(file_path):
            record["entropy"] = calculate_file_entropy(file_path)
            meta = MetadataExtractor.extract(file_path, fmt)
            if meta:
                record["metadata"] = meta

        if self.hasher:
            record["hash_algo"] = self.hasher.algo_name
            record["file_hash"] = self.hasher.hash_file(file_path)
        if self.validator:
            record["validation"] = self.validator.validate(file_path, fmt)
        if self.checkpoint_mgr:
            self.checkpoint_mgr.save_worker_progress(worker_id, current_offset, [record])
        return record

    def _write_gap_fill(self, current_file_handle: Any, gap_bytes: int, logger: Any) -> None:
        """Fills an inter-fragment gap with zeros up to max_gap_fill_bytes.

        Args:
            current_file_handle (Any): Open file handle to the carved file.
            gap_bytes (int): Total gap size in bytes.
            logger (Any): Active worker logger instance.
        """
        if gap_bytes <= 0 or not current_file_handle:
            return
        fill_remaining = gap_bytes
        if self.max_gap_fill_bytes > 0 and gap_bytes > self.max_gap_fill_bytes:
            logger.warning(
                f"Gap size ({gap_bytes} bytes) exceeds max_gap_fill_bytes "
                f"({self.max_gap_fill_bytes} bytes). Capping zero-fill."
            )
            fill_remaining = self.max_gap_fill_bytes

        # stream zeros in chunks to ensure low constant memory consumption
        chunk_size = min(fill_remaining, 1024 * 1024)
        zero_chunk = b'\x00' * chunk_size
        while fill_remaining > 0:
            to_write = min(fill_remaining, len(zero_chunk))
            current_file_handle.write(zero_chunk[:to_write])
            fill_remaining -= to_write

    def _handle_false_positive(
        self,
        output_dir: str,
        current_filename: str,
        current_file_handle: Any,
        f: Any,
        phys_start: int,
        best_idx: int,
        prev_overlap: bytes,
        raw_cluster: bytes,
        overlap_size: int,
    ) -> bytes:
        """Cleans up resources and repositions stream upon encountering a false positive signature.

        Args:
            output_dir (str): Output directory path.
            current_filename (str): Active output filename on disk.
            current_file_handle (Any): Open file handle to close.
            f (Any): File reader stream.
            phys_start (int): Start offset of current cluster.
            best_idx (int): Relative index of false signature.
            prev_overlap (bytes): Preceding buffer overlap.
            raw_cluster (bytes): Unmodified cluster bytes.
            overlap_size (int): Max signature overlap window.

        Returns:
            bytes: Updated prev_overlap for the next scan cycle.
        """
        if current_file_handle:
            current_file_handle.close()
            old_path = os.path.join(output_dir, current_filename)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        overlap_len_orig = len(prev_overlap)
        sig_in_cluster = best_idx - overlap_len_orig
        if sig_in_cluster >= 0:
            next_scan = phys_start + sig_in_cluster + 1
            f.seek(next_scan)
            pre_sig = raw_cluster[:sig_in_cluster]
            return pre_sig[-overlap_size:] if overlap_size > 0 else b""
        else:
            return raw_cluster[-overlap_size:] if overlap_size > 0 else b""

    def _finalize_partial_file(
        self,
        image_path: str,
        output_dir: str,
        current_filename: str,
        current_file_handle: Any,
        file_id: int,
        current_ext: str,
        fragments: List[Dict[str, Any]],
        worker_id: int,
        current_offset: int,
        status: str = "partial",
    ) -> Dict[str, Any]:
        """Closes handle, renames file with partial suffix, and builds forensic record.

        Args:
            image_path (str): Source disk image path.
            output_dir (str): Destination directory.
            current_filename (str): Active file name.
            current_file_handle (Any): Open file handle.
            file_id (int): Numerical file ID.
            current_ext (str): File extension.
            fragments (List[Dict[str, Any]]): Recorded fragments.
            worker_id (int): Worker thread identifier.
            current_offset (int): Current stream offset.
            status (str, optional): Recovery status ("partial" or "incomplete_eof").

        Returns:
            Dict[str, Any]: Forensic file record.
        """
        if current_file_handle and not current_file_handle.closed:
            current_file_handle.close()

        old_path = os.path.join(output_dir, current_filename)
        new_filename = f"carved_w{worker_id}_{file_id}_partial.{current_ext}"
        new_path = os.path.join(output_dir, new_filename)
        if os.path.exists(old_path):
            try:
                os.rename(old_path, new_path)
            except OSError:
                new_path = old_path
                new_filename = current_filename

        return self._finalize_file_record(
            image_path=image_path,
            file_path=new_path,
            file_id=file_id,
            filename=new_filename,
            fmt=current_ext,
            status=status,
            fragments=fragments,
            worker_id=worker_id,
            current_offset=current_offset,
        )

    def _handle_file_completion(
        self,
        image_path: str,
        output_dir: str,
        current_filename: str,
        current_file_handle: Any,
        file_id: int,
        current_ext: str,
        fragments: List[Dict[str, Any]],
        worker_id: int,
        cluster_to_write: bytes,
        bytes_to_advance: int,
        f: Any,
        overlap_size: int,
        logger: Any,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Finalizes a successfully carved file, triggers post-processing, and rewinds stream.

        Args:
            image_path (str): Source disk image path.
            output_dir (str): Destination directory.
            current_filename (str): File name on disk.
            current_file_handle (Any): Open file handle.
            file_id (int): Numerical file ID.
            current_ext (str): File extension.
            fragments (List[Dict[str, Any]]): Recorded fragments.
            worker_id (int): Worker thread identifier.
            cluster_to_write (bytes): Valid cluster data block.
            bytes_to_advance (int): Valid bytes to keep from cluster.
            f (Any): Stream reader source.
            overlap_size (int): Max signature overlap window.
            logger (Any): Active logger.

        Returns:
            Tuple[Dict[str, Any], bytes]: Final file record and updated prev_overlap buffer.
        """
        logger.info(f"Successfully carved file {file_id}!")
        write_len = max(0, bytes_to_advance)

        discarded_bytes = len(cluster_to_write) - write_len
        fragments[-1]["end_offset"] -= discarded_bytes
        fragments[-1]["size"] -= discarded_bytes

        if current_file_handle:
            current_file_handle.write(cluster_to_write[:write_len])
            current_file_handle.close()

        # trigger post-processing routines
        carved_file_path = os.path.join(output_dir, current_filename)
        new_ext, new_filename = self._post_process_file(carved_file_path, current_ext, output_dir, current_filename, logger)
        final_path = os.path.join(output_dir, new_filename)

        record = self._finalize_file_record(
            image_path=image_path,
            file_path=final_path,
            file_id=file_id,
            filename=new_filename,
            fmt=new_ext,
            status="complete",
            fragments=fragments,
            worker_id=worker_id,
            current_offset=f.tell(),
        )

        # if the completed file ended before the end of the cluster buffer,
        # rewind stream to exact file termination offset so remaining bytes
        # in the cluster are scanned immediately for subsequent file headers.
        if discarded_bytes > 0:
            final_phys_end = fragments[-1]["end_offset"]
            f.seek(final_phys_end)
            completed_bytes = cluster_to_write[:write_len]
            prev_overlap = completed_bytes[-overlap_size:] if overlap_size > 0 else b""
        else:
            prev_overlap = cluster_to_write[-overlap_size:] if overlap_size > 0 else b""

        return record, prev_overlap

    def carve(self, image_path: str, output_dir: str, start_offset: int = 0, end_offset: Optional[int] = None, worker_id: int = 0):
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
            total_size = get_image_size(image_path)
            end_boundary = end_offset if end_offset else total_size

            file_id = 0
            if self.checkpoint_mgr:
                resumed_start = self.checkpoint_mgr.get_worker_start_offset(worker_id, start_offset)
                if resumed_start > start_offset:
                    logger.info(f"Resuming worker {worker_id} from checkpoint offset {resumed_start} (originally {start_offset})")
                    start_offset = resumed_start
                recovered = self.checkpoint_mgr.get_recovered_files()
                if recovered:
                    existing_ids = [f["file_id"] for f in recovered if isinstance(f.get("file_id"), int)]
                    if existing_ids:
                        file_id = max(existing_ids) + 1

            with BufferedClusterReader(image_path) as f:
                if start_offset > 0:
                    f.seek(start_offset)

                carving = False
                current_file_handle = None
                current_file_bytes = 0
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

                pbar = tqdm(total=end_boundary - start_offset, unit='B', unit_scale=True, desc=f"Worker {worker_id}", leave=True, position=worker_id, disable=self.quiet)
                cluster_count = 0
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

                        cluster_count += 1
                        if self.checkpoint_mgr and cluster_count % 1000 == 0:
                            self.checkpoint_mgr.save_worker_progress(worker_id, phys_start)

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
                                current_ext = getattr(active_parser, 'ext', self.registry.get_extension(active_parser))
                                current_filename = f"carved_w{worker_id}_{file_id}.{current_ext}"
                                current_file_bytes = len(cluster)
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
                                    prev_overlap = self._handle_false_positive(
                                        output_dir=output_dir,
                                        current_filename=current_filename,
                                        current_file_handle=current_file_handle,
                                        f=f,
                                        phys_start=phys_start,
                                        best_idx=best_idx,
                                        prev_overlap=prev_overlap,
                                        raw_cluster=raw_cluster,
                                        overlap_size=overlap_size,
                                    )
                                    current_file_handle = None
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
                                        if current_file_handle:
                                            current_file_handle.write(cluster)
                                            current_file_bytes += len(cluster)
                                        gap_bytes = cand_start - phys_end
                                        self._write_gap_fill(current_file_handle, gap_bytes, logger)
                                        current_file_bytes += max(0, gap_bytes)
                                    current_fragments.append({"start_offset": cand_start, "end_offset": cand_end, "size": cand_end - cand_start})
                                else:
                                    carving = False
                                    active_parser = None
                                    record = self._finalize_partial_file(
                                        image_path=image_path,
                                        output_dir=output_dir,
                                        current_filename=current_filename,
                                        current_file_handle=current_file_handle,
                                        file_id=file_id,
                                        current_ext=current_ext,
                                        fragments=current_fragments,
                                        worker_id=worker_id,
                                        current_offset=f.tell(),
                                        status="partial",
                                    )
                                    current_file_handle = None
                                    report["files"].append(record)
                                    file_id += 1
                                    prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""
                                    continue

                            # check for completion
                            if carving and engine.is_empty() and len(tags) > 0:
                                record, prev_overlap = self._handle_file_completion(
                                    image_path=image_path,
                                    output_dir=output_dir,
                                    current_filename=current_filename,
                                    current_file_handle=current_file_handle,
                                    file_id=file_id,
                                    current_ext=current_ext,
                                    fragments=current_fragments,
                                    worker_id=worker_id,
                                    cluster_to_write=cluster_to_write,
                                    bytes_to_advance=bytes_to_advance,
                                    f=f,
                                    overlap_size=overlap_size,
                                    logger=logger,
                                )
                                report["files"].append(record)
                                file_id += 1
                                carving = False
                                active_parser = None
                                current_file_handle = None
                            else:
                                current_file_handle.write(cluster_to_write)
                                current_file_bytes += len(cluster_to_write)
                                if current_file_bytes >= self.max_file_size:
                                    logger.warning(
                                        f"Carved file {current_filename} reached max_file_size limit "
                                        f"({self.max_file_size} bytes). Truncating as partial."
                                    )
                                    record = self._finalize_partial_file(
                                        image_path=image_path,
                                        output_dir=output_dir,
                                        current_filename=current_filename,
                                        current_file_handle=current_file_handle,
                                        file_id=file_id,
                                        current_ext=current_ext,
                                        fragments=current_fragments,
                                        worker_id=worker_id,
                                        current_offset=f.tell(),
                                        status="partial",
                                    )
                                    current_file_handle = None
                                    report["files"].append(record)
                                    file_id += 1
                                    carving = False
                                    active_parser = None
                                    prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""
                except Exception as e:
                    logger.error(f"Worker {worker_id} crashed during carving: {e}", exc_info=True)
                    report["error"] = str(e)
                    raise
                finally:
                    pbar.close()
                    # ensure final file handle is closed if the image ends prematurely or an exception occurs
                    if current_file_handle and not current_file_handle.closed:
                        record = self._finalize_partial_file(
                            image_path=image_path,
                            output_dir=output_dir,
                            current_filename=current_filename,
                            current_file_handle=current_file_handle,
                            file_id=file_id,
                            current_ext=current_ext,
                            fragments=current_fragments,
                            worker_id=worker_id,
                            current_offset=f.tell(),
                            status="incomplete_eof",
                        )
                        report["files"].append(record)
                        current_file_handle = None

                    if self.checkpoint_mgr:
                        self.checkpoint_mgr.save_worker_progress(worker_id, f.tell(), report["files"])

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
