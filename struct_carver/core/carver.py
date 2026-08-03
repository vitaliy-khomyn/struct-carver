"""Core carving logic and orchestrator for Struct Carver!

This module provides the main Carver class, which orchestrates disk image buffering,
signature detection, gap-jumping heuristics, and post-carving processing.
"""

import os
import json
from typing import List, Dict, Tuple, Optional, Any
from tqdm import tqdm
from struct_carver.core.buffered_reader import BufferedClusterReader
from struct_carver.core.header_detector import HeaderDetector
from struct_carver.core.gap_jumper import GapJumper
from struct_carver.core.post_processor import PostProcessor
from struct_carver.core.hasher import CryptoHasher
from struct_carver.core.validator import FileValidator
from struct_carver.core.checkpoint import CheckpointManager
from struct_carver.formats.registry import ParserRegistry
from struct_carver.logger import setup_logger

# Re-export BufferedClusterReader for backwards compatibility
__all__ = ['Carver', 'BufferedClusterReader']


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
        """
        self.cluster_size = cluster_size
        self.max_search_clusters = max_search_clusters
        self.text_density_threshold = text_density_threshold
        self.max_gap_fill_bytes = max_gap_fill_bytes

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
        self.post_processor = PostProcessor()

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
        """Computes fragment-level cryptographic hashes if a hasher is configured."""
        if not self.hasher or not os.path.exists(image_path):
            return
        try:
            with open(image_path, "rb") as f_img:
                for frag in fragments:
                    f_img.seek(frag["start_offset"])
                    data = f_img.read(frag["size"])
                    frag["fragment_hash"] = self.hasher.hash_bytes(data)
        except Exception:
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
        """Builds a forensic file record with hashes, fragment hashes, and validation results."""
        self._hash_fragments(image_path, fragments)
        record: Dict[str, Any] = {
            "file_id": file_id,
            "filename": filename,
            "format": fmt,
            "status": status,
            "fragments": fragments,
            "total_size": sum(f["size"] for f in fragments)
        }
        if self.hasher:
            record["hash_algo"] = self.hasher.algo_name
            record["file_hash"] = self.hasher.hash_file(file_path)
        if self.validator:
            record["validation"] = self.validator.validate(file_path, fmt)
        if self.checkpoint_mgr:
            self.checkpoint_mgr.save_worker_progress(worker_id, current_offset, [record])
        return record

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
            total_size = os.path.getsize(image_path)
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
                                    # scanned for real headers. best_idx is relative to
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
                                        # file (e.g. last stream bytes of Fragment 1). writing it
                                        # preserves internal byte offsets (PDF xref tables, etc.).
                                        if current_file_handle:
                                            current_file_handle.write(cluster)
                                        # zero-fill the true inter-fragment gap so that subsequent
                                        # byte offsets in the carved file remain correct.
                                        gap_bytes = cand_start - phys_end
                                        if gap_bytes > 0 and current_file_handle:
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

                                    record = self._finalize_file_record(
                                        image_path=image_path,
                                        file_path=os.path.join(output_dir, current_filename),
                                        file_id=file_id,
                                        filename=current_filename,
                                        fmt=current_ext,
                                        status="partial",
                                        fragments=current_fragments,
                                        worker_id=worker_id,
                                        current_offset=f.tell(),
                                    )
                                    report["files"].append(record)
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
                                    fragments=current_fragments,
                                    worker_id=worker_id,
                                    current_offset=f.tell(),
                                )
                                report["files"].append(record)

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

                        record = self._finalize_file_record(
                            image_path=image_path,
                            file_path=new_path,
                            file_id=file_id,
                            filename=current_filename,
                            fmt=current_ext,
                            status="incomplete_eof",
                            fragments=current_fragments,
                            worker_id=worker_id,
                            current_offset=f.tell(),
                        )
                        report["files"].append(record)

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
