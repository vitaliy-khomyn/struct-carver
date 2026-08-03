"""Gap jumper module.

This module provides the GapJumper class, which handles non-sequential gap-jumping sweeps,
cluster candidate state evaluation, and candidate result caching.
"""

from typing import List, Tuple, Dict, Any, Optional


class GapJumper:
    """Manages non-sequential gap-jumping sweeps over corrupted or fragmented disk space.

    Attributes:
        cluster_size (int): Size of disk cluster blocks in bytes.
        max_search_clusters (int): Default maximum search threshold.
        text_density_threshold (float): Minimum text ratio required for non-tag clusters.
        cluster_cache (Dict): Cache storing cluster parsing evaluations.
    """

    def __init__(self, cluster_size: int = 4096, max_search_clusters: int = 1000, text_density_threshold: float = 0.8):
        """Initializes the gap jumper.

        Args:
            cluster_size (int, optional): Disk cluster size in bytes (default: 4096).
            max_search_clusters (int, optional): Maximum search depth limit (default: 1000).
            text_density_threshold (float, optional): Density threshold ratio (default: 0.8).
        """
        self.cluster_size = cluster_size
        self.max_search_clusters = max_search_clusters
        self.text_density_threshold = text_density_threshold
        self.cluster_cache: Dict[tuple, tuple] = {}

    def process_cluster(self, cluster: bytes, parser: Any, engine: Any, text_overlap: bytes = b"") -> Tuple[List[Any], bytes, int]:
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

    def attempt_gap_jump(
        self,
        f: Any,
        snapshot: Any,
        parser_snapshot: Any,
        file_id: int,
        current_text_overlap: bytes,
        logger: Any
    ) -> Tuple[bool, Any, Any, List[Any], bytes, int, bytes, int, int]:
        """Scans ahead in the raw image stream to bypass gaps and locate matching continuation structures.

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
                    # performance optimization: lazy check for text parsers to avoid regex matching
                    is_text_heavy = (len(candidate_cluster) - candidate_cluster.count(b'\x00')) >= (self.cluster_size * self.text_density_threshold)
                    has_interesting_chars = parser_snapshot.has_continuation_markers(candidate_cluster)
                    
                    if not is_text_heavy and not has_interesting_chars:
                        search_count += 1
                        continue

                test_engine = snapshot.clone()
                test_parser = parser_snapshot.clone()
                test_parser.prepare_for_gap_jump()

                if is_binary:
                    # reset remaining bytes expectation so candidate is evaluated from a clean boundary
                    test_engine.bytes_remaining = 0
                    # start with a clean corruption flag so process_binary reflects candidate result
                    test_engine.is_corrupted = False

                candidate_tags, new_overlap, bytes_to_advance = self.process_cluster(candidate_cluster, test_parser, test_engine, current_text_overlap)

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
