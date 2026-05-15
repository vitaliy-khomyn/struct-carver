import os
import json
from tqdm import tqdm
from struct_carver.formats.xml_parser import XMLParser
from struct_carver.formats.html_parser import HTMLParser
from struct_carver.formats.pdf_parser import PDFParser
from struct_carver.formats.json_parser import JSONParser
from struct_carver.formats.rtf_parser import RTFParser
from struct_carver.formats.zip_parser import ZIPParser
from struct_carver.core.stack_engine import StackEngine
from struct_carver.core.binary_engine import BinaryOffsetEngine


class BufferedClusterReader:
    """
    A custom buffered disk reader that pulls large chunks of data into memory to drastically
    reduce the system call overhead of reading cluster-by-cluster. It seamlessly supports
    the seek() and tell() methods required for gap-jumping heuristics.
    """
    def __init__(self, file_path: str, buffer_size: int = 16 * 1024 * 1024):
        self.file = open(file_path, 'rb')
        self.buffer_size = buffer_size
        self.buffer = memoryview(b"")
        self.buffer_start_pos = 0
        self.current_pos = 0
        self.eof_pos = -1

    def read(self, size: int) -> bytes:
        if self.eof_pos != -1 and self.current_pos >= self.eof_pos:
            return b""

        if self.current_pos < self.buffer_start_pos or self.current_pos + size > self.buffer_start_pos + len(self.buffer):
            self.file.seek(self.current_pos)
            raw_bytes = self.file.read(max(self.buffer_size, size))
            if not raw_bytes:
                self.eof_pos = self.current_pos
                return b""
            self.buffer = memoryview(raw_bytes)
            self.buffer_start_pos = self.current_pos

        offset = self.current_pos - self.buffer_start_pos
        chunk = self.buffer[offset:offset + size].tobytes()
        self.current_pos += len(chunk)
        return chunk

    def seek(self, pos: int):
        self.current_pos = pos

    def tell(self) -> int:
        return self.current_pos

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Carver:
    def __init__(self, cluster_size=4096, formats=None):
        self.cluster_size = cluster_size
        self.parsers = []

        AVAILABLE_PARSERS = {
            'xml': XMLParser,
            'html': HTMLParser,
            'pdf': PDFParser,
            'json': JSONParser,
            'rtf': RTFParser,
            'zip': ZIPParser
        }

        if formats is None:
            formats = list(AVAILABLE_PARSERS.keys())

        for fmt in formats:
            parser_class = AVAILABLE_PARSERS.get(fmt.lower())
            if parser_class:
                self.parsers.append(parser_class())

        # dynamically build the reverse lookup map for file extensions
        self.ext_map = {cls: fmt for fmt, cls in AVAILABLE_PARSERS.items()}

    def _detect_header(self, cluster: bytes, prev_overlap: bytes, file_id: int, output_dir: str):
        search_buffer = prev_overlap + cluster
        cluster_lower = search_buffer.lower()
        for parser in self.parsers:
            for sig in parser.header_signatures:
                if sig in cluster_lower:
                    parser.reset()
                    if getattr(parser, 'engine_type', 'semantic') == 'binary':
                        engine = BinaryOffsetEngine()
                    else:
                        engine = StackEngine()

                    ext = self.ext_map.get(type(parser), "bin")
                    out_path = os.path.join(output_dir, f"carved_{file_id}.{ext}")
                    handle = open(out_path, 'wb')
                    return True, parser, engine, handle, search_buffer
        return False, None, None, None, cluster

    def _process_cluster(self, cluster: bytes, parser, engine, text_overlap: bytes = b""):
        is_binary = getattr(parser, 'engine_type', 'semantic') == 'binary'
        if is_binary:
            is_corr, is_comp, bytes_to_advance, expected_remaining = parser.analyze_binary(cluster, engine.bytes_remaining)
            engine.process_binary(is_corr, is_comp, expected_remaining)
            return ["binary_chunk"], b"", bytes_to_advance
        else:
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
            bytes_to_advance = last_offset - len(text_overlap)
            return tags, held_back_bytes, bytes_to_advance

    def _attempt_gap_jump(self, f, snapshot, parser_snapshot, file_id: int, current_text_overlap: bytes):
        tqdm.write(f"[*] Fragmentation detected in file {file_id}. Initiating gap-jumping search...")
        max_search_clusters = 1000
        search_count = 0
        original_pos = f.tell()
        is_binary = getattr(parser_snapshot, 'engine_type', 'semantic') == 'binary'

        while search_count < max_search_clusters:
            cand_start = f.tell()
            candidate_cluster = f.read(self.cluster_size)
            cand_end = f.tell()
            if not candidate_cluster:
                break

            test_engine = snapshot.clone()
            test_parser = parser_snapshot.clone()
            candidate_tags, new_overlap, bytes_to_advance = self._process_cluster(candidate_cluster, test_parser, test_engine, current_text_overlap)

            is_text_heavy = False
            if not is_binary:
                is_text_heavy = (len(candidate_cluster) - candidate_cluster.count(b'\x00')) >= (self.cluster_size * 0.8)

            if not test_engine.is_corrupted and (len(candidate_tags) > 0 or is_text_heavy):
                tqdm.write(f"  [+] Found valid continuation after {search_count + 1} clusters!")
                return True, test_engine, test_parser, candidate_tags, new_overlap, bytes_to_advance, candidate_cluster, cand_start, cand_end

            search_count += 1

        tqdm.write(f"  [-] Search failed. Aborting recovery for file {file_id}.")
        f.seek(original_pos)
        return False, snapshot, parser_snapshot, [], b"", 0, b"", -1, -1

    def carve(self, image_path: str, output_dir: str):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        total_size = os.path.getsize(image_path)
        with BufferedClusterReader(image_path) as f:
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

            pbar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Carving Progress", leave=True)
            try:
                while True:
                    # dynamically update progress bar to current position, supporting gap jump rewinds
                    pbar.n = f.tell()
                    pbar.refresh()

                    # 1. read the disk cluster by cluster
                    phys_start = f.tell()
                    cluster = f.read(self.cluster_size)
                    phys_end = f.tell()
                    if not cluster:
                        break

                    just_started = False
                    if not carving:
                        # 2. search for the beginning of a file
                        carving, active_parser, engine, current_file_handle, search_buffer = self._detect_header(
                            cluster, prev_overlap, file_id, output_dir
                        )
                        if carving:
                            cluster = search_buffer
                            carve_text_overlap = b""

                            overlap_len = len(search_buffer) - (phys_end - phys_start)
                            adj_start = phys_start - overlap_len
                            current_fragments = [{"start_offset": adj_start, "end_offset": phys_end, "size": phys_end - adj_start}]
                            current_ext = self.ext_map.get(type(active_parser), "bin")
                            current_filename = f"carved_{file_id}.{current_ext}"
                            just_started = True
                        else:
                            prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""

                    if carving:
                        if not just_started:
                            if current_fragments[-1]["end_offset"] == phys_start:
                                current_fragments[-1]["end_offset"] = phys_end
                                current_fragments[-1]["size"] += (phys_end - phys_start)
                            else:
                                current_fragments.append({"start_offset": phys_start, "end_offset": phys_end, "size": phys_end - phys_start})

                        snapshot = engine.clone()
                        parser_snapshot = active_parser.clone()
                        tags, carve_text_overlap, bytes_to_advance = self._process_cluster(cluster, active_parser, engine, carve_text_overlap)

                        cluster_to_write = cluster
                        # 4. determine state
                        if engine.is_corrupted:
                            found, new_engine, new_parser, tags, new_overlap, bytes_to_advance, candidate_cluster, cand_start, cand_end = self._attempt_gap_jump(
                                f, snapshot, parser_snapshot, file_id, carve_text_overlap
                            )
                            if found:
                                engine = new_engine
                                active_parser = new_parser
                                carve_text_overlap = new_overlap
                                cluster_to_write = candidate_cluster
                                current_fragments.append({"start_offset": cand_start, "end_offset": cand_end, "size": cand_end - cand_start})
                            else:
                                carving = False
                                active_parser = None
                                if current_file_handle:
                                    current_file_handle.close()
                                    current_file_handle = None
                                report["files"].append({
                                    "file_id": file_id,
                                    "filename": current_filename,
                                    "format": current_ext,
                                    "status": "partial",
                                    "fragments": current_fragments,
                                    "total_size": sum(f["size"] for f in current_fragments)
                                })
                                file_id += 1
                                continue

                        # check for completion
                        if carving and engine.is_empty() and len(tags) > 0:
                            tqdm.write(f"[+] Successfully carved file {file_id}!")
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

                            file_id += 1
                            carving = False
                            active_parser = None
                            prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""
                        else:
                            current_file_handle.write(cluster_to_write)
            finally:
                pbar.close()
                # ensure final file handle is closed if the image ends prematurely or an exception occurs
                if current_file_handle and not current_file_handle.closed:
                    current_file_handle.close()
                    report["files"].append({
                        "file_id": file_id,
                        "filename": current_filename,
                        "format": current_ext,
                        "status": "incomplete_eof",
                        "fragments": current_fragments,
                        "total_size": sum(f["size"] for f in current_fragments)
                    })

            report_path = os.path.join(output_dir, "carve_report.json")
            with open(report_path, "w") as f_report:
                json.dump(report, f_report, indent=4)
            print(f"[*] Forensic carve report saved to {report_path}")
