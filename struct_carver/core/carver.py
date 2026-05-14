import os
from struct_carver.formats.xml_parser import XMLParser
from struct_carver.formats.html_parser import HTMLParser
from struct_carver.formats.pdf_parser import PDFParser
from struct_carver.formats.json_parser import JSONParser
from struct_carver.formats.rtf_parser import RTFParser
from struct_carver.formats.zip_parser import ZIPParser
from struct_carver.core.stack_engine import StackEngine
from struct_carver.core.binary_engine import BinaryOffsetEngine


class Carver:
    def __init__(self, cluster_size=4096, formats=None):
        self.cluster_size = cluster_size
        self.parsers = []

        if formats is None:
            formats = ['xml', 'html', 'pdf', 'json', 'rtf', 'zip']

        if 'xml' in formats:
            self.parsers.append(XMLParser())
        if 'html' in formats:
            self.parsers.append(HTMLParser())
        if 'pdf' in formats:
            self.parsers.append(PDFParser())
        if 'json' in formats:
            self.parsers.append(JSONParser())
        if 'rtf' in formats:
            self.parsers.append(RTFParser())
        if 'zip' in formats:
            self.parsers.append(ZIPParser())

        self.ext_map = {
            XMLParser: "xml",
            HTMLParser: "html",
            PDFParser: "pdf",
            JSONParser: "json",
            RTFParser: "rtf",
            ZIPParser: "zip"
        }

    def _detect_header(self, cluster: bytes, prev_overlap: bytes, file_id: int, output_dir: str):
        search_buffer = prev_overlap + cluster
        cluster_lower = search_buffer.lower()
        for parser in self.parsers:
            for sig in parser.header_signatures:
                if sig in cluster_lower:
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
            is_corr, is_comp, _ = parser.analyze_binary(cluster)
            engine.process_binary(is_corr, is_comp)
            return ["binary_chunk"], b""
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

            tags = parser.extract_tags(byte_data)
            engine.process_tags(tags)
            return tags, held_back_bytes

    def _attempt_gap_jump(self, f, snapshot, parser, file_handle, file_id: int, current_text_overlap: bytes):
        print(f"[*] Fragmentation detected in file {file_id}. Initiating gap-jumping search...")
        max_search_clusters = 1000
        search_count = 0
        original_pos = f.tell()
        is_binary = getattr(parser, 'engine_type', 'semantic') == 'binary'

        while search_count < max_search_clusters:
            candidate_cluster = f.read(self.cluster_size)
            if not candidate_cluster:
                break

            test_engine = snapshot.clone()
            candidate_tags, new_overlap = self._process_cluster(candidate_cluster, parser, test_engine, current_text_overlap)

            is_text_heavy = False
            if not is_binary:
                is_text_heavy = (len(candidate_cluster) - candidate_cluster.count(b'\x00')) >= (self.cluster_size * 0.8)

            if not test_engine.is_corrupted and (len(candidate_tags) > 0 or is_text_heavy):
                print(f"  [+] Found valid continuation after {search_count + 1} clusters!")
                file_handle.write(candidate_cluster)
                return True, test_engine, candidate_tags, new_overlap

            search_count += 1

        print(f"  [-] Search failed. Aborting recovery for file {file_id}.")
        f.seek(original_pos)
        return False, snapshot, [], b""

    def carve(self, image_path: str, output_dir: str):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(image_path, 'rb') as f:
            file_id = 0
            carving = False
            current_file_handle = None
            engine = None
            active_parser = None
            carve_text_overlap = b""

            max_sig_len = max([len(sig) for parser in self.parsers for sig in parser.header_signatures], default=0)
            overlap_size = max(0, max_sig_len - 1)
            prev_overlap = b""

            while True:
                # 1. read the disk cluster by cluster
                cluster = f.read(self.cluster_size)
                if not cluster:
                    break

                if not carving:
                    # 2. search for the beginning of a file
                    carving, active_parser, engine, current_file_handle, search_buffer = self._detect_header(
                        cluster, prev_overlap, file_id, output_dir
                    )
                    if carving:
                        cluster = search_buffer
                        carve_text_overlap = b""
                    else:
                        prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""

                if carving:
                    snapshot = engine.clone()
                    tags, carve_text_overlap = self._process_cluster(cluster, active_parser, engine, carve_text_overlap)

                    # 4. determine state
                    if engine.is_corrupted:
                        found, new_engine, tags, new_overlap = self._attempt_gap_jump(
                            f, snapshot, active_parser, current_file_handle, file_id, carve_text_overlap
                        )
                        if found:
                            engine = new_engine
                            carve_text_overlap = new_overlap
                        else:
                            carving = False
                            active_parser = None
                            if current_file_handle:
                                current_file_handle.close()
                                current_file_handle = None
                            file_id += 1
                            continue
                    else:
                        # append valid cluster
                        current_file_handle.write(cluster)

                    # check for completion
                    if carving and engine.is_empty() and len(tags) > 0:
                        print(f"[+] Successfully carved file {file_id}!")
                        if current_file_handle:
                            current_file_handle.close()
                            current_file_handle = None
                        file_id += 1
                        carving = False
                        active_parser = None
                        prev_overlap = cluster[-overlap_size:] if overlap_size > 0 else b""

            # ensure final file handle is closed if the image ends prematurely
            if current_file_handle and not current_file_handle.closed:
                current_file_handle.close()
