import os
from struct_carver.formats.xml_parser import XMLParser
from struct_carver.formats.html_parser import HTMLParser
from struct_carver.formats.pdf_parser import PDFParser
from struct_carver.formats.json_parser import JSONParser
from struct_carver.formats.rtf_parser import RTFParser
from struct_carver.formats.zip_parser import ZIPParser
from struct_carver.core.stack_engine import StackEngine


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

    def carve(self, image_path: str, output_dir: str):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(image_path, 'rb') as f:
            file_id = 0
            carving = False
            current_file_data = bytearray()
            engine = StackEngine()
            active_parser = None

            ext_map = {
                XMLParser: "xml",
                HTMLParser: "html",
                PDFParser: "pdf",
                JSONParser: "json",
                RTFParser: "rtf",
                ZIPParser: "zip"
            }

            while True:
                # 1. read the disk cluster by cluster
                cluster = f.read(self.cluster_size)
                if not cluster:
                    break

                if not carving:
                    # 2. search for the beginning of a file
                    cluster_lower = cluster.lower()
                    for parser in self.parsers:
                        for sig in parser.header_signatures:
                            if sig in cluster_lower:
                                carving = True
                                active_parser = parser
                                engine.reset()
                                current_file_data = bytearray()
                                break
                        if carving:
                            break

                if carving:
                    snapshot = engine.clone()

                    # decode bytes to string (ignore binary garbage)
                    text_data = cluster.decode('utf-8', errors='ignore')
                    tags = active_parser.extract_tags(text_data)

                    # 3. process the semantic structure
                    engine.process_tags(tags)

                    # 4. determine state
                    if engine.is_corrupted:
                        print(f"[*] Fragmentation detected in file {file_id}. Initiating gap-jumping search...")
                        engine = snapshot  # Restore to pre-corruption state

                        found_next_part = False
                        max_search_clusters = 1000  # Prevent infinite scanning on large drives
                        search_count = 0
                        original_pos = f.tell()

                        while search_count < max_search_clusters:
                            candidate_cluster = f.read(self.cluster_size)
                            if not candidate_cluster:
                                break

                            test_engine = engine.clone()
                            candidate_text = candidate_cluster.decode('utf-8', errors='ignore')
                            candidate_tags = active_parser.extract_tags(candidate_text)

                            test_engine.process_tags(candidate_tags)

                            # Valid continuation must not corrupt AND must contain structural tags
                            if not test_engine.is_corrupted and len(candidate_tags) > 0:
                                print(f"  [+] Found valid continuation after {search_count + 1} clusters!")
                                engine = test_engine
                                current_file_data.extend(candidate_cluster)
                                found_next_part = True
                                tags = candidate_tags  # Update tags for completion check
                                break

                            search_count += 1

                        if not found_next_part:
                            print(f"  [-] Search failed. Aborting recovery for file {file_id}.")
                            f.seek(original_pos)  # Rewind to continue normal scanning for other files
                            carving = False
                            active_parser = None
                            continue
                    else:
                        # append valid cluster
                        current_file_data.extend(cluster)

                    # check for completion
                    if carving and engine.is_empty() and len(tags) > 0:
                        print(f"[+] Successfully carved file {file_id}!")
                        ext = ext_map.get(type(active_parser), "bin")
                        out_path = os.path.join(output_dir, f"carved_{file_id}.{ext}")
                        with open(out_path, 'wb') as out_f:
                            out_f.write(current_file_data)
                        file_id += 1
                        carving = False
                        active_parser = None
