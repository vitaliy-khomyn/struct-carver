# Struct Carver

**Struct Carver** is an advanced digital forensics and incident response (DFIR) file carving framework designed to extract, validate, and reconstruct heavily fragmented, non-sequential files from raw disk images, memory dumps, and unallocated storage clusters.

Unlike traditional carving utilities that rely solely on linear, contiguous header-to-footer extraction, Struct Carver uses **semantic and structural stream analysis** to logically reconstruct files whose data clusters are scattered out-of-order across physical storage media.

---

## The Fragmentation Problem

When a filesystem deletes a file, its assigned clusters become unallocated. As new data is written to disk, files are frequently fragmented into discontiguous segments across non-adjacent clusters.

Standard forensic carvers fail in these scenarios because they assume data clusters follow sequentially from file header to footer. Struct Carver addresses this by combining syntactic document parsing, container-level offset tracking, heuristic gap-jumping sweeps, and forensic verification passes to piece together non-contiguous file fragments.

---

## Core Architecture

Struct Carver operates on a modular, multi-engine architecture designed for high throughput and forensic integrity:

```
                      Raw Disk Image / Multi-Segment Dumps (.001, .002, .raw)
                                                │
                                    BufferedClusterReader
                                                │
                                         HeaderDetector
                                       /                \
                        Semantic Stack Engine      Binary Offset Engine
                          (Hierarchical Text)     (Containers & Payloads)
                                       \                /
                                        GapJumper Engine
                               (Batch Heuristic Cluster Search)
                                                │
                                          PostProcessor
                             (Safe unpack, Zip Slip defense, TIFF/PNG fix)
                                                │
                                     Forensic Integrity Pass
                         (CRC32, SQLite PRAGMA, MP4/RIFF Atoms, Entropy, EXIF)
                                                │
                       Carve Report, Bodyfile 3.0, JSONL, Manifest & Dashboard
```

### 1. Semantic Stack Engine (Hierarchical Markup & Text)
* **Stack State Tracking:** As text clusters stream through the carver, opening and closing tags/delimiters are tracked on an internal stack state machine.
* **Non-Sequential Gap-Jumping:** If a cluster ends with an unclosed stack (e.g. open `<div>` or JSON array), the carver halts linear ingestion and initiates heuristic lookahead sweeps over candidate unallocated clusters to locate the logically matching continuation block.
* **Control Byte Validation:** Rejects corrupted binary noise masquerading as text via strict ASCII/UTF-8 control-byte checking.

### 2. Binary Offset Engine (Containers & Payloads)
* **Container Header Sizing:** Reads container headers, FourCC atom boxes, and size fields to track payload boundaries without destructive string decoding.
* **Zero-Fill Gap Reconstruction:** When non-contiguous binary fragments are reconnected (e.g. fragmented PDFs or RIFF streams), intervening disk gaps can be zero-filled to preserve internal byte offset tables (such as PDF cross-reference `xref` tables).

### 3. Modular Parser Hierarchy
Format parsers inherit from extensible base classes:
* **`BaseRIFFParser`**: Unified RIFF container parsing (`WAV`, `AVI`).
* **`BaseASFParser`**: Advanced Systems Format container parsing (`WMA`, `WMV`).
* **`BaseBoxParser`**: ISO Base Media / QuickTime atom parsing (`MP4`, `MOV`).
* **`BaseStreamingDecompressorParser`**: Stream-accumulating decompression parsers (`GZ`, `BZ2`).
* **`BaseMarkupParser`**: Regex-driven tag extraction and comment handling (`XML`, `HTML`).

---

## Supported File Formats & Categories

Struct Carver includes built-in support for **over 30 file formats** and supports **category presets** (`images`, `documents`, `media`, `archives`, `databases`):

| Category Preset | Supported Extensions | Description & Engine |
| :--- | :--- | :--- |
| `documents` | `pdf` | PDF cross-reference tables, stream tracking, dictionary metadata |
| | `docx`, `xlsx`, `pptx` | Microsoft Office Open XML packages (ZIP container + XML metadata) |
| | `json` | Balanced object/array bracket parsing with string-escape handling |
| | `xml`, `html` | Stack-based tag balancing, void-element filtering, CDATA/comment support |
| | `rtf` | Rich Text Format brace-balancing and control-word parsing |
| `databases` | `sqlite`, `db` | SQLite 3 database header validation and B-tree page verification |
| | `sqlitewal` | SQLite Write-Ahead Log (WAL) frame header parsing |
| `archives` | `zip` | ZIP local file headers, central directories, and data descriptors |
| | `tar` | POSIX ustar / GNU tar archive header verification |
| | `gz`, `bz2` | Streaming DEFLATE and BZIP2 compression stream verification |
| | `7z`, `rar`, `wim` | Modern multi-volume and solid archive signature containers |
| `images` | `jpg`, `jpeg` | JPEG SOI/EOI marker verification and EXIF metadata extraction |
| | `png` | PNG 8-byte signature, chunk CRC32 checksums, and `tIME`/`tEXt` chunks |
| | `gif` | GIF87a/GIF89a header checks and `0x3B` terminal trailer verification |
| | `bmp` | DIB header validation, pixel offset safety, and dimension bounds |
| | `tiff`, `tif` | Big/Little-endian IFD directory parsing and tag offset remapping |
| | `pcx` | ZSoft Paintbrush 128-byte header, RLE stream, and 256-color palette |
| `media` | `mp3` | MPEG audio frame header sync (`0xFFE`) and ID3v1/ID3v2 tags |
| | `wav`, `avi` | RIFF container header sizing, FourCC tags (`WAVE`, `AVI `), sub-chunk checks |
| | `mp4`, `mov` | ISO BMFF / QuickTime atom boxes (`ftyp`, `moov`, `mdat`, `free`, `wide`) |
| | `wma`, `wmv` | ASF header object GUIDs and video stream descriptor validation |
| | `flv`, `mpg` | Flash Video tag headers and MPEG program/transport stream packs |
| | `au` | Sun/NeXT AU sound header offset and sample size parsing |
| **Custom Formats** | User-defined | Configurable via external JSON signature definitions (`--config`) |

---

## Forensic (DFIR) Capabilities

Struct Carver is built to meet digital forensics and incident response evidentiary standards:

* **Chain of Custody & Image Hashing:** Computes cryptographic hashes (**SHA-256** and **MD5**) of the raw source evidence image before carving begins, recording them in audit logs, reports, and dashboards.
* **Segmented / Multi-Volume Disk Images:** Virtual seekable streaming reader automatically discovers and seamlessly traverses multi-part raw split disk dumps (`.001`, `.002`, `.part01.raw`, etc.).
* **Timeline Analysis (SleuthKit Bodyfile 3.0 & JSONL):**
  * Generates `bodyfile.txt` formatted for `mactime` timeline generation (`MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`).
  * Generates `carve_report.jsonl` with line-delimited streaming JSON for direct ingestion into SIEM tools (Splunk, Elastic).
* **Security Hardening (Zip Slip & Zip Bomb Protection):**
  * Safe opt-in archive extraction (`--extract-archives`) strictly sanitizes member target paths using common-path traversal checks to prevent directory escaping.
  * Enforces uncompressed volume limits (default: 250MB) and member count thresholds (10,000 files) to thwart zip bomb decompression attacks.
  * Maximum carved file size limit (`--max-file-size`, default: 2GB) halts runaway corrupted allocations.
* **Sector-Level Addressing (LBA):** Calculates starting Logical Block Addressing (LBA) sector offsets (`start_offset // 512`) for every carved file.
* **Cluster Slack Space Calculation:** Computes the exact physical cluster slack space remaining in the final sector block.
* **Shannon Entropy Analysis:** Computes whole-file Shannon entropy ($H \in [0.0, 8.0]$) to classify recovered data as plain text / zero-fill ($< 4.0$), structured data ($4.0 - 7.2$), or compressed/encrypted ($> 7.2$).
* **Forensic Metadata Extraction:** Automatically parses and extracts embedded document properties and timestamps:
  * **JPEG:** Camera make, camera model, `DateTimeOriginal`.
  * **PDF:** `CreationDate`, `ModDate`, author, title, producer.
  * **Office (`docx`, `xlsx`, `pptx`):** Author, last modified by, creation and modification timestamps from `docProps/core.xml`.
  * **PNG:** `tIME` chunk timestamps and `tEXt` key-value pairs.
* **Deep Forensic Validation:** Runs automated integrity validation passes on carved files:
  * ZIP CRC32 checks and member checksum validation.
  * SQLite `PRAGMA integrity_check(1)` read-only database verification.
  * MP4/MOV ISO base media box hierarchy verification (`ftyp`, `moov`, `mdat`).
  * RIFF sub-chunk verification for WAV (`fmt `, `data`) and AVI (`hdrl`, `movi`).
  * PNG chunk CRCs, GZ/BZ2 decompression verification, JPEG SOI/EOI checks.
* **Multi-Worker Overlap Deduplication:** Parallel workers split image segments; boundary deduplication automatically resolves files that straddle worker boundaries and prunes superseded partial files.
* **Intra-Cluster Stream Rewinding:** If a small file completes inside a cluster, the stream automatically rewinds to the exact termination offset to carve consecutive files packed into the same physical cluster block.
* **Resumable Carving Sessions:** Checkpoint state (`checkpoint.json`) allows long-running or interrupted carving sessions to be resumed cleanly with `--resume`.
* **Interactive HTML Dashboard:** Generates an evidence dashboard with summary metric cards, Chain of Custody records, filterable file tables, and graphical disk fragment distribution maps.

---

## Installation

### Requirements
* Python 3.8 or higher
* Standard CPython environment (Windows, macOS, or Linux)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vitaliy-khomyn/struct-carver.git
   cd struct-carver
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the package locally (optional, enables `structcarver` command):**
   ```bash
   pip install .
   ```

5. **Run the test suite:**
   ```bash
   python run_tests.py
   ```

---

## Usage

Carve an evidence disk image using either the installed CLI entry point or the Python module:

```bash
# Using the installed command
structcarver --image evidence.dd --output ./carved_output/ -d

# Running directly as a Python module
python -m struct_carver.cli --image evidence.dd --output ./carved_output/ -d
```

### Common Commands

#### 1. Targeted Format Carving
Carve only specific formats (e.g. PDFs, Word documents, and SQLite databases):
```bash
python -m struct_carver.cli -i evidence.dd -o ./output/ -f pdf,docx,sqlite -d
```

#### 2. Multi-Worker Parallel Processing
Accelerate carving across multiple CPU cores:
```bash
python -m struct_carver.cli -i evidence.raw -o ./output/ -w 4 -d
```

#### 3. Custom Forensic Hashing & Integrity Validation
Use SHA-512 for forensic manifests and enable strict payload validation:
```bash
python -m struct_carver.cli -i image.dd -o ./output/ --hash-algo sha512 --validate -d
```

#### 4. Resuming an Interrupted Session
Resume carving from the last saved checkpoint:
```bash
python -m struct_carver.cli -i image.dd -o ./output/ --resume -d
```

#### 5. Custom Dynamic Signatures via JSON Config
Carve proprietary or custom binary formats using hexadecimal signatures:
```json
[
  {
    "extension": "custombin",
    "header_hex": "435553544f4d",
    "footer_hex": "454e44435553"
  }
]
```
```bash
python -m struct_carver.cli -i disk.raw -o ./output/ --config custom_formats.json -d
```

---

## Command-Line Options

| Option | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-i`, `--image` | `PATH` | **Required.** Path to raw forensic image file (`.dd`, `.raw`, `.img`, `.001`). | *None* |
| `-o`, `--output` | `DIR` | **Required.** Output directory for carved files, reports, and logs. | *None* |
| `-f`, `--formats` | `LIST` | Comma-separated list of formats or category aliases (`images`, `documents`, `media`, `archives`, `databases`). | *All supported* |
| `-c`, `--cluster-size` | `BYTES` | Disk cluster/block size in bytes. | `4096` |
| `-w`, `--workers` | `INT` | Number of concurrent carving worker processes. | `1` |
| `-d`, `--dashboard` | *Flag* | Automatically generates an interactive HTML dashboard (`dashboard.html`). | `False` |
| `-q`, `--quiet` | *Flag* | Suppress non-essential console logs and progress indicators. | `False` |
| `--hash-algo` | `ALGO` | Forensic hash algorithm (`sha256`, `md5`, `sha1`, `sha512`). | `sha256` |
| `--validate` | *Flag* | Enable deep payload integrity checks (e.g. CRC32, PRAGMA, MP4/RIFF). | `True` |
| `--no-validate` | *Flag* | Disable deep payload integrity verification pass. | `False` |
| `--extract-archives` | *Flag* | Safely unpack carved ZIP/TAR archives into subdirectories with Zip Slip protection. | `False` |
| `--max-file-size` | `BYTES` | Maximum carved file size before truncation (prevents runaway allocations). | `2147483648` (2GB) |
| `--resume` | *Flag* | Resume an interrupted carving session using `checkpoint.json`. | `False` |
| `--max-search` | `INT` | Max lookahead clusters during a gap-jump search. | `1000` |
| `--text-density` | `FLOAT` | Printable character ratio threshold (0.0 to 1.0) for text clusters. | `0.8` |
| `--max-gap-fill` | `BYTES` | Maximum bytes to zero-fill across an inter-fragment gap. | `104857600` (100MB) |
| `--config` | `FILE` | Path to JSON file defining custom linear binary format signatures. | *None* |
| `--profile` | *Flag* | Enable cProfile performance profiling per worker (writes `.prof` files). | `False` |

---

## Output Artifacts

Every carving run generates standard, forensically verifiable output files:

* **Carved Files (`carved_w<worker>_<id>.<ext>`):** Intact recovered files. Partial files are identified with `_partial` suffixes.
* **`carve_report.json`:** Comprehensive JSON report with source image hashes, sector addresses, slack bytes, entropy scores, metadata dictionaries, and fragment lists.
* **`carve_report.jsonl`:** Line-delimited JSON stream formatted for direct ingestion into enterprise SIEM platforms (Splunk, Elastic).
* **`bodyfile.txt`:** SleuthKit Bodyfile 3.0 timeline export with synthetic inodes and timestamps for `mactime` timeline generation.
* **`manifest.csv`:** Tabular forensic evidence manifest with file hashes, LBA addresses, slack space, and entropy values for case logging.
* **`manifest.<algo>`:** Cryptographic hash manifest formatted identically to standard `sha256sum`/`md5sum` verification files.
* **`dashboard.html`:** Interactive standalone report with evidence summary cards, Chain of Custody hashes, status filtering, and visual disk segment maps.
* **`audit_*.log`:** Detailed audit logs recording worker progress, gap-jumping actions, and candidate resolutions.
* **`checkpoint.json`:** Transient worker offset state recorded periodically for session resumption.

---

## Testing

Struct Carver includes a comprehensive test suite containing unit tests, parser edge cases, corruption rejection tests, and end-to-end multi-worker integration tests:

```bash
# Run all unit tests
python run_tests.py

# Or run via unittest directly
python -m unittest discover tests
```

---

## Contributing

Contributions are welcome! If you would like to add support for new file formats, optimize gap-jumping heuristics, or contribute DFIR features, please open an Issue or submit a Pull Request.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
