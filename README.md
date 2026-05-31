# Struct Carver!

**Struct Carver!** is a digital forensics file carver designed to extract and reassemble heavily fragmented, non-sequential files from raw disk images and memory dumps. 

Unlike traditional file carvers that rely strictly on sequential header-to-footer extraction, Struct Carver! aims to utilize semantic analysis to logically reconstruct files whose data blocks are scattered out-of-order across a storage medium.

## The Problem

When a file system deletes a file, its data clusters become unallocated. Over time, these clusters get overwritten, leading to fragmentation. If a new file is written into these fragmented gaps, its data blocks are stored non-sequentially. Standard carving tools fail in these scenarios because they expect a file's data to follow linearly after its header.

## Solution (Dual-Engine Architecture)

Struct Carver! employs a **Dual-Engine Architecture** to handle both textual formats (`HTML`, `XML`, `JSON`) and binary hierarchical formats (`ZIP`, `PDF`).

### 1. Semantic Stack Engine (Text)
1. **Header Identification:** The carver finds an opening signature (e.g., `<?xml` or `<html>`).
2. **Stack Tracking:** As it reads the data cluster, it pushes opening tags (e.g., `<div>`, `<user>`) to a stack and pops them when encountering closing tags.
3. **Cluster Boundary Resolution:** When the carver reaches the end of a physical disk cluster and the stack is not empty, the file is incomplete.
4. **Heuristic Search:** Instead of blindly appending the next sequential cluster (which might belong to a different file), Struct Carver! scans unallocated space for a cluster that logically resolves the current stack state, stitching non-contiguous segments back together.

### 2. Binary Offset Engine (Binary)
Unlike text files, binary formats rely on byte offsets, lengths, and embedded signatures (e.g., `PK\x03\x04` for ZIP Local File Headers). The Binary Engine operates exclusively on raw bytes, validating chunk offsets and signature sequences to safely gap-jump over corrupted binary space without destructive string decoding.

## Features

* **Non-Sequential Reassembly:** Extracts files even when they are heavily fragmented and stored out of order.
* **Stack-Based Semantic Parsing:** Intelligently reconstructs HTML and XML by tracking document structure rather than just raw bytes.
* **Corrupted File Detection:** Aborts or flags reconstruction paths that violate syntax rules (e.g., mismatched tags).
* **Extensible Architecture:** Designed with a modular framework, allowing developers to easily plug in carving logic for new and unsupported file formats.
* **Cross-Platform:** Built to run on Linux, macOS, and Windows.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vitaliy-khomyn/struct-carver.git
   cd struct-carver
   ```

2. **Set up a virtual environment (recommended):**
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

4. **Install the package (to enable the `structcarver` CLI command globally):**
   ```bash
   pip install .
   ```

5. **Run the test suite to verify the installation:**
   ```bash
   python run_tests.py
   ```

## Usage

You can run the carver using either the installed global command `structcarver` or directly via Python with the package module:

```bash
# Using the globally installed CLI entry point
structcarver --image evidence.dd --output ./recovered_files/ --formats xml,html,pdf,zip -d

# Or running directly via Python module
python -m struct_carver.cli --image evidence.dd --output ./recovered_files/ --formats xml,html,pdf,zip -d
```

### Options:
* `-i, --image` (required): Path to the raw forensic image file (e.g., `.dd`, `.raw`, `.img`).
* `-o, --output` (required): Output directory to store the carved files, audit logs, and reports.
* `-f, --formats`: Comma-separated list of formats to carve (default: all supported formats).
* `-c, --cluster-size`: Disk cluster block size in bytes (default: `4096`).
* `-w, --workers`: Number of concurrent worker threads/processes for processing (default: `1`).
* `--config`: Path to a custom JSON configuration file to define additional linear formats dynamically.
* `--max-search`: Maximum number of clusters to scan ahead during a gap-jump search (default: `1000`).
* `--text-density`: Threshold ratio (0.0 to 1.0) of printable characters to accept non-markup text clusters (default: `0.8`).
* `-d, --dashboard`: Automatically generate an interactive HTML dashboard (`dashboard.html`) summarizing the results.
* `--profile`: Enable cProfile performance profiling per worker (saves `.prof` data per worker).

## Roadmap

- [x] **Phase 1:** Stack-matching engine for text-based hierarchical formats (`XML`, `HTML`).
- [x] **Phase 2:** Support for JSON and RTF with string-escape state machines.
- [x] **Phase 3:** Dual-Engine fork: `BinaryOffsetEngine` for non-sequential binary formats (e.g., `ZIP`, `PDF`).
- [x] **Phase 4:** Multi-threading and performance optimization for large disk images.
- [ ] **Phase 5:** Integration with popular forensic frameworks.
- [ ] **Phase 6:** Minimal GUI for ease of use (very low priority).

## Contributing

Contributions are welcome! If you're interested in digital forensics, algorithms, or low-level file parsing, please feel free to submit a Pull Request or open an Issue.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
