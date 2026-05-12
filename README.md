# StructCarver

**StructCarver** is a digital forensics file carver designed to extract and reassemble heavily fragmented, non-sequential files from raw disk images and memory dumps. 

Unlike traditional file carvers that rely strictly on sequential header-to-footer extraction, StructCarve aims to utilize semantic analysis to logically reconstruct files whose data blocks are scattered out-of-order across a storage medium.

## The Problem

When a file system deletes a file, its data clusters become unallocated. Over time, these clusters get overwritten, leading to fragmentation. If a new file is written into these fragmented gaps, its data blocks are stored non-sequentially. Standard carving tools fail in these scenarios because they expect a file's data to follow linearly after its header.

## Solution (The MVP)

For now, StructCarver focuses on **structured text formats** such as `HTML`, `XML`, and `JSON`. 

By leveraging the hierarchical, tag-based nature of these formats, StructCarver employs a **Stack-Matching Engine**:
1. **Header Identification:** The carver finds an opening signature (e.g., `<?xml` or `<html>`).
2. **Stack Tracking:** As it reads the data cluster, it pushes opening tags (e.g., `<div>`, `<user>`) to a stack and pops them when encountering closing tags.
3. **Cluster Boundary Resolution:** When the carver reaches the end of a physical disk cluster and the stack is not empty, it knows the file is incomplete.
4. **Heuristic Search:** Instead of blindly appending the next sequential cluster (which might belong to a different file), StructCarver scans unallocated space for a cluster that logically resolves the current stack state, stitching non-contiguous segments back together.

## Features

* **Non-Sequential Reassembly:** Extracts files even when they are heavily fragmented and stored out of order.
* **Stack-Based Semantic Parsing:** Intelligently reconstructs HTML and XML by tracking document structure rather than just raw bytes.
* **Corrupted File Detection:** Aborts or flags reconstruction paths that violate syntax rules (e.g., mismatched tags).
* **Extensible Architecture:** Designed with a modular framework, allowing developers to easily plug in carving logic for new and unsupported file formats.
* **Cross-Platform:** Built to run on Linux, macOS, and Windows.

## Installation

*(Instructions on how to clone, install dependencies, and build the project will go here.)*
*(For now, they are incomplete and are the subject to change.)*

	git clone https://github.com/vitaliy-khomyn/struct-carver
	cd struct-carver
	# e.g., pip install -r requirements.txt or make build

## Usage

Run StructCarve against a raw disk image (`.dd`, `.raw`, `.img`):

	structcarver --image evidence.dd --output ./recovered_files/ --formats xml,html


**Options:**
* `-i, --image`: Path to the raw forensic image.
* `-o, --output`: Directory to save the reassembled files.
* `-f, --formats`: Comma-separated list of formats to carve (default: html, xml).
* `--verbose`: Output detailed logs of the stack-matching process for forensic auditing.

## Roadmap

- [x] **Phase 1:** Stack-matching engine for text-based hierarchical formats (`XML`, `HTML`).
- [ ] **Phase 2:** Support for JSON (tracking nested braces `{}` and brackets `[]`).
- [ ] **Phase 3:** Advanced heuristics for non-sequential binary formats (e.g., `ZIP`, `DOCX`, which contain internal chunk offsets).
- [ ] **Phase 4:** Multi-threading and performance optimization for large disk images.
- [ ] **Phase 5:** Integration with popular forensic frameworks.
- [ ] **Phase 6:** Minimal GUI for ease of use (very low priority).

## Contributing

Contributions are welcome! If you're interested in digital forensics, algorithms, or low-level file parsing, please feel free to submit a Pull Request or open an Issue.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
