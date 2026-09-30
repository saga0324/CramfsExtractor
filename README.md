# CramfsExtractor

CramfsExtractor is a command-line utility for extracting CRAMFS images used by NEC and Panasonic feature phones. It parses the filesystem tree and handles the vendor-specific data layouts found in these images.

## Features

- Parse the CRAMFS superblock, inode table, directories, and regular files.
- Extract NEC images with zlib block decompression and raw-file detection.
- Extract Panasonic images using standard zlib blocks or Panasonic raw block tables.
- Preserve the filesystem directory structure in the output directory.
- Handle sparse blocks as zero-filled data.
- Skip symbolic links instead of creating links on the host system.

## Requirements

- Python 3.10 or newer
- No third-party Python packages

## Usage

Extract an NEC image:

```bash
python3 CramfsExtractor.py firmware.cramfs extracted
```

The default flavor is `nec`. It may also be selected explicitly:

```bash
python3 CramfsExtractor.py firmware.cramfs extracted --flavor nec
```

Extract a Panasonic image:

```bash
python3 CramfsExtractor.py firmware.cramfs extracted --flavor panasonic
```

Use `--help` to display all available options:

```bash
python3 CramfsExtractor.py --help
```

## Extraction Behavior

### NEC

The NEC extractor detects uncompressed ELF files and writes them directly. For other files, it reads the CRAMFS block pointer table and decompresses zlib blocks. Data that does not look like a valid block stream is written using the raw fallback.

### Panasonic

The Panasonic extractor first attempts strict standard CRAMFS zlib decompression. If that fails, it attempts the Panasonic raw block table layout. If neither layout can be validated, it writes data from the inode offset using the raw fallback.

Existing files with the same paths in the output directory are overwritten. Symbolic links are reported and skipped.

## Warning

This tool is intended for firmware analysis and extraction. Raw fallback output is not proof that a file was decoded correctly. Verify extracted file sizes, formats, and contents before using them for further analysis or modification.

The extractor does not rebuild CRAMFS images, recover damaged filesystems, or validate extracted data against the original firmware.
