import os
import struct
import zlib
import sys
import argparse

CRAMFS_MAGIC = 0x28CD3D45
BLK_SIZE = 4096


class CramFSExtractor:
    def __init__(self, filename, extract_path, flavor="nec"):
        self.filename = filename
        self.extract_path = extract_path
        self.flavor = flavor
        self.inodes = {}

        try:
            self.f = open(filename, "rb")
        except FileNotFoundError:
            print(f"[-] Error: File '{filename}' not found.")
            sys.exit(1)

        print(f"[*] Analyzing image: {filename}")
        print(f"[*] Target extraction path: {extract_path}")
        print(f"[*] Flavor: {flavor}\n")

    def unpack_inode(self, data, offset_in_file=0):
        v1, v2, v3 = struct.unpack("<III", data)

        return {
            "mode": v1 & 0xFFFF,
            "uid": (v1 >> 16) & 0xFFFF,
            "size": v2 & 0xFFFFFF,
            "gid": (v2 >> 24) & 0xFF,
            "namelen": v3 & 0x3F,
            "offset": (v3 >> 6) & 0x3FFFFFF,
        }

    def parse(self):
        self.f.seek(0)
        header_data = self.f.read(76)

        if len(header_data) < 76:
            print("[-] Error: Image file too small to read superblock.")
            return

        magic = struct.unpack("<I", header_data[:4])[0]

        if magic != CRAMFS_MAGIC:
            print(f"[!] Magic mismatch! Expected: 0x{CRAMFS_MAGIC:08X}, Got: 0x{magic:08X}")
            return

        _, fs_size, flags, future, signature = struct.unpack("<IIII16s", header_data[:32])

        print("[+] Superblock identified successfully!")
        print(f"    Signature: {signature.decode(errors='ignore').strip()}")
        print(f"    Total FS Size: {fs_size} bytes")
        print(f"    Flags: 0x{flags:08X}")
        print(f"    Future: 0x{future:08X}")

        root_inode_raw = header_data[64:76]
        self.inodes[0] = {
            "inode": self.unpack_inode(root_inode_raw, 64),
            "name": "",
        }

        files_count = struct.unpack("<I", header_data[48:52])[0]
        print(f"[*] Parsing file index table ({files_count} files recorded)...")

        for i in range(files_count):
            pos = self.f.tell()
            inode_raw = self.f.read(12)

            if not inode_raw or len(inode_raw) < 12:
                break

            inode_data = self.unpack_inode(inode_raw, pos)

            name_len = inode_data["namelen"] * 4
            if name_len > 0:
                name_raw = self.f.read(name_len)
                name = name_raw.decode("utf-8", errors="ignore").rstrip("\x00")
            else:
                name = f"unknown_file_{i}"

            self.inodes[pos] = {
                "inode": inode_data,
                "name": name,
            }

        print("\n" + "=" * 60)
        print("[*] Starting file tree extraction...")
        print("=" * 60)

        self.traverse(0, self.extract_path)

        print("\n[+] Extraction process finished.")

    def extract_nec(self, start_offset, size, target_path):
        self.f.seek(start_offset)

        magic_peek = self.f.read(4)
        if len(magic_peek) < 4:
            return False

        if magic_peek == b"\x7fELF":
            print("      [->] ELF header detected, performing RAW extraction...")
            self.f.seek(start_offset)
            with open(target_path, "wb") as wf:
                wf.write(self.f.read(size))
            return True

        num_blocks = (size + BLK_SIZE - 1) // BLK_SIZE
        pointers_size = num_blocks * 4
        expected_min_ptr = start_offset + pointers_size

        first_ptr = struct.unpack("<I", magic_peek)[0] & 0x3FFFFFFF

        if first_ptr < expected_min_ptr or first_ptr > (start_offset + size * 2 + 8192):
            print(f"      [->] Non-pointer signature 0x{first_ptr:X}, falling back to RAW extraction...")
            self.f.seek(start_offset)
            with open(target_path, "wb") as wf:
                wf.write(self.f.read(size))
            return True

        self.f.seek(start_offset)
        pointers_raw = self.f.read(pointers_size)

        if len(pointers_raw) < pointers_size:
            return False

        block_pointers = struct.unpack(f"<{num_blocks}I", pointers_raw)
        current_block_start = start_offset + pointers_size

        with open(target_path, "wb") as wf:
            for ptr in block_pointers:
                actual_ptr = ptr & 0x3FFFFFFF

                if actual_ptr == 0:
                    wf.write(b"\x00" * BLK_SIZE)
                    continue

                chunk_size = actual_ptr - current_block_start

                if chunk_size <= 0 or chunk_size > 8192:
                    wf.write(b"\x00" * BLK_SIZE)
                    current_block_start = actual_ptr
                    continue

                self.f.seek(current_block_start)
                chunk_data = self.f.read(chunk_size)

                try:
                    decompressed = zlib.decompress(chunk_data)
                    wf.write(decompressed)
                except zlib.error:
                    wf.write(chunk_data)

                current_block_start = actual_ptr

        return True

    def extract_standard_cramfs_strict(self, start_offset, size, target_path):
        if size == 0:
            open(target_path, "wb").close()
            return True

        num_blocks = (size + BLK_SIZE - 1) // BLK_SIZE
        pointers_size = num_blocks * 4

        self.f.seek(start_offset)
        pointers_raw = self.f.read(pointers_size)

        if len(pointers_raw) < pointers_size:
            return False

        block_pointers = struct.unpack(f"<{num_blocks}I", pointers_raw)

        current_block_start = start_offset + pointers_size
        written = 0

        with open(target_path, "wb") as wf:
            for i, ptr in enumerate(block_pointers):
                actual_ptr = ptr & 0x3FFFFFFF

                if actual_ptr == 0:
                    chunk = b"\x00" * min(BLK_SIZE, size - written)
                    wf.write(chunk)
                    written += len(chunk)
                    continue

                if actual_ptr <= current_block_start:
                    return False

                chunk_size = actual_ptr - current_block_start

                if chunk_size <= 0 or chunk_size > BLK_SIZE * 2:
                    return False

                self.f.seek(current_block_start)
                compressed = self.f.read(chunk_size)

                try:
                    data = zlib.decompress(compressed)
                except zlib.error:
                    return False

                if len(data) > BLK_SIZE:
                    return False

                remaining = size - written
                data = data[:remaining]

                wf.write(data)
                written += len(data)

                current_block_start = actual_ptr

        return written == size

    def extract_panasonic_raw_blocks(self, start_offset, size, target_path):
        if size == 0:
            open(target_path, "wb").close()
            return True

        num_blocks = (size - 1) // BLK_SIZE + 1

        self.f.seek(start_offset)
        table_raw = self.f.read(num_blocks * 4)

        if len(table_raw) < num_blocks * 4:
            return False

        block_offsets = struct.unpack(f"<{num_blocks}I", table_raw)

        with open(target_path, "wb") as wf:
            remaining = size

            for ofs in block_offsets:
                if remaining <= 0:
                    break

                if ofs == 0:
                    to_write = min(BLK_SIZE, remaining)
                    wf.write(b"\x00" * to_write)
                    remaining -= to_write
                    continue

                self.f.seek(ofs)

                to_read = min(BLK_SIZE, remaining)
                block = self.f.read(to_read)

                if len(block) == 0:
                    return False

                wf.write(block)
                remaining -= len(block)

        return remaining == 0

    def extract_panasonic(self, start_offset, size, target_path):
        tmp_path = target_path + ".tmp"

        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

            ok = self.extract_standard_cramfs_strict(start_offset, size, tmp_path)

            if ok and os.path.exists(tmp_path) and os.path.getsize(tmp_path) == size:
                os.replace(tmp_path, target_path)
                print("      [->] Standard zlib cramfs block extraction OK")
                return True

        except Exception:
            pass

        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

        try:
            ok = self.extract_panasonic_raw_blocks(start_offset, size, target_path)

            if ok and os.path.exists(target_path) and os.path.getsize(target_path) == size:
                print("      [->] Panasonic raw block table extraction OK")
                return True

        except Exception:
            pass

        try:
            print("      [->] Final RAW fallback")
            self.f.seek(start_offset)
            with open(target_path, "wb") as wf:
                wf.write(self.f.read(size))
            return True

        except Exception:
            return False

    def traverse(self, inode_index, prefix):
        ii = self.inodes.get(inode_index)

        if not ii:
            return

        inode = ii["inode"]
        name = ii["name"]

        full_path = os.path.join(prefix, name.lstrip("/"))
        file_type = inode["mode"] & 0o170000

        if file_type == 0o40000:
            os.makedirs(full_path, exist_ok=True)

            start = inode["offset"] * 4
            end = start + inode["size"]

            curr = start

            while curr < end:
                child = self.inodes.get(curr)

                if not child:
                    break

                self.traverse(curr, full_path)
                curr += 12 + child["inode"]["namelen"] * 4

        elif file_type == 0o100000:
            data_ofs = inode["offset"] * 4

            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            print(f"[FILE/{self.flavor.upper()}] Extracting: {full_path} ({inode['size']} bytes)")

            current_pos = self.f.tell()

            try:
                if inode["offset"] == 0 or inode["size"] == 0:
                    open(full_path, "wb").close()
                elif self.flavor == "nec":
                    self.extract_nec(data_ofs, inode["size"], full_path)
                elif self.flavor == "panasonic":
                    self.extract_panasonic(data_ofs, inode["size"], full_path)
                else:
                    raise ValueError(f"Unknown flavor: {self.flavor}")

            except Exception as e:
                print(f"  [-] Error extracting file: {e}")

            finally:
                self.f.seek(current_pos)

        elif file_type == 0o120000:
            print(f"[LINK] Skipping symbolic link: {full_path}")

        else:
            print(f"[?] Unknown inode type: {full_path}, mode=0o{inode['mode']:o}")

    def __del__(self):
        if hasattr(self, "f") and not self.f.closed:
            self.f.close()


def main():
    parser = argparse.ArgumentParser(
        description="Cramfs Extractor "
    )

    parser.add_argument("image", help="CRAMFS Image")
    parser.add_argument("output", help="Output Directory")

    parser.add_argument(
        "--flavor",
        choices=["nec", "panasonic"],
        default="nec",
        help="NEC and Panasonic Falvors",
    )

    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    extractor = CramFSExtractor(
        args.image,
        args.output,
        flavor=args.flavor,
    )

    extractor.parse()


if __name__ == "__main__":
    main()