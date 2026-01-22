import struct
import shutil
import os
import sys

# --- Decryption Logic (From pck.py) ---
def decipher_inplace(p_data: bytearray, seed: int, size: int, offset_to_file_start: int) -> None:
    CONST_M = 0x04E11C23
    CONST_X = 0x9C5A0B29

    def generate_key(counter: int) -> int:
        val = ((counter & 0xFF) ^ CONST_X) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 8) & 0xFF)) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 16) & 0xFF)) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 24) & 0xFF)) * CONST_M & 0xFFFFFFFF
        return val

    if size == 0:
        return

    idx = 0
    base_counter = seed + (offset_to_file_start >> 2)
    misalignment = offset_to_file_start & 3

    # Head (misaligned first bytes)
    if misalignment > 0:
        first_key = generate_key(base_counter)
        key_bytes = first_key.to_bytes(4, "little")
        bytes_to_process = min(4 - misalignment, size)
        for i in range(bytes_to_process):
            p_data[idx] ^= key_bytes[misalignment + i]
            idx += 1
        base_counter += 1

    # Body (aligned 4-byte blocks)
    aligned_size = (size - idx) & ~3
    num_blocks = aligned_size // 4

    for i in range(num_blocks):
        current_key = generate_key(base_counter + i)
        k_bytes = current_key.to_bytes(4, "little")
        base_idx = idx + i * 4
        p_data[base_idx] ^= k_bytes[0]
        p_data[base_idx+1] ^= k_bytes[1]
        p_data[base_idx+2] ^= k_bytes[2]
        p_data[base_idx+3] ^= k_bytes[3]

    idx += aligned_size

    # Tail (remaining bytes)
    if idx < size:
        last_key = generate_key(base_counter + num_blocks)
        key_bytes = last_key.to_bytes(4, "little")
        remaining = size - idx
        for i in range(remaining):
            p_data[idx + i] ^= key_bytes[i]

# --- Rebuild & Decrypt PCK ---
def rebuild_pck(input_path):
    if not os.path.exists(input_path):
        print("File not found.")
        return

    output_path = input_path + ".rebuilt.pck"
    print(f"Processing: {input_path}")

    # --- Step 1: Analyze and Decrypt Header ---
    with open(input_path, "rb") as f:
        header_prefix = f.read(8)
        h_magic, h_dsize = struct.unpack("<II", header_prefix)
        print(f"Magic: {hex(h_magic)}, Header Size: {h_dsize}")

        f.seek(8)
        raw_header_data = f.read(h_dsize)
        if len(raw_header_data) != h_dsize:
            print("Error: Could not read full header.")
            return

        # Prepare buffer for decryption (skip first 4 garbage bytes)
        decrypted_payload = bytearray(raw_header_data[4:])
        decipher_inplace(decrypted_payload, h_dsize, h_dsize - 4, 0)

        # --- Step 1a: Find first file entry (0x00000001 flag) ---
        first_flag_idx = None
        for i in range(0x24, len(decrypted_payload) - 4, 4):
            if decrypted_payload[i:i+4] == b"\x01\x00\x00\x00":
                first_flag_idx = i
                break
        if first_flag_idx is None:
            print("Error: Could not find file table in decrypted header.")
            return

        # File count is 4 bytes before flag
        count_offset = first_flag_idx - 8
        total_count = struct.unpack("<I", decrypted_payload[count_offset:count_offset+4])[0]
        print(f"Successfully parsed index: {total_count} files found.")

        # --- Step 1b: Parse file entries (support 32-bit & 64-bit ID) ---
        blocks = []
        pos = first_flag_idx - 4
        while pos + 20 <= len(decrypted_payload):
            try:
                # Try 32-bit entry first
                entry = struct.unpack("<5I", decrypted_payload[pos:pos+20])
                if entry[1] == 1 and entry[4] in (0, 1):
                    blocks.append(entry)
                    pos += 20
                    continue
                # Try 64-bit entry
                if pos + 24 <= len(decrypted_payload):
                    entry64 = struct.unpack("<6I", decrypted_payload[pos:pos+24])
                    if entry64[2] == 1 and entry64[5] in (0, 1):
                        wem_id = entry64[0] | (entry64[1] << 32)
                        blocks.append((wem_id, entry64[2], entry64[3], entry64[4], entry64[5]))
                        pos += 24
                        continue
                break
            except:
                break

    # --- Step 2: Build new file ---
    shutil.copy2(input_path, output_path)
    with open(output_path, "r+b") as f:
        # Overwrite header
        new_magic = b'\x41\x4B\x50\x4B'  # AKPK
        new_version = b'\x8C\x00\x00\x00'  # Version 140
        new_header_size = h_dsize.to_bytes(4, "little")
        full_new_header = new_magic + new_header_size + new_version + decrypted_payload
        f.seek(0)
        f.write(full_new_header)

        # --- Step 3: Decrypt audio streams ---
        print("Decrypting audio streams...")
        processed = 0
        for block in blocks:
            wem_id, flag, size, offset, _ = block
            if flag != 1:
                processed += 1
                continue

            f.seek(0, 2)
            file_end = f.tell()
            if offset + size > file_end:
                print(f"\nWarning: File {wem_id} is truncated. Skipping.")
                processed += 1
                continue

            f.seek(offset)
            audio_data = bytearray(f.read(size))

            # --- Attempt 32-bit decryption first ---
            try:
                decipher_inplace(audio_data, wem_id & 0xFFFFFFFF, size, 0)
                # Simple check for WEM/RIFF header
                if not audio_data[:4] in [b'RIFF', b'WEM']:
                    raise ValueError("32-bit decryption failed, try 64-bit")
            except:
                # 64-bit decryption
                decipher_inplace(audio_data, wem_id, size, 0)

            f.seek(offset)
            f.write(audio_data)

            processed += 1
            if processed % 200 == 0:
                print(f"Processed {processed}/{total_count}...", end='\r')

    print(f"\n\nSuccess! Valid Wwise PCK created: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Drag and drop a .pck file onto this script.")
    else:
        try:
            rebuild_pck(sys.argv[1])
        except Exception as e:
            print(f"\nAn error occurred: {e}")
        input("Press Enter to exit...")
