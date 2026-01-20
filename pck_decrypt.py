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

    # Head
    if misalignment > 0:
        first_key = generate_key(base_counter)
        key_bytes = first_key.to_bytes(4, "little")
        bytes_to_process = min(4 - misalignment, size)
        for i in range(bytes_to_process):
            p_data[idx] ^= key_bytes[misalignment + i]
            idx += 1
        base_counter += 1

    # Body
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

    # Tail
    if idx < size:
        last_key = generate_key(base_counter + num_blocks)
        key_bytes = last_key.to_bytes(4, "little")
        remaining = size - idx
        for i in range(remaining):
            p_data[idx + i] ^= key_bytes[i]

def rebuild_pck(input_path):
    if not os.path.exists(input_path):
        print("File not found.")
        return

    output_path = input_path + ".rebuilt.pck"
    print(f"Processing: {input_path}")

    # --- Step 1: Analyze and Decrypt Header in Memory ---
    with open(input_path, "rb") as f:
        # Read the first 8 bytes: Magic + HeaderSize
        header_prefix = f.read(8)
        h_magic, h_dsize = struct.unpack("<II", header_prefix)

        print(f"Magic: {hex(h_magic)}, Header Size: {h_dsize}")

        # In Endfield, the header data starts immediately after the first 8 bytes.
        # However, the decryption logic skips the first 4 bytes of that data block.
        # We assume those skipped 4 bytes are the 'Garbage Version' that we need to replace.
        
        f.seek(8)
        raw_header_data = f.read(h_dsize)
        
        if len(raw_header_data) != h_dsize:
            print("Error: Could not read full header.")
            return

        # Prepare buffer for decryption (skipping the first 4 garbage bytes)
        # We copy it to a bytearray to modify it
        decrypted_payload = bytearray(raw_header_data[4:])
        
        # Decrypt using HeaderSize as the seed (Standard Endfield logic)
        decipher_inplace(decrypted_payload, h_dsize, h_dsize - 4, 0)
        
        # Parse the file list from this decrypted payload
        # This uses the logic from pck_final.py which successfully found 2361 files
        first_flag_idx = None
        
        # Search for the "Bank Table" flag (0x01)
        for i in range(0x20, len(decrypted_payload) - 4, 4):
            if decrypted_payload[i : i + 4] == b"\x01\x00\x00\x00":
                first_flag_idx = i
                break
        
        if first_flag_idx is None:
            print("Error: Could not find file table in decrypted header.")
            return

        # The file count is 4 bytes before the flag (skip the size int)
        # Structure: [Count] [Size?] [Flag]
        # Actually usually: [Count] [Flag] ... wait, pck.py says `first_flag - 8`
        count_offset = first_flag_idx - 8
        total_count = struct.unpack("<I", decrypted_payload[count_offset : count_offset + 4])[0]
        
        print(f"Successfully parsed index: {total_count} files found.")

        # Parse the block info
        blocks = []
        blocks_start = first_flag_idx - 4
        
        for i in range(total_count):
            curr = blocks_start + i * 20
            # Block: ID(4), Flag(4), Size(4), Offset(4), Reserved(4)
            block_data = decrypted_payload[curr : curr + 20]
            if len(block_data) < 20: break
            block = struct.unpack("<5I", block_data)
            blocks.append(block)

    # --- Step 2: Build the New File ---
    print(f"Creating {output_path}...")
    
    # We will construct a completely valid Wwise header
    # Magic (AKPK) + HeaderSize + Version (140) + DecryptedPayload
    
    # 0x4B504B41 = AKPK
    new_magic = b'\x41\x4B\x50\x4B' 
    # 0x8C = Version 140
    new_version = b'\x8C\x00\x00\x00' 
    
    # The size remains h_dsize because we are replacing 4 bytes of garbage with 4 bytes of version
    new_header_size = h_dsize.to_bytes(4, "little")
    
    full_new_header = new_magic + new_header_size + new_version + decrypted_payload
    
    # Copy the original file first to get all the audio data content
    shutil.copy2(input_path, output_path)
    
    with open(output_path, "r+b") as f:
        # Overwrite the header with our clean, valid Wwise header
        f.seek(0)
        f.write(full_new_header)
        
        # Now decrypt the bodies
        print("Decrypting audio streams...")
        
        processed = 0
        for block in blocks:
            wem_id, flag, size, offset, _ = block
            
            # Flag 1 = Encrypted
            if flag == 1:
                # Sanity check offset
                f.seek(0, 2)
                file_end = f.tell()
                if offset + size > file_end:
                    print(f"\nWarning: File {wem_id} is truncated. Skipping.")
                    continue
                
                f.seek(offset)
                audio_data = bytearray(f.read(size))
                
                # Decrypt using File ID as Seed
                decipher_inplace(audio_data, wem_id, size, 0)
                
                # Write back
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