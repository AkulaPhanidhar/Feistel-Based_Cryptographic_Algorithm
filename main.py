## Feistel-Based Cryptographic Algorithm implementation in Python
# --------------------------------------------------------------
# Author: Phanidhar Akula

import secrets
import random

# ----------------- Bit Manipulation Functions ----------------- #
def rotate_left_16(x, n):
    """
    Rotate left a 16-bit value x by n bits.
    """
    n = n % 16
    return ((x << n) & 0xFFFF) | (x >> (16 - n))

# ----------------- LFSR Key Scheduling ----------------- #
def lfsr_step(state):
    """
    Advance a 32-bit LFSR one step using taps at positions 0, 1, 21, and 31.
    Returns the new state and an output word (here, the entire state).
    """
    b0 = (state >> 0) & 1
    b1 = (state >> 1) & 1
    b21 = (state >> 21) & 1
    b31 = (state >> 31) & 1
    new_bit = b0 ^ b1 ^ b21 ^ b31

    state = (state >> 1) & 0x7FFFFFFF
    if new_bit == 1:
        state |= (1 << 31)
    return state, state

# ------------------ Key-Dependent S-Box Generation -------------------- #
def generate_s_box(key):
    """
    Generate a random S-box mapping (a permutation of 0-15)
    using the provided key as the seed.
    Returns the S-box and its inverse as two lists.
    """
    rng = random.Random(key)
    box = list(range(16))
    rng.shuffle(box)
    inv_box = [0] * 16
    for i, val in enumerate(box):
        inv_box[val] = i
    return box, inv_box

# Global S-box variables (to be generated later based on the key)
s_box_nibble = None
inverse_s_box_nibble = None

def s_box(x):
    """
    Apply S-box substitution on a 16-bit value x.
    Process x four bits at a time using the generated s_box_nibble.
    """
    result = 0
    for i in range(4):
        nibble = (x >> (i * 4)) & 0xF
        sub = s_box_nibble[nibble]
        result |= (sub << (i * 4))
    return result

def inverse_s_box(x):
    """
    Apply the inverse S-box substitution on a 16-bit value.
    """
    result = 0
    for i in range(4):
        nibble = (x >> (i * 4)) & 0xF
        sub = inverse_s_box_nibble[nibble]
        result |= (sub << (i * 4))
    return result

# ------------------ P-Box and its Inverse -------------------- #
def p_box(x):
    """
    Permutation (P-box) on a 16-bit value.
    Each bit at position i moves to position (i * 3) mod 16.
    """
    result = 0
    for i in range(16):
        bit = (x >> i) & 1
        new_pos = (i * 3) % 16
        result |= (bit << new_pos)
    return result

def inverse_p_box(x):
    """
    Inverse permutation for the P-box.
    Mapping is derived from P(i) = (i * 3) mod 16.
    """
    mapping = {
        0: 0,  1: 11, 2: 6,  3: 1,
        4: 12, 5: 7,  6: 2,  7: 13,
        8: 8,  9: 3, 10: 14, 11: 9,
        12: 4, 13: 15, 14: 10, 15: 5
    }
    result = 0
    for i in range(16):
        bit = (x >> i) & 1
        original_pos = mapping[i]
        result |= (bit << original_pos)
    return result

# ----------------- Feistel Round Functions ----------------- #
def round_function(x, subkey):
    """
    Compute the round function F(x, subkey) = P-box(S-box(x)) XOR subkey.
    """
    return p_box(s_box(x)) ^ (subkey & 0xFFFF)

def encrypt_block(block, lfsr_state, rounds=4, print_subkeys=True):
    """
    Encrypt a single 32-bit block using a Feistel network.
    The block is split into two 16-bit halves.
    For each round:
      - Generate a 16-bit subkey from the LFSR.
      - Compute F = round_function(R, subkey) using the right half.
      - Set new_L = R and new_R = L XOR F.
    Returns the encrypted block and the updated LFSR state.
    """
    L = (block >> 16) & 0xFFFF
    R = block & 0xFFFF

    current_state = lfsr_state
    subkeys = []
    for _ in range(rounds):
        current_state, out_word = lfsr_step(current_state)
        subkeys.append(out_word & 0xFFFF)

    if print_subkeys:
        print("\n-------Encryption-------")
        for i, sk in enumerate(subkeys, start=1):
            print(f"Round {i} subkey: {sk:04X}")

    for i in range(rounds):
        F = round_function(R, subkeys[i])
        new_L = R
        new_R = L ^ F
        L, R = new_L, new_R

    encrypted_block = ((L & 0xFFFF) << 16) | (R & 0xFFFF)
    return encrypted_block, current_state

def decrypt_block(block, lfsr_state, rounds=4, print_subkeys=True):
    """
    Decrypt a single 32-bit block using the inverse Feistel network.
    Regenerate the same subkeys via the LFSR and, for each round in reverse order:
      - Compute F = round_function(L, subkey) using the left half.
      - Set new_R = L and new_L = R XOR F.
    Returns the decrypted block and the updated LFSR state.
    """
    L = (block >> 16) & 0xFFFF
    R = block & 0xFFFF

    current_state = lfsr_state
    subkeys = []
    for _ in range(rounds):
        current_state, out_word = lfsr_step(current_state)
        subkeys.append(out_word & 0xFFFF)

    if print_subkeys:
        print("\n-------Decryption-------")
        for i, sk in enumerate(reversed(subkeys), start=1):
            print(f"Round {i} subkey: {sk:04X}")

    for subkey in reversed(subkeys):
        F = round_function(L, subkey)
        new_R = L
        new_L = R ^ F
        L, R = new_L, new_R

    decrypted_block = ((L & 0xFFFF) << 16) | (R & 0xFFFF)
    return decrypted_block, current_state

# -------------------- Padding and Conversion ------------------- #
def pad_pkcs7(data, block_size=4):
    """
    Apply PKCS#7-like padding to data.
    """
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data, block_size=4):
    """
    Remove PKCS#7-like padding to data.
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding detected.")
    if any(p != pad_len for p in data[-pad_len:]):
        raise ValueError("Invalid padding detected.")
    return data[:-pad_len]

def bytes_to_blocks(data):
    """
    Convert a bytes object into a list of 32-bit integer blocks (4 bytes each).
    """
    blocks = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        block_val = int.from_bytes(chunk, byteorder='big')
        blocks.append(block_val)
    return blocks

def blocks_to_bytes(blocks):
    """
    Convert a list of 32-bit integer blocks into a bytes object (4 bytes per block).
    """
    output = b""
    for block in blocks:
        output += block.to_bytes(4, byteorder='big')
    return output

def encrypt_message(plaintext: bytes, key_32: int, rounds=4) -> bytes:
    """
    Encrypt an arbitrary-length plaintext.
    1) Pad the plaintext.
    2) Split it into 32-bit blocks.
    3) Encrypt each block sequentially.
    4) Return the ciphertext.
    """
    padded = pad_pkcs7(plaintext, 4)
    blocks = bytes_to_blocks(padded)
    
    lfsr_state = key_32
    encrypted_blocks = []
    for idx, blk in enumerate(blocks):
        # Print subkeys only for the first block
        print_flag = True if idx == 0 else False
        enc_blk, lfsr_state = encrypt_block(blk, lfsr_state, rounds=rounds, print_subkeys=print_flag)
        encrypted_blocks.append(enc_blk)
    
    return blocks_to_bytes(encrypted_blocks)

def decrypt_message(ciphertext: bytes, key_32: int, rounds=4) -> bytes:
    """
    Decrypt an arbitrary-length ciphertext.
    1) Split the ciphertext into 32-bit blocks.
    2) Decrypt each block sequentially.
    3) Remove the padding.
    """
    blocks = bytes_to_blocks(ciphertext)
    
    lfsr_state = key_32
    decrypted_blocks = []
    for idx, blk in enumerate(blocks):
        print_flag = True if idx == 0 else False
        dec_blk, lfsr_state = decrypt_block(blk, lfsr_state, rounds=rounds, print_subkeys=print_flag)
        decrypted_blocks.append(dec_blk)
    
    padded_plaintext = blocks_to_bytes(decrypted_blocks)
    return unpad_pkcs7(padded_plaintext, 4)

# ------------------ Print S-box Table ------------------ #
def print_s_box_table():
    """
    Print the S-box values in a nicely formatted table.
    """
    header = "+-------+-------+"
    print("\nRandomly Generated S-box Table based on Generated 32-bit master Key:")
    print(header)
    print("| Index | Value |")
    print(header)
    for i, val in enumerate(s_box_nibble):
        # Print hex value without '0x' and uppercase.
        print(f"| {i:^5} |{val:^7X}|")
    print(header)

# --------------------------- Main Routine --------------------------- #
if __name__ == "__main__":
    # Define the original message.
    original_message = "Dude, We are having a party tonight at 8pm. Don't be late and bring your friends."
    # Define the number of rounds.
    rounds = 4

    print(f"\nOriginal Message: {original_message}")
    print(f"\nNumber of Rounds: {rounds}")

    # Generate a random 32-bit key.
    key_32 = secrets.randbits(32)
    # Format key as hex without "0x", lower-case.
    key_str = hex(key_32)[2:]
    print(f"\nGenerated 32-bit Key: {key_str}")

    # Generate S-box values based on the key.
    s_box_nibble, inverse_s_box_nibble = generate_s_box(key_32)
    
    # Print the S-box table.
    print_s_box_table()
    
    # Convert the original message to bytes.
    original_bytes = original_message.encode('utf-8')
    
    # Encrypt the message.
    ciphertext = encrypt_message(original_bytes, key_32, rounds=rounds)
    print(f"\nCiphertext: {ciphertext.hex()}")
    
    # Decrypt the message.
    decrypted_bytes = decrypt_message(ciphertext, key_32, rounds=rounds)
    decrypted_message = decrypted_bytes.decode('utf-8')
    print(f"\nDecrypted Message: {decrypted_message}")
    
    if original_message == decrypted_message:
        print("\nSuccess: Original messages and Decrypted messages matchs!\n")
    else:
        print("\nError: Original messages and Decrypted messages do not match!\n")
