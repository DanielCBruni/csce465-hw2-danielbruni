import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_ctr(key, nonce, plaintext):
    """Encrypts plaintext using AES-CTR."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ctr(key, nonce, ciphertext):
    """Decrypts ciphertext using AES-CTR."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    # Setup key and nonce
    key = os.urandom(32)   # 256-bit key
    nonce = os.urandom(16) # 128-bit nonce/counter block
   
    # Target message
    original_msg = b'{"action":"READ","path":"notes.txt"}'
    print(f"[*] Original Plaintext: {original_msg.decode()}")
   
    # 1. Encrypt
    ciphertext = encrypt_ctr(key, nonce, original_msg)
    print(f"[*] Ciphertext (hex): {ciphertext.hex()}")
   
    # 2. Relay / Malleability Attack (Change "READ" to "EXEC")
    # Find index of "READ" in the plaintext to locate it in the ciphertext stream
    read_index = original_msg.find(b'READ')
    target_word = b'EXEC' # Must be the exact same length (4 bytes)
   
    # Convert ciphertext to mutable bytearray
    ct_list = bytearray(ciphertext)
   
    # Demonstrate XOR relation and modify bytes in-place
    print("\n--- Demonstrating Ciphertext Malleability (Bit-Flipping) ---")
    for i in range(len(target_word)):
        original_byte = original_msg[read_index + i]
        new_byte = target_word[i]
        xor_mask = original_byte ^ new_byte
       
        # Apply XOR mask to the ciphertext byte
        ct_list[read_index + i] ^= xor_mask
        print(f"Modified byte at index {read_index + i}: '{chr(original_byte)}' -> '{chr(new_byte)}' using XOR mask 0x{xor_mask:02x}")
       
    modified_ciphertext = bytes(ct_list)
   
    # Decrypt modified ciphertext
    forged_msg = decrypt_ctr(key, nonce, modified_ciphertext)
    print(f"[*] Receiver Processed Modified Message: {forged_msg.decode()}")
   
    # 3. Replay Protection Demonstration
    print("\n--- Demonstrating Replay Attack ---")
    print("Sending original valid ciphertext block 1st time...")
    processed_1 = decrypt_ctr(key, nonce, ciphertext)
    print(f"  -> Receiver successfully processed: {processed_1.decode()}")
   
    print("Sending exact same original valid ciphertext block 2nd time (Replay)...")
    processed_2 = decrypt_ctr(key, nonce, ciphertext)
    print(f"  -> Receiver successfully processed again: {processed_2.decode()}")
    print("[!] Warning: Receiver processed the exact same command twice because there is no counter or timestamp.")

if __name__ == "__main__":
    main()
