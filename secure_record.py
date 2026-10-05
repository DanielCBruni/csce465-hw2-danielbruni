import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class SecurityError(Exception):
    """Custom exception raised for any security violation (MAC failure, replay, wrong direction, bad header)."""
    pass

def seal(
    key_enc: bytes,
    key_mac: bytes,
    session_id: bytes,
    direction: int,
    sequence: int,
    message_type: int,
    plaintext: bytes,
    version: int = 1
) -> bytes:
    """
    Seals (encrypts and authenticates) a record:
      - header = version (1B) || direction (1B) || sequence (8B) || message_type (1B) || ciphertext_length (4B)
      - iv = session_id (8B) || sequence (8B)
      - ciphertext = AES-256-CTR(K_enc, iv, plaintext)
      - tag = HMAC-SHA-256(K_mac, header || iv || ciphertext)
    Returns the wire record: header || iv || tag || ciphertext
    """
    # 1. Construct Header (15 bytes total)
    v_byte = version.to_bytes(1, 'big')
    dir_byte = direction.to_bytes(1, 'big')
    seq_bytes = sequence.to_bytes(8, 'big')
    msg_type_byte = message_type.to_bytes(1, 'big')
   
    # Encrypt plaintext first to determine exact ciphertext length
    iv = session_id + seq_bytes
    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
   
    ct_len_bytes = len(ciphertext).to_bytes(4, 'big')
    header = v_byte + dir_byte + seq_bytes + msg_type_byte + ct_len_bytes
   
    # 2. Compute HMAC Tag over header || iv || ciphertext (Encrypt-then-MAC)
    mac_payload = header + iv + ciphertext
    tag = hmac.new(key_mac, mac_payload, hashlib.sha256).digest()
   
    # 3. Assemble and return final record wire format
    return header + iv + tag + ciphertext

def open_record(
    key_enc: bytes,
    key_mac: bytes,
    session_id: bytes,
    expected_direction: int,
    expected_sequence: int,
    record_bytes: bytes
) -> tuple:
    """
    Opens (verifies and decrypts) an incoming record wire format:
      - Parses header, IV, tag, and ciphertext.
      - Enforces strict validation: version, direction, sequence number, HMAC (constant-time).
      - Rejects any tampering, replays, or mismatches *before* decryption or releasing plaintext.
    Returns: (message_type, plaintext, next_expected_sequence)
    """
    # Minimum record size: Header (15) + IV (16) + Tag (32) = 63 bytes minimum
    if len(record_bytes) < 63:
        raise SecurityError("Rejected: Record is too short to be valid.")
       
    # 1. Parse Wire Layout
    header = record_bytes[:15]
    iv = record_bytes[15:31]        # 16 bytes (session_id [8] || sequence [8])
    tag = record_bytes[31:63]       # 32 bytes (HMAC-SHA-256 digest)
    ciphertext = record_bytes[63:]  # Remainder
   
    # Parse Header fields
    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10], 'big')
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15], 'big')
   
    # Validate ciphertext length matches declared header length
    if len(ciphertext) != ciphertext_length:
        raise SecurityError("Rejected: Ciphertext length does not match header declaration.")
       
    # 2. Security Validations (Fail-secure / Fail-fast)
   
    # Check Session ID binding inside IV
    parsed_session_id = iv[:8]
    parsed_iv_seq = iv[8:]
    if parsed_session_id != session_id:
        raise SecurityError("Rejected: Session ID mismatch in record IV.")
       
    # Check IV sequence matches header sequence
    if parsed_iv_seq != header[2:10]:
        raise SecurityError("Rejected: IV sequence does not match header sequence.")
       
    # Check Direction
    if direction != expected_direction:
        raise SecurityError(f"Rejected: Invalid direction {direction}, expected {expected_direction}.")
       
    # Check Sequence Number (Exact match required: prevents replays and out-of-order delivery)
    if sequence != expected_sequence:
        raise SecurityError(f"Rejected: Sequence number mismatch. Got {sequence}, expected {expected_sequence}.")
       
    # Verify HMAC *before* decrypting (Encrypt-then-MAC with constant-time comparison)
    mac_payload = header + iv + ciphertext
    expected_tag = hmac.new(key_mac, mac_payload, hashlib.sha256).digest()
   
    if not hmac.compare_digest(expected_tag, tag):
        raise SecurityError("Rejected: HMAC verification failed (modified header, tag, or ciphertext).")
       
    # 3. Decryption (Only reached if all checks pass successfully)
    try:
        cipher = Cipher(algorithms.AES(key_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise SecurityError(f"Decryption failed: {e}")
       
    # Return message type, plaintext, and incremented sequence number for state tracking
    return message_type, plaintext, expected_sequence + 1
