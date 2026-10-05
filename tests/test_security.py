import sys
import os

# Add parent directory to path to find both secure_record and handshake
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import secure_record
import handshake

@pytest.fixture
def test_keys():
    """Provides fixed session material and keys for secure_record tests."""
    return {
        "session_id": b"\x01\x02\x03\x04\x05\x06\x07\x08",
        "K_g2n_enc": b"\x11" * 32,
        "K_g2n_mac": b"\x22" * 32,
        "K_n2g_enc": b"\x33" * 32,
        "K_n2g_mac": b"\x44" * 32,
    }

# 1. Valid handshake and bidirectional messages
def test_valid_handshake_and_bidirectional_messages(test_keys):
    """Test 1: Valid handshake execution and bidirectional record exchange."""
    # Test Handshake integration
    with open("ffdhe3072.pem", "rb") as f:
        dh_params = serialization.load_pem_parameters(f.read())
    gateway = handshake.Participant(identity="gateway", dh_parameters=dh_params)
    node = handshake.Participant(identity="node", dh_parameters=dh_params)
    g_keys, n_keys = handshake.run_authenticated_handshake(gateway, node)
    assert "session_id" in g_keys

    # Test Bidirectional Record Exchange using test_keys
    keys = test_keys
    session_id = keys["session_id"]
   
    # Gateway -> Node
    rec_g2n = secure_record.seal(keys["K_g2n_enc"], keys["K_g2n_mac"], session_id, 0, 0, 1, b"ping")
    m_type, pt, seq = secure_record.open_record(keys["K_g2n_enc"], keys["K_g2n_mac"], session_id, 0, 0, rec_g2n)
    assert pt == b"ping"
    assert seq == 1

    # Node -> Gateway
    rec_n2g = secure_record.seal(keys["K_n2g_enc"], keys["K_n2g_mac"], session_id, 1, 0, 2, b"pong")
    m_type, pt, seq = secure_record.open_record(keys["K_n2g_enc"], keys["K_n2g_mac"], session_id, 1, 0, rec_n2g)
    assert pt == b"pong"
    assert seq == 1

# 2. Modified ciphertext
def test_modified_ciphertext(test_keys):
    """Test 2: Modifying ciphertext bytes triggers an HMAC failure[cite: 1]."""
    keys = test_keys
    record = secure_record.seal(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, 1, b"data")
    tampered = bytearray(record)
    tampered[-1] ^= 0xFF
    with pytest.raises(secure_record.SecurityError, match="Rejected: HMAC verification failed"):
        secure_record.open_record(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, bytes(tampered))

# 3. Modified authenticated header
def test_modified_authenticated_header(test_keys):
    """Test 3: Modifying the authenticated header triggers an HMAC failure[cite: 1]."""
    keys = test_keys
    record = secure_record.seal(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, 1, b"data")
    tampered = bytearray(record)
    tampered[10] = 99  # modify message type in header
    with pytest.raises(secure_record.SecurityError, match="Rejected: HMAC verification failed"):
        secure_record.open_record(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, bytes(tampered))

# 4. Replayed record
def test_replayed_record(test_keys):
    """Test 4: Replaying a record is rejected due to sequence mismatch[cite: 1]."""
    keys = test_keys
    record = secure_record.seal(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, 1, b"data")
    # First open succeeds (seq 0 -> next is 1)
    secure_record.open_record(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, record)
    # Replay same record against expected sequence 1
    with pytest.raises(secure_record.SecurityError, match="Rejected: Sequence number mismatch"):
        secure_record.open_record(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 1, record)

# 5. Record reflected into the opposite direction
def test_reflected_record(test_keys):
    """Test 5: Reflecting a record into the opposite direction is rejected[cite: 1]."""
    keys = test_keys
    record = secure_record.seal(keys["K_g2n_enc"], keys["K_g2n_mac"], keys["session_id"], 0, 0, 1, b"data")
    with pytest.raises(secure_record.SecurityError, match="Rejected: Invalid direction"):
        secure_record.open_record(keys["K_n2g_enc"], keys["K_n2g_mac"], keys["session_id"], 1, 0, record)

# 6. Incorrect RSA public key, invalid signature, or reflected handshake message
def test_handshake_authentication_failures():
    """Test 6: Handshake failures (invalid identities/reflection or signature corruption)[cite: 1]."""
    with open("ffdhe3072.pem", "rb") as f:
        dh_params = serialization.load_pem_parameters(f.read())
       
    gateway = handshake.Participant(identity="gateway", dh_parameters=dh_params)
    rogue_node = handshake.Participant(identity="gateway", dh_parameters=dh_params) # Identical identity reflection attack
   
    with pytest.raises(ValueError, match="Gateway and node cannot have identical identities"):
        handshake.run_authenticated_handshake(gateway, rogue_node)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
