import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def int_to_384_bytes(val) -> bytes:
    """Ensures a value (int or bytes) is encoded as a 384-byte big-endian string, left zero-padded."""
    if isinstance(val, int):
        return val.to_bytes(384, 'big')
    elif isinstance(val, bytes):
        return val.rjust(384, b'\x00')
    raise TypeError("Value must be int or bytes")

class Participant:
    def __init__(self, identity: str, dh_parameters: dh.DHParameters):
        self.identity = identity.encode('utf-8')
        self.dh_parameters = dh_parameters
       
        # Generate long-term 3072-bit RSA signing keypair (RSA-PSS)
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
       
        # Session state variables (reset per handshake)
        self.ephemeral_dh_private = None
        self.ephemeral_dh_public = None
        self.nonce = None
       
    def generate_ephemeral_material(self):
        """Generates fresh ephemeral DH private/public values and a fresh 16-byte nonce."""
        self.ephemeral_dh_private = self.dh_parameters.generate_private_key()
        self.ephemeral_dh_public = self.ephemeral_dh_private.public_key()
        self.nonce = os.urandom(16)

def build_canonical_transcript(
    protocol_label: bytes,
    group_id: bytes,
    id_gateway: bytes,
    id_node: bytes,
    dh_pub_g_bytes: bytes,
    dh_pub_n_bytes: bytes,
    nonce_g: bytes,
    nonce_n: bytes
) -> bytes:
    """
    Constructs a length-prefixed (TLV) canonical transcript.
    Each field is preceded by its length as a 4-byte big-endian integer.
    """
    fields = [
        protocol_label,
        group_id,
        id_gateway,
        id_node,
        dh_pub_g_bytes,
        dh_pub_n_bytes,
        nonce_g,
        nonce_n
    ]
   
    transcript = bytearray()
    for field in fields:
        length_prefix = len(field).to_bytes(4, 'big')
        transcript.extend(length_prefix)
        transcript.extend(field)
       
    return bytes(transcript)

def derive_session_keys(z_bytes: bytes, th: bytes) -> dict:
    """
    Derives master key, encryption/MAC keys for both directions, and session ID
    using the assignment-specific KDF.
    """
    k_master_input = b"CSCE465-KDF-v1" + z_bytes + th
    k_master = hashlib.sha256(k_master_input).digest()
   
    def hmac_sha256(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashlib.sha256).digest()
   
    keys = {
        "K_master": k_master,
        "K_g2n_enc": hmac_sha256(k_master, b"gateway-to-node encryption" + th),
        "K_g2n_mac": hmac_sha256(k_master, b"gateway-to-node MAC" + th),
        "K_n2g_enc": hmac_sha256(k_master, b"node-to-gateway encryption" + th),
        "K_n2g_mac": hmac_sha256(k_master, b"node-to-gateway MAC" + th),
        "session_id": hmac_sha256(k_master, b"session identifier" + th)[:8]
    }
    return keys

def run_authenticated_handshake(gateway: Participant, node: Participant):
    print("[*] Starting Authenticated Diffie-Hellman Handshake (Task 2)...")
   
    gateway.generate_ephemeral_material()
    node.generate_ephemeral_material()
   
    dh_pub_g_bytes = int_to_384_bytes(gateway.ephemeral_dh_public.public_numbers().y)
    dh_pub_n_bytes = int_to_384_bytes(node.ephemeral_dh_public.public_numbers().y)
   
    protocol_label = b"CSCE465-HS-v2"
    group_id = b"ffdhe3072"
   
    if gateway.identity == node.identity:
        raise ValueError("Security Error: Gateway and node cannot have identical identities.")

    transcript = build_canonical_transcript(
        protocol_label=protocol_label,
        group_id=group_id,
        id_gateway=gateway.identity,
        id_node=node.identity,
        dh_pub_g_bytes=dh_pub_g_bytes,
        dh_pub_n_bytes=dh_pub_n_bytes,
        nonce_g=gateway.nonce,
        nonce_n=node.nonce
    )
    th = hashlib.sha256(transcript).digest()
   
    node_role = b"node"
    node_signature = node.rsa_private_key.sign(
        node_role + th,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
   
    gateway_role = b"gateway"
    gateway_signature = gateway.rsa_private_key.sign(
        gateway_role + th,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
   
    try:
        node.rsa_public_key.verify(
            node_signature,
            node_role + th,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("Handshake Rejected: Node signature verification failed!")
       
    try:
        gateway.rsa_public_key.verify(
            gateway_signature,
            gateway_role + th,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("Handshake Rejected: Gateway signature verification failed!")

    z_gateway_int = gateway.ephemeral_dh_private.exchange(node.ephemeral_dh_public)
    z_node_int = node.ephemeral_dh_private.exchange(gateway.ephemeral_dh_public)
   
    if z_gateway_int != z_node_int:
        raise ValueError("Handshake Rejected: DH shared secrets do not match!")
       
    z_bytes = int_to_384_bytes(z_gateway_int)
   
    gateway_keys = derive_session_keys(z_bytes, th)
    node_keys = derive_session_keys(z_bytes, th)
   
    print("[+] Handshake successfully completed and verified by both parties!")
    print(f"    - Session ID: {gateway_keys['session_id'].hex()}")
    print(f"    - Master Key: {gateway_keys['K_master'].hex()[:32]}...")
   
    return gateway_keys, node_keys

if __name__ == "__main__":
    print("[*] Loading ffdhe3072 group parameters from ffdhe3072.pem...")
    try:
        with open("ffdhe3072.pem", "rb") as f:
            dh_params = serialization.load_pem_parameters(f.read())
    except FileNotFoundError:
        print("[!] Error: 'ffdhe3072.pem' not found in the current directory.")
        exit(1)
   
    gateway = Participant(identity="gateway", dh_parameters=dh_params)
    node = Participant(identity="node", dh_parameters=dh_params)
   
    run_authenticated_handshake(gateway, node)
