import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) as WireGuard-compatible base64 strings."""
    priv = X25519PrivateKey.generate()
    private_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
    public_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return private_b64, public_b64


def public_key_from_private(private_b64: str) -> str:
    raw = base64.b64decode(private_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode()
