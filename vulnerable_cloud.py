"""Dummy cloud API token service: ECDSA (P-256) signed tokens + SHA-1 checksums (quantum-vulnerable)."""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def make_signing_key():
    return ec.generate_private_key(ec.SECP256R1())


def issue_token(key, user: str, scope: str) -> dict:
    payload = json.dumps({"user": user, "scope": scope}).encode()
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return {"payload": payload, "signature": signature}


def validate_token(public_key, token: dict) -> bool:
    try:
        public_key.verify(token["signature"], token["payload"], ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def blob_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


if __name__ == "__main__":
    k = make_signing_key()
    t = issue_token(k, "alice", "storage:read")
    assert validate_token(k.public_key(), t)
    t["payload"] = t["payload"].replace(b"alice", b"mallory")
    assert not validate_token(k.public_key(), t)
    print("checksum:", blob_checksum(b"cloud-object"))
    print("Cloud demo OK: token issue/validate")
