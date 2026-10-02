"""Dummy legacy banking module: RSA-2048 transaction encryption + signing (quantum-vulnerable)."""
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_bank_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def encrypt_transaction(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_transaction(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def sign_statement(private_key, statement: bytes) -> bytes:
    return private_key.sign(
        statement,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_statement(public_key, signature: bytes, statement: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            statement,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def account_fingerprint(account_no: str) -> str:
    return hashlib.md5(account_no.encode()).hexdigest()


def new_session_key() -> bytes:
    return os.urandom(16)


if __name__ == "__main__":
    priv, pub = generate_bank_keys()
    tx = b"TRANSFER 2500 USD ACC-1001 -> ACC-2002"
    assert decrypt_transaction(priv, encrypt_transaction(pub, tx)) == tx
    sig = sign_statement(priv, tx)
    assert verify_statement(pub, sig, tx) and not verify_statement(pub, sig, b"tampered")
    print("fingerprint:", account_fingerprint("ACC-1001"))
    print("session key bytes:", len(new_session_key()))
    print("Bank demo OK: encrypt/decrypt + sign/verify")
