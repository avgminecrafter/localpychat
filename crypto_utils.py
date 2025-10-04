import base64
from typing import Tuple

from nacl import pwhash, secret, utils


ALG_IDENTIFIER = "nacl-secretbox-v1"


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derive a SecretBox key from a UTF-8 passphrase using Argon2id.

    Uses libsodium's Argon2id with MODERATE limits for interactive usage.
    """
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("salt must be bytes")
    passphrase_bytes = (passphrase or "").encode("utf-8")
    return pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase_bytes,
        salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )


def encrypt_bytes(plaintext: bytes, passphrase: str) -> Tuple[str, str, str]:
    """Encrypt bytes with a passphrase.

    Returns a tuple of base64 strings: (ciphertext_b64, nonce_b64, salt_b64)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("plaintext must be bytes")
    if not passphrase:
        raise ValueError("passphrase is required for encryption")
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = _derive_key_from_passphrase(passphrase, salt)
    box = secret.SecretBox(key)
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(bytes(plaintext), nonce)
    ciphertext = encrypted.ciphertext
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(salt).decode("ascii"),
    )


def decrypt_bytes(ciphertext_b64: str, nonce_b64: str, salt_b64: str, passphrase: str) -> bytes:
    """Decrypt base64-encoded ciphertext using passphrase, returning plaintext bytes."""
    if not passphrase:
        raise ValueError("passphrase is required for decryption")
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        salt = base64.b64decode(salt_b64)
    except Exception as e:
        raise ValueError("invalid base64 inputs for decryption") from e
    key = _derive_key_from_passphrase(passphrase, salt)
    box = secret.SecretBox(key)
    try:
        return box.decrypt(ciphertext, nonce)
    except Exception as e:
        raise ValueError("decryption failed") from e
