"""Independent generator for tests/vectors/golden_envelopes.json.

It implements the envelope v1 encoding and key schedule from README.md with other
libraries (OpenSSL AES-GCM via `cryptography`, libsodium XChaCha20-Poly1305 via
PyNaCl, the reference Argon2 via argon2-cffi, HKDF from hmac/hashlib), using the
same fixed inputs as the Rust test: every random byte is 0x42.

    uv run --with cryptography --with pynacl --with argon2-cffi python3 golden_envelopes.py
"""

import hashlib
import hmac
import json
import struct

import nacl.bindings as nb
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PT = b"a 256-bit vault DEK would go here"


def hkdf_sha256(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def lp8(b):
    return bytes([len(b)]) + b


def envelope(suite, wrap, secret=None, passphrase=None, cost=None, wrap_params=b""):
    salt = b"\x42" * 32
    nonce = b"\x42" * (24 if suite == 1 else 12)
    h = b"ONEV" + struct.pack(">HHBHQ", 1, suite, wrap, 1, 3)
    h += lp8(b"kek-1") + lp8(b"device-a") + lp8(b"vault-1")
    if passphrase is None:
        h += b"\x01" + salt
        w = secret
    else:
        m, t, p = cost
        h += b"\x02" + struct.pack(">IIB", m, t, p) + salt
        w = hash_secret_raw(passphrase, salt, time_cost=t, memory_cost=m, parallelism=p,
                            hash_len=32, type=Type.ID, version=19)
    h += wrap_params + nonce + struct.pack(">I", len(PT) + 16)
    key = hkdf_sha256(salt, w, b"oneiron-crypto/v1/aead-key" + h)
    if suite == 2:
        ct = AESGCM(key).encrypt(nonce, PT, h)
    else:
        ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(PT, h, nonce, key)
    return (h + ct).hex()


print(json.dumps({
    "aes256gcm_symmetric_kek": envelope(2, 1, secret=b"\x01" * 32),
    "xchacha20poly1305_symmetric_kek": envelope(1, 1, secret=b"\x01" * 32),
    "xchacha20poly1305_shamir_2_of_3": envelope(1, 5, secret=b"\x03" * 32, wrap_params=bytes([2, 3]) + b"\x07" * 16),
    "aes256gcm_passphrase_argon2id": envelope(2, 2, passphrase=b"correct horse battery staple", cost=(19 * 1024, 1, 1)),
}, indent=1))
