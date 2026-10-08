# oneiron-crypto

The crypto contract of the encryption pass (E0): one versioned format for sealed
envelopes and signature records, a suite table that fails closed, and a strict parser.
It depends on nothing in `oneiron` and builds no vault encryption. DEK custody (E1),
the vault at rest (E2), backups and exports (E3), signatures (E4) and capsules (E5)
call into it.

## Library choice and audit status

Every primitive comes from RustCrypto, pinned to an exact release. A version bump is a
reviewed change that reruns the known-answer tests in `tests/kat.rs`.

| Crate | Pin | Used for | Audit status (as stated upstream, 2026-10-08) |
|---|---|---|---|
| `ml-kem` | `=0.3.2` | ML-KEM-1024 (FIPS 203) | **Never independently audited.** |
| `slh-dsa` | `=0.2.0-rc.5` | SLH-DSA-SHA2-256s (FIPS 205) | **Unaudited, and a release candidate.** |
| `x25519-dalek` | `=3.0.0` | X25519 (RFC 7748) | dalek line; no audit claimed here for this release |
| `ed25519-dalek` | `=3.0.0` | Ed25519 (RFC 8032) | dalek line; no audit claimed here for this release |
| `chacha20poly1305` | `=0.11.0` | XChaCha20-Poly1305 | README: one NCC Group audit (of an earlier release), no significant findings |
| `aes-gcm` | `=0.11.1` | AES-256-GCM | README: one NCC Group audit (of an earlier release), no significant findings |
| `hkdf` / `sha2` / `sha3` | `=0.13.0` / `=0.11.0` / `=0.11.0` | HKDF-SHA256, SHA3-256 | no audit claimed here |
| `argon2` | `=0.6.0` | Argon2id (RFC 9106) | no audit claimed here |
| `zeroize` | `=1.9.0` | wiping secrets | — |

What this means, plainly:

- Passing the published vectors shows these exact versions compute the standard
  functions on these inputs. It is not an audit, not FIPS 140 validation, and not a
  constant-time proof. Constant-time behaviour is upstream's claim, not tested here.
- `aws-lc-rs` (FIPS lineage, ML-KEM-1024) was not chosen for E0: it has no
  XChaCha20-Poly1305, no Argon2id and no SLH-DSA, so it would add a second provider and
  a C build on every host, and its FIPS certificates do not cover this crate's use. It
  stays a candidate provider or interoperability oracle; suite ids name constructions,
  not providers, so a provider swap needs no format change.
- `pqcrypto` (unmaintained) and liboqs are not used. liboqs is for the E6
  McEliece/HQC pilot only.
- Nothing here claims hardware-backed PQ keys, vault encryption, or interoperability
  with any other implementation of these formats.

## Suite table

Ids are big-endian `u16` and never reused. Each suite is allowed, forbidden or reserved,
and has a minimum epoch (epoch 0 is never valid). Unknown, forbidden and reserved ids,
and ids of the wrong kind for their slot, are refused by the parser and by every
constructor. There is no fallback.

| Id | Name | Kind | Status |
|---|---|---|---|
| `0x0001` | `xchacha20poly1305-v1` | AEAD | allowed |
| `0x0002` | `aes256gcm-v1` | AEAD | allowed |
| `0x0003` | `aes128gcm-v1` | AEAD | forbidden (below the 256-bit key floor) |
| `0x0101` | `kem-x25519-mlkem1024-v1` | KEM | allowed |
| `0x0102` | `kem-x25519-mlkem768-v1` | KEM | forbidden (the TLS interim group, never a capsule) |
| `0x0103` | `kem-x25519-v1` | KEM | forbidden (classical only) |
| `0x01f0` | `kem-x25519-mlkem1024-mceliece8192128-v1` | KEM | reserved (PQC-4 pilot) |
| `0x01f1` | `kem-x25519-mlkem1024-hqc256-v1` | KEM | reserved (PQC-4 pilot) |
| `0x0201` | `sig-ed25519-v1` | signature | allowed |
| `0x0202` | `sig-slhdsa-sha2-256s-v1` | signature | allowed |
| `0x0203` | `sig-dual-ed25519-slhdsa-sha2-256s-v1` | dual signature | allowed (requires both) |

Readers also state what they accept (`OpenPolicy`, `VerifyPolicy`): the suites, wrap
types, purpose, vault, recipient, key id or signer, and a minimum epoch. The envelope's
own claims are never the expectation.

## Envelope encoding v1

Big-endian integers, fixed-size or `u8`-length-prefixed fields, no optional fields, no
trailing bytes, so each envelope has exactly one encoding. Identifiers are opaque bytes
(1..=64), compared exactly.

```
magic        "ONEV"                      4
version      u16 = 1                     2
suite        u16 (payload AEAD suite)    2
wrap         u8                          1   1 symmetric KEK, 2 passphrase, 3 device keystore,
                                             4 passkey, 5 Shamir recovery, 6 hybrid capsule
purpose      u16                         2   registered values only
epoch        u64                         8   >= the suite's minimum epoch
key_id       u8 len + bytes (1..=64)
recipient    u8 len + bytes (1..=64)
vault_id     u8 len + bytes (1..=64)
kdf          u8                          1   1 hkdf-sha256-v1, 2 argon2id-hkdf-sha256-v1
kdf params   hkdf:   salt[32]
             argon2: m_kib u32, t u32, p u8, salt[32]
wrap params  Shamir: threshold u8, shares u8, share_set_id[16]
             hybrid: kem suite u16, x25519 ephemeral[32], ML-KEM-1024 ciphertext[1568]
             others: none
nonce        24 (XChaCha20-Poly1305) or 12 (AES-256-GCM)
ct_len       u32                         4   16 ..= 16 MiB + 16
ciphertext   ct_len bytes (tag last)
```

`H` is every byte from `magic` through `ct_len`. The KDF/wrap pairs are a closed table:
passphrase wraps use `argon2id-hkdf-sha256-v1`, every other wrap uses `hkdf-sha256-v1`.
Argon2id costs are bounded on both sides (19 MiB..=2 GiB, 1..=64 passes, 1..=16 lanes)
and checked before Argon2 runs; a reader also sets its own budget
(`OpenPolicy::argon2_max`), and a header over it is refused before Argon2 runs. Shamir
parameters must satisfy 2 <= threshold <= shares <= 16. After decoding, the parser
re-encodes the header and refuses input that is not that exact encoding.

### Key schedule

Every wrap type yields a 32-byte wrap secret `W`:

- symmetric KEK, device keystore, passkey: the 256-bit KEK the caller holds;
- passphrase: Argon2id v0x13 (32-byte output) over the passphrase with the header salt;
- Shamir recovery: the secret recovered from the share set (combining shares and
  checking the threshold is E1's job; this wrap only names the share set);
- hybrid capsule: the combiner output below.

Then `K = HKDF-SHA256(salt = header salt, ikm = W, info = "oneiron-crypto/v1/aead-key" || H)`
and `ciphertext = AEAD(K, nonce, plaintext, aad = H)`. Every metadata field is bound
twice: into the key and into the AAD. Any failure to open is the single
`Error::OpenFailed`.

### Nonce rules

Salt (32 bytes) and nonce are fresh random bytes from the caller's CSPRNG for every
envelope; an RNG failure is `Error::Rng`, never a weaker envelope. Because the salt makes
`K` unique per envelope, a key/nonce pair does not repeat even with AES-256-GCM's 96-bit
random nonce under a long-lived KEK. `NonceLedger` adds a stricter, optional in-memory
check: it refuses a second envelope with the same `(key id, nonce)` it has seen. It is
not durable and should only be fed envelopes this process sealed or already opened.

### Hybrid capsule (`kem-x25519-mlkem1024-v1`)

The UniversalCombiner of draft-irtf-cfrg-hybrid-kems-12 (section 5.1.3), over the
nominal-group framework, with SHA3-256 as the KDF:

```
W = SHA3-256(ss_MLKEM || ss_X25519 || ct_MLKEM || ct_X25519 || ek_MLKEM || pk_X25519
             || "oneiron-crypto/kem-x25519-mlkem1024-v1")
```

`ct_X25519` is the ephemeral public key and `pk_X25519` the recipient's static key;
all inputs have fixed lengths. The envelope key schedule then binds the recipient id,
vault id, purpose, both suites, the epoch and both encapsulations through `H`. This is
not X-Wing (which is defined for ML-KEM-768 only). Where it differs from the draft's
framework text: the recipient key is two independent seeds (an ML-KEM seed and an X25519
secret) rather than one PRG-expanded seed; the two encapsulations sit in separate header
fields rather than one concatenated ciphertext; and the label is ours, not a registered
one. None of these changes the combiner's inputs or their order.

- The recipient's public keys are bound from the recipient's own key on open, never read
  from the wire. Recipient public keys must come from authenticated metadata.
- The sender is anonymous, as in HPKE base mode. Origin authentication comes only from a
  signature record.
- The encapsulation key passes the FIPS 203 modulus check on import; a non-contributory
  X25519 result is refused (`KemKeyRejected` when sealing, `OpenFailed` when opening).
- ML-KEM decapsulation rejects implicitly, so a tampered ciphertext shows up only as
  `OpenFailed`.

## Secret hygiene

- Key types (`Kek`, `RecoverySecret`, `Passphrase`, `HybridSecretKey`, `SigningKey`)
  zeroize on drop and print as `redacted`. The wrap secret, the payload key and returned
  plaintext are `Zeroizing`. Errors carry ids, names and lengths, never key or plaintext
  bytes.
- Argon2id runs in work memory this crate allocates (fallibly) and wipes; the provider
  frees its own buffer without wiping it.
- The providers' own wiping is turned on: the AEAD ciphers, Poly1305, GHASH, HMAC and the
  SHA-2/SHA-3 states, ML-KEM, SLH-DSA and the dalek keys. ML-KEM shared-key arrays are
  wiped by hand.
- Residual, accepted for E0: `hkdf 0.13.0` keeps its PRK and its last expand block (here
  the whole payload key) in plain stack values, and `hmac 0.13.0` keeps the padded key
  block (PRK XOR pad) in a plain buffer; none of them is wiped. Stack copies made by the
  compiler cannot be guaranteed wiped either. Recovering any of them needs a memory
  disclosure of this process. Closing it needs upstream changes to both providers; a local
  HKDF over `hmac` would not close it.

## Signature record encoding v1

```
magic        "ONSG"                      4
version      u16 = 1                     2
suite        u16 (signature or dual)     2
purpose      u16                         2
epoch        u64                         8
signer       u8 len + bytes (1..=64)
body         u8                          1   1 signature list, 2 checkpoint reference
list:        count u8 (1..=4), then per entry, in strictly ascending suite order:
             suite u16, key_id u8 len + bytes, sig_len u32 (exact for the suite), signature
checkpoint:  checkpoint_epoch u64, tree_size u64, leaf_index u64 (< tree_size), root[32],
             proof_len u8 (0..=64), proof_len x [32]
```

Every component signs `"oneiron-crypto/v1/sig" || T || subject`, where `T` is the record
without the signature bytes (so the suite, roster and component key ids are signed). The
entries must be exactly the suite's roster: one for a single suite, both components for
the dual suite. Duplicates, extras, missing components and unsorted entries are refused at
parse and at verify. Ed25519 is pure RFC 8032 checked with `verify_strict`; SLH-DSA is pure
FIPS 205 with an empty context and a fresh 32-byte randomizer per signature.

A checkpoint reference is parsed and bounded but never verifies in v1
(`Error::CheckpointRefUnverified`): it needs a separately verified checkpoint and the
Merkle tree rules, which are E4's.

## Tests

- `tests/kat.rs`: published vectors against the pinned crates. ML-KEM-1024 and
  SLH-DSA-SHA2-256s from NIST ACVP-Server, X25519 (RFC 7748), Ed25519 (RFC 8032),
  XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03), AES-256-GCM (Wycheproof), HKDF-SHA256
  (RFC 5869), Argon2id (RFC 9106). Sources and test-case ids are in
  `tests/vectors/kat.json`.
- `tests/envelope.rs`, `tests/record.rs`: round trips for every wrap type, the fail-closed
  list, tampering of every header field, ciphertext swaps, the hybrid capsule, the roster.
- `tests/parser_props.rs`: bounded property fuzzing of both parsers in the normal gate.
- `fuzz/`: coverage-guided cargo-fuzz targets for both parsers (nightly; outside the
  workspace): `cargo +nightly fuzz run envelope_parse -- -max_total_time=60`.

Not covered here: side-channel measurement, interoperability with another
implementation, and real-device (iOS) runs. Those belong to the lanes that ship the
formats.
