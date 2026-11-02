//! Sealing and opening one inference snapshot: a fresh random data key per
//! snapshot, wrapped under the vault's key, and the body chunked into one
//! envelope per piece under that data key.
//!
//! ```text
//! wrapped   u8 version ‖ nonce (12) ‖ AES-256-GCM(data key)
//! sealed    u8 version ‖ snapshot id (16) ‖ u64be chunks ‖ u64be length
//!             ‖ chunk*    one envelope of 64 KiB of the body each; the last
//!                         holds the rest, 0 to 64 KiB, and an empty body has
//!                         one, empty
//! ```
//!
//! The wrap's associated data is the wrap domain and the snapshot id; each
//! chunk binds, in its key id, the format version, the snapshot id, its index
//! and whether it is the last, and, as extra associated data, the snapshot's
//! manifest — the last chunk the manifest plus the body's length and chunk
//! count. A reader checks the sealed length and count before it opens a
//! chunk, and authenticates a chunk before it returns a byte of it: a body
//! cut short, reordered, extended or opened under another manifest does not
//! read. Every open failure is one [`Error::CorruptedIndex`], carrying no
//! manifest bytes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::world_keys::{os_fill, refused};

/// The format version both values' bytes and every chunk key id carry.
const VERSION: u8 = 1;
/// Plaintext per chunk: one envelope seals this much of the body.
const CHUNK_LEN: usize = 64 * 1024;
/// The snapshot id's width: fresh random bytes, never taken from a digest.
const ID_LEN: usize = 16;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const EPOCH: u64 = 1;
const RECIPIENT: &[u8] = b"oneiron/inference-snapshot/chunk";
/// The domain a wrapped data key's associated data opens with.
const WRAP_AAD_DOMAIN: &[u8] = b"oneiron/inference-snapshot-key/v1\0";
const WRAP_NONCE_LEN: usize = 12;
/// A wrapped key's fixed width: version ‖ nonce ‖ 32 key bytes + 16 tag.
const WRAPPED_LEN: usize = 1 + WRAP_NONCE_LEN + 48;

fn corrupt() -> Error {
    Error::CorruptedIndex("inference snapshot")
}

/// One snapshot's data key, wrapped under the vault's key: `u8` version 1, a
/// fresh 12-byte nonce, then the 32 key bytes sealed under it. The sealed
/// body never carries the key; whoever holds only [`SealedSnapshot`] opens
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSnapshotKey {
    bytes: Vec<u8>,
}

impl WrappedSnapshotKey {
    /// Parses wrapped bytes: the version, then nonce and ciphertext, exactly.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WRAPPED_LEN || bytes[0] != VERSION {
            return Err(corrupt());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// The canonical bytes: version, nonce, ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Retires this copy of the wrapped key: its bytes are wiped and dropped,
    /// so this handle never unwraps again. Durable erasure — the stored rows,
    /// copies and backups — is the store's erase wiring, not a filename
    /// delete here.
    pub fn retire(mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}

/// One snapshot's sealed body: the snapshot id, the chunk count, the
/// plaintext length, and one envelope per chunk. Opaque bytes: no key, no
/// manifest, no plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSnapshot {
    id: [u8; ID_LEN],
    count: u64,
    total: u64,
    frames: Vec<Vec<u8>>,
}

impl SealedSnapshot {
    /// Parses sealed bytes: version, id, count, length, then exactly `count`
    /// length-prefixed envelopes, each a well-formed envelope. Nothing is
    /// authenticated here; [`open_snapshot`] opens every chunk.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (version, rest) = bytes.split_first_chunk::<1>().ok_or_else(corrupt)?;
        if version[0] != VERSION {
            return Err(corrupt());
        }
        let (id, rest) = rest.split_first_chunk::<ID_LEN>().ok_or_else(corrupt)?;
        let (count, rest) = rest.split_first_chunk::<8>().ok_or_else(corrupt)?;
        let (total, mut rest) = rest.split_first_chunk::<8>().ok_or_else(corrupt)?;
        let count = u64::from_be_bytes(*count);
        let total = u64::from_be_bytes(*total);
        check_totals(count, total)?;
        let mut frames = Vec::new();
        for _ in 0..count {
            let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(corrupt)?;
            let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| corrupt())?;
            let frame = tail.get(..len).ok_or_else(corrupt)?;
            Envelope::parse(frame).map_err(|_| corrupt())?;
            frames.push(frame.to_vec());
            rest = &tail[len..];
        }
        if !rest.is_empty() {
            return Err(corrupt());
        }
        Ok(Self {
            id: *id,
            count,
            total,
            frames,
        })
    }

    /// The body's own id, drawn when it was sealed: its catalog row names
    /// it, so a body file swapped under another row does not read.
    #[must_use]
    pub fn seal_id(&self) -> [u8; ID_LEN] {
        self.id
    }

    /// The canonical bytes: version, id, count, length, then each envelope
    /// with its `u32be` length.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(VERSION);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        for frame in &self.frames {
            // A parsed frame is an envelope, capped far below `u32::MAX`.
            let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(frame);
        }
        out
    }
}

/// What one envelope of a sealed body is.
#[derive(Clone, Copy)]
enum Role {
    Chunk = 0,
    Last = 1,
}

/// Whether `count` chunks can hold `total` plaintext bytes: at least one
/// chunk, and the last one partial or full. Checked before a chunk opens.
fn check_totals(count: u64, total: u64) -> Result<()> {
    let chunk = CHUNK_LEN as u64;
    let least = count
        .checked_sub(1)
        .and_then(|rest| rest.checked_mul(chunk))
        .ok_or_else(corrupt)?;
    let most = count.checked_mul(chunk).ok_or_else(corrupt)?;
    if !(least..=most).contains(&total) {
        return Err(corrupt());
    }
    Ok(())
}

/// Plaintext bytes in a chunk of `role`: full chunks but the last, which
/// holds the rest. The header passed [`check_totals`] before this runs.
fn chunk_len(count: u64, total: u64, role: Role) -> Result<u64> {
    match role {
        Role::Chunk => Ok(CHUNK_LEN as u64),
        Role::Last => {
            let before = count
                .checked_sub(1)
                .and_then(|rest| rest.checked_mul(CHUNK_LEN as u64))
                .ok_or_else(corrupt)?;
            total.checked_sub(before).ok_or_else(corrupt)
        }
    }
}

/// Version ‖ snapshot id ‖ u64be index ‖ role: each envelope's key id.
fn key_id(id: &[u8; ID_LEN], index: u64, role: Role) -> [u8; 27] {
    let mut out = [0u8; 27];
    out[..2].copy_from_slice(&u16::from(VERSION).to_be_bytes());
    out[2..18].copy_from_slice(id);
    out[18..26].copy_from_slice(&index.to_be_bytes());
    out[26] = role as u8;
    out
}

/// The last chunk's extra associated data: the manifest plus the body's
/// length and chunk count the sealed header claims.
fn last_extra_aad(manifest: &[u8], total: u64, count: u64) -> Vec<u8> {
    let mut extra = Vec::with_capacity(manifest.len() + 16);
    extra.extend_from_slice(manifest);
    extra.extend_from_slice(&total.to_be_bytes());
    extra.extend_from_slice(&count.to_be_bytes());
    extra
}

fn seal_chunk(
    kek: &Kek,
    id: &[u8; ID_LEN],
    index: u64,
    role: Role,
    extra: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key_id = key_id(id, index, role);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::InferenceSnapshotChunk,
        epoch: EPOCH,
        key_id: &key_id,
        recipient: RECIPIENT,
        vault_id: id,
    };
    Ok(seal_with_aad(
        &params,
        SealKey::SymmetricKek(kek),
        plaintext,
        extra,
        &mut SysRng,
    )
    .map_err(|_| refused("sealing an inference snapshot failed"))?
    .to_bytes())
}

/// The plaintext of `frame`, authenticated as envelope `index` of `role`
/// under `extra` before a byte of it is returned, and checked to be `len`
/// bytes.
fn open_chunk(
    kek: &Kek,
    id: &[u8; ID_LEN],
    index: u64,
    role: Role,
    extra: &[u8],
    frame: &[u8],
    len: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let key_id = key_id(id, index, role);
    let policy = OpenPolicy {
        purpose: Purpose::InferenceSnapshotChunk,
        vault_id: id,
        recipient: RECIPIENT,
        key_id: &key_id,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let plaintext = Envelope::parse(frame)
        .map_err(|_| corrupt())?
        .open_with_aad(OpenKey::SymmetricKek(kek), &policy, extra)
        .map_err(|_| corrupt())?;
    if plaintext.len() as u64 != len {
        return Err(corrupt());
    }
    Ok(plaintext)
}

/// The associated data a data key is wrapped under: the wrap domain and its
/// snapshot's id.
fn wrap_aad(id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_DOMAIN.len() + ID_LEN);
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(id);
    aad
}

/// Wraps `raw` under `vault_key` for snapshot `id`.
fn wrap_key(vault_key: &[u8; 32], id: &[u8; ID_LEN], raw: &[u8; 32]) -> Result<WrappedSnapshotKey> {
    let mut nonce = [0; WRAP_NONCE_LEN];
    os_fill(&mut nonce)?;
    let cipher = Aes256Gcm::new_from_slice(vault_key)
        .map_err(|_| refused("sealing an inference snapshot failed"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: raw,
                aad: &wrap_aad(id),
            },
        )
        .map_err(|_| refused("sealing an inference snapshot failed"))?;
    let mut bytes = Vec::with_capacity(WRAPPED_LEN);
    bytes.push(VERSION);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(WrappedSnapshotKey { bytes })
}

/// Opens `wrapped` under `vault_key` for snapshot `id`.
fn open_wrapped(
    vault_key: &[u8; 32],
    id: &[u8; ID_LEN],
    wrapped: &WrappedSnapshotKey,
) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.bytes.len() != WRAPPED_LEN || wrapped.bytes[0] != VERSION {
        return Err(corrupt());
    }
    let (nonce, ciphertext) = wrapped.bytes[1..]
        .split_first_chunk::<WRAP_NONCE_LEN>()
        .ok_or_else(corrupt)?;
    let cipher = Aes256Gcm::new_from_slice(vault_key).map_err(|_| corrupt())?;
    let plain = cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &wrap_aad(id),
            },
        )
        .map_err(|_| corrupt())
        .map(Zeroizing::new)?;
    if plain.len() != 32 {
        return Err(corrupt());
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(&plain);
    Ok(raw)
}

/// Seals `plaintext` as one snapshot under a fresh random data key, wrapped
/// under `vault_key` for a fresh random snapshot id, binding `manifest` as
/// associated data. The wrapped key and the sealed body travel apart: erase
/// destroys the key alone. The caller's `vault_key` bytes stay the caller's
/// to wipe.
pub fn seal_snapshot(
    vault_key: &[u8; 32],
    manifest: &[u8],
    plaintext: &[u8],
) -> Result<(WrappedSnapshotKey, SealedSnapshot)> {
    let mut id = [0u8; ID_LEN];
    os_fill(&mut id)?;
    let mut raw = Zeroizing::new([0u8; 32]);
    os_fill(&mut raw[..])?;
    let kek = Kek::from_bytes_ref(&raw);
    let total = u64::try_from(plaintext.len()).map_err(|_| corrupt())?;
    let pieces = plaintext.len().div_ceil(CHUNK_LEN).max(1);
    let count = u64::try_from(pieces).map_err(|_| corrupt())?;
    let last_extra = last_extra_aad(manifest, total, count);
    let mut frames = Vec::new();
    if plaintext.is_empty() {
        frames.push(seal_chunk(&kek, &id, 0, Role::Last, &last_extra, &[])?);
    } else {
        for (at, piece) in plaintext.chunks(CHUNK_LEN).enumerate() {
            let index = u64::try_from(at).map_err(|_| corrupt())?;
            let role = if index + 1 == count {
                Role::Last
            } else {
                Role::Chunk
            };
            let extra = match role {
                Role::Chunk => manifest,
                Role::Last => last_extra.as_slice(),
            };
            frames.push(seal_chunk(&kek, &id, index, role, extra, piece)?);
        }
    }
    let wrapped = wrap_key(vault_key, &id, &raw)?;
    Ok((
        wrapped,
        SealedSnapshot {
            id,
            count,
            total,
            frames,
        },
    ))
}

/// Opens `sealed` with `wrapped` under `vault_key`, checking `manifest`
/// exactly as [`seal_snapshot`] bound it: a body cut short, reordered,
/// extended or opened under another manifest does not read. Returns the
/// plaintext, wiped on drop.
pub fn open_snapshot(
    vault_key: &[u8; 32],
    wrapped: &WrappedSnapshotKey,
    manifest: &[u8],
    sealed: &SealedSnapshot,
) -> Result<Zeroizing<Vec<u8>>> {
    check_totals(sealed.count, sealed.total)?;
    if sealed.frames.len() as u64 != sealed.count {
        return Err(corrupt());
    }
    let key = open_wrapped(vault_key, &sealed.id, wrapped)?;
    let kek = Kek::from_bytes_ref(&key);
    let last_extra = last_extra_aad(manifest, sealed.total, sealed.count);
    let mut plain = Zeroizing::new(Vec::new());
    for (at, frame) in sealed.frames.iter().enumerate() {
        let index = u64::try_from(at).map_err(|_| corrupt())?;
        let role = if index + 1 == sealed.count {
            Role::Last
        } else {
            Role::Chunk
        };
        let extra = match role {
            Role::Chunk => manifest,
            Role::Last => last_extra.as_slice(),
        };
        let piece = open_chunk(
            &kek,
            &sealed.id,
            index,
            role,
            extra,
            frame,
            chunk_len(sealed.count, sealed.total, role)?,
        )?;
        plain.extend_from_slice(&piece);
    }
    if plain.len() as u64 != sealed.total {
        return Err(corrupt());
    }
    Ok(plain)
}
