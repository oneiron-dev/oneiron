//! Sealed checkpoint artifacts (OF-570 (c)). A checkpoint or an owner's backup
//! leaves the vault only as E0 symmetric envelopes, under a key derived from
//! the vault data key (`oneiron/checkpoint-seal/v1`). One file:
//!
//! ```text
//! "ONEIRONS" ‖ u16be 1 ‖ u8 kind ‖ vault id (32) ‖ snapshot id (32)
//!   ‖ u32be n ‖ key header (n)    the vault key's commitment and sealed wraps
//!   ‖ frame*                      the image's chunks, then each body's in order
//!   ‖ frame                       the sealed manifest
//!   ‖ u32be n ‖ commitment (n)    clear, signed (`commitment`)
//!   ‖ u32be n ‖ signature (n)     E0 dual Ed25519 + SLH-DSA record
//!   ‖ u64be offset of the manifest frame
//! frame = u32be len ‖ E0 envelope
//! ```
//!
//! A chunk is up to 4 MiB of one stream, zstd-compressed, then sealed. Its
//! envelope binds the vault, the epoch, the vault key's commitment, the kind's
//! purpose (`CheckpointArtifact` or `BackupArtifact`) and, as its recipient,
//! the snapshot id, its stream and its place in it. The manifest, sealed last,
//! names the complete set in order: the image's length and BLAKE3, each result
//! body's, the BLAKE3 of every chunk's envelope, and the key header's. A reader
//! opens the manifest and every image chunk before a byte of the image is
//! decoded or anything is made; a body's chunks are opened, each checked
//! against the manifest, as the body is read back into the restored vault.
//!
//! The key header holds no key: it lets a host without the vault unlock the
//! artifact's key from one wrap ([`CheckpointKey::unlock`]). Claim keys are
//! never in an image either; exterior custody stays live (`checkpoint_custody`).
//!
//! The commitment names the sealed manifest by digest, and a reader verifies
//! its signature against the signers its key trusts before the manifest opens
//! (`commitment`).
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, MAX_PLAINTEXT_LEN, OpenKey, OpenPolicy, Purpose, SealKey,
    SealParams, SuiteId, WrapType, seal,
};
use serde::{Deserialize, Serialize};

use super::commitment::{self, ChainHead, CheckpointSigner, Link, Trust};
use crate::world_keys::{CarriedVaultKey, VaultKeyUnlock, VaultKeyWrapInfo, refused};
use crate::{Error, Result, Vault};

const MAGIC: &[u8; 8] = b"ONEIRONS";
const VERSION: u16 = 1;
const SEAL_CONTEXT: &str = "oneiron/checkpoint-seal/v1";
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The crypto epoch every artifact envelope is sealed at.
const EPOCH: u64 = 1;
/// Plaintext per chunk, before compression: well under E0's 16 MiB.
const CHUNK_LEN: usize = 4 << 20;
const ZSTD_LEVEL: i32 = 3;
const IMAGE_STREAM: u32 = 0;
const MANIFEST_STREAM: u32 = u32::MAX;
const PRELUDE_LEN: usize = MAGIC.len() + 2 + 1 + 32 + 32 + 4;
const MAX_KEY_HEADER: usize = 1 << 20;
/// No envelope's header and tag come near 64 KiB above its plaintext.
const MAX_FRAME: u64 = MAX_PLAINTEXT_LEN as u64 + (1 << 16);

fn codec() -> Error {
    Error::CorruptedIndex("sealed checkpoint artifact")
}

/// What a sealed artifact is for, which fixes its E0 purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A checkpoint, for restore, wake and migrate.
    Checkpoint,
    /// An owner's backup.
    Backup,
}

impl ArtifactKind {
    fn code(self) -> u8 {
        match self {
            Self::Checkpoint => 1,
            Self::Backup => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Checkpoint),
            2 => Some(Self::Backup),
            _ => None,
        }
    }

    fn purpose(self) -> Purpose {
        match self {
            Self::Checkpoint => Purpose::CheckpointArtifact,
            Self::Backup => Purpose::BackupArtifact,
        }
    }
}

/// The key one vault's sealed checkpoints and backups open with, derived from
/// its data key and never stored, and whose signatures it accepts. The open
/// vault gives it, trusting this device's signer ([`Vault::checkpoint_key`]); a
/// host without the vault unlocks it from a wrap the artifact carries
/// ([`CheckpointKey::unlock`]) and says whom it trusts.
pub struct CheckpointKey {
    vault_id: [u8; 32],
    kek: Kek,
    trust: Trust,
}

impl std::fmt::Debug for CheckpointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckpointKey(..)")
    }
}

/// What the clear head of an artifact says unlocks it, read before any key: a
/// host restoring with no vault picks its unlock from these. Nothing here is
/// authenticated until the artifact opens.
#[derive(Clone, Debug)]
pub struct ArtifactUnlocks {
    pub kind: ArtifactKind,
    pub vault_id: [u8; 32],
    /// The commitment naming the vault key it is sealed under: an escrow
    /// capsule kept elsewhere for this key names the same one.
    pub commitment: [u8; 32],
    /// The public facts of each vault-key wrap it carries.
    pub wraps: Vec<VaultKeyWrapInfo>,
}

impl CheckpointKey {
    /// What can unlock the artifact at `path`, from its clear head.
    pub fn unlocks(path: &Path) -> Result<ArtifactUnlocks> {
        let prelude = Prelude::read(&mut File::open(path)?)?;
        let carried = prelude.carried()?;
        Ok(ArtifactUnlocks {
            kind: prelude.kind,
            vault_id: prelude.vault_id,
            commitment: *carried.commitment(),
            wraps: carried.wrap_infos(),
        })
    }

    /// Unlocks the key of the artifact at `path` from one of the vault-key
    /// wraps it carries, or from an escrow capsule kept elsewhere for its
    /// vault and key ([`VaultKeyUnlock::EscrowCapsule`]). The carried wraps
    /// are bound to the artifact once its manifest opens; a forged header
    /// unlocks a key that opens nothing.
    /// It trusts no signer until told whom ([`CheckpointKey::trusting`]).
    pub fn unlock(path: &Path, unlock: &VaultKeyUnlock<'_>) -> Result<Self> {
        let prelude = Prelude::read(&mut File::open(path)?)?;
        let key = prelude
            .carried()?
            .subkey(&prelude.vault_id, unlock, SEAL_CONTEXT)?;
        Ok(Self {
            vault_id: prelude.vault_id,
            kek: Kek::from_bytes(*key),
            trust: Trust::Nobody,
        })
    }

    /// [`CheckpointKey::unlock`] with this install's keystore at the platform
    /// defaults, from the device wrap it holds a slot for, trusting the
    /// signers whose seeds that keystore holds. `vault_dir` is the vault's
    /// directory, which the keystore must lie outside.
    pub fn unlock_on_this_device(path: &Path, vault_dir: &Path) -> Result<Self> {
        let keystore = oneiron_keystore::default_platform_keystore(&[vault_dir])
            .map_err(crate::world_keys::keystore_error)?;
        Ok(
            Self::unlock(path, &VaultKeyUnlock::Device(keystore.as_ref()))?
                .trusting_device(keystore),
        )
    }

    /// Trusts exactly these signers, pinned through a channel of the
    /// caller's ([`Vault::checkpoint_signer`]), in place of any trust before.
    pub fn trusting(mut self, signers: Vec<CheckpointSigner>) -> Self {
        self.trust = Trust::Pinned(signers);
        self
    }

    /// Trusts the signers whose seeds `keystore` holds for the vault.
    pub fn trusting_device(
        mut self,
        keystore: std::sync::Arc<dyn oneiron_keystore::DeviceKeystore>,
    ) -> Self {
        self.trust = Trust::Device(keystore);
        self
    }
}

impl Vault {
    /// The key this vault's checkpoints and backups seal under, unlocking the
    /// vault key with this device's wrap when this handle does not hold it.
    /// It trusts the signers whose seeds this vault's keystore holds.
    pub fn checkpoint_key(&self) -> Result<CheckpointKey> {
        self.unlock_vault_key()?;
        Ok(CheckpointKey {
            vault_id: *self.vault_id().as_bytes(),
            kek: Kek::from_bytes(*self.vault_subkey(SEAL_CONTEXT)?),
            trust: Trust::Device(self.device_keystore()?),
        })
    }

    /// The vault key as it rests and the checkpoint key of the one this handle
    /// holds, read together in the snapshot's own transaction.
    pub(super) fn checkpoint_seal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<(CarriedVaultKey, CheckpointKey)> {
        let (carried, key) = self.carried_vault_key_in_txn(txn, SEAL_CONTEXT)?;
        Ok((
            carried,
            CheckpointKey {
                vault_id: *self.vault_id().as_bytes(),
                kek: Kek::from_bytes(*key),
                trust: Trust::Nobody,
            },
        ))
    }
}

/// One stream's line in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamEntry {
    len: u64,
    /// BLAKE3 of the stream's bytes: the checkpoint id, or the body's name.
    digest: [u8; 32],
    /// BLAKE3 of each chunk's envelope, in order.
    chunks: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    kind: u8,
    vault_id: [u8; 32],
    snapshot: [u8; 32],
    epoch: u64,
    created_at: u64,
    /// BLAKE3 of the clear key header.
    key_header: [u8; 32],
    image: StreamEntry,
    bodies: Vec<StreamEntry>,
}

/// The clear head of an artifact file.
struct Prelude {
    kind: ArtifactKind,
    vault_id: [u8; 32],
    snapshot: [u8; 32],
    key_header: Vec<u8>,
    /// Where the first frame starts.
    end: u64,
}

impl Prelude {
    fn read(file: &mut File) -> Result<Self> {
        let mut fixed = [0u8; PRELUDE_LEN];
        file.read_exact(&mut fixed).map_err(|_| codec())?;
        let (magic, rest) = fixed.split_at(MAGIC.len());
        if magic != MAGIC || rest[..2] != VERSION.to_be_bytes() {
            return Err(codec());
        }
        let kind = ArtifactKind::from_code(rest[2]).ok_or_else(codec)?;
        let vault_id: [u8; 32] = rest[3..35].try_into().map_err(|_| codec())?;
        let snapshot: [u8; 32] = rest[35..67].try_into().map_err(|_| codec())?;
        let len = u32::from_be_bytes(rest[67..71].try_into().map_err(|_| codec())?) as usize;
        if len > MAX_KEY_HEADER {
            return Err(codec());
        }
        let mut key_header = vec![0u8; len];
        file.read_exact(&mut key_header).map_err(|_| codec())?;
        Ok(Self {
            kind,
            vault_id,
            snapshot,
            key_header,
            end: (PRELUDE_LEN + len) as u64,
        })
    }

    fn carried(&self) -> Result<CarriedVaultKey> {
        rmp_serde::from_slice(&self.key_header).map_err(|_| codec())
    }
}

/// Seals and opens one artifact's envelopes.
struct Sealer<'k> {
    key: &'k CheckpointKey,
    purpose: Purpose,
    commitment: [u8; 32],
    snapshot: [u8; 32],
}

impl Sealer<'_> {
    /// Snapshot id ‖ u32be stream ‖ u32be index: each envelope's recipient.
    fn recipient(&self, stream: u32, index: u32) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.snapshot);
        out[32..36].copy_from_slice(&stream.to_be_bytes());
        out[36..].copy_from_slice(&index.to_be_bytes());
        out
    }

    fn seal(&self, stream: u32, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let compressed = zstd::bulk::compress(plaintext, ZSTD_LEVEL)?;
        let recipient = self.recipient(stream, index);
        let params = SealParams {
            suite: AEAD,
            purpose: self.purpose,
            epoch: EPOCH,
            key_id: &self.commitment,
            recipient: &recipient,
            vault_id: &self.key.vault_id,
        };
        let envelope = seal(
            &params,
            SealKey::SymmetricKek(&self.key.kek),
            &compressed,
            &mut SysRng,
        )
        .map_err(|_| refused("sealing the checkpoint failed"))?;
        Ok(envelope.to_bytes())
    }

    fn open(&self, stream: u32, index: u32, envelope: &[u8]) -> Result<Vec<u8>> {
        let recipient = self.recipient(stream, index);
        let policy = OpenPolicy {
            purpose: self.purpose,
            vault_id: &self.key.vault_id,
            recipient: &recipient,
            key_id: &self.commitment,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[AEAD],
            kem_suites: &[],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let compressed = Envelope::parse(envelope)
            .map_err(|_| codec())?
            .open(OpenKey::SymmetricKek(&self.key.kek), &policy)
            .map_err(|_| refused("the checkpoint does not open with this key"))?;
        zstd::bulk::decompress(&compressed, CHUNK_LEN).map_err(|_| codec())
    }
}

/// Writes the artifact at `path`, create-new and owner-only: the image, then
/// each body `open_body` hands back, then the manifest, then the commitment
/// `link` signs. Returns the image's BLAKE3 and the chain head the signed
/// commitment makes. A write that fails removes the file, so no part of one is
/// left.
#[allow(clippy::too_many_arguments)]
pub(super) fn write_artifact(
    path: &Path,
    key: &CheckpointKey,
    kind: ArtifactKind,
    carried: &CarriedVaultKey,
    link: &Link,
    created_at: u64,
    image: &[u8],
    bodies: &[([u8; 32], u64)],
    mut open_body: impl FnMut(&[u8; 32], u64) -> Result<File>,
) -> Result<([u8; 32], ChainHead)> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let mut partial = Partial(Some(path.to_path_buf()));
    let mut snapshot = [0u8; 32];
    crate::world_keys::os_fill(&mut snapshot)?;
    let key_header = rmp_serde::to_vec_named(carried).map_err(|_| codec())?;
    let len = u32::try_from(key_header.len())
        .ok()
        .filter(|len| *len as usize <= MAX_KEY_HEADER)
        .ok_or_else(codec)?;
    let mut sink = Sink {
        out: BufWriter::new(file),
        offset: 0,
        sealer: Sealer {
            key,
            purpose: kind.purpose(),
            commitment: *carried.commitment(),
            snapshot,
        },
    };
    sink.put(MAGIC)?;
    sink.put(&VERSION.to_be_bytes())?;
    sink.put(&[kind.code()])?;
    sink.put(&key.vault_id)?;
    sink.put(&snapshot)?;
    sink.put(&len.to_be_bytes())?;
    sink.put(&key_header)?;
    let image = sink.stream(IMAGE_STREAM, &mut &image[..])?;
    let mut sealed_bodies = Vec::with_capacity(bodies.len());
    for (index, (digest, len)) in bodies.iter().enumerate() {
        let stream = u32::try_from(index + 1)
            .ok()
            .filter(|stream| *stream != MANIFEST_STREAM)
            .ok_or_else(codec)?;
        let entry = sink.stream(stream, &mut open_body(digest, *len)?)?;
        // A body file is named by its digest; one that reads otherwise is
        // refused here, not found out at a restore.
        if entry.len != *len || entry.digest != *digest {
            return Err(Error::CorruptedIndex("code-run result body file"));
        }
        sealed_bodies.push(entry);
    }
    let manifest = Manifest {
        version: VERSION,
        kind: kind.code(),
        vault_id: key.vault_id,
        snapshot,
        epoch: EPOCH,
        created_at,
        key_header: *blake3::hash(&key_header).as_bytes(),
        image,
        bodies: sealed_bodies,
    };
    let manifest_at = sink.offset;
    let bytes = rmp_serde::to_vec_named(&manifest).map_err(|_| codec())?;
    let envelope = sink.sealer.seal(MANIFEST_STREAM, 0, &bytes)?;
    sink.frame(&envelope)?;
    let commitment = commitment::new_commitment(
        link,
        key.vault_id,
        kind.code(),
        snapshot,
        *blake3::hash(&envelope).as_bytes(),
        created_at,
    )?;
    let (commitment, signature, head) = link.sign(&commitment)?;
    sink.frame(&commitment)?;
    sink.frame(&signature)?;
    sink.put(&manifest_at.to_be_bytes())?;
    let file = sink.out.into_inner().map_err(|error| error.into_error())?;
    file.sync_all()?;
    partial.0 = None;
    Ok((manifest.image.digest, head))
}

/// The file a write is making, removed unless the write finishes.
struct Partial(Option<PathBuf>);

impl Drop for Partial {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct Sink<'k> {
    out: BufWriter<File>,
    offset: u64,
    sealer: Sealer<'k>,
}

impl Sink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    fn frame(&mut self, envelope: &[u8]) -> Result<()> {
        let len = u32::try_from(envelope.len()).map_err(|_| codec())?;
        self.put(&len.to_be_bytes())?;
        self.put(envelope)
    }

    /// Seals `source` as `stream`, chunk by chunk.
    fn stream(&mut self, stream: u32, source: &mut impl Read) -> Result<StreamEntry> {
        let mut hasher = blake3::Hasher::new();
        let mut chunks = Vec::new();
        let mut len = 0u64;
        let mut buffer = vec![0u8; CHUNK_LEN];
        loop {
            let filled = read_full(source, &mut buffer)?;
            if filled == 0 {
                break;
            }
            hasher.update(&buffer[..filled]);
            len += filled as u64;
            let index = u32::try_from(chunks.len()).map_err(|_| codec())?;
            let envelope = self.sealer.seal(stream, index, &buffer[..filled])?;
            chunks.push(*blake3::hash(&envelope).as_bytes());
            self.frame(&envelope)?;
            if filled < CHUNK_LEN {
                break;
            }
        }
        Ok(StreamEntry {
            len,
            digest: *hasher.finalize().as_bytes(),
            chunks,
        })
    }
}

/// Reads until `buffer` is full or `source` ends; returns how much it holds.
fn read_full(source: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(filled)
}

/// An artifact whose manifest and image have opened.
pub(super) struct OpenedArtifact<'k> {
    pub(super) image: Vec<u8>,
    /// BLAKE3 of the image: the checkpoint id.
    pub(super) image_id: [u8; 32],
    pub(super) created_at: u64,
    pub(super) bodies: SealedBodies<'k>,
}

/// The result bodies an opened artifact carries, each read back through its
/// sealed chunks.
pub(super) struct SealedBodies<'k> {
    file: File,
    sealer: Sealer<'k>,
    /// Each body's manifest line and its frames (offset, length).
    streams: Vec<(StreamEntry, Vec<(u64, u64)>)>,
}

/// Opens the artifact at `path` with `key`: its manifest, checked against the
/// clear head, the complete set of frames, and the image, before any of the
/// image is decoded. Refuses another vault's artifact before anything opens.
pub(super) fn open_artifact<'k>(path: &Path, key: &'k CheckpointKey) -> Result<OpenedArtifact<'k>> {
    let mut file = File::open(path)?;
    let prelude = Prelude::read(&mut file)?;
    if prelude.vault_id != key.vault_id {
        return Err(refused("the checkpoint is another vault's"));
    }
    let sealer = Sealer {
        key,
        purpose: prelude.kind.purpose(),
        commitment: *prelude.carried()?.commitment(),
        snapshot: prelude.snapshot,
    };
    let footer_at = file
        .metadata()?
        .len()
        .checked_sub(8)
        .filter(|at| *at >= prelude.end)
        .ok_or_else(codec)?;
    let manifest_at = u64::from_be_bytes(
        read_at(&mut file, footer_at, 8)?
            .try_into()
            .map_err(|_| codec())?,
    );
    if manifest_at < prelude.end || manifest_at > footer_at {
        return Err(codec());
    }
    let (manifest_len, signed_at) = frame_at(&mut file, manifest_at)?;
    let manifest_bytes = read_at(&mut file, manifest_at + 4, manifest_len)?;
    // The signed commitment comes first: nothing opens for a signer the key
    // does not trust, or a commitment that names another manifest.
    let (commitment_len, record_at) = signed_frame_at(&mut file, signed_at)?;
    let (record_len, end) = signed_frame_at(&mut file, record_at)?;
    if end != footer_at {
        return Err(codec());
    }
    let commitment = commitment::verify(
        &key.trust,
        &key.vault_id,
        &read_at(&mut file, signed_at + 4, commitment_len)?,
        &read_at(&mut file, record_at + 4, record_len)?,
    )?;
    if commitment.kind != prelude.kind.code()
        || commitment.snapshot != prelude.snapshot
        || commitment.manifest != *blake3::hash(&manifest_bytes).as_bytes()
        || manifest_at + 4 + manifest_len != signed_at
    {
        return Err(codec());
    }
    let manifest: Manifest =
        rmp_serde::from_slice(&sealer.open(MANIFEST_STREAM, 0, &manifest_bytes)?)
            .map_err(|_| codec())?;
    if manifest.version != VERSION
        || manifest.kind != prelude.kind.code()
        || manifest.vault_id != prelude.vault_id
        || manifest.snapshot != prelude.snapshot
        || manifest.epoch != EPOCH
        || manifest.created_at != commitment.created_at
        || manifest.key_header != *blake3::hash(&prelude.key_header).as_bytes()
    {
        return Err(codec());
    }
    // The frames between the head and the manifest are exactly the chunks it
    // names, in its order: nothing added, dropped or moved.
    let mut frames = Vec::new();
    let mut at = prelude.end;
    while at < manifest_at {
        let (len, next) = frame_at(&mut file, at)?;
        frames.push((at + 4, len));
        at = next;
    }
    let named = manifest.image.chunks.len()
        + manifest
            .bodies
            .iter()
            .map(|body| body.chunks.len())
            .sum::<usize>();
    if at != manifest_at || frames.len() != named {
        return Err(codec());
    }
    let mut rest = frames.into_iter();
    let image_frames: Vec<_> = rest.by_ref().take(manifest.image.chunks.len()).collect();
    let mut image = Vec::new();
    for (index, (offset, len)) in image_frames.into_iter().enumerate() {
        let envelope = read_at(&mut file, offset, len)?;
        if *blake3::hash(&envelope).as_bytes() != manifest.image.chunks[index] {
            return Err(codec());
        }
        let index = u32::try_from(index).map_err(|_| codec())?;
        image.extend_from_slice(&sealer.open(IMAGE_STREAM, index, &envelope)?);
    }
    if image.len() as u64 != manifest.image.len
        || *blake3::hash(&image).as_bytes() != manifest.image.digest
    {
        return Err(codec());
    }
    let streams: Vec<_> = manifest
        .bodies
        .into_iter()
        .map(|entry| {
            let frames: Vec<_> = rest.by_ref().take(entry.chunks.len()).collect();
            (entry, frames)
        })
        .collect();
    Ok(OpenedArtifact {
        image,
        image_id: manifest.image.digest,
        created_at: manifest.created_at,
        bodies: SealedBodies {
            file,
            sealer,
            streams,
        },
    })
}

/// The commitment or signature frame at `at`: its length, and where the next
/// one starts.
fn signed_frame_at(file: &mut File, at: u64) -> Result<(u64, u64)> {
    let (len, next) = frame_at(file, at)?;
    if len > commitment::MAX_SIGNED_FRAME {
        return Err(codec());
    }
    Ok((len, next))
}

/// The frame at `at`: its envelope's length, and where the next one starts.
fn frame_at(file: &mut File, at: u64) -> Result<(u64, u64)> {
    let len = u32::from_be_bytes(read_at(file, at, 4)?.try_into().map_err(|_| codec())?);
    let len = u64::from(len);
    if len == 0 || len > MAX_FRAME {
        return Err(codec());
    }
    Ok((len, at + 4 + len))
}

fn read_at(file: &mut File, at: u64, len: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(at))?;
    let mut out = vec![0u8; usize::try_from(len).map_err(|_| codec())?];
    file.read_exact(&mut out).map_err(|_| codec())?;
    Ok(out)
}

impl<'k> SealedBodies<'k> {
    /// Each body's BLAKE3 and length, in the manifest's order.
    pub(super) fn list(&self) -> Vec<([u8; 32], u64)> {
        self.streams
            .iter()
            .map(|(entry, _)| (entry.digest, entry.len))
            .collect()
    }

    /// The `index`th body's bytes, each chunk checked and opened as it is read.
    #[cfg(unix)]
    pub(super) fn body(&mut self, index: usize) -> BodyReader<'_, 'k> {
        BodyReader {
            bodies: self,
            index,
            next: 0,
            chunk: Vec::new(),
            at: 0,
        }
    }

    #[cfg(unix)]
    fn chunk(&mut self, index: usize, chunk: usize) -> Result<Option<Vec<u8>>> {
        let (entry, frames) = &self.streams[index];
        let Some(&(offset, len)) = frames.get(chunk) else {
            return Ok(None);
        };
        let digest = entry.chunks[chunk];
        let envelope = read_at(&mut self.file, offset, len)?;
        if *blake3::hash(&envelope).as_bytes() != digest {
            return Err(codec());
        }
        let stream = u32::try_from(index + 1).map_err(|_| codec())?;
        let chunk = u32::try_from(chunk).map_err(|_| codec())?;
        self.sealer.open(stream, chunk, &envelope).map(Some)
    }
}

/// One sealed body, read in the clear.
#[cfg(unix)]
pub(super) struct BodyReader<'a, 'k> {
    bodies: &'a mut SealedBodies<'k>,
    index: usize,
    next: usize,
    chunk: Vec<u8>,
    at: usize,
}

#[cfg(unix)]
impl Read for BodyReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at == self.chunk.len() {
            match self
                .bodies
                .chunk(self.index, self.next)
                .map_err(std::io::Error::other)?
            {
                Some(chunk) => {
                    self.chunk = chunk;
                    self.at = 0;
                    self.next += 1;
                }
                None => return Ok(0),
            }
        }
        let read = out.len().min(self.chunk.len() - self.at);
        out[..read].copy_from_slice(&self.chunk[self.at..self.at + read]);
        self.at += read;
        Ok(read)
    }
}
