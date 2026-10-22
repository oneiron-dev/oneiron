//! Writing a sealed artifact: the envelopes one artifact's chunks seal into,
//! and the sink that streams the image, each body and the manifest's pieces
//! into them.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use getrandom::SysRng;
use oneiron_crypto::backup::{
    ArtifactPrelude, BackupEvidence, MANIFEST_PIECE_STREAM, registry_binding,
};
use oneiron_crypto::{
    Argon2Cost, Envelope, MAX_PLAINTEXT_LEN, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    WrapType, seal,
};

use super::commitment::{self, ChainHead, Link, SignedRefs};
use super::manifest::{self, Manifest, StreamEntry};
use super::{
    AEAD, ArtifactKind, CHUNK_LEN, CheckpointKey, EPOCH, IMAGE_STREAM, MAX_FRAME, MAX_KEY_HEADER,
    PRELUDE_LEN, VERSION, ZSTD_LEVEL, codec, custody_ref,
};
use crate::recovery::checkpoint::payload::PayloadStreams;
use crate::recovery::checkpoint::write_budget::{self, RecoveryWriteBudget};
use crate::world_keys::{CarriedVaultKey, refused};
use crate::{Error, Result};

/// Seals and opens one artifact's envelopes.
pub(super) struct Sealer<'k> {
    pub(super) key: &'k CheckpointKey,
    pub(super) purpose: Purpose,
    pub(super) commitment: [u8; 32],
    pub(super) snapshot: [u8; 32],
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

    pub(super) fn seal(&self, stream: u32, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
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

    pub(super) fn open(&self, stream: u32, index: u32, envelope: &[u8]) -> Result<Vec<u8>> {
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

/// What one carried body's stream must be (FIX 5348).
pub(in crate::recovery::checkpoint) struct ArtifactBody {
    /// Its length as it rests: the body's own, or its envelope's.
    pub(in crate::recovery::checkpoint) len: u64,
    /// The BLAKE3 of a plain body's bytes. An envelope's stream checks each
    /// of its frames, and the body they hold, as the artifact reads it.
    pub(in crate::recovery::checkpoint) digest: Option<[u8; 32]>,
}

/// Writes the artifact at `path`, create-new and owner-only: the image, then
/// each body `open_body` hands back by its place in `bodies`, then each of
/// `payload`'s streams (KS-7; `None` writes none), then the manifest's
/// pieces and root (`manifest`, FIX 8823), then the commitment `link`
/// signs. Its prelude and commitment
/// carry the binding of the vault id to `registry`, the registry's id for
/// the vault, or say none was known (FIX 5826). Returns the image's BLAKE3,
/// the chain head the signed commitment makes, and the artifact's evidence
/// as the shared inspector reads it back (`oneiron_crypto::backup`): every
/// byte written goes into its outer BLAKE3. A write that fails removes the
/// file, so no part of one is left. The artifact's room is claimed on
/// `budget` before its first byte, at [`artifact_room`], and set to what is
/// left before each frame (FIX 5479); a claim the floor refuses fails the
/// write.
#[allow(clippy::too_many_arguments)]
pub(in crate::recovery::checkpoint) fn write_artifact(
    path: &Path,
    key: &CheckpointKey,
    kind: ArtifactKind,
    registry: Option<&str>,
    carried: &CarriedVaultKey,
    link: &Link,
    custody: Option<&crate::store::CustodyRequirement>,
    created_at: u64,
    image: &[u8],
    bodies: &[ArtifactBody],
    mut open_body: impl FnMut(usize) -> Result<Box<dyn Read + Send>>,
    payload: Option<&PayloadStreams>,
    budget: &dyn RecoveryWriteBudget,
) -> Result<([u8; 32], ChainHead, BackupEvidence)> {
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
    let key_header = carried.encode()?;
    let len = u32::try_from(key_header.len())
        .ok()
        .filter(|len| *len as usize <= MAX_KEY_HEADER)
        .ok_or_else(codec)?;
    let binding = registry
        .map(|registry| registry_binding(&key.vault_id, registry))
        .transpose()
        .map_err(|_| codec())?;
    let prelude = ArtifactPrelude {
        version: VERSION,
        kind,
        engine_vault_id: key.vault_id,
        registry_binding: binding,
        snapshot,
        key_header_len: len,
    }
    .encode()
    .map_err(|_| codec())?;
    let mut sink = Sink {
        out: BufWriter::new(file),
        offset: 0,
        outer: blake3::Hasher::new(),
        sealer: Sealer {
            key,
            purpose: kind.purpose(),
            commitment: *carried.commitment(),
            snapshot,
        },
        room: artifact_room(key_header.len(), image.len(), bodies, payload).saturating_add(
            manifest::manifest_room(
                kind.code(),
                custody,
                payload.map(|payload| &payload.section),
                image.len() as u64,
                &bodies.iter().map(|body| body.len).collect::<Vec<_>>(),
                &payload
                    .iter()
                    .flat_map(|payload| payload.streams.iter())
                    .map(|bytes| bytes.len() as u64)
                    .collect::<Vec<_>>(),
            )?,
        ),
        budget,
    };
    sink.claim_rest()?;
    sink.put(&prelude)?;
    sink.put(&key_header)?;
    let image = sink.stream(IMAGE_STREAM, &mut &image[..])?;
    let mut sealed_bodies = Vec::with_capacity(bodies.len());
    for (index, body) in bodies.iter().enumerate() {
        let stream = data_stream(index + 1)?;
        let entry = sink.stream(stream, &mut open_body(index)?)?;
        // A body file is named by its digest; one that reads otherwise is
        // refused here, not found out at a restore.
        if entry.len != body.len || body.digest.is_some_and(|digest| digest != entry.digest) {
            return Err(Error::CorruptedIndex("code-run result body file"));
        }
        sealed_bodies.push(entry);
    }
    // Each payload bundle's stream follows the bodies', sealed already
    // under its compartment's key (KS-7).
    let mut payload_streams = Vec::new();
    for (index, bytes) in payload
        .iter()
        .flat_map(|payload| payload.streams.iter())
        .enumerate()
    {
        let stream = data_stream(bodies.len() + 1 + index)?;
        payload_streams.push(sink.stream(stream, &mut bytes.as_slice())?);
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
        custody: custody.cloned(),
        payload: payload.map(|payload| payload.section.clone()),
        payload_streams,
    };
    let (manifest_at, manifest_blake3, pieces) = manifest::write_manifest(&mut sink, &manifest)?;
    let commitment = commitment::new_commitment(
        link,
        key.vault_id,
        kind.code(),
        snapshot,
        manifest_blake3,
        created_at,
        SignedRefs {
            registry_binding: binding,
            key_commitment: *carried.commitment(),
            key_header_blake3: manifest.key_header,
            custody_ref: custody_ref(custody)?,
        },
    )?;
    let (commitment_bytes, signature, head) = link.sign(&commitment)?;
    sink.frame(&commitment_bytes)?;
    sink.frame(&signature)?;
    sink.put(&manifest_at.to_be_bytes())?;
    let frames = std::iter::once(&manifest.image)
        .chain(&manifest.bodies)
        .chain(&manifest.payload_streams)
        .map(|stream| stream.chunks.len() as u64)
        .sum::<u64>()
        + u64::from(pieces)
        + 1;
    let evidence = BackupEvidence {
        format_version: VERSION,
        kind,
        engine_vault_id: key.vault_id,
        registry_binding: binding,
        snapshot,
        key_commitment: *carried.commitment(),
        key_header_blake3: manifest.key_header,
        wrap_refs: carried.wrap_infos(),
        commitment_digest: head.digest(),
        commitment_bytes,
        commitment,
        signature,
        manifest_blake3,
        manifest_offset: manifest_at,
        frames,
        outer_blake3: *sink.outer.finalize().as_bytes(),
        size: sink.offset,
    };
    let file = sink.out.into_inner().map_err(|error| error.into_error())?;
    file.sync_all()?;
    partial.0 = None;
    Ok((manifest.image.digest, head, evidence))
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

/// The stream number of the `index`th data stream (the image's is 0): one
/// below the manifest's reserved pieces and root (FIX 8823).
fn data_stream(index: usize) -> Result<u32> {
    u32::try_from(index)
        .ok()
        .filter(|stream| *stream < MANIFEST_PIECE_STREAM)
        .ok_or_else(codec)
}

/// The most one frame of `plain` bytes takes: its zstd bound plus the slack
/// [`MAX_FRAME`] leaves an envelope over its plaintext, and its length.
pub(super) fn frame_room(plain: usize) -> u64 {
    let slack = MAX_FRAME.saturating_sub(MAX_PLAINTEXT_LEN as u64);
    (zstd::zstd_safe::compress_bound(plain) as u64).saturating_add(slack.saturating_add(4))
}

/// The most a stream of `len` bytes takes, chunked and framed.
pub(super) fn stream_room(len: u64) -> u64 {
    let chunk = CHUNK_LEN as u64;
    let rest = len % chunk;
    (len / chunk)
        .saturating_mul(frame_room(CHUNK_LEN))
        .saturating_add(if rest == 0 {
            0
        } else {
            frame_room(rest as usize)
        })
}

/// The most an artifact of these streams takes on the disk (FIX 5479), its
/// manifest aside ([`manifest::manifest_room`]): its prelude and key header;
/// each stream's chunks framed at their zstd bound plus the slack
/// [`MAX_FRAME`] leaves an envelope over its plaintext; and the commitment
/// and signature at the most a reader takes of each, with the closing
/// offset. A bound read off the streams' lengths, never a guess at what they
/// compress to; a payload's streams count as a body's (KS-7).
fn artifact_room(
    key_header: usize,
    image: usize,
    bodies: &[ArtifactBody],
    payload: Option<&PayloadStreams>,
) -> u64 {
    let tail = commitment::MAX_SIGNED_FRAME
        .saturating_mul(2)
        .saturating_add(4 * 2 + 8);
    let payload = payload.iter().flat_map(|payload| payload.streams.iter());
    bodies
        .iter()
        .map(|body| body.len)
        .chain(payload.map(|bytes| bytes.len() as u64))
        .fold(
            ((PRELUDE_LEN + key_header) as u64)
                .saturating_add(stream_room(image as u64))
                .saturating_add(tail),
            |room, len| room.saturating_add(stream_room(len)),
        )
}

pub(super) struct Sink<'k> {
    out: BufWriter<File>,
    pub(super) offset: u64,
    /// BLAKE3 of every byte written: the evidence's outer digest.
    outer: blake3::Hasher,
    pub(super) sealer: Sealer<'k>,
    /// The most the artifact takes ([`artifact_room`]).
    room: u64,
    /// The floor the artifact's writes claim their room on.
    budget: &'k dyn RecoveryWriteBudget,
}

impl Sink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes)?;
        self.outer.update(bytes);
        self.offset += bytes.len() as u64;
        Ok(())
    }

    /// Claims what is left of the artifact's room.
    fn claim_rest(&self) -> Result<()> {
        write_budget::hold(self.budget, self.room.saturating_sub(self.offset))
    }

    pub(super) fn frame(&mut self, envelope: &[u8]) -> Result<()> {
        self.claim_rest()?;
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
