//! Writing a sealed artifact: the envelopes one artifact's chunks seal into,
//! and the sink that streams the image and each body into them.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, WrapType, seal,
};

use super::commitment::{self, ChainHead, Link};
use super::{
    AEAD, ArtifactKind, CHUNK_LEN, CheckpointKey, EPOCH, IMAGE_STREAM, MAGIC, MANIFEST_STREAM,
    MAX_KEY_HEADER, Manifest, StreamEntry, VERSION, ZSTD_LEVEL, codec,
};
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
/// each body `open_body` hands back by its place in `bodies`, then the
/// manifest, then the commitment `link` signs. Returns the image's BLAKE3 and
/// the chain head the signed commitment makes. A write that fails removes the
/// file, so no part of one is left.
#[allow(clippy::too_many_arguments)]
pub(in crate::recovery::checkpoint) fn write_artifact(
    path: &Path,
    key: &CheckpointKey,
    kind: ArtifactKind,
    carried: &CarriedVaultKey,
    link: &Link,
    created_at: u64,
    image: &[u8],
    bodies: &[ArtifactBody],
    mut open_body: impl FnMut(usize) -> Result<Box<dyn Read + Send>>,
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
    for (index, body) in bodies.iter().enumerate() {
        let stream = u32::try_from(index + 1)
            .ok()
            .filter(|stream| *stream != MANIFEST_STREAM)
            .ok_or_else(codec)?;
        let entry = sink.stream(stream, &mut open_body(index)?)?;
        // A body file is named by its digest; one that reads otherwise is
        // refused here, not found out at a restore.
        if entry.len != body.len || body.digest.is_some_and(|digest| digest != entry.digest) {
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
