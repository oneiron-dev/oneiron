//! Evidence of one sealed artifact, read in one pass with no key: its clear
//! prelude, key header and signed commitment, the BLAKE3 of every byte it
//! holds, and its size; and the check of that evidence against pinned signers.
//!
//! The frames between the key header and the commitment are read through
//! their ONEV headers ([`Header::parse_prefix`]) and streamed, never held:
//!
//! ```text
//! frame*      u32be len ‖ ONEV envelope   chunks: stream 0 (the image),
//!                                         then 1.. (bodies), in order
//! frame*      u32be len ‖ ONEV envelope   the manifest's pieces (stream
//!                                         MAX-1), in order
//! frame       u32be len ‖ ONEV envelope   the sealed manifest root (stream MAX)
//! u32be n ‖ commitment (n)
//! u32be n ‖ signature record (n)
//! u64be offset of the manifest root's frame
//! ```
//!
//! A checkpoint's metadata is streamed into bounded pieces on their own
//! reserved stream, and the frame the commitment names is the fixed-small
//! root after them (FIX 8823): the frame order every reader checks takes
//! them as any other stream's, and the root, the last sealed frame, is the
//! manifest the evidence names. [`inspect_backup_tail`] reads only the clear
//! head and the tail from the root on, for a cheap check of a recorded
//! backup that is no proof of its other bytes.

use std::io::{Read, Seek, SeekFrom};

use super::commitment::{
    CHECKPOINT_SIGNATURE_EPOCH, COMMITMENT_VERSION, COMMITMENT_VERSION_V1, CheckpointSigner,
    Commitment, CustodyRef, MAX_SIGNED_FRAME, commitment_digest, verify_commitment_signature,
};
use super::prelude::{
    ARTIFACT_VERSION_V2, ArtifactPrelude, RegistryMatch, match_binding, read_exact,
};
use super::wire::{ArtifactKind, KeyHeader, MAX_KEY_HEADER_LEN, VaultKeyWrapInfo};
use crate::MAX_PLAINTEXT_LEN;
use crate::envelope::{Header, ONEV_HEADER_PREFIX_MAX, WrapType};
use crate::error::{Error, Result};
use crate::suite::SuiteId;

/// The AEAD suite every artifact frame is sealed with.
pub const ARTIFACT_SEAL_SUITE: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The crypto epoch every artifact frame is sealed at.
pub const ARTIFACT_SEAL_EPOCH: u64 = 1;
/// The stream of the image's chunks; bodies follow at 1, 2, ...
pub const IMAGE_STREAM: u32 = 0;
/// The stream the sealed manifest root is framed under: the last frame.
pub const MANIFEST_STREAM: u32 = u32::MAX;
/// The stream the manifest's pieces are framed under, just before its root
/// (FIX 8823): no body or payload stream takes it.
pub const MANIFEST_PIECE_STREAM: u32 = u32::MAX - 1;
/// Longest frame a reader takes: no envelope's header and tag come near 64 KiB
/// above its plaintext.
pub const MAX_FRAME_LEN: u64 = MAX_PLAINTEXT_LEN as u64 + (1 << 16);

/// Bytes streamed through the hasher at once, past a frame's header.
const SCRATCH_LEN: usize = 64 << 10;

/// What one artifact says of itself in the clear, and what its bytes are.
/// Nothing in it is authentic until [`verify_with_pins`] passes; the outer
/// BLAKE3 and size are facts of the bytes read, which nothing signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupEvidence {
    /// The prelude version.
    pub format_version: u16,
    pub kind: ArtifactKind,
    /// The engine's vault id.
    pub engine_vault_id: [u8; 32],
    /// The prelude's registry binding; `None` for version 1, or where a version
    /// 2 artifact was written with no registry id.
    pub registry_binding: Option<[u8; 32]>,
    pub snapshot: [u8; 32],
    /// The commitment naming the vault data key, as the key header carries it.
    /// Signed in version 2.
    pub key_commitment: [u8; 32],
    /// BLAKE3 of the key header's exact bytes. Signed in version 2.
    pub key_header_blake3: [u8; 32],
    /// The public facts of each vault-key wrap the key header carries.
    pub wrap_refs: Vec<VaultKeyWrapInfo>,
    /// The clear commitment's exact bytes.
    pub commitment_bytes: Vec<u8>,
    /// Those bytes decoded.
    pub commitment: Commitment,
    /// BLAKE3 of the commitment's exact bytes.
    pub commitment_digest: [u8; 32],
    /// The signature record's exact bytes.
    pub signature: Vec<u8>,
    /// BLAKE3 of the sealed manifest's envelope.
    pub manifest_blake3: [u8; 32],
    /// Where the manifest's frame starts.
    pub manifest_offset: u64,
    /// The sealed frames: every chunk, and the manifest.
    pub frames: u64,
    /// BLAKE3 of every byte of the artifact, as held.
    pub outer_blake3: [u8; 32],
    /// The artifact's length in bytes.
    pub size: u64,
}

impl BackupEvidence {
    /// Where the vault's exterior key custody stood at the snapshot, as the
    /// commitment says; `None` for version 1, or where none was published.
    pub fn custody_ref(&self) -> Option<&CustodyRef> {
        self.commitment.custody_ref.as_ref()
    }

    /// How the prelude's registry binding stands against `registry_id`.
    pub fn registry_match(&self, registry_id: &str) -> Result<RegistryMatch> {
        match_binding(self.registry_binding, &self.engine_vault_id, registry_id)
    }
}

/// Reads one sealed artifact of either version from `reader` once, start to
/// end, holding only its clear parts: no seek, no second read, no buffer of
/// the whole. Every byte goes into the outer BLAKE3 and the size. Refused when
/// the bytes are not the format: a frame whose header is not canonical, does
/// not name this artifact's vault, kind, key and snapshot, or whose length is
/// not its header's and ciphertext's; frames out of order; a footer that does
/// not name the manifest; anything after it. Opens nothing.
pub fn inspect_backup<R: Read>(reader: R) -> Result<BackupEvidence> {
    let mut input = Hashed {
        inner: reader,
        hasher: blake3::Hasher::new(),
        size: 0,
    };
    let prelude = ArtifactPrelude::read(&mut input)?;
    let key_header_len = usize::try_from(prelude.key_header_len)
        .ok()
        .filter(|len| *len <= MAX_KEY_HEADER_LEN)
        .ok_or(Error::BackupMalformed("key header length"))?;
    let mut key_header_bytes = vec![0u8; key_header_len];
    read_exact(&mut input, &mut key_header_bytes, "key header")?;
    let key_header = KeyHeader::decode(&key_header_bytes)?;
    let expect = FrameExpect {
        kind: prelude.kind,
        vault_id: &prelude.engine_vault_id,
        key_id: &key_header.commitment,
        snapshot: &prelude.snapshot,
    };
    let mut scratch = vec![0u8; SCRATCH_LEN];
    let mut frames = 0u64;
    let mut last = None;
    let (manifest_offset, manifest_blake3) = loop {
        let at = input.size;
        let frame = read_frame(&mut input, &expect, &mut scratch)?;
        frames = frames
            .checked_add(1)
            .ok_or(Error::BackupMalformed("frame count"))?;
        let next = (frame.stream, frame.index);
        let in_order = match last {
            None => next == (IMAGE_STREAM, 0),
            Some((stream, index)) => {
                (next.0 == stream && Some(next.1) == u32::checked_add(index, 1))
                    || (next.0 > stream && next.1 == 0)
            }
        };
        if !in_order {
            return Err(Error::BackupMalformed("frame order"));
        }
        last = Some(next);
        if let Some(manifest) = frame.manifest {
            break (at, manifest);
        }
    };
    let commitment_bytes = read_signed(&mut input, "commitment")?;
    let signature = read_signed(&mut input, "signature")?;
    let mut footer = [0u8; 8];
    read_exact(&mut input, &mut footer, "footer")?;
    if u64::from_be_bytes(footer) != manifest_offset {
        return Err(Error::BackupMalformed("footer"));
    }
    if !input.at_end()? {
        return Err(Error::BackupMalformed("bytes after the footer"));
    }
    let commitment = Commitment::decode(&commitment_bytes)?;
    Ok(BackupEvidence {
        format_version: prelude.version,
        kind: prelude.kind,
        engine_vault_id: prelude.engine_vault_id,
        registry_binding: prelude.registry_binding,
        snapshot: prelude.snapshot,
        key_commitment: key_header.commitment,
        key_header_blake3: *blake3::hash(&key_header_bytes).as_bytes(),
        wrap_refs: key_header.wrap_infos(),
        commitment_digest: commitment_digest(&commitment_bytes),
        commitment_bytes,
        commitment,
        signature,
        manifest_blake3,
        manifest_offset,
        frames,
        outer_blake3: *input.hasher.finalize().as_bytes(),
        size: input.size,
    })
}

/// Checks `evidence` against signers trusted from outside the artifact: its
/// commitment is signed by one of `pins` (install id and both public keys),
/// with the dual suite, as a `BatchCheckpoint` record, at the signature epoch;
/// and what the commitment signs is what the clear parts say: version, engine
/// vault id, kind, snapshot and sealed manifest, and for version 2 the
/// registry binding, the key header's commitment and its BLAKE3. The
/// evidence's own decoded commitment and digest are recomputed from its bytes,
/// not taken as given. It proves the artifact's clear parts and manifest are
/// the signer's; it opens nothing, so not the image or a body.
pub fn verify_with_pins(evidence: &BackupEvidence, pins: &[CheckpointSigner]) -> Result<()> {
    let commitment = Commitment::decode(&evidence.commitment_bytes)?;
    if commitment != evidence.commitment
        || commitment_digest(&evidence.commitment_bytes) != evidence.commitment_digest
    {
        return Err(Error::BackupCommitmentMismatch("commitment"));
    }
    if !pins.contains(&commitment.signer) {
        return Err(Error::SignerMismatch);
    }
    verify_commitment_signature(
        &evidence.commitment_bytes,
        &evidence.signature,
        &commitment.signer,
    )?;
    signs_clear_parts(
        &commitment,
        &ClearParts {
            format_version: evidence.format_version,
            kind: evidence.kind,
            engine_vault_id: &evidence.engine_vault_id,
            registry_binding: evidence.registry_binding,
            snapshot: &evidence.snapshot,
            key_commitment: &evidence.key_commitment,
            key_header_blake3: &evidence.key_header_blake3,
            manifest_blake3: &evidence.manifest_blake3,
        },
    )
}

/// What an artifact's clear parts say, as a commitment must sign them.
struct ClearParts<'a> {
    format_version: u16,
    kind: ArtifactKind,
    engine_vault_id: &'a [u8; 32],
    registry_binding: Option<[u8; 32]>,
    snapshot: &'a [u8; 32],
    key_commitment: &'a [u8; 32],
    key_header_blake3: &'a [u8; 32],
    manifest_blake3: &'a [u8; 32],
}

/// Whether `commitment` signs what `parts` say: version, epoch, engine vault
/// id, kind, snapshot and sealed manifest, and for version 2 the registry
/// binding, the key header's commitment and its BLAKE3.
fn signs_clear_parts(commitment: &Commitment, parts: &ClearParts<'_>) -> Result<()> {
    let version = if parts.format_version == ARTIFACT_VERSION_V2 {
        COMMITMENT_VERSION
    } else {
        COMMITMENT_VERSION_V1
    };
    let checks: [(bool, &'static str); 9] = [
        (commitment.version == version, "version"),
        (commitment.epoch == CHECKPOINT_SIGNATURE_EPOCH, "epoch"),
        (commitment.vault_id == *parts.engine_vault_id, "vault id"),
        (commitment.kind == parts.kind.code(), "kind"),
        (commitment.snapshot == *parts.snapshot, "snapshot"),
        (commitment.manifest == *parts.manifest_blake3, "manifest"),
        (
            commitment.registry_binding == parts.registry_binding,
            "registry binding",
        ),
        (
            version == COMMITMENT_VERSION_V1
                || commitment.key_commitment == Some(*parts.key_commitment),
            "key commitment",
        ),
        (
            version == COMMITMENT_VERSION_V1
                || commitment.key_header_blake3 == Some(*parts.key_header_blake3),
            "key header",
        ),
    ];
    match checks.into_iter().find(|(holds, _)| !holds) {
        Some((_, field)) => Err(Error::BackupCommitmentMismatch(field)),
        None => Ok(()),
    }
}

/// What the clear head and the tail of one artifact say (FIX 6777), read by
/// [`inspect_backup_tail`]: never a proof of the bytes between them, which
/// only [`inspect_backup`] hashes, nor of anything sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupTailEvidence {
    /// The prelude version.
    pub format_version: u16,
    pub kind: ArtifactKind,
    /// The engine's vault id.
    pub engine_vault_id: [u8; 32],
    pub registry_binding: Option<[u8; 32]>,
    pub snapshot: [u8; 32],
    /// The commitment naming the vault data key, as the key header carries it.
    pub key_commitment: [u8; 32],
    /// The clear commitment, decoded; its signature verifies against the
    /// signer it names, which no pin has vouched for.
    pub commitment: Commitment,
    /// BLAKE3 of the commitment's exact bytes.
    pub commitment_digest: [u8; 32],
    /// BLAKE3 of the sealed manifest root's envelope.
    pub manifest_blake3: [u8; 32],
    /// Where the manifest root's frame starts.
    pub manifest_offset: u64,
    /// The artifact's length in bytes.
    pub size: u64,
}

/// Reads one sealed artifact's clear head and its tail (FIX 6777): the
/// prelude and key header from its start, then from the footer's offset the
/// manifest root's frame, the commitment and the signature record, which end
/// where the footer starts. The commitment must sign those clear parts and
/// the root, and its signature must verify against the signer it names.
/// Each part is bounded as [`inspect_backup`] bounds it; the frames between
/// the head and the root are never read, so this proves neither their bytes
/// nor the artifact's outer BLAKE3, and opens nothing.
pub fn inspect_backup_tail<R: Read + Seek>(mut reader: R) -> Result<BackupTailEvidence> {
    let seek = |error: std::io::Error| Error::BackupRead(error.kind());
    reader.seek(SeekFrom::Start(0)).map_err(seek)?;
    let prelude = ArtifactPrelude::read(&mut reader)?;
    let key_header_len = usize::try_from(prelude.key_header_len)
        .ok()
        .filter(|len| *len <= MAX_KEY_HEADER_LEN)
        .ok_or(Error::BackupMalformed("key header length"))?;
    let mut key_header_bytes = vec![0u8; key_header_len];
    read_exact(&mut reader, &mut key_header_bytes, "key header")?;
    let key_header = KeyHeader::decode(&key_header_bytes)?;
    let head_end = reader.stream_position().map_err(seek)?;
    let size = reader.seek(SeekFrom::End(0)).map_err(seek)?;
    let footer_at = size
        .checked_sub(8)
        .filter(|at| *at >= head_end)
        .ok_or(Error::BackupMalformed("footer"))?;
    reader.seek(SeekFrom::Start(footer_at)).map_err(seek)?;
    let mut footer = [0u8; 8];
    read_exact(&mut reader, &mut footer, "footer")?;
    let manifest_offset = u64::from_be_bytes(footer);
    if manifest_offset < head_end || manifest_offset >= footer_at {
        return Err(Error::BackupMalformed("footer"));
    }
    reader
        .seek(SeekFrom::Start(manifest_offset))
        .map_err(seek)?;
    let expect = FrameExpect {
        kind: prelude.kind,
        vault_id: &prelude.engine_vault_id,
        key_id: &key_header.commitment,
        snapshot: &prelude.snapshot,
    };
    let mut input = Hashed {
        inner: &mut reader,
        hasher: blake3::Hasher::new(),
        size: 0,
    };
    let mut scratch = vec![0u8; SCRATCH_LEN];
    let root = read_frame(&mut input, &expect, &mut scratch)?;
    let (Some(manifest_blake3), 0) = (root.manifest, root.index) else {
        return Err(Error::BackupMalformed("frame order"));
    };
    let commitment_bytes = read_signed(&mut input, "commitment")?;
    let signature = read_signed(&mut input, "signature")?;
    if manifest_offset.checked_add(input.size) != Some(footer_at) {
        return Err(Error::BackupMalformed("footer"));
    }
    let commitment = Commitment::decode(&commitment_bytes)?;
    verify_commitment_signature(&commitment_bytes, &signature, &commitment.signer)?;
    let key_header_blake3 = *blake3::hash(&key_header_bytes).as_bytes();
    signs_clear_parts(
        &commitment,
        &ClearParts {
            format_version: prelude.version,
            kind: prelude.kind,
            engine_vault_id: &prelude.engine_vault_id,
            registry_binding: prelude.registry_binding,
            snapshot: &prelude.snapshot,
            key_commitment: &key_header.commitment,
            key_header_blake3: &key_header_blake3,
            manifest_blake3: &manifest_blake3,
        },
    )?;
    Ok(BackupTailEvidence {
        format_version: prelude.version,
        kind: prelude.kind,
        engine_vault_id: prelude.engine_vault_id,
        registry_binding: prelude.registry_binding,
        snapshot: prelude.snapshot,
        key_commitment: key_header.commitment,
        commitment_digest: commitment_digest(&commitment_bytes),
        commitment,
        manifest_blake3,
        manifest_offset,
        size,
    })
}

/// What every sealed frame of one artifact must name.
struct FrameExpect<'a> {
    kind: ArtifactKind,
    vault_id: &'a [u8; 32],
    key_id: &'a [u8; 32],
    snapshot: &'a [u8; 32],
}

/// One sealed frame as read: its place, and for the manifest its envelope's
/// BLAKE3.
struct FrameRead {
    stream: u32,
    index: u32,
    manifest: Option<[u8; 32]>,
}

/// Reads one `u32be len ‖ envelope` frame: its header through
/// [`Header::parse_prefix`], its ciphertext streamed through `scratch`.
fn read_frame<R: Read>(
    input: &mut Hashed<R>,
    expect: &FrameExpect<'_>,
    scratch: &mut [u8],
) -> Result<FrameRead> {
    let mut len = [0u8; 4];
    read_exact(input, &mut len, "frame length")?;
    let len = u64::from(u32::from_be_bytes(len));
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(Error::BackupMalformed("frame length"));
    }
    let head_len = usize::try_from(len)
        .map_err(|_| Error::BackupMalformed("frame length"))?
        .min(ONEV_HEADER_PREFIX_MAX);
    let mut head = vec![0u8; head_len];
    read_exact(input, &mut head, "frame")?;
    let (header, used) =
        Header::parse_prefix(&head).map_err(|_| Error::BackupMalformed("frame header"))?;
    let framed = (used as u64).checked_add(u64::from(header.ciphertext_len));
    if framed != Some(len) {
        return Err(Error::BackupMalformed("frame length"));
    }
    let (stream, index) = frame_place(&header, expect)?;
    let mut envelope = (stream == MANIFEST_STREAM).then(|| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&head);
        hasher
    });
    let mut rest = len - head_len as u64;
    while rest > 0 {
        let take = scratch
            .len()
            .min(usize::try_from(rest).unwrap_or(usize::MAX));
        read_exact(input, &mut scratch[..take], "frame")?;
        if let Some(hasher) = envelope.as_mut() {
            hasher.update(&scratch[..take]);
        }
        rest -= take as u64;
    }
    Ok(FrameRead {
        stream,
        index,
        manifest: envelope.map(|hasher| *hasher.finalize().as_bytes()),
    })
}

/// A frame header's stream and index, once it names this artifact: its kind's
/// purpose, vault, key commitment, snapshot, symmetric wrap, suite and epoch.
/// The recipient is `snapshot ‖ u32be stream ‖ u32be index`.
fn frame_place(header: &Header, expect: &FrameExpect<'_>) -> Result<(u32, u32)> {
    let recipient = &header.recipient;
    let names_artifact = header.purpose == expect.kind.purpose()
        && header.vault_id[..] == expect.vault_id[..]
        && header.key_id[..] == expect.key_id[..]
        && header.wrap == WrapType::SymmetricKek
        && header.suite == ARTIFACT_SEAL_SUITE
        && header.epoch == ARTIFACT_SEAL_EPOCH
        && recipient.len() == 40
        && recipient[..32] == expect.snapshot[..];
    if !names_artifact {
        return Err(Error::BackupMalformed("frame header"));
    }
    let word = |at: usize| {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&recipient[at..at + 4]);
        u32::from_be_bytes(bytes)
    };
    Ok((word(32), word(36)))
}

/// A `u32be len ‖ bytes` commitment or signature frame, held whole.
fn read_signed<R: Read>(input: &mut Hashed<R>, field: &'static str) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    read_exact(input, &mut len, field)?;
    let len = u32::from_be_bytes(len);
    if len == 0 || u64::from(len) > MAX_SIGNED_FRAME {
        return Err(Error::BackupMalformed(field));
    }
    let mut bytes = vec![0u8; len as usize];
    read_exact(input, &mut bytes, field)?;
    Ok(bytes)
}

/// A reader that hashes and counts every byte it hands on.
struct Hashed<R> {
    inner: R,
    hasher: blake3::Hasher,
    size: u64,
}

impl<R: Read> Hashed<R> {
    /// Whether the input ends here.
    fn at_end(&mut self) -> Result<bool> {
        let mut probe = [0u8; 1];
        loop {
            match self.read(&mut probe) {
                Ok(read) => return Ok(read == 0),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::BackupRead(error.kind())),
            }
        }
    }
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(out)?;
        self.hasher.update(&out[..read]);
        self.size = self
            .size
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("artifact size overflows"))?;
        Ok(read)
    }
}
