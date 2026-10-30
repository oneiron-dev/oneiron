//! Sealed checkpoint artifacts (OF-570 (c)). A checkpoint or an owner's backup
//! leaves the vault only as E0 symmetric envelopes, under a key derived from
//! the vault data key (`oneiron/checkpoint-seal/v1`). One file:
//!
//! ```text
//! "ONEIRONS" ‖ u16be 2 ‖ u8 kind ‖ vault id (32)
//!   ‖ u8 has_registry ‖ registry binding (32) ‖ snapshot id (32)
//!   ‖ u32be n ‖ key header (n)    the vault key's commitment and sealed wraps
//!   ‖ frame*                      the image's chunks, then each body's in order
//!   ‖ frame*                      the manifest's pieces (`manifest`)
//!   ‖ frame                       the manifest's sealed root
//!   ‖ u32be n ‖ commitment (n)    clear, signed (`commitment`)
//!   ‖ u32be n ‖ signature (n)     E0 dual Ed25519 + SLH-DSA record
//!   ‖ u64be offset of the manifest root's frame
//! frame = u32be len ‖ E0 envelope
//! ```
//!
//! A chunk is up to 4 MiB of one stream, zstd-compressed, then sealed. Its
//! envelope binds the vault, the epoch, the vault key's commitment, the kind's
//! purpose (`CheckpointArtifact` or `BackupArtifact`) and, as its recipient,
//! the snapshot id, its stream and its place in it. The manifest, sealed last
//! in bounded pieces under a fixed-small root (FIX 8823), names the complete
//! set in order: the image's length and BLAKE3, each result body's, the BLAKE3
//! of every chunk's envelope, and the key header's. A reader opens the
//! manifest and every image chunk before a byte of the image is
//! decoded or anything is made; a body's chunks are opened, each checked
//! against the manifest, as the body is read back into the restored vault.
//!
//! The key header holds no key: it lets a host without the vault unlock the
//! artifact's key from one wrap ([`CheckpointKey::unlock`]). Claim keys and
//! body instance keys are never in an image either, nor a wrap that
//! recovers one: exterior custody stays live (`checkpoint_custody`), and each
//! body travels sealed under its instance's key (KS-2A).
//!
//! The commitment names the sealed manifest root by digest, and a reader
//! verifies its signature against the signers its key trusts before the
//! manifest opens (`commitment`).
//!
//! The registry binding (FIX 5826) ties the engine's vault id to the
//! registry's id for the vault, where the host that took the artifact knew
//! one: `BLAKE3-derive_key("oneiron/backup-registry-binding/v1", vault id ‖
//! u32be id length ‖ id)`, or `0 ‖ zero (32)` where it knew none. The
//! commitment signs the same binding, with the key header's commitment and
//! BLAKE3 and the custody position, so a host that never opens the artifact
//! reads them signed. A reader compares the binding with the signed one,
//! never with where it restores to. The prelude, key header and commitment
//! codecs are the shared ones in `oneiron_crypto::backup`; the engine reads
//! version 2 only.
mod manifest;
mod payload_inventory;
mod sink;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use oneiron_crypto::Kek;
pub use oneiron_crypto::backup::ArtifactKind;
use oneiron_crypto::backup::{
    ARTIFACT_SEAL_EPOCH as EPOCH, ARTIFACT_SEAL_SUITE as AEAD, ARTIFACT_VERSION_V2 as VERSION,
    ArtifactPrelude, CustodyRef, IMAGE_STREAM, MANIFEST_PIECE_STREAM, MAX_FRAME_LEN as MAX_FRAME,
    MAX_KEY_HEADER_LEN as MAX_KEY_HEADER, PRELUDE_V2_LEN as PRELUDE_LEN,
};

use self::manifest::StreamEntry;
pub(super) use self::payload_inventory::write_payload_inventory;
use self::sink::Sealer;
pub(super) use self::sink::{ArtifactBody, write_artifact};
use super::admission::{
    RestoreAdmissionError, RestoreAdmissionReason, RestoreDestinationState, RestorePhase,
    SourceExpectation,
};
use super::commitment::{self, CheckpointSigner, Trust};
use super::payload::PayloadSection;
use crate::world_keys::{
    CarriedVaultKey, OpenedDataKey, VaultKeyUnlock, VaultKeyWrapInfo, VaultPageSeal, refused,
};
use crate::{Error, Result, Vault};

const SEAL_CONTEXT: &str = "oneiron/checkpoint-seal/v1";
/// Plaintext per chunk, before compression: well under E0's 16 MiB. A
/// payload compartment's pieces are as long (KS-7).
pub(super) const CHUNK_LEN: usize = 4 << 20;
pub(super) const ZSTD_LEVEL: i32 = 3;

fn codec() -> Error {
    Error::CorruptedIndex("sealed checkpoint artifact")
}

/// The prelude's registry binding is not the one its commitment signs: a
/// corrupt artifact, named with no bytes of either.
fn binding_mismatch() -> Error {
    Error::CorruptedIndex("sealed checkpoint artifact registry binding")
}

/// The key one vault's sealed checkpoints and backups open with, derived from
/// its data key and never stored, and whose signatures it accepts. The open
/// vault gives it, trusting this device's signer ([`Vault::checkpoint_key`]); a
/// host without the vault unlocks it from a wrap the artifact carries
/// ([`CheckpointKey::unlock`]) and says whom it trusts.
pub struct CheckpointKey {
    pub(super) vault_id: [u8; 32],
    kek: Kek,
    /// The data key's custody-head subkey, which opens a custody head's
    /// host-readable compartments on a host without the vault (KS-4).
    custody_wrap: zeroize::Zeroizing<[u8; 32]>,
    trust: Trust,
    /// The data key a carried wrap opened to, kept opaque for a sealed vault
    /// restored from the artifact ([`Self::restored_page_seal`]); `None` for
    /// the key an open vault gives.
    opened: Option<OpenedDataKey>,
    /// What a cold managed restore's plan expects of the artifact, for the
    /// key [`CheckpointKey::from_delivered`] made; `None` for every other.
    expected: Option<Box<SourceExpectation>>,
    /// The least checkpoint sequence a wake or migrate takes (OF-570 (e)):
    /// set only by [`CheckpointKey::with_wake_sequence_floor`]; `None` for a
    /// historical restore and a local open, which compare nothing.
    wake_floor: Option<u64>,
    /// The family a host's worker opened from the artifact's host-private
    /// member, for a cold restore (`with_artifact_host_holds`, FIX 6817).
    pub(super) artifact_host_holds: Option<Box<super::ArtifactHostOrderHolds>>,
    /// The signers the vault's mode roots delegated, trusted beside `trust`
    /// (`trusting_mode_roots`, FIX 968).
    pub(super) delegated: Option<Box<super::signer_delegation::DelegatedSigners>>,
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
        let (key, opened) =
            prelude
                .carried()?
                .subkey_opened(&prelude.vault_id, unlock, SEAL_CONTEXT)?;
        Ok(Self {
            vault_id: prelude.vault_id,
            kek: Kek::from_zeroizing(key),
            custody_wrap: opened.subkey(crate::store::CUSTODY_HEAD_WRAP_CONTEXT),
            trust: Trust::Nobody,
            opened: Some(opened),
            expected: None,
            wake_floor: None,
            artifact_host_holds: None,
            delegated: None,
        })
    }

    /// The key of a cold managed restore (LC FIX 5384/5385), from the data
    /// key `dek` its supervisor delivered: copied into guarded storage, its
    /// commitment under the plan's source vault id checked against the
    /// plan's, and trusting the plan's external signer pins alone. It opens
    /// the artifact as the SOURCE vault's: its page seal is a fresh
    /// incarnation under that vault id and key, never a new vault, and
    /// nothing leaves as bytes or is rekeyed.
    /// [`Vault::restore_checkpoint_admitted`] checks the artifact against
    /// `expected` before it opens.
    ///
    /// # Errors
    /// `data_key_mismatch` when the delivered key is not the one the plan
    /// names.
    pub fn from_delivered(
        dek: &[u8; 32],
        expected: &SourceExpectation,
    ) -> std::result::Result<Self, RestoreAdmissionError> {
        let opened = OpenedDataKey::delivered(expected.engine_vault_id, dek);
        if opened.commitment() != expected.data_key_commitment {
            return Err(RestoreAdmissionError::new(
                RestoreAdmissionReason::DataKeyMismatch,
                RestorePhase::SourceCheck,
                RestoreDestinationState::Removed,
                refused("the delivered key is not the data key the restore plan names"),
            ));
        }
        Ok(Self {
            vault_id: expected.engine_vault_id,
            kek: Kek::from_zeroizing(opened.subkey(SEAL_CONTEXT)),
            custody_wrap: opened.subkey(crate::store::CUSTODY_HEAD_WRAP_CONTEXT),
            trust: Trust::Pinned(expected.signer_pins.clone()),
            opened: Some(opened),
            expected: Some(Box::new(expected.clone())),
            wake_floor: None,
            artifact_host_holds: None,
            delegated: None,
        })
    }

    /// This key, refusing an artifact whose signed checkpoint sequence is
    /// below `floor` (OF-570 (e)): the explicit floor a wake or migrate
    /// supervisor gives from the copy it verified, so an older copy of the
    /// same vault is never woken in its place. The comparison runs once the
    /// signature and every binding checked, before the manifest opens; a
    /// copy below it is refused as [`CheckpointSequenceBelowFloor`]. Nothing
    /// else sets one: a historical restore and a local open compare nothing.
    #[must_use]
    pub fn with_wake_sequence_floor(mut self, floor: u64) -> Self {
        self.wake_floor = Some(floor);
        self
    }

    /// The plan's expectation, for a key [`Self::from_delivered`] made.
    pub(super) fn expected(&self) -> Option<&SourceExpectation> {
        self.expected.as_deref()
    }

    /// The data key a delivered or carried wrap's key came from, opaque.
    pub(super) fn opened(&self) -> Option<&OpenedDataKey> {
        self.opened.as_ref()
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

    /// A page seal for a sealed vault restored from this key's artifact where
    /// no vault is (OF-570 maximum tier): the artifact's vault id and data
    /// key under a fresh incarnation. The key never leaves as bytes. `None`
    /// for the key an open vault gave ([`Vault::checkpoint_key`]), whose own
    /// seal gives a fresh incarnation instead.
    pub fn restored_page_seal(&self) -> Result<Option<VaultPageSeal>> {
        self.opened
            .as_ref()
            .map(OpenedDataKey::restored_page_seal)
            .transpose()
    }

    /// The custody-head subkey of the data key this key came from (KS-4).
    pub(super) fn custody_wrap(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.custody_wrap.clone()
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
            kek: Kek::from_zeroizing(self.vault_subkey(SEAL_CONTEXT)?),
            custody_wrap: self.vault_subkey(crate::store::CUSTODY_HEAD_WRAP_CONTEXT)?,
            trust: Trust::Device(self.device_keystore()?),
            opened: None,
            expected: None,
            wake_floor: None,
            artifact_host_holds: None,
            delegated: None,
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
                kek: Kek::from_zeroizing(key),
                custody_wrap: self.vault_subkey(crate::store::CUSTODY_HEAD_WRAP_CONTEXT)?,
                trust: Trust::Nobody,
                opened: None,
                expected: None,
                wake_floor: None,
                artifact_host_holds: None,
                delegated: None,
            },
        ))
    }
}

/// Why a wake or migrate refused an artifact (OF-570 (e)): its signed
/// checkpoint sequence is below the explicit floor its key carries
/// ([`CheckpointKey::with_wake_sequence_floor`]). It comes as an
/// [`std::io::ErrorKind::InvalidData`] error; [`Self::of`] reads it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointSequenceBelowFloor {
    /// The least sequence the wake or migrate takes.
    pub floor: u64,
    /// The sequence the artifact's verified commitment signs.
    pub observed: u64,
}

impl CheckpointSequenceBelowFloor {
    /// This refusal, if `error` is one.
    #[must_use]
    pub fn of(error: &Error) -> Option<&Self> {
        let Error::Io(io) = error else {
            return None;
        };
        io.get_ref()?.downcast_ref::<Self>()
    }

    fn into_error(self) -> Error {
        Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, self))
    }
}

impl std::fmt::Display for CheckpointSequenceBelowFloor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the checkpoint's signed sequence {} is below the floor {} this wake or migrate \
             takes: an older copy of the vault",
            self.observed, self.floor
        )
    }
}

impl std::error::Error for CheckpointSequenceBelowFloor {}

/// The clear head of an artifact file.
struct Prelude {
    kind: ArtifactKind,
    vault_id: [u8; 32],
    /// The registry binding the prelude carries, if any (FIX 5826).
    registry_binding: Option<[u8; 32]>,
    snapshot: [u8; 32],
    key_header: Vec<u8>,
    /// Where the first frame starts.
    end: u64,
}

impl Prelude {
    /// The shared prelude codec's read, version 2 only.
    fn read(file: &mut File) -> Result<Self> {
        let fixed = ArtifactPrelude::read(file).map_err(|_| codec())?;
        let len = fixed.key_header_len as usize;
        if fixed.version != VERSION || len > MAX_KEY_HEADER {
            return Err(codec());
        }
        let mut key_header = vec![0u8; len];
        file.read_exact(&mut key_header).map_err(|_| codec())?;
        Ok(Self {
            kind: fixed.kind,
            vault_id: fixed.engine_vault_id,
            registry_binding: fixed.registry_binding,
            snapshot: fixed.snapshot,
            key_header,
            end: (PRELUDE_LEN + len) as u64,
        })
    }

    fn carried(&self) -> Result<CarriedVaultKey> {
        CarriedVaultKey::decode(&self.key_header)
    }
}

/// An artifact whose manifest and image have opened.
pub(super) struct OpenedArtifact<'k> {
    pub(super) image: Vec<u8>,
    /// BLAKE3 of the image: the checkpoint id.
    pub(super) image_id: [u8; 32],
    /// BLAKE3 of the signed commitment's exact bytes.
    pub(super) commitment_digest: [u8; 32],
    pub(super) created_at: u64,
    pub(super) bodies: SealedBodies<'k>,
    /// The manifest's custody requirement (KS-4).
    pub(super) custody: Option<crate::store::CustodyRequirement>,
    /// The checkpoint sequence its verified commitment signs (OF-570 (e)).
    pub(super) sequence: u64,
    /// The snapshot id its verified commitment signs.
    pub(super) snapshot: [u8; 32],
}

/// The result bodies an opened artifact carries, each read back through its
/// sealed chunks.
pub(super) struct SealedBodies<'k> {
    file: File,
    sealer: Sealer<'k>,
    /// Each body's manifest line and its frames (offset, length).
    streams: Vec<(StreamEntry, Vec<(u64, u64)>)>,
    /// The payload compartments it carries, apart from its bodies (KS-7).
    pub(super) payload: Option<SealedPayload<'k>>,
}

/// Opens the artifact at `path` with `key`: its manifest, checked against the
/// clear head, the complete set of frames, and the image, before any of the
/// image is decoded. Refuses another vault's artifact before anything opens.
pub(super) fn open_artifact<'k>(path: &Path, key: &'k CheckpointKey) -> Result<OpenedArtifact<'k>> {
    open_artifact_file(File::open(path)?, key)
}

/// [`open_artifact`] on a file already open: a cold managed restore opens
/// the very file it inspected, never its path again.
pub(super) fn open_artifact_file(
    mut file: File,
    key: &CheckpointKey,
) -> Result<OpenedArtifact<'_>> {
    file.seek(SeekFrom::Start(0))?;
    let prelude = Prelude::read(&mut file)?;
    if prelude.vault_id != key.vault_id {
        return Err(refused("the checkpoint is another vault's"));
    }
    let carried = prelude.carried()?;
    let sealer = Sealer {
        key,
        purpose: prelude.kind.purpose(),
        commitment: *carried.commitment(),
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
    let commitment_bytes = read_at(&mut file, signed_at + 4, commitment_len)?;
    let commitment = commitment::verify(
        &key.trust,
        key.delegated_signers(),
        &key.vault_id,
        &commitment_bytes,
        &read_at(&mut file, record_at + 4, record_len)?,
    )?;
    if commitment.kind != prelude.kind.code()
        || commitment.snapshot != prelude.snapshot
        || commitment.manifest != *blake3::hash(&manifest_bytes).as_bytes()
        || manifest_at + 4 + manifest_len != signed_at
        || commitment.key_commitment != Some(*carried.commitment())
        || commitment.key_header_blake3 != Some(*blake3::hash(&prelude.key_header).as_bytes())
    {
        return Err(codec());
    }
    // The prelude's registry binding is the one the signature covers (FIX
    // 5826), compared after the signature verifies and never with where the
    // artifact restores to.
    if commitment.registry_binding != prelude.registry_binding {
        return Err(binding_mismatch());
    }
    // An explicit wake or migrate floor (OF-570 (e)) is compared with the
    // signed sequence once every check above passed, before the manifest
    // opens.
    if let Some(floor) = key.wake_floor
        && commitment.sequence < floor
    {
        return Err(CheckpointSequenceBelowFloor {
            floor,
            observed: commitment.sequence,
        }
        .into_error());
    }
    // The manifest's root, then its pieces, each checked before the encoding
    // they hold is read (FIX 8823).
    let (manifest, pieces_at) = manifest::read_manifest(
        &mut file,
        &sealer,
        (manifest_at, manifest_bytes.as_slice()),
        prelude.end,
    )?;
    if manifest.version != VERSION
        || manifest.kind != prelude.kind.code()
        || manifest.vault_id != prelude.vault_id
        || manifest.snapshot != prelude.snapshot
        || manifest.epoch != EPOCH
        || manifest.created_at != commitment.created_at
        || manifest.key_header != *blake3::hash(&prelude.key_header).as_bytes()
        || commitment.custody_ref != custody_ref(manifest.custody.as_ref())?
    {
        return Err(codec());
    }
    // The frames between the head and the manifest's pieces are exactly the
    // chunks it names, in its order: nothing added, dropped or moved.
    let mut frames = Vec::new();
    let mut at = prelude.end;
    while at < pieces_at {
        let (len, next) = frame_at(&mut file, at)?;
        frames.push((at + 4, len));
        at = next;
    }
    let named = manifest.image.chunks.len()
        + manifest
            .bodies
            .iter()
            .chain(&manifest.payload_streams)
            .map(|body| body.chunks.len())
            .sum::<usize>();
    if at != pieces_at || frames.len() != named {
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
    let first = u32::try_from(manifest.bodies.len() + 1).map_err(|_| codec())?;
    let mut streams: Vec<_> = manifest
        .bodies
        .into_iter()
        .chain(manifest.payload_streams)
        .map(|entry| {
            let frames: Vec<_> = rest.by_ref().take(entry.chunks.len()).collect();
            (entry, frames)
        })
        .collect();
    // The payload's streams follow the bodies' and are read apart from
    // them (KS-7).
    let payload_streams = streams.split_off(first as usize - 1);
    let payload = match manifest.payload {
        Some(section) if section.names_streams(payload_streams.len()) => Some(SealedPayload {
            section,
            file: file.try_clone()?,
            sealer: Sealer {
                key,
                purpose: sealer.purpose,
                commitment: sealer.commitment,
                snapshot: sealer.snapshot,
            },
            first,
            streams: payload_streams,
        }),
        None if payload_streams.is_empty() => None,
        _ => return Err(codec()),
    };
    Ok(OpenedArtifact {
        image,
        image_id: manifest.image.digest,
        commitment_digest: oneiron_crypto::backup::commitment_digest(&commitment_bytes),
        created_at: manifest.created_at,
        bodies: SealedBodies {
            file,
            sealer,
            streams,
            payload,
        },
        custody: manifest.custody,
        sequence: commitment.sequence,
        snapshot: prelude.snapshot,
    })
}

/// The payload compartments an opened artifact carries (KS-7), read apart
/// from its bodies: each bundle's stream after the last body's.
pub(super) struct SealedPayload<'k> {
    pub(super) section: PayloadSection,
    file: File,
    sealer: Sealer<'k>,
    /// The first payload stream's number.
    first: u32,
    streams: Vec<(StreamEntry, Vec<(u64, u64)>)>,
}

impl SealedPayload<'_> {
    /// The vault its compartments are sealed for.
    pub(super) fn vault_id(&self) -> [u8; 32] {
        self.sealer.key.vault_id
    }

    /// The `index`th payload stream's bytes, each chunk checked against the
    /// manifest and opened as it is read, the whole checked after.
    pub(super) fn stream(&mut self, index: usize) -> Result<Vec<u8>> {
        let (entry, frames) = self.streams.get(index).ok_or_else(codec)?;
        let stream = u32::try_from(index)
            .ok()
            .and_then(|index| self.first.checked_add(index))
            .filter(|stream| *stream < MANIFEST_PIECE_STREAM)
            .ok_or_else(codec)?;
        let mut out = Vec::new();
        for (chunk, &(offset, len)) in frames.iter().enumerate() {
            let envelope = read_at(&mut self.file, offset, len)?;
            if *blake3::hash(&envelope).as_bytes() != entry.chunks[chunk] {
                return Err(codec());
            }
            let chunk = u32::try_from(chunk).map_err(|_| codec())?;
            out.extend_from_slice(&self.sealer.open(stream, chunk, &envelope)?);
        }
        if out.len() as u64 != entry.len || *blake3::hash(&out).as_bytes() != entry.digest {
            return Err(codec());
        }
        Ok(out)
    }
}

/// The custody position a manifest's requirement names, as the commitment
/// signs it.
pub(super) fn custody_ref(
    custody: Option<&crate::store::CustodyRequirement>,
) -> Result<Option<CustodyRef>> {
    custody
        .map(|required| {
            let position = required.position()?;
            Ok(CustodyRef {
                vault: *position.vault.as_bytes(),
                namespace: *position.namespace.as_bytes(),
                epoch: position.epoch.get(),
                seq: position.seq,
                tip: position.tip,
            })
        })
        .transpose()
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
    /// Each body stream's BLAKE3 and length, in the manifest's order.
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
