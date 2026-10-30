//! The vault's one sealed cloud bundle (DEC-0005 "Sealed copies", FIX 922), and the
//! sealed pad object beside it. This is the carrier only: what goes into the base
//! section and each world's section is the caller's.
//!
//! - Outside its ciphertext a bundle shows a generation id (its UTC upload slot and
//!   16 fresh random bytes), its byte length, a positive multiple of
//!   [`SEALED_BUNDLE_PAD_STEP_BYTES`], and the digest of its bytes. No world, key,
//!   window, tag, pad, per-world length or reader is in the clear.
//! - Each upload draws a fresh outer key. Hybrid capsules seal it to every machine
//!   mine here and to the pinned recovery root, and grant it to an asked executor
//!   not mine here for its request (`publication_grant`, FIX 4785), in anonymous
//!   slots padded with blanks to a multiple of 16. The outer body rides E0
//!   envelopes under that key (purpose `SealedVaultBundle`), sized so the whole
//!   frame lands on the size step; the padding is inside the ciphertext.
//! - Inside: the publishing machine and its signature, the base section, then the
//!   catalog of world sections, the world capsules and, last, the owner work
//!   request it published for, if any (`publication`). Each section is sealed
//!   again under a key derived
//!   from its world's key and filed under a tag only a holder of that key can
//!   compute, so a reader of the outer layer opens only the worlds it holds keys
//!   for. A publisher carries a section it cannot read unchanged.
//! - Which worlds a bundle carries depends on its holder ([`bundle_carries`]):
//!   every private world whose sealed copies go to "Cloud + my machines", and, for
//!   a holder that is a machine of the owner's, those on "My machines" too. "Off"
//!   stays out everywhere.
//! - The pads of every carried world's keys ride their own object (purpose
//!   `SealedKeyPads`): same generation, same readers, padded to 64 KiB steps. A
//!   world key is a root wrap from the world's authority capsule joined with its
//!   pad, so the kit alone restores. The base section carries no pad row and no
//!   wrap.
//! - The pad object also indexes each section's tag under the key it is sealed
//!   under, where its publisher knew it (FIX 3359), so a publisher that cannot
//!   read a world still knows which section is that world's and stops carrying
//!   it once the world is deleted here or no longer eligible.
//! - Each carried private world's signed key wraps also ride a capsule of
//!   their own inside the bundle, sealed to the world's readers and the root
//!   ([`SealedWorldAuthority`], FIX 4211), which a publisher that may not read
//!   the world carries unchanged, as it carries the world's section. Its
//!   settings ride the base, as main-log metadata (PR1a #2961).
//! - Erase rewrites every kept pad object without the world's pads: that world's
//!   section in every kept bundle stops opening, and every other world's still
//!   does. A machine admitted after a generation was sealed opens its pad object
//!   with a grant of the object's outer key that an old reader or the kit sealed
//!   to it (`SealedPadAdmissionGrant`, FIX 4271). Delete rewrites nothing; a
//!   deleted world restores from the bundles it is in until they age out
//!   (DEC-0006: delete is backup-only undo).
//! - A holder keeps [`SEALED_BUNDLE_KEEP`] generations, each bundle with its pad
//!   object, and never retires the newest by age ([`retired_bundle_generations`]).

#[cfg(feature = "sync")]
mod admission;
mod authority;
mod carrier;
mod frame_seal;
mod holder_policy;
mod key_erase;
mod pad_objects;
mod plan;
mod publication;
mod publication_grant;
mod retirement;
mod sections;

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose,
    SealKey, SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::pads::{WorldKeyPad, pad_in_txn, pad_row_in_txn, world_keys_destroyed_in_txn};
use super::{
    MachineSecret, RecoveryRootId, RecoveryRootSeed, WORLD_KEY_EPOCH, WorldKey, WorldKeyId,
    WrapRecipient, base_world, open_counted, os_fill, recipients, refused,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, Destination, EffectiveRead};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::ports::TombstoneStoreRead;
use crate::store::Store;

#[cfg(feature = "sync")]
pub use self::admission::{PadAdmissionTarget, SealedPadAdmissionGrant};
pub(crate) use self::authority::{BundleCarry, SealedWorldAuthority};
pub use self::carrier::{SealedVaultUpload, WorldCapsuleImport};
use self::frame_seal::{
    encode_bundle_body, encode_section_body, even_sizes, seal_outer, seal_parts,
    section_padded_len, signed_digest,
};
pub(crate) use self::key_erase::{PadEraseSubject, stage_retained_pad_key_erase_in_txn};
use self::plan::{SealPlan, seal_object};
pub(crate) use self::publication::bundle_publish_executor;
pub use self::retirement::{
    SEALED_BUNDLE_KEEP, SEALED_BUNDLE_PAD_STEP_BYTES, SEALED_BUNDLE_UPLOAD_INTERVAL_SECS,
    SealedBundleGeneration, retired_bundle_generations, sealed_bundle_slot,
};
pub use self::sections::OpenedBundleSection;

/// The pad object's size step. Pads are small: a bundle's step would cost 64 MiB
/// a day for a few kilobytes.
const SEALED_KEY_PADS_STEP_BYTES: usize = 64 * 1024;
/// Reader capsules come in whole multiples of this, blanks included.
const SLOT_STEP: usize = 16;

const FRAME_VERSION: u8 = 1;
/// The byte before an upload's owner work request in a bundle body.
const REQUEST_TAG: u8 = 1;
const SLOT_LABEL: &[u8] = b"oneiron/sealed-vault-slot/v1\0";
const PART_LABEL: &[u8] = b"oneiron/sealed-vault-part/v1\0";
const BUNDLE_LABEL: &[u8] = b"oneiron/sealed-vault-bundle/v1\0";
const SECTION_LABEL: &[u8] = b"oneiron/sealed-vault-section/v1\0";
const PADS_LABEL: &[u8] = b"oneiron/sealed-key-pads/v2\0";
const SIGNATURE_CONTEXT: &str = "oneiron/sealed-vault-bundle-signature/v1";
const SECTION_KEY_CONTEXT: &str = "oneiron/sealed-vault-section-key/v1";
const SECTION_TAG_CONTEXT: &str = "oneiron/sealed-vault-section-tag/v1";
/// The E0 recipients: a capsule names no reader, and a part or a section no world.
const SLOT_RECIPIENT: &[u8] = b"oneiron/sealed-vault-slot";
const BODY_RECIPIENT: &[u8] = b"oneiron/sealed-vault-body";
const SECTION_RECIPIENT: &[u8] = b"oneiron/sealed-vault-section";
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
const SYMMETRIC: &[WrapType] = &[WrapType::SymmetricKek];
const HYBRID: &[WrapType] = &[WrapType::HybridCapsule];
/// The most body one envelope carries, under E0's 16 MiB plaintext bound.
const CHUNK: usize = 8 * 1024 * 1024;
/// The smallest padded section body.
const SECTION_PAD_FLOOR: usize = 4096;
const GENERATION_LEN: usize = 24;
const KEY_ID_LEN: usize = 40;
const SLOT_PLAINTEXT_LEN: usize = SLOT_LABEL.len() + GENERATION_LEN + 32;
/// label ‖ digest (32) ‖ index (4) ‖ count (4).
const PART_HEADER_LEN: usize = PART_LABEL.len() + 32 + 4 + 4;
const KEEP_SLOTS: u64 = SEALED_BUNDLE_KEEP as u64;

/// A key erase opens a kept pad object with.
#[cfg(feature = "sync")]
enum EraseKey {
    /// This machine's capsule.
    Machine,
    /// A grant of the object's outer key to this machine, sealed by an old
    /// reader or the kit since (FIX 4271).
    AdmissionGrant,
    /// The recovery kit the owner hands that one erase; nothing keeps it.
    Kit,
}

/// The keys erase opens each kept pad object with, in order (CALLS:
/// SEALED_BUNDLE_ERASE_KEY_SOURCE): this machine's capsule, then a grant
/// sealed to it since, then a kit the owner hands it. So a machine added after
/// older generations were sealed sweeps them unattended once an old reader
/// granted it access, and with the kit before that (FIX 3355, FIX 4271).
#[cfg(feature = "sync")]
const SEALED_BUNDLE_ERASE_KEY_SOURCE: &[EraseKey] =
    &[EraseKey::Machine, EraseKey::AdmissionGrant, EraseKey::Kit];

/// What a new pad object holds of a world deleted here (CALLS:
/// SEALED_BUNDLE_NEW_PAD_DELETED_WORLD).
enum DeletedWorldPads {
    /// None of its pads: its section no longer rides either (FIX 4275). Its pad
    /// rows here and every kept object stay as they are; erase strips those.
    Omit,
}

const SEALED_BUNDLE_NEW_PAD_DELETED_WORLD: DeletedWorldPads = DeletedWorldPads::Omit;

/// A bundle or a pad object: its frame magic, its envelope purpose, its size step.
#[derive(Clone, Copy)]
struct Kind {
    magic: &'static [u8; 4],
    purpose: Purpose,
    step: usize,
}

const BUNDLE: Kind = Kind {
    magic: b"OSVB",
    purpose: Purpose::SealedVaultBundle,
    step: SEALED_BUNDLE_PAD_STEP_BYTES,
};
const PADS: Kind = Kind {
    magic: b"OSKP",
    purpose: Purpose::SealedKeyPads,
    step: SEALED_KEY_PADS_STEP_BYTES,
};

impl SealedBundleGeneration {
    fn fresh(slot: u64) -> Result<Self> {
        let mut nonce = [0u8; 16];
        os_fill(&mut nonce)?;
        Ok(Self { slot, nonce })
    }
}

/// One sealed object's bytes and the generation its frame names.
#[derive(Clone, PartialEq, Eq)]
struct SealedObject {
    generation: SealedBundleGeneration,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SealedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedObject")
            .field("generation", &self.generation)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The vault's sealed cloud bundle for one generation. A holder reads only its
/// generation, its length and its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedVaultBundle(SealedObject);

impl SealedVaultBundle {
    fn open_with(
        &self,
        vault_id: &[u8; 32],
        secret: &HybridSecretKey,
    ) -> Result<OpenedVaultBundle> {
        let opened = open_outer(BUNDLE, vault_id, &self.0.bytes, secret)?;
        decode_bundle_body(vault_id, opened.generation, &opened.body)
    }
}

/// The sealed pads of one generation: every key of every carried world whose pad
/// was on the publisher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKeyPads(SealedObject);

impl SealedKeyPads {
    fn open_with(&self, vault_id: &[u8; 32], secret: &HybridSecretKey) -> Result<OpenedKeyPads> {
        self.opened(vault_id, open_outer(PADS, vault_id, &self.0.bytes, secret)?)
    }

    /// Opens the pads with `outer`, the object's outer key from an admission
    /// grant (FIX 4271). Only the object's own key opens its body.
    #[cfg(feature = "sync")]
    fn open_with_outer(&self, vault_id: &[u8; 32], outer: &[u8; 32]) -> Result<OpenedKeyPads> {
        let opened = open_outer_with_key(PADS, vault_id, &self.0.bytes, Zeroizing::new(*outer))?;
        self.opened(vault_id, opened)
    }

    fn opened(&self, vault_id: &[u8; 32], opened: OpenedOuter) -> Result<OpenedKeyPads> {
        let body = decode_pads_body(vault_id, opened.generation, &opened.body)?;
        Ok(OpenedKeyPads {
            vault_id: *vault_id,
            generation: opened.generation,
            total: self.0.bytes.len(),
            slots: opened.slots,
            outer: opened.outer,
            entries: body.pads,
            index: body.index,
        })
    }
}

/// One world's section of a bundle, still sealed under its world's key. Opaque to
/// every reader of the bundle that does not hold that key.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBundleSection {
    tag: [u8; 32],
    parts: Vec<Envelope>,
}

/// A bundle's outer layer, opened: who sealed it, the base section, and the
/// catalog of world sections.
pub struct OpenedVaultBundle {
    vault_id: [u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
    signature: [u8; 64],
    /// The owner work request the publisher published it for, inside the
    /// signed content; `None` for the cadence's own upload.
    request: Option<AuthorityEntryHash>,
    /// The digest the publisher's signature covers.
    signed: [u8; 32],
    base: Zeroizing<Vec<u8>>,
    sections: Vec<SealedBundleSection>,
    /// One capsule per private world whose authority the bundle files.
    authorities: Vec<SealedWorldAuthority>,
}

/// One generation's pads, opened.
pub struct OpenedKeyPads {
    vault_id: [u8; 32],
    generation: SealedBundleGeneration,
    /// The sealed object's length, which a rewrite keeps.
    total: usize,
    /// The capsules, which a rewrite keeps.
    slots: Vec<Envelope>,
    outer: Zeroizing<[u8; 32]>,
    /// Each pad, with the time its row was learned (FIX 3790).
    entries: Vec<(WorldKeyId, Zeroizing<[u8; 32]>, u64)>,
    /// Each section's tag, by the key it is sealed under (FIX 3359).
    index: Vec<(WorldKeyId, [u8; 32])>,
}

impl OpenedKeyPads {
    fn pad(&self, key: &WorldKeyId) -> Option<WorldKeyPad> {
        self.entries
            .iter()
            .find(|(id, _, _)| id == key)
            .map(|(_, pad, _)| WorldKeyPad::from_bytes(Zeroizing::new(**pad)))
    }
}

/// Every world `fold` names, by its settings or a key.
#[cfg(feature = "sync")]
fn known_worlds(fold: &AuthorityFold) -> impl Iterator<Item = EntityId> + '_ {
    fold.worlds
        .keys()
        .copied()
        .chain(fold.all_world_keys().map(|key| key.id.world))
}

/// Whether a bundle `holder` keeps carries `world` (owner ruling Q1, FIX 922):
/// a private world whose sealed copies go to "Cloud + my machines", or to "My
/// machines" when the holder is a machine trusted as the owner's here. Any other
/// holder (unknown, hosted, not mine) gets only the first. Base reality and
/// worlds read everywhere ride the base section, the latter under the same
/// setting (FIX 8886); "Off" stays out everywhere.
fn bundle_carries(fold: &AuthorityFold, world: EntityId, holder: Destination) -> bool {
    world != base_world()
        && fold.world_privacy(world).read != EffectiveRead::Everywhere
        && fold.holder_keeps_sealed_copies(world, holder)
}

/// Whether a new pad object holds `world`'s pads, by its deletion state in `txn`
/// ([`SEALED_BUNDLE_NEW_PAD_DELETED_WORLD`]).
fn new_pads_hold(store: &Store, txn: &heed::RoTxn<'_>, world: EntityId) -> Result<bool> {
    let deleted = TombstoneStoreRead::port_deletion_state(store, txn, &world)?.deleted;
    Ok(match SEALED_BUNDLE_NEW_PAD_DELETED_WORLD {
        DeletedWorldPads::Omit => !deleted,
    })
}

fn open_sections(
    opened: &OpenedVaultBundle,
    keys: &[WorldKey],
) -> Result<Vec<OpenedBundleSection>> {
    let mut out = Vec::new();
    for key in keys {
        if let Some(section) = opened.open_section(key)? {
            out.push(section);
        }
    }
    Ok(out)
}

/// The outer key in one anonymous capsule per reader, then blanks to a whole
/// multiple of [`SLOT_STEP`]. A blank seals a random key to a throwaway keypair,
/// so no holder tells it from a reader's.
fn seal_slots(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    readers: &[HybridPublicKey],
) -> Result<Vec<Envelope>> {
    let id = generation.to_bytes();
    let params = seal_params(kind.purpose, vault_id, &id, SLOT_RECIPIENT);
    let count = readers.len().div_ceil(SLOT_STEP).max(1) * SLOT_STEP;
    let mut blanks = Vec::with_capacity(count - readers.len());
    for _ in readers.len()..count {
        let blank = HybridSecretKey::generate(&mut SysRng)
            .map_err(|_| refused("os entropy unavailable"))?;
        blanks.push(blank.public_key().clone());
    }
    let mut slots = Vec::with_capacity(count);
    for (index, public) in readers.iter().chain(&blanks).enumerate() {
        let mut key = Zeroizing::new(*outer);
        if index >= readers.len() {
            os_fill(&mut key[..])?;
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(SLOT_PLAINTEXT_LEN));
        plaintext.extend_from_slice(SLOT_LABEL);
        plaintext.extend_from_slice(&id);
        plaintext.extend_from_slice(&key[..]);
        let sealed = seal(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            &plaintext,
            &mut SysRng,
        )
        .map_err(|_| refused("sealing failed"))?;
        slots.push(sealed);
    }
    Ok(slots)
}

/// The outer key from the first capsule `secret` opens.
fn open_slots(
    kind: Kind,
    vault_id: &[u8; 32],
    frame: &Frame,
    secret: &HybridSecretKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let id = frame.generation.to_bytes();
    let policy = OpenPolicy {
        purpose: kind.purpose,
        vault_id,
        recipient: SLOT_RECIPIENT,
        key_id: &id,
        wraps: HYBRID,
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    for slot in &frame.slots {
        let Ok(plaintext) = slot.open(OpenKey::Hybrid(secret), &policy) else {
            continue;
        };
        if plaintext.len() == SLOT_PLAINTEXT_LEN
            && plaintext.starts_with(SLOT_LABEL)
            && plaintext[SLOT_LABEL.len()..SLOT_LABEL.len() + GENERATION_LEN] == id
        {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&plaintext[SLOT_LABEL.len() + GENERATION_LEN..]);
            return Ok(key);
        }
    }
    // Typed, so a relay whose take this machine cannot open defers its slot.
    Err(Error::Secret(SecretError::SealedBundleNoCapsule))
}

/// Opens `parts` back into one body, refusing parts out of order, of another
/// body, or missing.
fn open_parts(
    policy: &OpenPolicy<'_>,
    kek: &Kek,
    parts: &[Envelope],
) -> Result<Zeroizing<Vec<u8>>> {
    let disagree = || refused("the sealed parts disagree");
    let mut body = Zeroizing::new(Vec::new());
    let mut expected: Option<[u8; 32]> = None;
    for (index, part) in parts.iter().enumerate() {
        let plaintext = part
            .open(OpenKey::SymmetricKek(kek), policy)
            .map_err(|_| refused("a sealed part does not open under its key"))?;
        if plaintext.len() < PART_HEADER_LEN || !plaintext.starts_with(PART_LABEL) {
            return Err(disagree());
        }
        let header = &plaintext[PART_LABEL.len()..PART_HEADER_LEN];
        let digest: [u8; 32] = header[..32].try_into().map_err(|_| disagree())?;
        let at = u32::from_be_bytes([header[32], header[33], header[34], header[35]]);
        let of = u32::from_be_bytes([header[36], header[37], header[38], header[39]]);
        if at as usize != index
            || of as usize != parts.len()
            || expected.is_some_and(|first| first != digest)
        {
            return Err(disagree());
        }
        expected = Some(digest);
        body.extend_from_slice(&plaintext[PART_HEADER_LEN..]);
    }
    if expected != Some(*blake3::hash(&body).as_bytes()) {
        return Err(disagree());
    }
    Ok(body)
}

fn seal_params<'a>(
    purpose: Purpose,
    vault_id: &'a [u8; 32],
    key_id: &'a [u8],
    recipient: &'a [u8],
) -> SealParams<'a> {
    SealParams {
        suite: AEAD,
        purpose,
        epoch: WORLD_KEY_EPOCH,
        key_id,
        recipient,
        vault_id,
    }
}

fn symmetric_policy<'a>(
    purpose: Purpose,
    vault_id: &'a [u8; 32],
    key_id: &'a [u8],
    recipient: &'a [u8],
) -> OpenPolicy<'a> {
    OpenPolicy {
        purpose,
        vault_id,
        recipient,
        key_id,
        wraps: SYMMETRIC,
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    }
}

/// A parsed frame: the capsules, then the body's parts.
struct Frame {
    generation: SealedBundleGeneration,
    slots: Vec<Envelope>,
    parts: Vec<Envelope>,
}

/// An outer layer opened: what a pad rewrite keeps, and the padded body.
struct OpenedOuter {
    generation: SealedBundleGeneration,
    slots: Vec<Envelope>,
    outer: Zeroizing<[u8; 32]>,
    body: Zeroizing<Vec<u8>>,
}

fn open_outer(
    kind: Kind,
    vault_id: &[u8; 32],
    bytes: &[u8],
    secret: &HybridSecretKey,
) -> Result<OpenedOuter> {
    let frame = parse_frame(kind, bytes)?;
    let outer = open_slots(kind, vault_id, &frame, secret)?;
    open_framed(kind, vault_id, frame, outer)
}

/// [`open_outer`] with `outer`, a key the caller holds already, as from an
/// admission grant (FIX 4271): the body's AEAD is the proof that it is the
/// object's own outer key. The frame's capsules are kept, unopened.
#[cfg(feature = "sync")]
fn open_outer_with_key(
    kind: Kind,
    vault_id: &[u8; 32],
    bytes: &[u8],
    outer: Zeroizing<[u8; 32]>,
) -> Result<OpenedOuter> {
    open_framed(kind, vault_id, parse_frame(kind, bytes)?, outer)
}

/// The body of `frame` under `outer`.
fn open_framed(
    kind: Kind,
    vault_id: &[u8; 32],
    frame: Frame,
    outer: Zeroizing<[u8; 32]>,
) -> Result<OpenedOuter> {
    let id = frame.generation.to_bytes();
    let policy = symmetric_policy(kind.purpose, vault_id, &id, BODY_RECIPIENT);
    let body = open_parts(&policy, &Kek::from_bytes_ref(&outer), &frame.parts)?;
    Ok(OpenedOuter {
        generation: frame.generation,
        slots: frame.slots,
        outer,
        body,
    })
}

/// magic (4) ‖ version (1) ‖ generation (24) ‖ capsule count (2) ‖ capsules ‖ part
/// count (4) ‖ parts, each envelope `u32`-length-prefixed, and nothing after.
fn parse_frame(kind: Kind, bytes: &[u8]) -> Result<Frame> {
    let malformed = || refused("malformed sealed vault object");
    if bytes.is_empty() || bytes.len() % kind.step != 0 {
        return Err(malformed());
    }
    let mut cursor = Cursor { bytes, at: 0 };
    if cursor.take(4) != Some(&kind.magic[..]) || cursor.take(1) != Some(&[FRAME_VERSION][..]) {
        return Err(malformed());
    }
    let generation =
        SealedBundleGeneration::from_bytes(cursor.take(GENERATION_LEN).ok_or_else(malformed)?)?;
    let id = generation.to_bytes();
    let mut vault = None;
    let slot_count = u16::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut slots = Vec::new();
    for _ in 0..slot_count {
        slots.push(parse_envelope(
            &mut cursor,
            kind.purpose,
            WrapType::HybridCapsule,
            &id,
            SLOT_RECIPIENT,
            &mut vault,
        )?);
    }
    let part_count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut parts = Vec::new();
    for _ in 0..part_count {
        parts.push(parse_envelope(
            &mut cursor,
            kind.purpose,
            WrapType::SymmetricKek,
            &id,
            BODY_RECIPIENT,
            &mut vault,
        )?);
    }
    if slots.is_empty() || parts.is_empty() || cursor.at != bytes.len() {
        return Err(malformed());
    }
    Ok(Frame {
        generation,
        slots,
        parts,
    })
}

/// One `u32`-length-prefixed canonical envelope of `purpose` and `wrap`, bound to
/// `key_id` and `recipient`, naming the same vault as the ones before it.
fn parse_envelope(
    cursor: &mut Cursor<'_>,
    purpose: Purpose,
    wrap: WrapType,
    key_id: &[u8],
    recipient: &[u8],
    vault: &mut Option<Vec<u8>>,
) -> Result<Envelope> {
    let malformed = || refused("malformed sealed vault object");
    let envelope =
        Envelope::parse(cursor.counted().ok_or_else(malformed)?).map_err(|_| malformed())?;
    let header = envelope.header();
    let same_vault = *vault.get_or_insert_with(|| header.vault_id.clone()) == header.vault_id;
    if header.purpose != purpose
        || header.wrap != wrap
        || header.suite != AEAD
        || header.key_id != key_id
        || header.recipient != recipient
        || !same_vault
    {
        return Err(malformed());
    }
    Ok(envelope)
}

fn decode_bundle_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    body: &[u8],
) -> Result<OpenedVaultBundle> {
    let malformed = || refused("the bundle's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(BUNDLE_LABEL.len()) != Some(BUNDLE_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(GENERATION_LEN) != Some(&generation.to_bytes()[..])
    {
        return Err(refused("the bundle names another vault or generation"));
    }
    let publisher =
        EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
    let signature: [u8; 64] = cursor.array().ok_or_else(malformed)?;
    let content_at = cursor.at;
    let base_len = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let base = usize::try_from(base_len)
        .ok()
        .and_then(|len| cursor.take(len))
        .ok_or_else(malformed)?;
    let base = Zeroizing::new(base.to_vec());
    let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut sections = Vec::new();
    let mut tags = BTreeSet::new();
    for _ in 0..count {
        let section = SealedBundleSection::parse(&mut cursor, vault_id)?;
        if !tags.insert(section.tag) {
            return Err(malformed());
        }
        sections.push(section);
    }
    let authorities = SealedWorldAuthority::parse_all(&mut cursor)?;
    // The request, when the content names one; a padding zero, or the body's
    // end, is none, and is not signed content.
    let mut content_end = cursor.at;
    let request = match cursor.take(1) {
        None | Some([0]) => None,
        Some([REQUEST_TAG]) => {
            let request = cursor.array().ok_or_else(malformed)?;
            content_end = cursor.at;
            Some(request)
        }
        Some(_) => return Err(malformed()),
    };
    let signed = signed_digest(
        vault_id,
        generation,
        publisher,
        &body[content_at..content_end],
    );
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(OpenedVaultBundle {
        vault_id: *vault_id,
        generation,
        publisher,
        signature,
        request,
        signed,
        base,
        sections,
        authorities,
    })
}

/// `BLAKE3-derive_key(context, vault ‖ key id ‖ world key)`: a section's key or
/// its tag. Only a holder of the world key computes either.
fn section_digest(context: &str, vault_id: &[u8; 32], key: &WorldKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    section_digest_into(context, vault_id, key, &mut out);
    out
}

/// The section's key, derived as [`section_digest`] under
/// [`SECTION_KEY_CONTEXT`] straight into guarded storage (FIX 6048).
fn section_kek(vault_id: &[u8; 32], key: &WorldKey) -> Kek {
    let mut out = Zeroizing::new([0u8; 32]);
    section_digest_into(SECTION_KEY_CONTEXT, vault_id, key, &mut out);
    Kek::from_zeroizing(out)
}

/// `BLAKE3-derive_key(context, vault id ‖ key id ‖ key)`, written into `out`.
fn section_digest_into(context: &str, vault_id: &[u8; 32], key: &WorldKey, out: &mut [u8; 32]) {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(vault_id);
    hasher.update(&key.id().envelope_key_id());
    hasher.update(key.expose());
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    // The hasher's block buffer and the reader's state still hold the key's bytes.
    zeroize::Zeroize::zeroize(&mut hasher);
    zeroize::Zeroize::zeroize(&mut reader);
}

fn decode_section_body(
    vault_id: &[u8; 32],
    key: &WorldKeyId,
    body: &[u8],
) -> Result<OpenedBundleSection> {
    let malformed = || refused("the bundle section's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(SECTION_LABEL.len()) != Some(SECTION_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(KEY_ID_LEN) != Some(&key.envelope_key_id()[..])
    {
        return Err(refused("the section names another vault or key"));
    }
    let len = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let payload = usize::try_from(len)
        .ok()
        .and_then(|len| cursor.take(len))
        .ok_or_else(malformed)?;
    let payload = Zeroizing::new(payload.to_vec());
    if !cursor.rest_is_zero() || body.len() != section_padded_len(cursor.at) {
        return Err(malformed());
    }
    Ok(OpenedBundleSection { key: *key, payload })
}

/// label ‖ vault (32) ‖ generation (24) ‖ count (4) ‖ each key id (40) ‖ pad (32)
/// ‖ learned at (8, big-endian) ‖ index count (4) ‖ each key id (40) ‖ the tag of
/// the section sealed under it (32), leaving out `without`'s keys.
fn encode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    entries: &[(WorldKeyId, Zeroizing<[u8; 32]>, u64)],
    index: &[(WorldKeyId, [u8; 32])],
    without: Option<EntityId>,
) -> Result<Zeroizing<Vec<u8>>> {
    let kept: Vec<_> = entries
        .iter()
        .filter(|(key, _, _)| Some(key.world) != without)
        .collect();
    let indexed: Vec<_> = index
        .iter()
        .filter(|(key, _)| Some(key.world) != without)
        .collect();
    let count = u32::try_from(kept.len()).map_err(|_| refused("too many pads"))?;
    let indexed_count =
        u32::try_from(indexed.len()).map_err(|_| refused("too many indexed sections"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(
        PADS_LABEL.len()
            + 32
            + GENERATION_LEN
            + 8
            + kept.len() * (KEY_ID_LEN + 32 + 8)
            + indexed.len() * (KEY_ID_LEN + 32),
    ));
    body.extend_from_slice(PADS_LABEL);
    body.extend_from_slice(vault_id);
    body.extend_from_slice(&generation.to_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    for (key, pad, learned_at) in kept {
        body.extend_from_slice(&key.envelope_key_id());
        body.extend_from_slice(&pad[..]);
        body.extend_from_slice(&learned_at.to_be_bytes());
    }
    body.extend_from_slice(&indexed_count.to_be_bytes());
    for (key, tag) in indexed {
        body.extend_from_slice(&key.envelope_key_id());
        body.extend_from_slice(tag);
    }
    Ok(body)
}

/// A pad object's body, opened.
struct PadsBody {
    pads: Vec<(WorldKeyId, Zeroizing<[u8; 32]>, u64)>,
    index: Vec<(WorldKeyId, [u8; 32])>,
}

fn decode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    body: &[u8],
) -> Result<PadsBody> {
    let malformed = || refused("the pad object's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(PADS_LABEL.len()) != Some(PADS_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(GENERATION_LEN) != Some(&generation.to_bytes()[..])
    {
        return Err(refused("the pad object names another vault or generation"));
    }
    let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut pads = Vec::new();
    for _ in 0..count {
        let key = cursor.key_id().ok_or_else(malformed)?;
        let pad = Zeroizing::new(cursor.array().ok_or_else(malformed)?);
        let learned_at = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
        pads.push((key, pad, learned_at));
    }
    let indexed = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut index = Vec::new();
    for _ in 0..indexed {
        let key = cursor.key_id().ok_or_else(malformed)?;
        index.push((key, cursor.array().ok_or_else(malformed)?));
    }
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(PadsBody { pads, index })
}

fn put_counted(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| refused("a sealed part is too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A forward reader over a frame or a body.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A `u32`-length-prefixed field.
    fn counted(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(len as usize)
    }

    /// A key id as [`WorldKeyId::envelope_key_id`] spells it.
    fn key_id(&mut self) -> Option<WorldKeyId> {
        Some(WorldKeyId {
            world: EntityId::from_bytes(self.array()?).ok()?,
            generation: u64::from_be_bytes(self.array()?),
            mint: self.array()?,
        })
    }

    fn rest_is_zero(&self) -> bool {
        self.bytes[self.at..].iter().all(|byte| *byte == 0)
    }
}
