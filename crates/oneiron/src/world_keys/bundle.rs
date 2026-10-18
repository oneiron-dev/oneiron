//! The vault's one sealed cloud bundle (DEC-0005 "Sealed copies", FIX 922), and the
//! sealed pad object beside it. This is the carrier only: what goes into the base
//! section and each world's section is the caller's.
//!
//! - Outside its ciphertext a bundle shows a generation id (its UTC upload slot and
//!   16 fresh random bytes), its byte length, a positive multiple of
//!   [`SEALED_BUNDLE_PAD_STEP_BYTES`], and the digest of its bytes. No world, key,
//!   window, tag, pad, per-world length or reader is in the clear.
//! - Each upload draws a fresh outer key. Hybrid capsules seal it to every machine
//!   mine here and to the pinned recovery root, in anonymous slots padded with
//!   blanks to a multiple of 16. The outer body rides E0 envelopes under that key
//!   (purpose `SealedVaultBundle`), sized so the whole frame lands on the size
//!   step; the padding is inside the ciphertext.
//! - Inside: the publishing machine and its signature, the base section, then the
//!   catalog of world sections. Each section is sealed again under a key derived
//!   from its world's key and filed under a tag only a holder of that key can
//!   compute, so a reader of the outer layer opens only the worlds it holds keys
//!   for. A publisher carries a section it cannot read unchanged.
//! - Which worlds a bundle carries depends on its holder ([`bundle_carries`]):
//!   every private world whose sealed copies go to "Cloud + my machines", and, for
//!   a holder that is a machine of the owner's, those on "My machines" too. "Off"
//!   stays out everywhere.
//! - The pads of every carried world's keys ride their own object (purpose
//!   `SealedKeyPads`): same generation, same readers, padded to 64 KiB steps. A
//!   world key is a root wrap from the base section's authority joined with its
//!   pad, so the kit alone restores. The base section therefore carries no pad
//!   row.
//! - Erase rewrites every kept pad object without the world's pads: that world's
//!   section in every kept bundle stops opening, and every other world's still
//!   does. Delete rewrites nothing; a deleted world restores from the bundles it is
//!   in until they age out (DEC-0006: delete is backup-only undo).
//! - A holder keeps [`SEALED_BUNDLE_KEEP`] generations, each bundle with its pad
//!   object, and never retires the newest by age ([`retired_bundle_generations`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose,
    SealKey, SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::pads::{WorldKeyPad, pad_in_txn, world_keys_destroyed_in_txn};
use super::{
    MachineSecret, RecoveryRootSeed, WORLD_KEY_EPOCH, WorldKey, WorldKeyId, WrapRecipient,
    base_world, open_counted, os_fill, recipients, refused,
};
use crate::Vault;
use crate::authority::{AuthorityFold, Destination, EffectiveRead, SealedCopies};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The bundle's size step: every bundle is a positive multiple of it.
pub const SEALED_BUNDLE_PAD_STEP_BYTES: usize = 64 * 1024 * 1024;
/// One upload per vault in each fixed UTC slot of this length, changed or not.
pub const SEALED_BUNDLE_UPLOAD_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// The generations a holder keeps: 90 daily ones (ARCH-0038: backups keep a
/// deleted thing up to 90 days).
pub const SEALED_BUNDLE_KEEP: usize = 90;
/// The pad object's size step. Pads are small: a bundle's step would cost 64 MiB
/// a day for a few kilobytes.
const SEALED_KEY_PADS_STEP_BYTES: usize = 64 * 1024;
/// Reader capsules come in whole multiples of this, blanks included.
const SLOT_STEP: usize = 16;

const FRAME_VERSION: u8 = 1;
const SLOT_LABEL: &[u8] = b"oneiron/sealed-vault-slot/v1\0";
const PART_LABEL: &[u8] = b"oneiron/sealed-vault-part/v1\0";
const BUNDLE_LABEL: &[u8] = b"oneiron/sealed-vault-bundle/v1\0";
const SECTION_LABEL: &[u8] = b"oneiron/sealed-vault-section/v1\0";
const PADS_LABEL: &[u8] = b"oneiron/sealed-key-pads/v1\0";
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
/// The most envelopes one world section holds: a 1 GiB section.
const MAX_SECTION_PARTS: usize = 128;
/// The smallest padded section body.
const SECTION_PAD_FLOOR: usize = 4096;
const GENERATION_LEN: usize = 24;
const KEY_ID_LEN: usize = 40;
const SLOT_PLAINTEXT_LEN: usize = SLOT_LABEL.len() + GENERATION_LEN + 32;
/// label ‖ digest (32) ‖ index (4) ‖ count (4).
const PART_HEADER_LEN: usize = PART_LABEL.len() + 32 + 4 + 4;
const KEEP_SLOTS: u64 = SEALED_BUNDLE_KEEP as u64;

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

/// The UTC upload slot `unix_secs` falls in.
#[must_use]
pub fn sealed_bundle_slot(unix_secs: u64) -> u64 {
    unix_secs / SEALED_BUNDLE_UPLOAD_INTERVAL_SECS
}

/// The generations a holder retires from `kept` in slot `now_slot`: every one
/// past the newest [`SEALED_BUNDLE_KEEP`], and every older one that many slots
/// old, so nothing but the last copy outlives 90 days when uploads stop. The
/// newest is never retired by age (owner ruling: spare the last copy). A retired
/// generation's pad object goes with it.
#[must_use]
pub fn retired_bundle_generations(
    now_slot: u64,
    kept: &[SealedBundleGeneration],
) -> Vec<SealedBundleGeneration> {
    let mut newest_first = kept.to_vec();
    newest_first.sort_unstable();
    newest_first.dedup();
    newest_first.reverse();
    newest_first
        .into_iter()
        .enumerate()
        .filter(|(rank, generation)| {
            *rank >= SEALED_BUNDLE_KEEP
                || (*rank > 0 && generation.slot.saturating_add(KEEP_SLOTS) <= now_slot)
        })
        .map(|(_, generation)| generation)
        .collect()
}

/// One generation's id: the UTC slot it was sealed for and 16 fresh random
/// bytes. Its bundle and its pad object carry the same id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedBundleGeneration {
    pub slot: u64,
    pub nonce: [u8; 16],
}

impl SealedBundleGeneration {
    fn fresh(slot: u64) -> Result<Self> {
        let mut nonce = [0u8; 16];
        os_fill(&mut nonce)?;
        Ok(Self { slot, nonce })
    }

    /// `slot (8, big-endian) ‖ nonce (16)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; GENERATION_LEN] {
        let mut out = [0u8; GENERATION_LEN];
        out[..8].copy_from_slice(&self.slot.to_be_bytes());
        out[8..].copy_from_slice(&self.nonce);
        out
    }

    /// Parses [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GENERATION_LEN {
            return Err(refused("a bundle generation is 24 bytes"));
        }
        let mut slot = [0u8; 8];
        let mut nonce = [0u8; 16];
        slot.copy_from_slice(&bytes[..8]);
        nonce.copy_from_slice(&bytes[8..]);
        Ok(Self {
            slot: u64::from_be_bytes(slot),
            nonce,
        })
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
    /// Strict parse of a frame: a positive multiple of the size step, the bundle
    /// magic, then capsules and parts, each one canonical E0 envelope bound to the
    /// generation and one vault. Whether it opens is a reader's question.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let frame = parse_frame(BUNDLE, bytes)?;
        Ok(Self(SealedObject {
            generation: frame.generation,
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.0.generation
    }

    /// The padded byte length.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.bytes.len()
    }

    /// BLAKE3 of the bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0.bytes).as_bytes()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }

    /// Opens the bundle with the kit's root, for a restore with no machine. Its
    /// publisher is unchecked: the restore checks [`OpenedVaultBundle::signed_by`]
    /// once the base section's authority is back.
    pub fn open_with_kit(
        &self,
        vault_id: &[u8; 32],
        seed: &RecoveryRootSeed,
    ) -> Result<OpenedVaultBundle> {
        self.open_with(vault_id, &seed.recovery_secret()?)
    }

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
    /// Strict parse of a frame, as [`SealedVaultBundle::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let frame = parse_frame(PADS, bytes)?;
        Ok(Self(SealedObject {
            generation: frame.generation,
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.0.generation
    }

    /// The padded byte length.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.bytes.len()
    }

    /// BLAKE3 of the bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0.bytes).as_bytes()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }

    /// Opens the pads with the kit's root.
    pub fn open_with_kit(
        &self,
        vault_id: &[u8; 32],
        seed: &RecoveryRootSeed,
    ) -> Result<OpenedKeyPads> {
        self.open_with(vault_id, &seed.recovery_secret()?)
    }

    fn open_with(&self, vault_id: &[u8; 32], secret: &HybridSecretKey) -> Result<OpenedKeyPads> {
        let opened = open_outer(PADS, vault_id, &self.0.bytes, secret)?;
        let entries = decode_pads_body(vault_id, opened.generation, &opened.body)?;
        Ok(OpenedKeyPads {
            vault_id: *vault_id,
            generation: opened.generation,
            total: self.0.bytes.len(),
            slots: opened.slots,
            outer: opened.outer,
            entries,
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

impl std::fmt::Debug for SealedBundleSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedBundleSection")
            .field("parts", &self.parts.len())
            .finish_non_exhaustive()
    }
}

impl SealedBundleSection {
    fn seal(vault_id: &[u8; 32], key: &WorldKey, payload: &[u8]) -> Result<Self> {
        let body = encode_section_body(vault_id, key.id(), payload);
        let count = body.len().div_ceil(CHUNK);
        if count > MAX_SECTION_PARTS {
            return Err(refused("the world is too large for one bundle section"));
        }
        let tag = section_digest(SECTION_TAG_CONTEXT, vault_id, key);
        let params = seal_params(BUNDLE.purpose, vault_id, &tag, SECTION_RECIPIENT);
        let kek = Kek::from_bytes(section_digest(SECTION_KEY_CONTEXT, vault_id, key));
        let mut parts = Vec::with_capacity(count);
        seal_parts(
            &params,
            &kek,
            &body,
            &even_sizes(body.len(), count),
            |part| {
                parts.push(part);
                Ok(())
            },
        )?;
        Ok(Self { tag, parts })
    }

    fn open(&self, vault_id: &[u8; 32], key: &WorldKey) -> Result<OpenedBundleSection> {
        let policy = symmetric_policy(BUNDLE.purpose, vault_id, &self.tag, SECTION_RECIPIENT);
        let kek = Kek::from_bytes(section_digest(SECTION_KEY_CONTEXT, vault_id, key));
        let body = open_parts(&policy, &kek, &self.parts)?;
        decode_section_body(vault_id, key.id(), &body)
    }

    /// tag (32) ‖ count (2) ‖ each part `u32`-length-prefixed.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.tag);
        let count = u16::try_from(self.parts.len()).map_err(|_| refused("too many parts"))?;
        out.extend_from_slice(&count.to_be_bytes());
        for part in &self.parts {
            put_counted(out, &part.to_bytes())?;
        }
        Ok(())
    }

    fn parse(cursor: &mut Cursor<'_>, vault_id: &[u8; 32]) -> Result<Self> {
        let malformed = || refused("malformed bundle section");
        let tag: [u8; 32] = cursor.array().ok_or_else(malformed)?;
        let count = usize::from(u16::from_be_bytes(cursor.array().ok_or_else(malformed)?));
        if count == 0 || count > MAX_SECTION_PARTS {
            return Err(malformed());
        }
        let mut vault = Some(vault_id.to_vec());
        let mut parts = Vec::with_capacity(count);
        for _ in 0..count {
            parts.push(parse_envelope(
                cursor,
                BUNDLE.purpose,
                WrapType::SymmetricKek,
                &tag,
                SECTION_RECIPIENT,
                &mut vault,
            )?);
        }
        Ok(Self { tag, parts })
    }
}

/// An opened world section: the key it was sealed under and its bytes, wiped on
/// drop.
pub struct OpenedBundleSection {
    pub key: WorldKeyId,
    pub payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedBundleSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedBundleSection")
            .field("key", &self.key)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// A bundle's outer layer, opened: who sealed it, the base section, and the
/// catalog of world sections.
pub struct OpenedVaultBundle {
    vault_id: [u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
    signature: [u8; 64],
    /// The digest the publisher's signature covers.
    signed: [u8; 32],
    base: Zeroizing<Vec<u8>>,
    sections: Vec<SealedBundleSection>,
}

impl std::fmt::Debug for OpenedVaultBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedVaultBundle")
            .field("generation", &self.generation)
            .field("publisher", &self.publisher)
            .field("base_len", &self.base.len())
            .field("sections", &self.sections.len())
            .finish_non_exhaustive()
    }
}

impl OpenedVaultBundle {
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The machine that sealed the bundle, as the bundle claims it.
    #[must_use]
    pub fn publisher(&self) -> EntityId {
        self.publisher
    }

    /// Whether `machine_key`, the publisher's Ed25519 key, signed this bundle.
    #[must_use]
    pub fn signed_by(&self, machine_key: &[u8; 32]) -> bool {
        VerifyingKey::from_bytes(machine_key).is_ok_and(|key| {
            key.verify_strict(&self.signed, &Signature::from_bytes(&self.signature))
                .is_ok()
        })
    }

    /// The base section's bytes.
    #[must_use]
    pub fn base(&self) -> &[u8] {
        &self.base
    }

    /// The world sections, still sealed: what a publisher carries into the next
    /// generation for the worlds it cannot read.
    #[must_use]
    pub fn sections(&self) -> &[SealedBundleSection] {
        &self.sections
    }

    /// The section sealed under `key`, opened; `None` when the bundle holds none.
    pub fn open_section(&self, key: &WorldKey) -> Result<Option<OpenedBundleSection>> {
        let tag = section_digest(SECTION_TAG_CONTEXT, &self.vault_id, key);
        self.sections
            .iter()
            .find(|section| section.tag == tag)
            .map(|section| section.open(&self.vault_id, key))
            .transpose()
    }

    /// The world sections not sealed under any of `keys`, still sealed: what a
    /// publisher carries on when it replaces or drops the sections of those
    /// keys.
    #[must_use]
    pub fn sections_except(&self, keys: &[&WorldKey]) -> Vec<SealedBundleSection> {
        let tags: BTreeSet<[u8; 32]> = keys
            .iter()
            .map(|key| section_digest(SECTION_TAG_CONTEXT, &self.vault_id, key))
            .collect();
        self.sections
            .iter()
            .filter(|section| !tags.contains(&section.tag))
            .cloned()
            .collect()
    }

    /// Whether a machine the owner vouched for signed the bundle, mine here now
    /// or removed since: the key of its roster chain an owner-held key accepted,
    /// or of its chain under an owner anchor, in `fold`.
    #[cfg(feature = "sync")]
    #[must_use]
    pub(crate) fn signed_by_owner_machine(&self, fold: &AuthorityFold) -> bool {
        fold.machine(self.publisher).is_some_and(|machine| {
            machine
                .roster_trusted
                .iter()
                .chain(machine.anchored.values())
                .any(|chain| self.signed_by(&chain.profile.machine_key))
        })
    }
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
    entries: Vec<(WorldKeyId, Zeroizing<[u8; 32]>)>,
}

impl std::fmt::Debug for OpenedKeyPads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedKeyPads")
            .field("generation", &self.generation)
            .field("pads", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl OpenedKeyPads {
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The keys whose pads this object holds.
    pub fn keys(&self) -> impl Iterator<Item = &WorldKeyId> {
        self.entries.iter().map(|(key, _)| key)
    }

    /// Erase's rewrite of one object: the same generation, capsules, outer key and
    /// length, sealed afresh without `world`'s pads. It replaces the old object,
    /// which the holder deletes.
    pub fn without_world(&self, world: EntityId) -> Result<SealedKeyPads> {
        let body = encode_pads_body(&self.vault_id, self.generation, &self.entries, Some(world))?;
        let bytes = seal_outer(
            PADS,
            &self.vault_id,
            self.generation,
            &self.outer,
            &self.slots,
            body,
            Some(self.total),
        )?;
        Ok(SealedKeyPads(SealedObject {
            generation: self.generation,
            bytes,
        }))
    }

    fn pad(&self, key: &WorldKeyId) -> Option<WorldKeyPad> {
        self.entries
            .iter()
            .find(|(id, _)| id == key)
            .map(|(_, pad)| WorldKeyPad::from_bytes(Zeroizing::new(**pad)))
    }
}

/// One upload: the bundle and the pad object of its generation.
#[derive(Debug)]
pub struct SealedVaultUpload {
    pub bundle: SealedVaultBundle,
    pub pads: SealedKeyPads,
    /// Whether the pinned recovery root holds a capsule. False: no root is pinned
    /// here, and no kit opens this upload.
    pub kit: bool,
}

/// What one seal reads from the vault, in one snapshot.
struct SealPlan {
    vault_id: [u8; 32],
    signing: SigningKey,
    publisher: EntityId,
    readers: Vec<HybridPublicKey>,
    kit: bool,
    pads: Vec<(WorldKeyId, Zeroizing<[u8; 32]>)>,
}

impl Vault {
    /// Seals this vault's bundle for upload `slot` ([`sealed_bundle_slot`]) and
    /// the pad object beside it, to every machine mine here and the pinned root,
    /// for `holder`, the home that keeps it.
    ///
    /// `base` is the base section. It must hold no world key pad row: pads ride
    /// only the pad object, or erase would not reach old bundles. Each of `worlds`
    /// is sealed under its current key; this machine must read it now, and the
    /// bundle must carry it for `holder` ([`bundle_carries`]; owner ruling Q1).
    /// `carried` are sections of an earlier generation, kept unchanged unless one
    /// of `worlds` replaces it. The pad object holds the pad of every key here of
    /// every world the bundle carries for `holder`.
    pub fn seal_vault_bundle(
        &self,
        slot: u64,
        holder: Destination,
        base: &[u8],
        worlds: &[(EntityId, &[u8])],
        carried: &[SealedBundleSection],
    ) -> Result<SealedVaultUpload> {
        self.seal_vault_bundle_carrying(slot, holder, base, worlds, carried, None)
    }

    /// [`Self::seal_vault_bundle`] for a publisher that carries `carried` on
    /// from the generation whose pad object is `latest`: the new pad object
    /// also holds each pad of `latest` this machine has no row for, of a world
    /// the bundle still carries for `holder` whose keys were not destroyed here,
    /// so a carried section's key still restores with the kit.
    pub(crate) fn seal_vault_bundle_carrying(
        &self,
        slot: u64,
        holder: Destination,
        base: &[u8],
        worlds: &[(EntityId, &[u8])],
        carried: &[SealedBundleSection],
        latest: Option<&OpenedKeyPads>,
    ) -> Result<SealedVaultUpload> {
        let secret = self.machine_secret_outside_txn()?;
        let mut keys: Vec<(Arc<WorldKey>, &[u8])> = Vec::with_capacity(worlds.len());
        for &(world, payload) in worlds {
            if keys.iter().any(|(key, _)| key.id().world == world) {
                return Err(refused("a world appears twice in one bundle"));
            }
            keys.push((self.world_key(world)?, payload));
        }
        let plan = self.seal_plan(&secret, holder, &keys, latest)?;
        let generation = SealedBundleGeneration::fresh(slot)?;
        let mut sections = Vec::with_capacity(keys.len() + carried.len());
        for (key, payload) in &keys {
            sections.push(SealedBundleSection::seal(&plan.vault_id, key, payload)?);
        }
        for section in carried {
            if !sections
                .iter()
                .any(|kept: &SealedBundleSection| kept.tag == section.tag)
            {
                sections.push(section.clone());
            }
        }
        let body = encode_bundle_body(&plan, generation, base, &sections)?;
        drop(sections);
        let bundle = seal_object(BUNDLE, &plan, generation, body)?;
        let pads_body = encode_pads_body(&plan.vault_id, generation, &plan.pads, None)?;
        let pads = seal_object(PADS, &plan, generation, pads_body)?;
        Ok(SealedVaultUpload {
            bundle: SealedVaultBundle(bundle),
            pads: SealedKeyPads(pads),
            kit: plan.kit,
        })
    }

    fn seal_plan(
        &self,
        secret: &MachineSecret,
        holder: Destination,
        keys: &[(Arc<WorldKey>, &[u8])],
        latest: Option<&OpenedKeyPads>,
    ) -> Result<SealPlan> {
        let txn = self.store.env.read_txn()?;
        let signing = self.door_signing_key_in_txn(&txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let mine = fold.trusted_machine(secret.machine).is_some_and(|trusted| {
            trusted.profile.machine_key == signing.verifying_key().to_bytes()
        });
        if !mine {
            return Err(refused("this machine is not one of the owner's here"));
        }
        for (key, _) in keys {
            let world = key.id().world;
            if !bundle_carries(&fold, world, holder) {
                return Err(refused(
                    "the world's sealed copies may not rest on the holder",
                ));
            }
            if fold
                .current_world_key(world)
                .is_none_or(|current| current.id != *key.id())
            {
                return Err(refused(
                    "the world's key changed while its section was sealed",
                ));
            }
        }
        let root = self.pinned_root_recipient_in_txn(&txn, &fold)?;
        let kit = root.is_some();
        // Base reality reads on every machine mine here: its recipients are the
        // vault's own readers, and the root.
        let readers: Vec<HybridPublicKey> = recipients(&fold, base_world(), root)
            .into_iter()
            .map(|(_, public)| public)
            .collect();
        if readers.is_empty() {
            return Err(refused("no machine and no kit could open the bundle"));
        }
        let mut pads = Vec::new();
        for key in fold.all_world_keys() {
            if bundle_carries(&fold, key.id.world, holder)
                && let Some(pad) = pad_in_txn(&self.store, &txn, &key.id)?
            {
                pads.push((key.id, Zeroizing::new(*pad.bytes())));
            }
        }
        // A carried section's key keeps the pad the latest generation held for
        // it, unless the bundle no longer carries its world for this holder or
        // its keys were destroyed here.
        for (key, pad) in latest.map_or(&[][..], |latest| &latest.entries[..]) {
            if bundle_carries(&fold, key.world, holder)
                && !pads.iter().any(|(held, _)| held == key)
                && !world_keys_destroyed_in_txn(&self.store, &txn, key.world)?
            {
                pads.push((*key, Zeroizing::new(**pad)));
            }
        }
        Ok(SealPlan {
            vault_id,
            signing,
            publisher: secret.machine,
            readers,
            kit,
            pads,
        })
    }

    /// Opens `bundle` with this machine's capsule, and checks that a machine mine
    /// here signed it with its own key.
    pub fn open_vault_bundle(&self, bundle: &SealedVaultBundle) -> Result<OpenedVaultBundle> {
        let secret = self.machine_secret_outside_txn()?;
        let opened = bundle.open_with(&self.bundle_vault_id()?, &secret.secret)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !fold
            .trusted_machine(opened.publisher)
            .is_some_and(|trusted| opened.signed_by(&trusted.profile.machine_key))
        {
            return Err(refused("no machine mine here signed the bundle"));
        }
        Ok(opened)
    }

    /// [`Self::open_vault_bundle`] for a publisher that carries the bundle's
    /// sections on: it opens with this machine's capsule, and a machine the
    /// owner vouched for signed it, mine here now or removed since
    /// ([`OpenedVaultBundle::signed_by_owner_machine`]). So a latest generation
    /// that a machine removed since sealed does not stop the next upload.
    #[cfg(feature = "sync")]
    pub(crate) fn open_vault_bundle_to_carry(
        &self,
        bundle: &SealedVaultBundle,
    ) -> Result<OpenedVaultBundle> {
        let secret = self.machine_secret_outside_txn()?;
        let opened = bundle.open_with(&self.bundle_vault_id()?, &secret.secret)?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !opened.signed_by_owner_machine(&fold) {
            return Err(refused("no machine of the owner's signed the bundle"));
        }
        Ok(opened)
    }

    /// Every world a bundle for `holder` carries now ([`bundle_carries`]).
    #[cfg(feature = "sync")]
    pub(crate) fn sealed_bundle_worlds(&self, holder: Destination) -> Result<BTreeSet<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold
            .worlds
            .keys()
            .copied()
            .chain(fold.all_world_keys().map(|key| key.id.world))
            .filter(|world| bundle_carries(&fold, *world, holder))
            .collect())
    }

    /// Kit restore: stores each pad of `pads` whose key this vault's authority
    /// names and whose row is not here, so the root's wraps open again (the
    /// base section carries no pad row). A world whose keys were destroyed here
    /// gets none. Returns how many it stored.
    #[cfg(feature = "sync")]
    pub(crate) fn restore_key_pads(&self, pads: &OpenedKeyPads) -> Result<usize> {
        self.with_write_txn(|txn| {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let now = self.instant_in_txn(txn)?.secs();
            let mut stored = 0;
            for (key, pad) in &pads.entries {
                if fold.world_key(key).is_none()
                    || pad_in_txn(&self.store, txn, key)?.is_some()
                    || world_keys_destroyed_in_txn(&self.store, txn, key.world)?
                {
                    continue;
                }
                let pad = WorldKeyPad::from_bytes(Zeroizing::new(**pad));
                self.put_pad_in_txn(txn, key, &pad, now)?;
                stored += 1;
            }
            Ok(stored)
        })
    }

    /// The sections of `opened` this machine may read now, opened. A key whose pad
    /// row is not here takes its pad from `pads`, the pad object of the bundle's
    /// generation. Whether to import a section, a deleted world's included, is the
    /// caller's question.
    pub fn open_vault_bundle_sections(
        &self,
        opened: &OpenedVaultBundle,
        pads: Option<&OpenedKeyPads>,
    ) -> Result<Vec<OpenedBundleSection>> {
        open_sections(opened, &self.bundle_reader_keys(pads, false)?)
    }

    /// Every key this machine opens of a world it may read now, its pad from
    /// this machine or else from `pads`, the pad object of the bundle's
    /// generation. A world read everywhere counts only with `public_too`.
    pub(crate) fn bundle_reader_keys(
        &self,
        pads: Option<&OpenedKeyPads>,
        public_too: bool,
    ) -> Result<Vec<WorldKey>> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let me = WrapRecipient::Machine(secret.machine);
        let mut keys = Vec::new();
        for key in fold.all_world_keys() {
            let world = key.id.world;
            if (!public_too && fold.world_privacy(world).read == EffectiveRead::Everywhere)
                || !fold.world_readable_on(world, Destination::Machine(secret.machine))
            {
                continue;
            }
            let pad = pad_in_txn(&self.store, &txn, &key.id)?
                .or_else(|| pads.and_then(|pads| pads.pad(&key.id)));
            if let Some(world_key) =
                pad.and_then(|pad| open_counted(&fold, key, me, &secret.secret, &pad))
            {
                keys.push(world_key);
            }
        }
        Ok(keys)
    }

    /// Kit restore: every section of `opened` whose key is wrapped to the kit's
    /// root, opened with that key's pad from `pads`, the pad object of the
    /// bundle's generation. This vault's authority must already hold the bundle's
    /// base, which carries the root's wraps.
    pub fn open_vault_bundle_sections_with_kit(
        &self,
        opened: &OpenedVaultBundle,
        pads: &OpenedKeyPads,
        seed: &RecoveryRootSeed,
    ) -> Result<Vec<OpenedBundleSection>> {
        let secret = seed.recovery_secret()?;
        let keys: Vec<WorldKey> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold
                .vault_id
                .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
            let root = WrapRecipient::RecoveryRoot(seed.public(&vault_id)?.id);
            fold.all_world_keys()
                .filter_map(|key| open_counted(&fold, key, root, &secret, &pads.pad(&key.id)?))
                .collect()
        };
        open_sections(opened, &keys)
    }

    /// Opens `pads` with this machine's capsule.
    pub fn open_key_pads(&self, pads: &SealedKeyPads) -> Result<OpenedKeyPads> {
        let secret = self.machine_secret_outside_txn()?;
        pads.open_with(&self.bundle_vault_id()?, &secret.secret)
    }

    /// Erase's rewrite, in one call: every kept pad object, the current one and
    /// every older one, without `world`'s pads, each opened with this machine's
    /// capsule or else the kit's. A pad object holds pads only. The root wraps of
    /// the world's keys stay in each kept bundle's base section, and with the pads
    /// gone from every kept object they open to nothing, for the kit too, so the
    /// world's section in every kept bundle stops opening. Every other world's
    /// pads stay, so every kept bundle still restores them. Each object is
    /// rewritten at its own length, held the world or not.
    ///
    /// The holder keeps no prior object versions: a rewrite replaces the old
    /// object and deletes it (no versioning or object lock is assumed). Refused
    /// when one object opens with neither key, before anything is rewritten.
    pub fn drop_world_from_key_pads(
        &self,
        world: EntityId,
        kept: &[SealedKeyPads],
        kit: Option<&RecoveryRootSeed>,
    ) -> Result<Vec<SealedKeyPads>> {
        let vault_id = self.bundle_vault_id()?;
        let mut secrets = Vec::new();
        // A kit restore runs before this install has a machine of its own.
        if let Ok(machine) = self.machine_secret_outside_txn() {
            secrets.push(machine.secret);
        }
        if let Some(seed) = kit {
            secrets.push(seed.recovery_secret()?);
        }
        let opened = kept
            .iter()
            .map(|pads| {
                secrets
                    .iter()
                    .find_map(|secret| pads.open_with(&vault_id, secret).ok())
                    .ok_or_else(|| refused("a kept pad object opens neither here nor with the kit"))
            })
            .collect::<Result<Vec<_>>>()?;
        opened
            .iter()
            .map(|pads| pads.without_world(world))
            .collect()
    }

    fn bundle_vault_id(&self) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        self.authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))
    }
}

/// Whether a bundle `holder` keeps carries `world` (owner ruling Q1, FIX 922):
/// a private world whose sealed copies go to "Cloud + my machines", or to "My
/// machines" when the holder is a machine trusted as the owner's here. Any other
/// holder (unknown, hosted, not mine) gets only the first. Base reality and
/// worlds read everywhere ride the base section; "Off" stays out everywhere.
fn bundle_carries(fold: &AuthorityFold, world: EntityId, holder: Destination) -> bool {
    let privacy = fold.world_privacy(world);
    world != base_world()
        && privacy.read != EffectiveRead::Everywhere
        && match privacy.sealed {
            SealedCopies::Off => false,
            SealedCopies::MyMachines => matches!(
                holder,
                Destination::Machine(machine) if fold.trusted_machine(machine).is_some()
            ),
            SealedCopies::CloudAndMyMachines => true,
        }
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

/// A fresh outer key, its capsules to the plan's readers, and `body` framed under
/// it.
fn seal_object(
    kind: Kind,
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    body: Zeroizing<Vec<u8>>,
) -> Result<SealedObject> {
    let mut outer = Zeroizing::new([0u8; 32]);
    os_fill(&mut outer[..])?;
    let slots = seal_slots(kind, &plan.vault_id, generation, &outer, &plan.readers)?;
    let bytes = seal_outer(kind, &plan.vault_id, generation, &outer, &slots, body, None)?;
    Ok(SealedObject { generation, bytes })
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
    Err(refused("no capsule of the object opens for this key"))
}

/// Frames `body` under the outer key behind `slots`, padded inside the
/// ciphertext so the object is `total` bytes, or the smallest positive multiple
/// of the kind's step it fits in.
fn seal_outer(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    slots: &[Envelope],
    mut body: Zeroizing<Vec<u8>>,
    total: Option<usize>,
) -> Result<Vec<u8>> {
    let too_large = || refused("the sealed object outgrows its size");
    let id = generation.to_bytes();
    let kek = Kek::from_bytes(*outer);
    let params = seal_params(kind.purpose, vault_id, &id, BODY_RECIPIENT);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(kind.magic);
    bytes.push(FRAME_VERSION);
    bytes.extend_from_slice(&id);
    let slot_count = u16::try_from(slots.len()).map_err(|_| too_large())?;
    bytes.extend_from_slice(&slot_count.to_be_bytes());
    for slot in slots {
        put_counted(&mut bytes, &slot.to_bytes())?;
    }
    // A part's frame bytes beyond its chunk: the length prefix and the envelope
    // around the part header.
    let probe = seal(
        &params,
        SealKey::SymmetricKek(&kek),
        &[0u8; PART_HEADER_LEN],
        &mut SysRng,
    )
    .map_err(|_| refused("sealing failed"))?;
    let per_part = 4 + probe.to_bytes().len();
    let fixed = bytes.len() + 4;
    let total = match total {
        Some(total) => total,
        None => fitting_total(kind.step, fixed, per_part, body.len()).ok_or_else(too_large)?,
    };
    let (count, room) = fit(total, fixed, per_part)
        .filter(|(_, room)| *room >= body.len())
        .ok_or_else(too_large)?;
    body.resize(room, 0);
    bytes.reserve(total.saturating_sub(bytes.len()));
    let count_bytes = u32::try_from(count).map_err(|_| too_large())?.to_be_bytes();
    bytes.extend_from_slice(&count_bytes);
    seal_parts(&params, &kek, &body, &even_sizes(room, count), |part| {
        put_counted(&mut bytes, &part.to_bytes())
    })?;
    if bytes.len() != total {
        return Err(refused("the sealed object missed its size"));
    }
    Ok(bytes)
}

/// The parts an object of `total` bytes holds after `fixed` frame bytes, and the
/// body bytes they carry: `None` when not even one part fits.
fn fit(total: usize, fixed: usize, per_part: usize) -> Option<(usize, usize)> {
    let room = total.checked_sub(fixed)?;
    let count = room.div_ceil(per_part + CHUNK).max(1);
    Some((count, room.checked_sub(count.checked_mul(per_part)?)?))
}

/// The smallest positive multiple of `step` whose parts carry `len` body bytes.
fn fitting_total(step: usize, fixed: usize, per_part: usize, len: usize) -> Option<usize> {
    let mut steps = len.checked_add(fixed)?.div_ceil(step).max(1);
    loop {
        let total = steps.checked_mul(step)?;
        if fit(total, fixed, per_part).is_some_and(|(_, room)| room >= len) {
            return Some(total);
        }
        steps = steps.checked_add(1)?;
    }
}

/// `len` bytes in `count` parts, as even as can be.
fn even_sizes(len: usize, count: usize) -> Vec<usize> {
    let (each, extra) = (len / count, len % count);
    (0..count)
        .map(|index| each + usize::from(index < extra))
        .collect()
}

/// Seals `body` in parts of `sizes` bytes. Each part names the body's digest, its
/// index and the count, so parts of two bodies never mix.
fn seal_parts(
    params: &SealParams<'_>,
    kek: &Kek,
    body: &[u8],
    sizes: &[usize],
    mut push: impl FnMut(Envelope) -> Result<()>,
) -> Result<()> {
    let digest = *blake3::hash(body).as_bytes();
    let count = u32::try_from(sizes.len()).map_err(|_| refused("too many sealed parts"))?;
    let mut at = 0usize;
    for (index, size) in sizes.iter().enumerate() {
        let chunk = body
            .get(at..at + size)
            .ok_or_else(|| refused("the sealed parts outrun their body"))?;
        at += size;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(PART_HEADER_LEN + size));
        plaintext.extend_from_slice(PART_LABEL);
        plaintext.extend_from_slice(&digest);
        plaintext.extend_from_slice(&(index as u32).to_be_bytes());
        plaintext.extend_from_slice(&count.to_be_bytes());
        plaintext.extend_from_slice(chunk);
        push(
            seal(params, SealKey::SymmetricKek(kek), &plaintext, &mut SysRng)
                .map_err(|_| refused("sealing failed"))?,
        )?;
    }
    if at != body.len() {
        return Err(refused("the sealed parts fall short of their body"));
    }
    Ok(())
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
    let id = frame.generation.to_bytes();
    let policy = symmetric_policy(kind.purpose, vault_id, &id, BODY_RECIPIENT);
    let body = open_parts(&policy, &Kek::from_bytes(*outer), &frame.parts)?;
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

/// label ‖ vault (32) ‖ generation (24) ‖ publisher (16) ‖ signature (64) ‖ base
/// length (8) ‖ base ‖ section count (4) ‖ sections. The signature covers vault,
/// generation, publisher and everything after it; the zeros after are padding.
fn encode_bundle_body(
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    base: &[u8],
    sections: &[SealedBundleSection],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    body.extend_from_slice(BUNDLE_LABEL);
    body.extend_from_slice(&plan.vault_id);
    body.extend_from_slice(&generation.to_bytes());
    body.extend_from_slice(plan.publisher.as_bytes());
    let signature_at = body.len();
    body.extend_from_slice(&[0u8; 64]);
    let content_at = body.len();
    body.extend_from_slice(&(base.len() as u64).to_be_bytes());
    body.extend_from_slice(base);
    let count = u32::try_from(sections.len()).map_err(|_| refused("too many sections"))?;
    body.extend_from_slice(&count.to_be_bytes());
    for section in sections {
        section.encode(&mut body)?;
    }
    let digest = signed_digest(
        &plan.vault_id,
        generation,
        plan.publisher,
        &body[content_at..],
    );
    body[signature_at..content_at].copy_from_slice(&plan.signing.sign(&digest).to_bytes());
    Ok(body)
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
    let signed = signed_digest(
        vault_id,
        generation,
        publisher,
        &body[content_at..cursor.at],
    );
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(OpenedVaultBundle {
        vault_id: *vault_id,
        generation,
        publisher,
        signature,
        signed,
        base,
        sections,
    })
}

fn signed_digest(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
    content: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SIGNATURE_CONTEXT);
    hasher.update(vault_id);
    hasher.update(&generation.to_bytes());
    hasher.update(publisher.as_bytes());
    hasher.update(content);
    *hasher.finalize().as_bytes()
}

/// `BLAKE3-derive_key(context, vault ‖ key id ‖ world key)`: a section's key or
/// its tag. Only a holder of the world key computes either.
fn section_digest(context: &str, vault_id: &[u8; 32], key: &WorldKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(vault_id);
    hasher.update(&key.id().envelope_key_id());
    hasher.update(key.expose());
    let out = *hasher.finalize().as_bytes();
    // The hasher's block buffer still holds the key's bytes.
    zeroize::Zeroize::zeroize(&mut hasher);
    out
}

/// A section body's padded size: a power of two from 4 KiB, then whole chunks.
fn section_padded_len(unpadded: usize) -> usize {
    if unpadded <= CHUNK {
        unpadded.next_power_of_two().max(SECTION_PAD_FLOOR)
    } else {
        unpadded.div_ceil(CHUNK) * CHUNK
    }
}

/// label ‖ vault (32) ‖ key id (40) ‖ payload length (8) ‖ payload ‖ zeros.
fn encode_section_body(
    vault_id: &[u8; 32],
    key: &WorldKeyId,
    payload: &[u8],
) -> Zeroizing<Vec<u8>> {
    let unpadded = SECTION_LABEL.len() + 32 + KEY_ID_LEN + 8 + payload.len();
    let mut body = Zeroizing::new(Vec::with_capacity(section_padded_len(unpadded)));
    body.extend_from_slice(SECTION_LABEL);
    body.extend_from_slice(vault_id);
    body.extend_from_slice(&key.envelope_key_id());
    body.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    body.extend_from_slice(payload);
    body.resize(section_padded_len(unpadded), 0);
    body
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

/// label ‖ vault (32) ‖ generation (24) ‖ count (4) ‖ each key id (40) ‖ pad (32),
/// leaving out `without`'s keys.
fn encode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    entries: &[(WorldKeyId, Zeroizing<[u8; 32]>)],
    without: Option<EntityId>,
) -> Result<Zeroizing<Vec<u8>>> {
    let kept: Vec<_> = entries
        .iter()
        .filter(|(key, _)| Some(key.world) != without)
        .collect();
    let count = u32::try_from(kept.len()).map_err(|_| refused("too many pads"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(
        PADS_LABEL.len() + 32 + GENERATION_LEN + 4 + kept.len() * (KEY_ID_LEN + 32),
    ));
    body.extend_from_slice(PADS_LABEL);
    body.extend_from_slice(vault_id);
    body.extend_from_slice(&generation.to_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    for (key, pad) in kept {
        body.extend_from_slice(&key.envelope_key_id());
        body.extend_from_slice(&pad[..]);
    }
    Ok(body)
}

fn decode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    body: &[u8],
) -> Result<Vec<(WorldKeyId, Zeroizing<[u8; 32]>)>> {
    let malformed = || refused("the pad object's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(PADS_LABEL.len()) != Some(PADS_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(GENERATION_LEN) != Some(&generation.to_bytes()[..])
    {
        return Err(refused("the pad object names another vault or generation"));
    }
    let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut entries = Vec::new();
    for _ in 0..count {
        let world =
            EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let key = WorldKeyId {
            world,
            generation: u64::from_be_bytes(cursor.array().ok_or_else(malformed)?),
            mint: cursor.array().ok_or_else(malformed)?,
        };
        let pad = Zeroizing::new(cursor.array().ok_or_else(malformed)?);
        entries.push((key, pad));
    }
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(entries)
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

    fn rest_is_zero(&self) -> bool {
        self.bytes[self.at..].iter().all(|byte| *byte == 0)
    }
}
