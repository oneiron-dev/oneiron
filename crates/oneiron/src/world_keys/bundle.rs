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
mod bodies;
mod carrier;
mod codec;
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
use self::bodies::{
    PadsBody, decode_bundle_body, decode_pads_body, decode_section_body, encode_bundle_body,
    encode_pads_body, encode_section_body, section_digest, section_digest_into, section_kek,
    section_padded_len, signed_digest,
};
pub use self::carrier::{SealedVaultUpload, WorldCapsuleImport};
use self::codec::{
    AEAD, BODY_RECIPIENT, BUNDLE, BUNDLE_LABEL, CHUNK, Cursor, DeletedWorldPads, FRAME_VERSION,
    Frame, HYBRID, KEM, KEY_ID_LEN, Kind, OpenedOuter, PADS, PADS_LABEL, PART_HEADER_LEN,
    PART_LABEL, REQUEST_TAG, SEALED_BUNDLE_NEW_PAD_DELETED_WORLD, SEALED_KEY_PADS_STEP_BYTES,
    SECTION_KEY_CONTEXT, SECTION_LABEL, SECTION_PAD_FLOOR, SECTION_RECIPIENT, SECTION_TAG_CONTEXT,
    SIGNATURE_CONTEXT, SLOT_LABEL, SLOT_PLAINTEXT_LEN, SLOT_RECIPIENT, SLOT_STEP, SYMMETRIC,
    SealedObject, even_sizes, fit, fitting_total, open_framed, open_outer, open_parts, open_slots,
    parse_envelope, parse_frame, put_counted, seal_outer, seal_params, seal_parts, seal_slots,
    symmetric_policy,
};
#[cfg(feature = "sync")]
use self::codec::{EraseKey, SEALED_BUNDLE_ERASE_KEY_SOURCE, open_outer_with_key};
pub(crate) use self::key_erase::{PadEraseSubject, stage_retained_pad_key_erase_in_txn};
use self::plan::{SealPlan, seal_object};
pub(crate) use self::publication::bundle_publish_executor;
pub use self::retirement::{
    SEALED_BUNDLE_KEEP, SEALED_BUNDLE_PAD_STEP_BYTES, SEALED_BUNDLE_UPLOAD_INTERVAL_SECS,
    SealedBundleGeneration, retired_bundle_generations, sealed_bundle_slot,
};
pub use self::sections::OpenedBundleSection;

use crate::bundle_generations::GENERATION_LEN;

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
