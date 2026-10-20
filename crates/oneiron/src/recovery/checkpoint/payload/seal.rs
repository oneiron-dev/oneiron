//! Sealing the payload's bundles (KS7-2b): one bundle per compartment and
//! role, split into pieces of at most the artifact's chunk length, each
//! piece one E0 envelope under its compartment's key
//! (`Purpose::CheckpointPayload`). The manifest's [`PayloadSection`] names
//! what a restore needs: each compartment's item and generation, and each
//! bundle's compartment, role, locator commitment and pieces (where each
//! starts in its payload stream, its length and its envelope's BLAKE3). It
//! never holds a key, a wrap, a custody head or a pad, nor a row's locator:
//! the locators travel inside the ciphertext, bound by their commitment.

use std::collections::{BTreeMap, BTreeSet};

use getrandom::SysRng;
use oneiron_crypto::backup::{ARTIFACT_SEAL_EPOCH as EPOCH, ARTIFACT_SEAL_SUITE as AEAD};
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, SealKey, SealParams, WrapType, seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::super::artifact::{CHUNK_LEN, ZSTD_LEVEL};
use super::{Carrier, Getter};
use crate::error::{Error, Result};
use crate::store::CustodyKind;
use crate::store::checkpoint_payload::rows::{
    OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, read_actor_parts,
};
use crate::store::checkpoint_payload::{PAYLOAD_PURPOSE, PayloadItem, Subtype};
use crate::world_keys::refused;

/// CALLS PAYLOAD_SEAL_UNIT (Engine 10-20 07:3x): one bundle per
/// compartment and role, and one E0 envelope per piece of it at most this
/// long, the artifact's own chunk length: a large owner is a run of
/// envelopes, never a size refusal.
const PIECE_LEN: usize = CHUNK_LEN;

/// CALLS PAYLOAD_AAD (Engine 10-20 07:3x): an envelope's `key_id` is the
/// BLAKE3, in this domain, of its compartment's custody id (kind, item,
/// generation), its bundle's role, its bundle's locator commitment
/// ([`LOCATOR_DOMAIN`]) and the piece's index and count; its recipient is
/// the custody id and its vault the vault's id. A piece opens only as that
/// piece of that bundle, in that compartment of that vault.
const KEY_ID_DOMAIN: &str = "oneiron/checkpoint-payload/key-id/v1";

/// The commitment to a bundle's locators: each one's database, full key
/// and fragment path, in its frame's order. An opened bundle must read back
/// to the commitment it was sealed with.
const LOCATOR_DOMAIN: &str = "oneiron/checkpoint-payload/locators/v1";

fn corrupt() -> Error {
    CustodyKind::CheckpointPayload.corrupt()
}

/// What one bundle holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::recovery::checkpoint) enum BundleRole {
    /// An owner getter's rows, framed by that getter.
    Content(Getter),
    /// A mixed carrier's fragments, split by KS7-3's port.
    Carrier(Carrier),
    /// One actor's parts, across every owner.
    Actors,
}

impl BundleRole {
    fn code(self) -> [u8; 2] {
        match self {
            Self::Content(getter) => [1, getter.tag()],
            Self::Carrier(carrier) => [2, carrier.tag()],
            Self::Actors => [3, 0],
        }
    }
}

/// One compartment a payload is sealed under: its item and generation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Required {
    subtype: u8,
    owner: [u8; 32],
    incarnation: [u8; 16],
    generation: u64,
}

impl Required {
    fn of(item: &PayloadItem, generation: u64) -> Self {
        Self {
            subtype: item.subtype().tag(),
            owner: *item.owner(),
            incarnation: *item.incarnation(),
            generation,
        }
    }

    fn item(&self) -> Result<PayloadItem> {
        let subtype = Subtype::from_tag(self.subtype).ok_or_else(corrupt)?;
        PayloadItem::new(subtype, self.owner, self.incarnation)
    }

    /// The custody id: the kind's tag, the item, then the generation.
    fn custody_id(&self) -> Result<Vec<u8>> {
        let mut out = vec![CustodyKind::CheckpointPayload.tag()];
        out.extend_from_slice(&self.item()?.encode());
        out.extend_from_slice(&self.generation.to_be_bytes());
        Ok(out)
    }
}

/// One sealed piece: where it starts in its payload stream, its length and
/// its envelope's BLAKE3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Piece {
    position: u64,
    len: u64,
    digest: [u8; 32],
}

/// One bundle's line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleEntry {
    /// Its compartment's place in the section's required list.
    compartment: u32,
    role: BundleRole,
    /// The commitment to its rows' locators ([`LOCATOR_DOMAIN`]).
    locators: [u8; 32],
    /// Its payload stream's place among the artifact's.
    stream: u32,
    pieces: Vec<Piece>,
}

/// The manifest's payload section (KS-7): every compartment the payload is
/// sealed under, and every bundle sealed under one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::recovery::checkpoint) struct PayloadSection {
    required: Vec<Required>,
    bundles: Vec<BundleEntry>,
}

impl PayloadSection {
    /// Every compartment the payload needs, its item and generation, for a
    /// restore's custody plan (`checkpoint_payload::require_all`).
    pub(in crate::recovery::checkpoint) fn required(&self) -> Result<Vec<(PayloadItem, u64)>> {
        self.required
            .iter()
            .map(|required| Ok((required.item()?, required.generation)))
            .collect()
    }

    /// Each bundle: its compartment's place in [`Self::required`], its role
    /// and its payload stream's place.
    pub(in crate::recovery::checkpoint) fn bundles(&self) -> Vec<(usize, BundleRole, usize)> {
        self.bundles
            .iter()
            .map(|bundle| {
                (
                    bundle.compartment as usize,
                    bundle.role,
                    bundle.stream as usize,
                )
            })
            .collect()
    }

    /// Whether the section names exactly `streams` payload streams, one
    /// bundle each, in order.
    pub(in crate::recovery::checkpoint) fn names_streams(&self, streams: usize) -> bool {
        self.bundles.len() == streams
            && self
                .bundles
                .iter()
                .enumerate()
                .all(|(at, bundle)| bundle.stream as usize == at)
    }
}

/// What a capture hands the artifact's writer: the section its manifest
/// names, and each bundle's sealed pieces, one payload stream per bundle in
/// the section's order.
pub(in crate::recovery::checkpoint) struct PayloadStreams {
    pub(in crate::recovery::checkpoint) section: PayloadSection,
    pub(in crate::recovery::checkpoint) streams: Vec<Vec<u8>>,
}

/// The compartment an owner's bundles are sealed under. Its key was minted
/// or read under the custody guard (`Store::checkpoint_payload_keys_in_txn`):
/// the seal adds no lifecycle of its own.
pub(in crate::recovery::checkpoint) struct Compartment {
    pub(in crate::recovery::checkpoint) item: PayloadItem,
    pub(in crate::recovery::checkpoint) generation: u64,
    pub(in crate::recovery::checkpoint) key: Zeroizing<[u8; 32]>,
}

/// One bundle before it is sealed: its owner, its role and its plaintext.
pub(super) struct Bundle {
    pub(super) owner: OwnerRef,
    pub(super) role: BundleRole,
    pub(super) plain: Vec<u8>,
}

fn db_code(db: RowDb) -> u8 {
    match db {
        RowDb::Entities => 1,
        RowDb::EdgesOut => 2,
        RowDb::EdgesIn => 3,
        RowDb::VaultMeta => 4,
        RowDb::SyncState => 5,
    }
}

fn put_len(hasher: &mut blake3::Hasher, len: usize) {
    hasher.update(&(len as u64).to_be_bytes());
}

/// The commitment to `locators` ([`LOCATOR_DOMAIN`]).
fn commitment(locators: &[&RowLocator]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(LOCATOR_DOMAIN);
    put_len(&mut hasher, locators.len());
    for at in locators {
        hasher.update(&[db_code(at.db)]);
        put_len(&mut hasher, at.key.len());
        hasher.update(&at.key);
        put_len(&mut hasher, at.path.len());
        hasher.update(at.path.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The commitment to the locators `plain` holds, read back with the frame
/// its role writes; refused unless every part is `owner`'s.
fn locators_of(role: BundleRole, plain: &[u8], owner: &OwnerRef) -> Result<[u8; 32]> {
    match role {
        BundleRole::Actors => {
            let parts = read_actor_parts(plain)?;
            if parts
                .iter()
                .any(|part| OwnerRef::entity(&part.actor_entity) != *owner)
            {
                return Err(corrupt());
            }
            let locators: Vec<&RowLocator> =
                parts.iter().map(|part| &part.content_locator).collect();
            Ok(commitment(&locators))
        }
        BundleRole::Content(_) | BundleRole::Carrier(_) => {
            let content = OpenedOwnerRows::open(plain, Vec::new(), BTreeSet::new())?;
            if content.subtype != owner.subtype || content.owner32 != owner.owner32 {
                return Err(corrupt());
            }
            let locators: Vec<&RowLocator> = content.rows.iter().map(RowPart::at).collect();
            Ok(commitment(&locators))
        }
    }
}

/// A piece's `key_id` ([`KEY_ID_DOMAIN`]).
fn key_id(
    custody: &[u8],
    role: BundleRole,
    locators: &[u8; 32],
    index: u32,
    count: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_DOMAIN);
    put_len(&mut hasher, custody.len());
    hasher.update(custody);
    hasher.update(&role.code());
    hasher.update(locators);
    hasher.update(&index.to_be_bytes());
    hasher.update(&count.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Seals each of `bundles` for `vault` under its owner's compartment in
/// `compartments`, one payload stream per bundle, in order. A bundle whose
/// owner has no compartment there, or one that is not that owner's, refuses.
pub(super) fn seal_bundles(
    vault: &[u8; 32],
    bundles: &[Bundle],
    compartments: &BTreeMap<OwnerRef, Compartment>,
) -> Result<PayloadStreams> {
    let mut required: Vec<Required> = Vec::new();
    let mut places: BTreeMap<Required, u32> = BTreeMap::new();
    let mut entries = Vec::with_capacity(bundles.len());
    let mut streams = Vec::with_capacity(bundles.len());
    for (index, bundle) in bundles.iter().enumerate() {
        let compartment = compartments
            .get(&bundle.owner)
            .ok_or(Error::InvariantViolation(
                "a checkpoint payload owner has no compartment",
            ))?;
        let item = &compartment.item;
        if item.subtype() != bundle.owner.subtype || *item.owner() != bundle.owner.owner32 {
            return Err(Error::InvariantViolation(
                "a checkpoint payload bundle is not its compartment's owner's",
            ));
        }
        let line = Required::of(item, compartment.generation);
        let custody = line.custody_id()?;
        let place = match places.get(&line) {
            Some(place) => *place,
            None => {
                let place = u32::try_from(required.len()).map_err(|_| corrupt())?;
                places.insert(line.clone(), place);
                required.push(line);
                place
            }
        };
        let locators = locators_of(bundle.role, &bundle.plain, &bundle.owner)?;
        let kek = Kek::from_bytes(*compartment.key);
        let count = u32::try_from(bundle.plain.chunks(PIECE_LEN).len()).map_err(|_| corrupt())?;
        let mut stream = Vec::new();
        let mut pieces = Vec::new();
        for (at, piece) in bundle.plain.chunks(PIECE_LEN).enumerate() {
            let at = u32::try_from(at).map_err(|_| corrupt())?;
            let compressed = zstd::bulk::compress(piece, ZSTD_LEVEL)?;
            let key_id = key_id(&custody, bundle.role, &locators, at, count);
            let params = SealParams {
                suite: AEAD,
                purpose: PAYLOAD_PURPOSE,
                epoch: EPOCH,
                key_id: &key_id,
                recipient: &custody,
                vault_id: vault,
            };
            let envelope = seal(
                &params,
                SealKey::SymmetricKek(&kek),
                &compressed,
                &mut SysRng,
            )
            .map_err(|_| refused("sealing a checkpoint payload compartment failed"))?
            .to_bytes();
            pieces.push(Piece {
                position: stream.len() as u64,
                len: envelope.len() as u64,
                digest: *blake3::hash(&envelope).as_bytes(),
            });
            stream.extend_from_slice(&envelope);
        }
        entries.push(BundleEntry {
            compartment: place,
            role: bundle.role,
            locators,
            stream: u32::try_from(index).map_err(|_| corrupt())?,
            pieces,
        });
        streams.push(stream);
    }
    Ok(PayloadStreams {
        section: PayloadSection {
            required,
            bundles: entries,
        },
        streams,
    })
}

/// Opens bundle `index` of `section` for `vault`, out of its payload
/// stream's bytes `stream`, with its compartment's `key`. The pieces must
/// tile the stream where the section says, each read to its digest and
/// open under the binding it was sealed with, and the opened bundle's
/// locators must be the ones it committed to. Returns its plaintext, for
/// its role's reader.
pub(in crate::recovery::checkpoint) fn open_bundle(
    vault: &[u8; 32],
    section: &PayloadSection,
    index: usize,
    stream: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>> {
    let bundle = section.bundles.get(index).ok_or_else(corrupt)?;
    let required = section
        .required
        .get(bundle.compartment as usize)
        .ok_or_else(corrupt)?;
    let custody = required.custody_id()?;
    let count = u32::try_from(bundle.pieces.len()).map_err(|_| corrupt())?;
    let kek = Kek::from_bytes(*key);
    let mut next = 0_u64;
    let mut plain = Vec::new();
    for (at, piece) in bundle.pieces.iter().enumerate() {
        if piece.position != next {
            return Err(corrupt());
        }
        let start = usize::try_from(piece.position).map_err(|_| corrupt())?;
        let len = usize::try_from(piece.len).map_err(|_| corrupt())?;
        let envelope = start
            .checked_add(len)
            .and_then(|end| stream.get(start..end))
            .ok_or_else(corrupt)?;
        if *blake3::hash(envelope).as_bytes() != piece.digest {
            return Err(corrupt());
        }
        let at = u32::try_from(at).map_err(|_| corrupt())?;
        let key_id = key_id(&custody, bundle.role, &bundle.locators, at, count);
        let policy = OpenPolicy {
            purpose: PAYLOAD_PURPOSE,
            vault_id: vault,
            recipient: &custody,
            key_id: &key_id,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[AEAD],
            kem_suites: &[],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let compressed = Envelope::parse(envelope)
            .map_err(|_| corrupt())?
            .open(OpenKey::SymmetricKek(&kek), &policy)
            .map_err(|_| refused("a checkpoint payload compartment does not open with its key"))?;
        plain.extend_from_slice(
            &zstd::bulk::decompress(&compressed, PIECE_LEN).map_err(|_| corrupt())?,
        );
        next = next.checked_add(piece.len).ok_or_else(corrupt)?;
    }
    if next != stream.len() as u64 {
        return Err(corrupt());
    }
    let owner = OwnerRef {
        subtype: required.item()?.subtype(),
        owner32: required.owner,
    };
    if locators_of(bundle.role, &plain, &owner)? != bundle.locators {
        return Err(corrupt());
    }
    Ok(plain)
}
