//! The home's current pad objects as one read names them (FIX 7106, its
//! copy half): each kept generation's entry, its pad object's stored parts
//! and its late joiners' grants, read in one transaction, and the revision
//! that names the read. Nothing here opens a pad: every object stays sealed,
//! and no second index is kept beside the generations, parts and grants.
//!
//! A restore or a side copy carries them whole, with the bundles of the
//! generations a copy may adopt ([`capture_current_pad_objects_in_txn`], or
//! from the rows a source door read, [`capture_current_pad_objects_in_rows`])
//! into a store whose image kept older objects, installs them over that
//! store's own while it still holds what the caller saw there, the
//! generations it keeps first brought to the source's ([`membership`],
//! [`install_captured_pad_objects_in_txn`]), and reads them back as the
//! capture carries them ([`read_back_captured_in_txn`]).
//! A kept pad object whose parts are missing takes its bytes again from a
//! current provider's capture or a machine's upload of that same object
//! ([`refill_pad_object`]); an erase's rewrite keeps the replace door.
//!
//! A read of a kept pad object below its length whose stored part is missing
//! or short is typed unavailable ([`BundlePartRead`]), never its end and
//! never a missing generation. A complete object reads as before, cold or
//! not, with no provider asked.

use super::super::bundle_access::{generation_prefix, grant_row};
use super::{
    Asked, GENERATIONS, PARTS, SealedBundleEntry, SealedBundleObject, denied, object_prefix,
    owner_machine, put_parts_in, retire_aged, sealed_generation_from_hex, sealed_generation_hex,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, PeerMachine};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::sync::residence::PadAccessState;
use crate::world_keys::{PadAdmissionTarget, SealedBundleGeneration, SealedKeyPads};

mod membership;

pub(crate) use membership::{PadObjectMembership, generations_an_install_retires_in_txn};

/// The late joiners' grants and the admission outbox (`bundle_access`).
const ACCESS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_ACCESS);
/// The admission outbox's rows, under [`ACCESS`].
const QUEUED_PREFIX: &[u8] = b"q:";
/// What the revision of one read of the current pad objects is derived under.
const REVISION_CONTEXT: &str = "oneiron/sealed-pad-objects/revision/v1";

/// What a capture of the home's pad objects carries (CALLS:
/// PAD_OBJECT_CAPTURE_FORM, ruled by the Engine 10-22).
enum CaptureForm {
    /// The current entries, sealed pad object parts and grant rows, from one
    /// read revision: no opened pad, and no historical image's metadata mixed
    /// with today's objects.
    OpaqueMetadataPartsGrantsAtOneCurrentRevision,
}

const PAD_OBJECT_CAPTURE_FORM: CaptureForm =
    CaptureForm::OpaqueMetadataPartsGrantsAtOneCurrentRevision;

/// A kept pad object a read found missing or short below its length: its
/// generation, its digest and the offset read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PadObjectUnavailable {
    pub generation: SealedBundleGeneration,
    /// BLAKE3 of the whole pad object the home keeps for the generation.
    pub digest: [u8; 32],
    pub offset: u64,
}

/// One read of a slice of a kept object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundlePartRead {
    /// The slice.
    Part(Vec<u8>),
    /// The offset is at or past the object's end.
    End,
    /// The pad object is kept, and its bytes there are not (FIX 7106).
    PadObjectUnavailable(PadObjectUnavailable),
}

impl BundlePartRead {
    /// The outcome a reply names for [`Self::PadObjectUnavailable`], beside
    /// the generation's entry.
    pub const PAD_OBJECT_UNAVAILABLE: &'static str = "PAD_OBJECT_UNAVAILABLE";
}

/// The home's kept generations as one read names them: the revision of
/// that read, and each entry, newest committed first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBundleIndex {
    /// The read's revision: BLAKE3 over the vault, the home, and each kept
    /// generation's entry and grant rows in commit order. Opaque, never an
    /// order.
    pub retained_revision: [u8; 32],
    pub entries: Vec<SealedBundleEntry>,
}

/// One kept generation's pad object as the home keeps it now.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "02A2 reads the copy and the grants (L02)")]
pub(crate) struct PadObjectMeta {
    pub(crate) entry: SealedBundleEntry,
    /// The entry's own commit order, never another counter.
    pub(crate) commit_order: u64,
    /// Its grants, pending and offered, that decode.
    pub(crate) grants: Vec<(PadAdmissionTarget, PadAccessState)>,
}

/// The home's current pad objects, read in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CurrentPadObjects {
    pub(crate) vault_id: [u8; 32],
    /// The home that keeps them.
    pub(crate) home: EntityId,
    /// The read's revision ([`SealedBundleIndex::retained_revision`]).
    pub(crate) retained_revision: [u8; 32],
    /// Oldest committed first.
    pub(crate) entries: Vec<PadObjectMeta>,
}

/// One kept pad object as a capture carries it.
struct CapturedObject {
    /// Each stored part, by its offset, as the home keeps it; a missing part
    /// stays a gap, never certified whole.
    parts: Vec<(u64, Vec<u8>)>,
    /// Each stored part of its generation's bundle, by its offset, where the
    /// capture carries it (a copy may adopt the generation); else none.
    bundle: Vec<(u64, Vec<u8>)>,
    /// Its grant rows, undecoded: the key after the table prefix and the
    /// stored bytes.
    grants: Rows,
}

/// The home's current pad objects, carried whole from one read: their
/// entries, sealed parts and grant rows (PAD_OBJECT_CAPTURE_FORM).
pub(crate) struct CapturedPadObjects {
    index: CurrentPadObjects,
    /// One per entry of `index`, in its order.
    objects: Vec<CapturedObject>,
    /// The admission outbox's rows.
    queued: Rows,
}

impl CapturedPadObjects {
    /// What the capture read.
    #[allow(dead_code, reason = "02A2 wires the object copy (L02)")]
    pub(crate) fn index(&self) -> &CurrentPadObjects {
        &self.index
    }

    fn object(
        &self,
        generation: &SealedBundleGeneration,
    ) -> Option<(&PadObjectMeta, &CapturedObject)> {
        self.index
            .entries
            .iter()
            .zip(&self.objects)
            .find(|(meta, _)| meta.entry.generation == *generation)
    }
}

/// What an install or a refill did.
#[allow(dead_code, reason = "02A2 wires the object copy (L02)")]
pub(crate) enum PadObjectInstall {
    /// Written; the current objects after it, to read back once committed.
    Installed(CurrentPadObjects),
    /// The store holds other objects than the caller saw, or the source's
    /// is not the one kept here: nothing was written.
    CurrentChanged,
    /// The object to write is not whole: nothing was written.
    Unavailable(PadObjectUnavailable),
}

/// Where a refill takes a kept pad object's bytes from. Never discovered
/// here: the caller names it.
#[allow(dead_code, reason = "02A2 wires the object copy (L02)")]
pub(crate) enum PadObjectRefillSource<'a> {
    /// A capture of the current objects an authenticated current provider
    /// served.
    CurrentProvider(&'a CapturedPadObjects),
    /// A machine of the owner's uploading the object it holds.
    Reupload {
        peer: PeerMachine,
        pads: &'a SealedKeyPads,
    },
}

/// Rows of one table: the key after the table's prefix and the stored bytes,
/// in key order.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// One of the tables a capture reads.
#[derive(Clone, Copy)]
enum Family {
    Generations,
    Parts,
    Access,
}

impl Family {
    fn table(self) -> SideTable<String, Vec<u8>, Raw> {
        match self {
            Self::Generations => GENERATIONS,
            Self::Parts => PARTS,
            Self::Access => ACCESS,
        }
    }
}

/// The rows of `family` under `prefix` in `txn`.
fn txn_rows(store: &Store, txn: &heed::RoTxn<'_>, family: Family, prefix: &[u8]) -> Result<Rows> {
    family.table().iter_raw_from(store, txn, prefix)?.collect()
}

/// The rows of `family` under `prefix` among `rows`, full `sync_state` keys
/// as a source door read them.
fn source_rows(rows: &[(Vec<u8>, Vec<u8>)], family: Family, prefix: &[u8]) -> Rows {
    let table = family.table().decl().prefix;
    let mut out: Rows = rows
        .iter()
        .filter_map(|(key, raw)| {
            let rest = key.strip_prefix(table)?;
            rest.starts_with(prefix)
                .then(|| (rest.to_vec(), raw.clone()))
        })
        .collect();
    out.sort();
    out
}

fn framed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// The revision of one read: the vault, the home, and each kept entry and
/// its grant rows, in commit order.
fn revision(
    vault_id: &[u8; 32],
    home: &EntityId,
    entries: &[PadObjectMeta],
    grants: &[Rows],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(REVISION_CONTEXT);
    hasher.update(vault_id);
    hasher.update(home.as_bytes());
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for (meta, rows) in entries.iter().zip(grants) {
        hasher.update(&meta.entry.generation.to_bytes());
        framed(&mut hasher, &meta.entry.encode());
        hasher.update(&(rows.len() as u64).to_be_bytes());
        for (key, raw) in rows {
            framed(&mut hasher, key);
            framed(&mut hasher, raw);
        }
    }
    *hasher.finalize().as_bytes()
}

/// The current index `read` names, and each entry's grant rows.
fn index_from(
    vault_id: [u8; 32],
    home: EntityId,
    mut read: impl FnMut(Family, &[u8]) -> Result<Rows>,
) -> Result<(CurrentPadObjects, Vec<Rows>)> {
    let mut kept = Vec::new();
    for (key, raw) in read(Family::Generations, &[])? {
        let generation = std::str::from_utf8(&key)
            .ok()
            .and_then(sealed_generation_from_hex)
            .ok_or(Error::InvalidKey)?;
        kept.push(SealedBundleEntry::decode(generation, &raw)?);
    }
    kept.sort_by_key(|entry| entry.commit_order);
    let mut entries = Vec::with_capacity(kept.len());
    let mut grants = Vec::with_capacity(kept.len());
    for entry in kept {
        let rows = read(
            Family::Access,
            generation_prefix(&entry.generation).as_bytes(),
        )?;
        entries.push(PadObjectMeta {
            entry,
            commit_order: entry.commit_order,
            grants: rows
                .iter()
                .filter_map(|(key, raw)| grant_row(key, raw))
                .collect(),
        });
        grants.push(rows);
    }
    let retained_revision = revision(&vault_id, &home, &entries, &grants);
    Ok((
        CurrentPadObjects {
            vault_id,
            home,
            retained_revision,
            entries,
        },
        grants,
    ))
}

/// A part's offset, from its key after the table prefix.
fn part_offset(key: &[u8], prefix: &str) -> Result<u64> {
    key.strip_prefix(prefix.as_bytes())
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .filter(|rest| rest.len() == 16)
        .and_then(|rest| u64::from_str_radix(rest, 16).ok())
        .ok_or(Error::InvalidKey)
}

/// The pad object parts `read` holds for `generation`, by offset.
fn pad_parts(
    generation: &SealedBundleGeneration,
    read: impl FnMut(Family, &[u8]) -> Result<Rows>,
) -> Result<Vec<(u64, Vec<u8>)>> {
    object_parts(generation, SealedBundleObject::Pads, read)
}

/// The parts of `generation`'s `object` `read` holds, by offset.
fn object_parts(
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    mut read: impl FnMut(Family, &[u8]) -> Result<Rows>,
) -> Result<Vec<(u64, Vec<u8>)>> {
    let prefix = object_prefix(generation, object);
    read(Family::Parts, prefix.as_bytes())?
        .into_iter()
        .map(|(key, part)| Ok((part_offset(&key, &prefix)?, part)))
        .collect()
}

/// A capture of what `read` holds, with the bundle of each generation
/// `bundles` names.
fn capture_from(
    vault_id: [u8; 32],
    home: EntityId,
    mut read: impl FnMut(Family, &[u8]) -> Result<Rows>,
    bundles: impl Fn(&SealedBundleGeneration) -> bool,
) -> Result<CapturedPadObjects> {
    match PAD_OBJECT_CAPTURE_FORM {
        CaptureForm::OpaqueMetadataPartsGrantsAtOneCurrentRevision => {}
    }
    let (index, grants) = index_from(vault_id, home, &mut read)?;
    let mut objects = Vec::with_capacity(index.entries.len());
    for (meta, grants) in index.entries.iter().zip(grants) {
        let generation = &meta.entry.generation;
        let bundle = if bundles(generation) {
            object_parts(generation, SealedBundleObject::Bundle, &mut read)?
        } else {
            Vec::new()
        };
        objects.push(CapturedObject {
            parts: pad_parts(generation, &mut read)?,
            bundle,
            grants,
        });
    }
    let queued = read(Family::Access, QUEUED_PREFIX)?;
    Ok(CapturedPadObjects {
        index,
        objects,
        queued,
    })
}

/// The whole pad object `entry` names, from `parts`: contiguous from offset
/// 0, its length and digest, a sealed pad object of its generation. Else the
/// first offset its bytes are not there from.
fn whole(entry: &SealedBundleEntry, parts: &[(u64, Vec<u8>)]) -> std::result::Result<Vec<u8>, u64> {
    let mut bytes = Vec::new();
    for (offset, part) in parts {
        if *offset != bytes.len() as u64 {
            break;
        }
        bytes.extend_from_slice(part);
    }
    let held = bytes.len() as u64;
    if held < entry.pads_len {
        return Err(held);
    }
    if !is_object(entry, &bytes) {
        return Err(0);
    }
    Ok(bytes)
}

/// Whether `bytes` are the pad object `entry` names: its length and digest,
/// sealed for its generation.
fn is_object(entry: &SealedBundleEntry, bytes: &[u8]) -> bool {
    bytes.len() as u64 == entry.pads_len
        && *blake3::hash(bytes).as_bytes() == entry.pads_digest
        && SealedKeyPads::from_bytes(bytes).is_ok_and(|pads| pads.generation() == entry.generation)
}

/// Whether `held` and `brought` are one generation: its bundle, its kit
/// root and its pad object's length.
fn same_generation(held: &SealedBundleEntry, brought: &SealedBundleEntry) -> bool {
    held.generation == brought.generation
        && held.bundle_len == brought.bundle_len
        && held.bundle_digest == brought.bundle_digest
        && held.pads_len == brought.pads_len
        && held.kit == brought.kit
}

fn put_access(store: &Store, wtxn: &mut heed::RwTxn<'_>, key: &[u8], raw: &[u8]) -> Result<()> {
    let key = std::str::from_utf8(key).map_err(|_| Error::InvalidKey)?;
    ACCESS.put(store, wtxn, &key.to_owned(), &raw.to_vec())
}

/// Replaces `entry`'s pad object with `bytes`, digest `digest`, in parts.
fn put_pads(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    mut entry: SealedBundleEntry,
    digest: [u8; 32],
    bytes: &[u8],
) -> Result<()> {
    let prefix = object_prefix(&entry.generation, SealedBundleObject::Pads);
    PARTS.delete_from(store, wtxn, prefix.as_bytes())?;
    put_parts_in(
        store,
        wtxn,
        &entry.generation,
        SealedBundleObject::Pads,
        bytes,
    )?;
    entry.pads_digest = digest;
    GENERATIONS.put(
        store,
        wtxn,
        &sealed_generation_hex(&entry.generation),
        &entry.encode(),
    )
}

/// The home's current pad objects in `txn`, named for `vault_id` and the
/// home `home`: entries and grants, no object bytes.
///
/// # Errors
///
/// An entry that does not decode; storage errors.
pub(crate) fn current_pad_objects_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    vault_id: [u8; 32],
    home: EntityId,
) -> Result<CurrentPadObjects> {
    Ok(index_from(vault_id, home, |family, prefix| {
        txn_rows(store, txn, family, prefix)
    })?
    .0)
}

/// The home's current pad objects carried whole from `txn`: entries, sealed
/// parts and grant rows from that one read (PAD_OBJECT_CAPTURE_FORM), and
/// the bundle of each generation `bundles` names. The caller names the vault
/// and the home from the same read.
///
/// # Errors
///
/// An entry or a part key that does not decode; storage errors.
pub(crate) fn capture_current_pad_objects_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    vault_id: [u8; 32],
    home: EntityId,
    bundles: impl Fn(&SealedBundleGeneration) -> bool,
) -> Result<CapturedPadObjects> {
    capture_from(
        vault_id,
        home,
        |family, prefix| txn_rows(store, txn, family, prefix),
        bundles,
    )
}

/// [`capture_current_pad_objects_in_txn`] from the `sync_state` rows a source
/// door read in one transaction, full keys, table prefix included: its pad
/// object rows, and apart from them the bundle parts it read, each carried
/// with its generation. Rows of other tables are passed over.
///
/// # Errors
///
/// An entry or a part key that does not decode.
pub(crate) fn capture_current_pad_objects_in_rows(
    vault_id: [u8; 32],
    home: EntityId,
    sync_state: &[(Vec<u8>, Vec<u8>)],
    bundle_parts: &[(Vec<u8>, Vec<u8>)],
) -> Result<CapturedPadObjects> {
    capture_from(
        vault_id,
        home,
        |family, prefix| {
            let mut rows = source_rows(sync_state, family, prefix);
            rows.extend(source_rows(bundle_parts, family, prefix));
            rows.sort();
            Ok(rows)
        },
        |_| true,
    )
}

/// Installs `captured` over the store's current pad objects, while it holds
/// what the caller saw there: `expected`, its read after the bulk copy (an
/// empty one included). First the generations kept here are brought to the
/// capture's as `membership` says: each the capture alone keeps adopted,
/// each kept here alone retired where proven, the rest left as they are.
/// Then each captured object of a generation kept here takes the place of
/// the one kept, whole, with its grant rows; the admission outbox's rows
/// land too. A store's own objects put back (`StoreOwnPutBack`) go back
/// part by part as it held them, whole or not (FIX 11825). Every check
/// comes before the first write: a store that moved, or a capture of
/// another generation under the same name, writes nothing
/// (`CurrentChanged`), nor does a source's object not whole of a generation
/// kept here (`Unavailable`). The caller commits, then reads back
/// ([`read_back_captured_in_txn`]).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn install_captured_pad_objects_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    expected: &CurrentPadObjects,
    captured: &CapturedPadObjects,
    membership: PadObjectMembership,
) -> Result<PadObjectInstall> {
    let held = current_pad_objects_in_txn(store, wtxn, expected.vault_id, expected.home)?;
    if held.retained_revision != expected.retained_revision
        || captured.index.vault_id != expected.vault_id
    {
        return Ok(PadObjectInstall::CurrentChanged);
    }
    let mut installs = Vec::new();
    for (meta, object) in captured.index.entries.iter().zip(&captured.objects) {
        let Some(here) = held
            .entries
            .iter()
            .find(|here| here.entry.generation == meta.entry.generation)
        else {
            continue;
        };
        if !same_generation(&here.entry, &meta.entry) {
            return Ok(PadObjectInstall::CurrentChanged);
        }
        // `None`: a store's own object, put back as it held it.
        let bytes = match membership {
            PadObjectMembership::StoreOwnPutBack => None,
            PadObjectMembership::SourceKeepRuleProvesRetired => {
                match whole(&meta.entry, &object.parts) {
                    Ok(bytes) => Some(bytes),
                    Err(offset) => {
                        return Ok(PadObjectInstall::Unavailable(PadObjectUnavailable {
                            generation: meta.entry.generation,
                            digest: meta.entry.pads_digest,
                            offset,
                        }));
                    }
                }
            }
        };
        installs.push((here.entry, meta.entry.pads_digest, bytes, object));
    }
    let change = membership::membership_change(&held, captured, membership);
    membership::write_membership_change_in_txn(store, wtxn, captured, &change)?;
    for (entry, digest, bytes, object) in installs {
        match bytes {
            Some(bytes) => put_pads(store, wtxn, entry, digest, &bytes)?,
            None => membership::put_pads_as_held(store, wtxn, entry, digest, &object.parts)?,
        }
        for (key, raw) in &object.grants {
            put_access(store, wtxn, key, raw)?;
        }
    }
    for (key, raw) in &captured.queued {
        put_access(store, wtxn, key, raw)?;
    }
    Ok(PadObjectInstall::Installed(current_pad_objects_in_txn(
        store,
        wtxn,
        expected.vault_id,
        expected.home,
    )?))
}

/// Whether the store holds what an install of `captured` wrote, in `txn`, a
/// read after it, in the install's own transaction or once it committed:
/// the revision `installed` names, and each kept pad object the capture
/// carries as it carries it: whole where it carries it whole, else part for
/// part, as a store's own object not whole goes back (FIX 11825). Another
/// kept object whose bytes are missing stays as it is, and does not fail
/// this read (PAD-1).
///
/// # Errors
///
/// An entry or a part key that does not decode; storage errors.
pub(crate) fn read_back_captured_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    installed: &CurrentPadObjects,
    captured: &CapturedPadObjects,
) -> Result<bool> {
    let held = current_pad_objects_in_txn(store, txn, installed.vault_id, installed.home)?;
    if held.retained_revision != installed.retained_revision {
        return Ok(false);
    }
    for meta in &held.entries {
        let Some((carried, object)) = captured.object(&meta.entry.generation) else {
            continue;
        };
        let parts = pad_parts(&meta.entry.generation, |family, prefix| {
            txn_rows(store, txn, family, prefix)
        })?;
        let as_carried = if whole(&carried.entry, &object.parts).is_ok() {
            whole(&meta.entry, &parts).is_ok()
        } else {
            parts == object.parts
        };
        if !as_carried {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Fills the bytes of `generation`'s kept pad object again from `source`,
/// while the home holds what `expected` names: the same object, its length
/// and digest, so a refill never brings back an object an erase rewrote
/// since (that takes the replace door). An upload is taken from a machine of
/// the owner's whose proof stands here. The object is checked whole before
/// it is written; nothing else changes.
///
/// # Errors
///
/// A refused peer, or an upload of another generation; storage errors.
#[allow(dead_code, reason = "02A2 wires the object copy (L02)")]
pub(crate) fn refill_pad_object(
    vault: &Vault,
    expected: &CurrentPadObjects,
    generation: SealedBundleGeneration,
    source: PadObjectRefillSource<'_>,
) -> Result<PadObjectInstall> {
    let (digest, bytes) = match source {
        PadObjectRefillSource::CurrentProvider(captured) => {
            let Some((meta, object)) = captured.object(&generation) else {
                return Ok(PadObjectInstall::CurrentChanged);
            };
            match whole(&meta.entry, &object.parts) {
                Ok(bytes) => (meta.entry.pads_digest, bytes),
                Err(offset) => {
                    return Ok(PadObjectInstall::Unavailable(PadObjectUnavailable {
                        generation,
                        digest: meta.entry.pads_digest,
                        offset,
                    }));
                }
            }
        }
        PadObjectRefillSource::Reupload { peer, pads } => {
            owner_machine(vault, peer, false, Asked::No)?;
            if pads.generation() != generation {
                return Err(denied());
            }
            (pads.digest(), pads.as_bytes().to_vec())
        }
    };
    vault.with_write_txn_grouped(|wtxn| {
        let held =
            current_pad_objects_in_txn(&vault.store, wtxn, expected.vault_id, expected.home)?;
        let kept = held
            .entries
            .iter()
            .find(|meta| meta.entry.generation == generation)
            .map(|meta| meta.entry);
        let Some(entry) = kept.filter(|entry| {
            held.retained_revision == expected.retained_revision
                && entry.pads_digest == digest
                && is_object(entry, &bytes)
        }) else {
            return Ok(PadObjectInstall::CurrentChanged);
        };
        put_pads(&vault.store, wtxn, entry, digest, &bytes)?;
        Ok(PadObjectInstall::Installed(current_pad_objects_in_txn(
            &vault.store,
            wtxn,
            expected.vault_id,
            expected.home,
        )?))
    })
}

/// The vault and the home `txn` names this vault's pad objects for: the
/// vault id its authority folds to (`None` before its genesis: no vault, so
/// no capture is named for it, FIX 11826), and this install's machine id
/// (the zero id before it has one). One read names both, with the objects
/// it reads (PAD-1).
///
/// # Errors
///
/// An authority fold or a machine id row that does not read.
pub(crate) fn pad_objects_identity_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(Option<[u8; 32]>, EntityId)> {
    let vault_id = vault.authority_view_readonly_in_txn(txn)?.vault_id;
    let home = crate::identity::read_machine_id_in_txn(vault, txn)?
        .unwrap_or_else(|| EntityId::from_bytes_unchecked([0; 16]));
    Ok((vault_id, home))
}

/// The home's current pad objects in `txn`, named for this vault and this
/// home ([`pad_objects_identity_in_txn`]): the zero vault id before its
/// genesis, as served before.
pub(crate) fn index_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<CurrentPadObjects> {
    let (vault_id, home) = pad_objects_identity_in_txn(vault, txn)?;
    current_pad_objects_in_txn(&vault.store, txn, vault_id.unwrap_or_default(), home)
}

/// `current` as its list serves it: newest first, entries kept where `keep`
/// says.
pub(in crate::sync::residence) fn served_index(
    current: CurrentPadObjects,
    keep: impl Fn(&SealedBundleEntry) -> bool,
) -> SealedBundleIndex {
    SealedBundleIndex {
        retained_revision: current.retained_revision,
        entries: current
            .entries
            .into_iter()
            .rev()
            .map(|meta| meta.entry)
            .filter(keep)
            .collect(),
    }
}

/// The generations the home keeps, newest first, with the revision of the
/// one read that named them (FIX 7106), for a machine of the owner's whose
/// proof stands here, or the one his `request` asked to publish here. The
/// generations aged out are retired first, as the list retires them
/// ([`super::sealed_bundle_generations`]).
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn sealed_bundle_index(
    vault: &Vault,
    peer: PeerMachine,
    request: Option<AuthorityEntryHash>,
) -> Result<SealedBundleIndex> {
    owner_machine(vault, peer, false, Asked::named(request))?;
    retire_aged(vault)?;
    let txn = vault.store.env.read_txn()?;
    Ok(served_index(index_in(vault, &txn)?, |_| true))
}
