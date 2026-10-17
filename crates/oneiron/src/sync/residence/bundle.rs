//! The home's custody of the vault's sealed cloud bundle (DEC-0005 "Sealed
//! copies", FIX 922). The home keeps whole generations it cannot open, each a
//! bundle and its pad object (`world_keys::bundle`), stored in bounded parts.
//! A machine of the owner's stages an upload in parts, then commits the
//! generation whole, naming the newest generation it took as its parent: a
//! parent that moved, or a slot that already has a generation, is refused, so
//! each UTC slot gets one upload. The home then retires what
//! `retired_bundle_generations` names, each bundle with its pad object.
//!
//! Erase replaces a kept generation's pad object in place, at the same length;
//! the old object is deleted, and the home keeps no prior versions. Every door
//! serves only a machine of the owner's whose proof stands here, and none asks
//! which worlds it reads: the home never learns which worlds a reader wants.

use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{
    SealedBundleGeneration, SealedKeyPads, SealedVaultBundle, retired_bundle_generations,
    sealed_bundle_slot,
};

/// The most object bytes one upload part carries; in base64 it stays under the
/// 8 MiB request bound.
pub const SEALED_BUNDLE_PUT_PART_MAX: usize = 4 * 1024 * 1024;
/// The most object bytes one read reply carries; in base64 it stays under the
/// 32 MiB reply bound.
pub const SEALED_BUNDLE_READ_PART_MAX: usize = 16 * 1024 * 1024;
/// How long a staged upload waits for its next part before the home drops it.
const STAGE_IDLE_SECS: u64 = 60 * 60;
/// The length of each stored part of a kept object but its last.
const STORED_PART: usize = SEALED_BUNDLE_PUT_PART_MAX;

/// Each kept generation's lengths and digests.
const GENERATIONS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_GENERATION);
/// Each kept object's stored parts.
const PARTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_PART);
/// Each staged upload's header.
const STAGES: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_STAGE);
/// Each staged upload's parts.
const STAGE_PARTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_STAGE_PART);

/// u64be bundle length ‖ digest ‖ u64be pad object length ‖ digest.
const ENTRY_LEN: usize = 8 + 32 + 8 + 32;
/// u64be second ‖ generation ‖ u64be total ‖ digest ‖ u64be bytes staged.
const STAGE_LEN: usize = 8 + 24 + 8 + 32 + 8;

/// One of a generation's two objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedBundleObject {
    /// The sealed vault bundle.
    Bundle,
    /// Its sealed pad object.
    Pads,
}

impl SealedBundleObject {
    /// The name the wire spells it by.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Pads => "pads",
        }
    }

    /// Parses [`Self::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "bundle" => Some(Self::Bundle),
            "pads" => Some(Self::Pads),
            _ => None,
        }
    }

    /// Its letter in the home's keys.
    fn letter(self) -> char {
        match self {
            Self::Bundle => 'b',
            Self::Pads => 'k',
        }
    }
}

/// One generation the home keeps, as a reader lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleEntry {
    pub generation: SealedBundleGeneration,
    pub bundle_len: u64,
    /// BLAKE3 of the bundle's bytes.
    pub bundle_digest: [u8; 32],
    pub pads_len: u64,
    /// BLAKE3 of the pad object's bytes.
    pub pads_digest: [u8; 32],
}

impl SealedBundleEntry {
    /// One object's length and digest.
    #[must_use]
    pub fn object(&self, object: SealedBundleObject) -> (u64, [u8; 32]) {
        match object {
            SealedBundleObject::Bundle => (self.bundle_len, self.bundle_digest),
            SealedBundleObject::Pads => (self.pads_len, self.pads_digest),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTRY_LEN);
        out.extend_from_slice(&self.bundle_len.to_be_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out.extend_from_slice(&self.pads_len.to_be_bytes());
        out.extend_from_slice(&self.pads_digest);
        out
    }

    fn decode(generation: SealedBundleGeneration, raw: &[u8]) -> Result<Self> {
        if raw.len() != ENTRY_LEN {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            generation,
            bundle_len: be_u64(&raw[..8])?,
            bundle_digest: raw[8..40].try_into().map_err(|_| Error::InvalidKey)?,
            pads_len: be_u64(&raw[40..48])?,
            pads_digest: raw[48..].try_into().map_err(|_| Error::InvalidKey)?,
        })
    }
}

/// What one staged upload is bound to, past the machine that stages it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleStage {
    pub generation: SealedBundleGeneration,
    pub object: SealedBundleObject,
    /// The whole object's length.
    pub total: u64,
    /// BLAKE3 of the whole object.
    pub digest: [u8; 32],
}

fn denied() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
}

fn be_u64(raw: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        raw.try_into().map_err(|_| Error::InvalidKey)?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `N` bytes spelled in lower-case hex, and nothing else.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// A generation as the wire and the home's keys spell it: 48 lower-case hex
/// characters, the slot first, so they sort as the generations do.
#[must_use]
pub fn sealed_generation_hex(generation: &SealedBundleGeneration) -> String {
    hex(&generation.to_bytes())
}

/// Parses [`sealed_generation_hex`].
#[must_use]
pub fn sealed_generation_from_hex(text: &str) -> Option<SealedBundleGeneration> {
    SealedBundleGeneration::from_bytes(&unhex::<24>(text)?).ok()
}

/// A digest as the wire spells it: 64 lower-case hex characters.
#[must_use]
pub fn sealed_digest_hex(digest: &[u8; 32]) -> String {
    hex(digest)
}

/// Parses [`sealed_digest_hex`].
#[must_use]
pub fn sealed_digest_from_hex(text: &str) -> Option<[u8; 32]> {
    unhex::<32>(text)
}

/// The machine `peer` proved, when it is a machine of the owner's whose proof
/// stands here on the key it proved. Any other peer is refused.
fn owner_machine(vault: &Vault, peer: PeerMachine) -> Result<EntityId> {
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    if fold.machine_proof_key(machine) == Some(key) && fold.trusted_machine(machine).is_some() {
        Ok(machine)
    } else {
        Err(denied())
    }
}

fn stage_key(machine: EntityId, object: SealedBundleObject) -> String {
    format!("{}:{}", machine.to_hex(), object.letter())
}

fn object_prefix(generation: &SealedBundleGeneration, object: SealedBundleObject) -> String {
    format!("{}:{}:", sealed_generation_hex(generation), object.letter())
}

fn part_key(
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    offset: u64,
) -> String {
    format!("{}{offset:016x}", object_prefix(generation, object))
}

fn encode_stage(at: u64, stage: &SealedBundleStage, staged: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(STAGE_LEN);
    out.extend_from_slice(&at.to_be_bytes());
    out.extend_from_slice(&stage.generation.to_bytes());
    out.extend_from_slice(&stage.total.to_be_bytes());
    out.extend_from_slice(&stage.digest);
    out.extend_from_slice(&staged.to_be_bytes());
    out
}

/// A stage header's second, binding and bytes staged; `object` comes from its
/// key.
fn decode_stage(raw: &[u8], object: SealedBundleObject) -> Result<(u64, SealedBundleStage, u64)> {
    if raw.len() != STAGE_LEN {
        return Err(Error::InvalidKey);
    }
    Ok((
        be_u64(&raw[..8])?,
        SealedBundleStage {
            generation: SealedBundleGeneration::from_bytes(&raw[8..32])?,
            object,
            total: be_u64(&raw[32..40])?,
            digest: raw[40..72].try_into().map_err(|_| Error::InvalidKey)?,
        },
        be_u64(&raw[72..])?,
    ))
}

/// Drops one staged upload, its header and its parts.
fn drop_stage_in(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, key: &str) -> Result<()> {
    STAGES.delete(&vault.store, wtxn, &key.to_owned())?;
    STAGE_PARTS.delete_from(&vault.store, wtxn, format!("{key}:").as_bytes())?;
    Ok(())
}

/// Every kept generation, oldest first.
fn entries_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<SealedBundleEntry>> {
    let mut out = Vec::new();
    for row in GENERATIONS.iter_raw_from(&vault.store, txn, &[])? {
        let (key, raw) = row?;
        let generation = std::str::from_utf8(&key)
            .ok()
            .and_then(sealed_generation_from_hex)
            .ok_or(Error::InvalidKey)?;
        out.push(SealedBundleEntry::decode(generation, &raw)?);
    }
    Ok(out)
}

fn entry_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    generation: &SealedBundleGeneration,
) -> Result<Option<SealedBundleEntry>> {
    GENERATIONS
        .get_bytes(&vault.store, txn, &sealed_generation_hex(generation))?
        .map(|raw| SealedBundleEntry::decode(*generation, &raw))
        .transpose()
}

/// Stores one object of a generation in parts of [`STORED_PART`].
fn put_object_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    bytes: &[u8],
) -> Result<()> {
    for (index, chunk) in bytes.chunks(STORED_PART).enumerate() {
        let offset = (index * STORED_PART) as u64;
        PARTS.put(
            &vault.store,
            wtxn,
            &part_key(generation, object, offset),
            &chunk.to_vec(),
        )?;
    }
    Ok(())
}

/// Retires what [`retired_bundle_generations`] names in slot `now_slot`, each
/// bundle with its pad object.
fn retire_in(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, now_slot: u64) -> Result<()> {
    let kept: Vec<SealedBundleGeneration> = entries_in(vault, wtxn)?
        .into_iter()
        .map(|entry| entry.generation)
        .collect();
    for generation in retired_bundle_generations(now_slot, &kept) {
        let key = sealed_generation_hex(&generation);
        GENERATIONS.delete(&vault.store, wtxn, &key)?;
        PARTS.delete_from(&vault.store, wtxn, format!("{key}:").as_bytes())?;
    }
    Ok(())
}

/// Stages one part of an upload from the machine `peer` proved, bound to
/// `stage`. `offset` must be the bytes staged so far, and 0 starts the upload
/// over; a machine stages one bundle and one pad object at a time. Any staged
/// upload idle for an hour is dropped. Returns the bytes staged.
///
/// # Errors
///
/// A refused peer; an empty or oversized part, or one past the total; an
/// offset other than the bytes staged, or an upload staged with another
/// binding; storage errors.
pub fn stage_sealed_bundle_part(
    vault: &Vault,
    peer: PeerMachine,
    stage: &SealedBundleStage,
    offset: u64,
    part: &[u8],
) -> Result<u64> {
    let machine = owner_machine(vault, peer)?;
    let end = offset.checked_add(part.len() as u64).ok_or_else(denied)?;
    if part.is_empty() || part.len() > SEALED_BUNDLE_PUT_PART_MAX || end > stage.total {
        return Err(denied());
    }
    let key = stage_key(machine, stage.object);
    vault.with_write_txn_grouped(|wtxn| {
        let now = vault.instant_in_txn(wtxn)?.secs();
        // Each staged upload whose header does not decode or has idled out,
        // and this one when it starts over.
        let mut dropped = Vec::new();
        let mut staged: Option<u64> = None;
        for row in STAGES.iter_raw_from(&vault.store, wtxn, &[])? {
            let (row_key, raw) = row?;
            let Ok(row_key) = String::from_utf8(row_key) else {
                continue;
            };
            let object = match row_key.chars().last() {
                Some('k') => SealedBundleObject::Pads,
                _ => SealedBundleObject::Bundle,
            };
            let header = decode_stage(&raw, object);
            let idle = header
                .as_ref()
                .map_or(true, |(at, _, _)| at.saturating_add(STAGE_IDLE_SECS) < now);
            if row_key == key && offset > 0 && !idle {
                staged = header
                    .ok()
                    .filter(|(_, held, _)| held == stage)
                    .map(|(_, _, staged)| staged);
            } else if row_key == key || idle {
                dropped.push(row_key);
            }
        }
        if staged.unwrap_or(0) != offset {
            return Err(denied());
        }
        for head in &dropped {
            drop_stage_in(vault, wtxn, head)?;
        }
        STAGES.put(&vault.store, wtxn, &key, &encode_stage(now, stage, end))?;
        STAGE_PARTS.put(
            &vault.store,
            wtxn,
            &format!("{key}:{offset:016x}"),
            &part.to_vec(),
        )?;
        Ok(end)
    })
}

/// The object the machine staged whole under `object`, with its binding: every
/// part from offset 0, contiguous, its total long, its digest matching. `None`
/// otherwise.
fn staged_whole(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    object: SealedBundleObject,
) -> Result<Option<(SealedBundleStage, Vec<u8>)>> {
    let key = stage_key(machine, object);
    let Some(header) = STAGES.get_bytes(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let Ok((_, stage, _)) = decode_stage(&header, object) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    for row in STAGE_PARTS.iter_raw_from(&vault.store, txn, format!("{key}:").as_bytes())? {
        let (row_key, part) = row?;
        if row_key != format!("{key}:{:016x}", bytes.len()).into_bytes()
            || bytes.len() as u64 + part.len() as u64 > stage.total
        {
            return Ok(None);
        }
        bytes.extend_from_slice(&part);
    }
    Ok(
        (bytes.len() as u64 == stage.total && *blake3::hash(&bytes).as_bytes() == stage.digest)
            .then_some((stage, bytes)),
    )
}

/// Commits `generation` as the vault's newest, from the bundle and the pad
/// object the machine `peer` proved staged whole for it, and drops its stages.
/// `parent` is the newest generation that machine took, or `None` when the
/// home kept none. Refused when the home's newest is another by now, when the
/// generation's slot is not past the newest's (one generation per slot), and
/// for a slot not yet open on the home's clock. The home opens nothing: it
/// keeps only objects that parse as the generation named. Then it retires
/// what [`retired_bundle_generations`] names.
///
/// # Errors
///
/// A refused peer, parent or slot; no whole stage of either object, or one of
/// another generation; storage errors.
pub fn commit_sealed_bundle(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
    parent: Option<SealedBundleGeneration>,
) -> Result<SealedBundleEntry> {
    let machine = owner_machine(vault, peer)?;
    let (bundle, pads) = {
        let txn = vault.store.env.read_txn()?;
        (
            staged_whole(vault, &txn, machine, SealedBundleObject::Bundle)?,
            staged_whole(vault, &txn, machine, SealedBundleObject::Pads)?,
        )
    };
    let (Some((bundle_stage, bundle_bytes)), Some((pads_stage, pads_bytes))) = (bundle, pads)
    else {
        return Err(denied());
    };
    let bundle = SealedVaultBundle::from_bytes(&bundle_bytes).map_err(|_| denied())?;
    drop(bundle_bytes);
    let pads = SealedKeyPads::from_bytes(&pads_bytes).map_err(|_| denied())?;
    drop(pads_bytes);
    if [
        bundle_stage.generation,
        pads_stage.generation,
        bundle.generation(),
        pads.generation(),
    ]
    .iter()
    .any(|staged| *staged != generation)
    {
        return Err(denied());
    }
    let entry = SealedBundleEntry {
        generation,
        bundle_len: bundle_stage.total,
        bundle_digest: bundle_stage.digest,
        pads_len: pads_stage.total,
        pads_digest: pads_stage.digest,
    };
    vault.with_write_txn_grouped(|wtxn| {
        let latest = entries_in(vault, wtxn)?
            .last()
            .map(|entry| entry.generation);
        let now_slot = sealed_bundle_slot(vault.instant_in_txn(wtxn)?.secs());
        if latest != parent
            || latest.is_some_and(|latest| generation.slot <= latest.slot)
            || generation.slot > now_slot
        {
            return Err(denied());
        }
        put_object_in(
            vault,
            wtxn,
            &generation,
            SealedBundleObject::Bundle,
            bundle.as_bytes(),
        )?;
        put_object_in(
            vault,
            wtxn,
            &generation,
            SealedBundleObject::Pads,
            pads.as_bytes(),
        )?;
        GENERATIONS.put(
            &vault.store,
            wtxn,
            &sealed_generation_hex(&generation),
            &entry.encode(),
        )?;
        for object in [SealedBundleObject::Bundle, SealedBundleObject::Pads] {
            drop_stage_in(vault, wtxn, &stage_key(machine, object))?;
        }
        retire_in(vault, wtxn, now_slot)?;
        Ok(entry)
    })
}

/// Erase's rewrite of one kept generation's pad object
/// (`Vault::drop_world_from_key_pads`): replaces it with the pad object the
/// machine `peer` proved staged whole for `generation`, of the same length,
/// and drops the stage. `replaces` is the digest of the object the rewrite
/// was made from; refused when the home holds another by now, so two erases
/// never undo each other. The old object is deleted: the home keeps no prior
/// versions.
///
/// # Errors
///
/// A refused peer; no such generation, another object there by now, or no
/// whole stage of a pad object of it at that length; storage errors.
pub fn replace_sealed_bundle_pads(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
    replaces: &[u8; 32],
) -> Result<SealedBundleEntry> {
    let machine = owner_machine(vault, peer)?;
    let staged = {
        let txn = vault.store.env.read_txn()?;
        staged_whole(vault, &txn, machine, SealedBundleObject::Pads)?
    };
    let Some((stage, bytes)) = staged.filter(|(stage, _)| stage.generation == generation) else {
        return Err(denied());
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| denied())?;
    drop(bytes);
    if pads.generation() != generation {
        return Err(denied());
    }
    vault.with_write_txn_grouped(|wtxn| {
        let Some(mut entry) = entry_in(vault, wtxn, &generation)? else {
            return Err(denied());
        };
        if entry.pads_digest != *replaces || entry.pads_len != stage.total {
            return Err(denied());
        }
        let old = object_prefix(&generation, SealedBundleObject::Pads);
        PARTS.delete_from(&vault.store, wtxn, old.as_bytes())?;
        put_object_in(
            vault,
            wtxn,
            &generation,
            SealedBundleObject::Pads,
            pads.as_bytes(),
        )?;
        entry.pads_digest = stage.digest;
        GENERATIONS.put(
            &vault.store,
            wtxn,
            &sealed_generation_hex(&generation),
            &entry.encode(),
        )?;
        drop_stage_in(vault, wtxn, &stage_key(machine, SealedBundleObject::Pads))?;
        Ok(entry)
    })
}

/// The generations the home keeps, newest first, for a machine of the owner's
/// whose proof stands here. Generations aged out since the last commit are
/// retired first, so they go even when uploads stop.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn sealed_bundle_generations(
    vault: &Vault,
    peer: PeerMachine,
) -> Result<Vec<SealedBundleEntry>> {
    owner_machine(vault, peer)?;
    let (now_slot, mut kept) = {
        let txn = vault.store.env.read_txn()?;
        (
            sealed_bundle_slot(vault.instant_in_txn(&txn)?.secs()),
            entries_in(vault, &txn)?,
        )
    };
    let generations: Vec<SealedBundleGeneration> =
        kept.iter().map(|entry| entry.generation).collect();
    let retired = retired_bundle_generations(now_slot, &generations);
    if !retired.is_empty() {
        vault.with_write_txn_grouped(|wtxn| retire_in(vault, wtxn, now_slot))?;
        kept.retain(|entry| !retired.contains(&entry.generation));
    }
    kept.reverse();
    Ok(kept)
}

/// One slice of a kept generation's `object`, at most
/// [`SEALED_BUNDLE_READ_PART_MAX`] bytes from `offset`, with the generation's
/// entry, for a machine of the owner's whose proof stands here: an object is
/// read in slices. `generation` names one, or `None` the newest. `None` for a
/// generation not kept and an offset at or past the object's end.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn sealed_bundle_part(
    vault: &Vault,
    peer: PeerMachine,
    generation: Option<SealedBundleGeneration>,
    object: SealedBundleObject,
    offset: u64,
) -> Result<Option<(SealedBundleEntry, Vec<u8>)>> {
    owner_machine(vault, peer)?;
    let txn = vault.store.env.read_txn()?;
    let entry = match generation {
        Some(generation) => entry_in(vault, &txn, &generation)?,
        None => entries_in(vault, &txn)?.pop(),
    };
    let Some(entry) = entry else {
        return Ok(None);
    };
    let (total, _) = entry.object(object);
    if offset >= total {
        return Ok(None);
    }
    let end = total.min(offset.saturating_add(SEALED_BUNDLE_READ_PART_MAX as u64));
    let stored = STORED_PART as u64;
    let mut part = Vec::new();
    let mut at = offset - offset % stored;
    while at < end {
        let row = PARTS
            .get_borrowed(&vault.store, &txn, &part_key(&entry.generation, object, at))?
            .ok_or(Error::CorruptedIndex("sealed bundle part"))?;
        let from = usize::try_from(offset.saturating_sub(at)).map_err(|_| Error::InvalidKey)?;
        let to =
            usize::try_from((end - at).min(row.len() as u64)).map_err(|_| Error::InvalidKey)?;
        part.extend_from_slice(
            row.get(from..to)
                .ok_or(Error::CorruptedIndex("sealed bundle part"))?,
        );
        at += stored;
    }
    if part.len() as u64 != end - offset {
        return Err(Error::CorruptedIndex("sealed bundle part"));
    }
    Ok(Some((entry, part)))
}
