//! A row's floor (READ-LINEAGE step L1; Fable design pass 30, section 4):
//! the sources its words came from, written once in the write that gives it
//! its words, so a read meets them without walking the lineage.
//!
//! A **source** is a place where an outsider's words enter the vault, named
//! by one id: a source-audience policy (a mailbox, a shared mail thread) or
//! a phone thread's CONVERSATION. A row's **floor** is its own source (the
//! policy it is bound to, or the thread its bytes are stamped with) and the
//! floor of every row it was written from, one level per write: each source
//! row already holds the floor of everything below it. The inherited part is
//! kept in the `DERIVED` side table beside the policies a full-window
//! carrier brought, and like them it only grows (fix list row 17207): no
//! write, rebuild or merge takes a source off a floor.
//!
//! A floor names sources, never readers, so who reads a source is decided
//! live at each read: sharing a thread or granting a caller's history, and
//! revoking either, reach every row learnt from it at the next read. A
//! policy is told from a thread by looking the id up (Engine E4 = A): a
//! stored policy is a policy, a CONVERSATION whose body names its line agent
//! is a thread, and any other id names no source and admits no reader.
//!
//! What binds (READ-LINEAGE-L1 = A, the lead 17 Nov 02:0x): every row a row
//! was written from (the source-audience walk's lineage, the source
//! dependency index, the birth's inputs of every role, a carried summary)
//! adds its floor. A CLAIM's supports attest it: one free attestation frees,
//! otherwise every attestation's floor binds. A row whose lineage cannot be
//! read when it is written is born under [`sealed_source`], which admits no
//! one, the vault owner included (READ-LINEAGE-L3 = A); doctor counts such
//! rows ([`facts_hidden_source_unknown_in`]).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use crate::{EntityId, Vault};

/// The bytes of [`sealed_source`]: version nibble 2, which no id this
/// engine mints or derives carries, so it names no row, policy or thread.
const SEALED_SOURCE: [u8; 16] = *b"sealed.source.v1";

/// The source a row is born under when a source its words came from cannot
/// be read at the write (C5, READ-LINEAGE-L3 = A): it names no policy and no
/// thread, so it admits no reader.
pub(crate) fn sealed_source() -> EntityId {
    EntityId::from_bytes_unchecked(SEALED_SOURCE)
}

/// What one id on a floor names, as a read judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloorSource {
    /// A source-audience policy: it reads to the policy's people
    /// ([`super::readers_in`]).
    Policy,
    /// A phone thread's CONVERSATION: it reads to the vault owner and under
    /// a live `ConversationMessages` grant naming it.
    Thread,
    /// [`sealed_source`], a policy that does not resolve here, or a thread
    /// that is gone: it reads to no one.
    Unknown,
}

/// What the id `source` on a floor names in `txn` (E4 = A: by lookup, with
/// no tag stored beside it).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_source_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<FloorSource> {
    if super::POLICIES.contains(&vault.store, txn, source)? {
        return Ok(FloorSource::Policy);
    }
    if *source == sealed_source() {
        return Ok(FloorSource::Unknown);
    }
    let Some(raw) = vault.get_raw_in(txn, source)? else {
        return Ok(FloorSource::Unknown);
    };
    let thread = EntityMetadataHeader::parse(&raw).is_some_and(|header| {
        header.entity_type == ENTITY_TYPE_CONVERSATION
            && crate::voice_call::phone_thread_agent(
                raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default(),
            )
            .is_some()
    });
    Ok(if thread {
        FloorSource::Thread
    } else {
        FloorSource::Unknown
    })
}

/// The source the row `row` (bytes `raw`) was born in, if any: the policy
/// it is bound to; the thread its own bytes name (a phone CONVERSATION is
/// its own thread; a TURN, MESSAGE or SESSION carries its thread's stamp).
/// A row a source landed whose binding is absent here, and a row whose
/// phone mark names no thread, are [`sealed_source`]: such a row reads to no
/// one, and so does what is written from it. A row its landing is binding
/// in this very write (its birth mark stands until the binding lands) names
/// no source yet: the landing binds it after staging its rows.
fn own_source_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<Option<EntityId>> {
    if let Some(policy) = super::binding_in(vault, txn, row)? {
        return Ok(Some(policy));
    }
    if super::obligation::row_obligation(raw).is_present() {
        if super::BIRTHS.contains(&vault.store, txn, row)? {
            return Ok(None);
        }
        return Ok(Some(sealed_source()));
    }
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let thread = match header.entity_type {
        ENTITY_TYPE_CONVERSATION => crate::voice_call::phone_thread_agent(body).map(|_| *row),
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SESSION => {
            crate::voice_call::phone_thread_stamp(body)
        }
        _ => None,
    };
    Ok(match thread {
        Some(thread) => Some(thread),
        None if crate::voice_call::row_phone_marked(raw) => Some(sealed_source()),
        None => None,
    })
}

/// The sources the row `row` (bytes `raw`) reads under: the one it was born
/// in and its stored floor. Empty for a row no source reaches.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<BTreeSet<EntityId>> {
    let mut floor = super::DERIVED
        .get(&vault.store, txn, row)?
        .unwrap_or_default();
    floor.extend(own_source_in(vault, txn, row, raw)?);
    Ok(floor)
}

/// [`floor_in`] over the row `row` as `txn` holds it. A row gone from this
/// vault carries no words; what its stored floor still names stands.
fn stored_floor_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<BTreeSet<EntityId>> {
    match vault.get_raw_in(txn, row)? {
        Some(raw) => floor_in(vault, txn, row, &raw),
        None => Ok(super::DERIVED
            .get(&vault.store, txn, row)?
            .unwrap_or_default()),
    }
}

/// What the words of one row came from, one level.
#[derive(Debug, Default)]
pub(crate) struct RowSources {
    /// Every row it was written from: each binds.
    pub(crate) written_from: Vec<EntityId>,
    /// A CLAIM's supports: one free one frees, otherwise all bind.
    pub(crate) attested_by: Vec<EntityId>,
    /// Whether a source it names cannot be read: a summary's word sources
    /// that do not resolve, a named word source not held here, or a carried
    /// summary that does not decode.
    pub(crate) unresolved: bool,
}

/// What the words of the row `row` (bytes `raw`) came from, one level: the
/// single list both the source-audience walk and the phone lineage read
/// (a MESSAGE's TURN, a TURN's MESSAGEs, every `DerivedFrom`, a summary's or
/// merge header's word sources, a scope summary's covers, a CLAIM's subject;
/// the source dependency index; the birth's inputs of every role; a carried
/// summary), and a CLAIM's supports.
///
/// # Errors
///
/// Storage failures, and bytes with no readable header.
pub(crate) fn row_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<RowSources> {
    let mut sources = RowSources::default();
    match crate::scope_summary::word_sources_in(vault, txn, row, raw) {
        Ok(crate::scope_summary::WordSources::Own) => {}
        Ok(crate::scope_summary::WordSources::From(named)) => {
            for source in named {
                if vault.get_raw_in(txn, &source)?.is_none() {
                    sources.unresolved = true;
                }
            }
        }
        Ok(crate::scope_summary::WordSources::Unresolved)
        | Err(Error::InvalidClaimBody(_) | Error::Record(_)) => sources.unresolved = true,
        Err(error) => return Err(error),
    }
    match crate::scope_summary::carried_summary(raw) {
        Ok(carried) => sources.written_from.extend(carried),
        Err(_) => sources.unresolved = true,
    }
    let (every, supports) = vault.lineage_word_sources_in(txn, *row, raw)?;
    sources.written_from.extend(every);
    sources
        .written_from
        .extend(crate::ports::dependency_sources_in(&vault.store, txn, row)?);
    sources
        .written_from
        .extend(crate::store::birth_record::input_rows_in_txn(
            &vault.store,
            txn,
            row,
        )?);
    sources.attested_by = supports;
    Ok(sources)
}

/// Whether a write here can give any row a floor: the vault holds a policy
/// or a stored floor, or a row a source landed (a mail row or a phone
/// thread's) was written here. A vault with none gives no row a floor, so
/// its writes read no lineage.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floors_possible_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(super::any_policy_in(vault, txn)? || super::any_landed_in(vault, txn)?)
}

/// Raises the floor of `row` over what its words came from, one level, in
/// the write that gives it words or a source. Whether it grew.
fn raise_floor_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<bool> {
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(false);
    };
    let sources = row_sources_in(vault, txn, row, &raw)?;
    let mut add = BTreeSet::new();
    if sources.unresolved {
        add.insert(sealed_source());
    }
    for source in &sources.written_from {
        if source != row {
            add.extend(stored_floor_in(vault, txn, source)?);
        }
    }
    let mut attested = BTreeSet::new();
    let mut freed = false;
    for support in &sources.attested_by {
        if support == row {
            continue;
        }
        let floor = stored_floor_in(vault, txn, support)?;
        if floor.is_empty() {
            freed = true;
            break;
        }
        attested.extend(floor);
    }
    if !freed {
        add.extend(attested);
    }
    if let Some(own) = own_source_in(vault, txn, row, &raw)? {
        add.remove(&own);
    }
    if add.is_empty() {
        return Ok(false);
    }
    super::add_derived_policies_in_txn(vault, txn, row, &add)
}

/// Raises the floor of each of `rows` in `txn`, the write that gave them
/// words or a source (READ-LINEAGE L1: a born row, a row that gained a
/// `PartOf`, `DerivedFrom` or `Supports` source, a row whose dependencies
/// were registered). It repeats until no floor grows, so a row this write
/// gave a floor passes it on to a row the same write wrote from it. A vault
/// where no row can have a floor reads nothing ([`floors_possible_in`]).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn raise_floors_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    let rows: BTreeSet<EntityId> = rows.into_iter().collect();
    if rows.is_empty() || !floors_possible_in(vault, txn)? {
        return Ok(());
    }
    loop {
        let mut grew = false;
        for row in &rows {
            grew |= raise_floor_in_txn(vault, txn, row)?;
        }
        if !grew {
            return Ok(());
        }
    }
}

/// The threads on the stored floor of `row` that a read must hold, or
/// `None` when an id on it names no source, so the row reads to no one
/// (READ-LINEAGE-L3 = A). Its policies are the source-audience walk's to
/// judge ([`super::readable_with_read_in`]).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_threads_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let Some(floor) = super::DERIVED.get(&vault.store, txn, row)? else {
        return Ok(Some(Vec::new()));
    };
    let mut threads = Vec::new();
    for source in floor {
        match floor_source_in(vault, txn, &source)? {
            FloorSource::Policy => {}
            FloorSource::Thread => threads.push(source),
            FloorSource::Unknown => return Ok(None),
        }
    }
    Ok(Some(threads))
}

/// How many rows this vault reads to no one because an id on their stored
/// floor names no source: doctor's "N facts hidden: source unknown"
/// (READ-LINEAGE-L3 = A; design pass 30 section 4.7). One scan of the
/// stored floors; only the count leaves, never a row, its text or its
/// sources.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn facts_hidden_source_unknown_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<u64> {
    let mut hidden = 0_u64;
    for entry in super::DERIVED.iter_from(&vault.store, txn, &[])? {
        let (_, floor) = entry?;
        for source in &floor {
            if floor_source_in(vault, txn, source)? == FloorSource::Unknown {
                hidden += 1;
                break;
            }
        }
    }
    Ok(hidden)
}
