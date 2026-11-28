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
//! otherwise every attestation's floor binds. Each link is judged once, in
//! the write that creates it here ([`super::source_state`]): a bound input's
//! floor joins the row's; an input not bound and whole yet leaves the row
//! waiting on it; a birth input, a dependency source or a named word source
//! this vault erased seals the row under [`sealed_source`], which admits no
//! one, the vault owner included (READ-LINEAGE-L3 = A). Doctor counts sealed
//! rows ([`super::facts_hidden_source_unknown_in`]), and the owner's
//! re-derive writes their facts again from the sources that resolve now
//! ([`crate::Vault::rederive_sealed_rows`]).

use std::collections::BTreeSet;

use heed::RoTxn;

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
    /// A phone thread's CONVERSATION: it reads to the vault owner and to
    /// the readers [`SOURCE_READERS`] admits.
    Thread,
    /// [`sealed_source`], a policy that does not resolve here, or a thread
    /// that is gone: it reads to no one.
    Unknown,
}

/// Who besides the vault owner reads a source on a floor. Until the owner
/// answers the OUTSIDER-REACH-FAMILY card it is the strictest reading (the
/// Engine, 21 Nov 04:30): per surface, only that source's own readers. The
/// card widens it by a variant here; every floor read matches on
/// [`SOURCE_READERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceReaders {
    /// A phone thread reads under a live `ConversationMessages` grant naming
    /// that very thread, and a policy to its own people. A grant over
    /// another thread of the same line, a standing permission over a line or
    /// a mailbox, and a generic MESSAGE or CLAIM grant read none of it.
    OwnSourceReaders,
}

/// The admission every floor read applies ([`SourceReaders`]).
pub(crate) const SOURCE_READERS: SourceReaders = SourceReaders::OwnSourceReaders;

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

/// The source a row was born in, as a floor reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnSource {
    /// None: its words are its own.
    None,
    /// The policy it is bound to; the thread its own bytes name (a phone
    /// CONVERSATION is its own thread; a TURN, MESSAGE or SESSION carries its
    /// thread's stamp); or [`sealed_source`] for a row whose phone mark names
    /// no thread, which reads to no one, and neither does what is written
    /// from it.
    Source(EntityId),
    /// A row a source landed whose binding is not here: its landing binds it
    /// later in this very write, or its carried binding waits for its
    /// policy. It names no source yet; its own read waits for its binding,
    /// and a row written from it waits too ([`super::source_state`]).
    Unbound,
}

/// The source the row `row` (bytes `raw`) was born in.
pub(super) fn own_source_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<OwnSource> {
    own_source_of_in(&vault.store, txn, row, raw)
}

/// [`own_source_in`] for a write that holds only the store (a purge's
/// deindex, a blob release).
pub(super) fn own_source_of_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<OwnSource> {
    if let Some(policy) = super::RECORDS.get(store, txn, row)? {
        return Ok(OwnSource::Source(policy));
    }
    if super::obligation::row_obligation(raw).is_present() {
        return Ok(OwnSource::Unbound);
    }
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(OwnSource::None);
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
        Some(thread) => OwnSource::Source(thread),
        None if crate::voice_call::row_phone_marked(raw) => OwnSource::Source(sealed_source()),
        None => OwnSource::None,
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
    floor_of_in(&vault.store, txn, row, raw)
}

/// [`floor_in`] for a write that holds only the store.
pub(super) fn floor_of_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<BTreeSet<EntityId>> {
    let mut floor = super::DERIVED.get(store, txn, row)?.unwrap_or_default();
    if let OwnSource::Source(own) = own_source_of_in(store, txn, row, raw)? {
        floor.insert(own);
    }
    Ok(floor)
}

/// What the words of one row came from, one level.
#[derive(Debug, Default)]
pub(crate) struct RowSources {
    /// Every row it was written from: each binds.
    pub(crate) written_from: Vec<EntityId>,
    /// A CLAIM's supports: one free one frees, otherwise all bind.
    pub(crate) attested_by: Vec<EntityId>,
    /// The rows of `written_from` no read walks: the birth's inputs and the
    /// source dependency index. A row waits for one of them that has not
    /// landed; a read walks the rest live.
    pub(crate) unwalked: Vec<EntityId>,
    /// The word sources it names that this vault does not hold.
    pub(crate) unheld: Vec<EntityId>,
    /// Whether its lineage does not resolve here: a summary's word sources
    /// that do not resolve yet (an epoch whose head has not landed), or a
    /// body or carried summary that does not decode.
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
                    sources.unheld.push(source);
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
        .unwalked
        .extend(crate::ports::dependency_sources_in(&vault.store, txn, row)?);
    sources
        .unwalked
        .extend(crate::store::birth_record::input_rows_in_txn(
            &vault.store,
            txn,
            row,
        )?);
    sources
        .written_from
        .extend(sources.unwalked.iter().copied());
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

/// [`floors_possible_in`] for a write that holds only the store.
pub(super) fn floors_possible_of_in(store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(super::POLICIES.iter_from(store, txn, &[])?.next().is_some()
        || super::DERIVED.iter_from(store, txn, &[])?.next().is_some()
        || super::LANDED.get(store, txn, &())?.unwrap_or(false))
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
