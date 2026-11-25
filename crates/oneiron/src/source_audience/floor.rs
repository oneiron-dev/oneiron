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
//! otherwise every attestation's floor binds. A row whose birth names an
//! input this vault erased is born under [`sealed_source`]
//! ([`seal_births_from_erased_inputs_in_txn`]), which admits no one, the
//! vault owner included (READ-LINEAGE-L3 = A); doctor counts such rows
//! ([`super::facts_hidden_source_unknown_in`]), and the owner's re-derive
//! writes their facts again from the sources that resolve now
//! ([`crate::Vault::rederive_sealed_rows`]). Only proof of erasure seals
//! (#9289 review 2 P1-1): a row it was written from that has not landed here
//! yet, or lineage that does not resolve yet, leaves its floor pending, and
//! the write that lands what it waits on raises it again
//! ([`super::floor_state`]).

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
    /// and a row written from it waits too ([`super::floor_state`]).
    Unbound,
}

/// The source the row `row` (bytes `raw`) was born in.
pub(super) fn own_source_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<OwnSource> {
    if let Some(policy) = super::binding_in(vault, txn, row)? {
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
    let mut floor = super::DERIVED
        .get(&vault.store, txn, row)?
        .unwrap_or_default();
    if let OwnSource::Source(own) = own_source_in(vault, txn, row, raw)? {
        floor.insert(own);
    }
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

/// Raises the floor of `row` over what its words came from, one level
/// (`sources`), in the write that gives it words or a source. Whether it
/// grew. A row it was written from that is not held here adds the floor it
/// left, if any; whether the row waits for it is [`super::floor_state`]'s.
pub(super) fn raise_floor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    sources: &RowSources,
) -> Result<bool> {
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(false);
    };
    let mut add = BTreeSet::new();
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
    match own_source_in(vault, txn, row, &raw)? {
        // A held row born under no source (a peer's phone mark that names
        // no thread) reads to no one, so its stored floor says so too: the
        // phone read and doctor read the stored floor (#9289 review 2 P2-5).
        // An archived row is held, so it keeps the seal through its raise
        // while archived and its restore (#10265 Opus review 3 P2-1). An
        // erased row's shell is no fact; what is written from it inherits
        // the seal from its own source.
        OwnSource::Source(own) if own == sealed_source() => {
            if !crate::ports::removed_in_txn(&vault.store, &**txn, row)? {
                add.insert(own);
            }
        }
        OwnSource::Source(own) => {
            add.remove(&own);
        }
        OwnSource::None | OwnSource::Unbound => {}
    }
    if add.is_empty() {
        return Ok(false);
    }
    super::add_derived_policies_in_txn(vault, txn, row, &add)
}

/// Raises the floor of each of `rows` in `txn`, the write that gave them
/// words or a source (READ-LINEAGE L1: a born row, a row that gained a
/// `PartOf`, `DerivedFrom` or `Supports` source, a row whose dependencies
/// were registered, a row that landed here). It repeats until no floor
/// grows, so a row this write gave a floor passes it on to a row the same
/// write wrote from it; it settles whether each floor is whole, and raises
/// again the rows that waited on a row it settled ([`super::floor_state`]).
/// A vault where no row can have a floor reads nothing
/// ([`floors_possible_in`]).
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
    super::floor_state::raise_and_settle_in_txn(vault, txn, rows)
}

/// Seals each row of `born`, in the write that stamps its birth, when that
/// birth names an input this vault erased: its deletion shell or record
/// stands (#9289 review r1 P1). An erase takes the input's own source with
/// its body (a phone row's stamp) and its stored floor with its row
/// (`erase_derived_policies_in_txn`), so nothing here says any more whose
/// words the input held: a prompt that read caller A's kept TURN, erased
/// before the CLAIM it wrote landed, left that CLAIM no source to inherit.
/// The row is born under [`sealed_source`] (C5, READ-LINEAGE-L3 = A). Only
/// the birth's own write seals: a row born while its inputs stood already
/// holds their floor, and a later erase takes no source off it. A vault
/// where no row can have a floor seals nothing ([`floors_possible_in`]).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn seal_births_from_erased_inputs_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    born: &[EntityId],
) -> Result<()> {
    if born.is_empty() || !floors_possible_in(vault, txn)? {
        return Ok(());
    }
    let sealed = BTreeSet::from([sealed_source()]);
    for row in born {
        for input in crate::store::birth_record::input_rows_in_txn(&vault.store, txn, row)? {
            if input != *row
                && crate::ports::TombstoneStoreRead::port_deletion_state(
                    &vault.store,
                    &**txn,
                    &input,
                )?
                .deleted
            {
                super::add_derived_policies_in_txn(vault, txn, row, &sealed)?;
                break;
            }
        }
    }
    Ok(())
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
