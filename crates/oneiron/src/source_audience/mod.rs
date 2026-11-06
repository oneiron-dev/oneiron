//! Source audience: the rows imported from a source read only to that
//! source's people (owner MAIL-SHARE = A, 2026-11-03, ledger
//! engine-20261103-mail-four-calls; ARCH-0063 #mail-pack, #thread-sharing;
//! ARCH-0027 #mail-import-audience).
//!
//! A **source policy** names the PERSONs who read one source: the owner of a
//! personal mailbox alone, the members of a group address, or the owner of a
//! calendar whose details stay private. A source may stand open to the vault
//! (a calendar its owner shared in detail), which restricts nothing. A
//! **thread policy** names its source policy and the people the thread was
//! shared with by an explicit act; its readers are the source's readers as
//! they are now, plus those. Each imported row (a mail CONVERSATION, its
//! TURNs and MESSAGEs, an attachment ASSET and its blob artifacts) is bound
//! to one policy at birth ([`bind_record_in_txn`]), and the binding never
//! moves.
//!
//! Every audience read meets the binding before anything else
//! ([`readable_with_read_in`], called from the private-thread conjunct
//! every scoped read path applies): the vault Owner's read and an Admin's
//! read included. A vault role is no reader of someone's mailbox; only the
//! org's compliance search, off by default and logged at each use, reads
//! across ([`crate::mail_pack`]). A row written from bound rows reads only
//! to those who read what it came from ([`walk`]): the facts learned from a
//! personal mailbox stay with its owner.
//!
//! Bindings and policies travel with their rows on the owner's full-window
//! lane only (Engine A, 6 Nov 03:46; [`replica`]): the highest revision of a
//! policy wins and a binding never moves. The share events, the thread index
//! and every other lane carry none, so a bound row whose policy does not
//! resolve, a row whose words came from a row bound otherwise, and every
//! bound row on another lane stay out of replication
//! ([`withheld_from_replication_in`]); and a row a source landed, read where
//! its binding is absent, reads to no one. A vault that holds no policy
//! binds no row, and the conjunct answers at once for every row no source
//! landed.

pub(crate) mod carried;
mod replica;
mod wake;
mod walk;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

pub(crate) use replica::{
    ReplicaMerge, bind_replicated_in_txn, event_conflicts_in, event_join,
    event_names_erased_actor_in, event_without_erased_actors, merge_event_in_txn,
    merge_policy_in_txn, names_erased_actor_in, policy_closure_in, policy_conflicts_in, policy_in,
    publishable_in, published_closure_in, redacted_successor_in, thread_source_in,
};
#[cfg(feature = "sync")]
pub(crate) use wake::{
    PolicyWake, advance_policy_wake, forget_policy_window, note_policy_windows, policy_wakes,
    policy_windows_after,
};
#[cfg(feature = "sync")]
pub(crate) use walk::derived_travel_in;
pub(crate) use walk::{
    ReplicationScope, lineage_held_in, readable_with_read_in, withheld_by_lineage_in,
    withheld_from_replication_in,
};

/// One policy, by its id.
const POLICIES: SideTable<EntityId, SourceAudiencePolicy, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_POLICY);
/// The policy each bound row was born under, by the row's id.
const RECORDS: SideTable<EntityId, EntityId, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_RECORD);
/// Each row this vault reads to no one meanwhile, and why.
const HELD: SideTable<EntityId, HeldBack, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_HELD);
/// The thread policy of one thread of a source policy, by the source policy
/// and the BLAKE3 of the source's own thread key. A second policy another
/// install minted for the same thread before the two met is filed beside it,
/// under the BLAKE3 of that key and its own id, so every merged thread
/// policy of a source is found by a scan of the source's rows; the thread's
/// own key keeps the first.
const THREADS: SideTable<(EntityId, [u8; 32]), EntityId, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_THREAD);
/// The policies each derived row reads under beside its own lineage (fix
/// list row 17207), by the row: the union of every set a full-window carrier
/// brought. It only grows; a carrier that goes takes nothing from it.
const DERIVED: SideTable<EntityId, BTreeSet<EntityId>, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_DERIVED);
/// Every change to a policy's readers, by the policy and the revision the
/// change made.
const EVENTS: SideTable<(EntityId, u64), SourceAudienceEvent, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_EVENT);

/// Who reads under one policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SourceAudienceKind {
    /// One source's readers: a personal mailbox's owner, a group address's
    /// members, a calendar's owner. `open` stands the source open to the
    /// whole vault, restricting nothing (a calendar shared in detail).
    Source {
        readers: BTreeSet<EntityId>,
        open: bool,
    },
    /// One thread of a source: the source's readers now, and the people the
    /// thread was shared with.
    Thread {
        source: EntityId,
        /// The BLAKE3 of the source's own thread key: where the thread index
        /// files it, here and on every replica that merges it (fix list row
        /// 17204).
        thread: [u8; 32],
        shared_with: BTreeSet<EntityId>,
    },
}

/// One stored policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SourceAudiencePolicy {
    pub(crate) kind: SourceAudienceKind,
    /// Who made it; `None` once that actor was erased.
    pub(crate) created_by: Option<EntityId>,
    pub(crate) created_at: u64,
    /// Bumped by every change to its readers; the key of that change's event.
    pub(crate) revision: u64,
}

/// What one change to a policy's readers did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceAudienceOp {
    /// A source's readers were set (connect, or a group's members edited).
    ReaderAdded,
    ReaderRemoved,
    /// A thread was shared with a person by an explicit act.
    Shared,
    /// A thread's share with a person was withdrawn.
    Unshared,
    /// A source was stood open to the vault, or closed again.
    Opened,
    Closed,
}

/// One change to a policy's readers, kept as its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SourceAudienceEvent {
    pub(crate) op: SourceAudienceOp,
    /// The person the change names; `None` for an open or a close, or once
    /// that person was erased.
    pub(crate) person: Option<EntityId>,
    /// Who made the change; `None` once that actor was erased.
    pub(crate) by: Option<EntityId>,
    pub(crate) at: u64,
}

/// Why a row reads to no one here meanwhile (FIX 12559 follow-up). Either
/// way it never leaves this vault while held, and no read of it, or of a
/// row whose words came from it, passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HeldBack {
    /// Its carried binding names a policy that has not arrived; it lifts
    /// once the binding lands.
    Pending,
    /// The vault it came from withheld it after it travelled (its words
    /// joined a row bound otherwise); it lifts once its carrier comes back
    /// with no marker.
    Withheld,
}

/// Why the row `id` reads to no one here, when it is held back.
pub(crate) fn held_back_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<HeldBack>> {
    HELD.get(&vault.store, txn, id)
}

/// Whether the vault holds any row back.
pub(crate) fn any_held_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(HELD.iter_from(&vault.store, txn, &[])?.next().is_some())
}

/// Every row held back here, and why.
pub(crate) fn held_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, HeldBack)>> {
    HELD.scan(&vault.store, txn)
}

/// Holds the row `id` back for `why`, in `txn`: a withholding stands over a
/// pending binding. Whether that changed what is held.
pub(crate) fn hold_back_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    why: HeldBack,
) -> Result<bool> {
    let held = HELD.get(&vault.store, txn, id)?;
    if held == Some(why) || held == Some(HeldBack::Withheld) {
        return Ok(false);
    }
    HELD.put(&vault.store, txn, id, &why)?;
    Ok(true)
}

/// Lifts the hold on the row `id` when it is held for `why`, in `txn`.
/// Whether that changed what is held.
pub(crate) fn lift_hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    why: HeldBack,
) -> Result<bool> {
    if HELD.get(&vault.store, txn, id)? != Some(why) {
        return Ok(false);
    }
    HELD.delete(&vault.store, txn, id)?;
    Ok(true)
}

/// Whether the vault holds any policy, or a derived row's carried policies
/// (fix list row 17207): one that holds neither binds no row, and no read of
/// it walks.
pub(crate) fn any_policy_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(POLICIES.iter_from(&vault.store, txn, &[])?.next().is_some()
        || DERIVED.iter_from(&vault.store, txn, &[])?.next().is_some())
}

/// The policies the derived row `row` reads under beside its own lineage,
/// as full-window carriers brought them (fix list row 17207).
pub(crate) fn derived_policies_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    DERIVED.get(&vault.store, txn, row)
}

/// Adds `policies` to those the derived row `row` reads under, in `txn`.
/// Whether the set grew.
///
/// # Errors
///
/// Storage failures.
#[cfg(feature = "sync")]
pub(crate) fn add_derived_policies_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &EntityId,
    policies: &BTreeSet<EntityId>,
) -> Result<bool> {
    let mut held = DERIVED.get(&vault.store, txn, row)?.unwrap_or_default();
    let before = held.len();
    held.extend(policies.iter().copied());
    if held.len() == before {
        return Ok(false);
    }
    DERIVED.put(&vault.store, txn, row, &held)?;
    Ok(true)
}

/// Drops the derived row `row`'s carried policies with the row: the
/// entity erase's (fix list row 17207).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn erase_derived_policies_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    DERIVED.delete(store, txn, row).map(drop)
}

/// The policy the row `record` was born under, if it was bound.
pub(crate) fn binding_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<EntityId>> {
    RECORDS.get(&vault.store, txn, record)
}

/// Who reads under `policy` now: `None` for a policy that does not resolve
/// (it denies every reader), `Some(None)` for one open to the vault, else
/// the readers.
pub(crate) fn readers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Option<Option<BTreeSet<EntityId>>>> {
    let Some(row) = POLICIES.get(&vault.store, txn, policy)? else {
        return Ok(None);
    };
    match row.kind {
        SourceAudienceKind::Source { open: true, .. } => Ok(Some(None)),
        SourceAudienceKind::Source { readers, .. } => Ok(Some(Some(readers))),
        SourceAudienceKind::Thread {
            source,
            shared_with,
            ..
        } => {
            let Some(parent) = POLICIES.get(&vault.store, txn, &source)? else {
                return Ok(None);
            };
            match parent.kind {
                SourceAudienceKind::Source { open: true, .. } => Ok(Some(None)),
                SourceAudienceKind::Source { readers, .. } => {
                    Ok(Some(Some(readers.union(&shared_with).copied().collect())))
                }
                // A thread of a thread is no policy this module writes.
                SourceAudienceKind::Thread { .. } => Ok(None),
            }
        }
    }
}

/// The readers a source policy names, whether or not it stands open: the
/// people who own the source. `None` for a policy that is no source's.
pub(crate) fn source_readers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    Ok(match POLICIES.get(&vault.store, txn, policy)? {
        Some(SourceAudiencePolicy {
            kind: SourceAudienceKind::Source { readers, .. },
            ..
        }) => Some(readers),
        _ => None,
    })
}

/// The PERSON the embedded owner actor stands for in a vault with no
/// authority root, where it is that vault's one owner: its one owner PERSON,
/// or the actor itself while the vault records none. `None` for any other
/// actor, in a rooted vault, or where several owners make it ambiguous.
pub(crate) fn embedded_owner_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Option<EntityId>> {
    if actor != crate::vault::embedded_owner_actor_id()?
        || vault
            .authority_fold_readonly_in_txn(txn)?
            .vault_id
            .is_some()
    {
        return Ok(None);
    }
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    Ok(match owners.as_slice() {
        [] => Some(actor),
        [owner] => Some(*owner),
        _ => None,
    })
}

/// Whether `readers` names `viewer`: by its id, a pen by the PERSON its
/// subject anchor names ([`crate::workspace_roster::names_actor_in`]), or
/// the embedded owner actor by the PERSON it stands for
/// ([`embedded_owner_person_in`]).
pub(crate) fn names_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    readers: &BTreeSet<EntityId>,
    viewer: EntityId,
) -> Result<bool> {
    if crate::workspace_roster::names_actor_in(vault, txn, readers, viewer)? {
        return Ok(true);
    }
    Ok(embedded_owner_person_in(vault, txn, viewer)?
        .is_some_and(|person| readers.contains(&person)))
}

/// Whether `actor` reads under `policy` now ([`names_reader_in`]).
pub(crate) fn actor_reads_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
    actor: EntityId,
) -> Result<bool> {
    match readers_in(vault, txn, policy)? {
        None => Ok(false),
        Some(None) => Ok(true),
        Some(Some(readers)) => names_reader_in(vault, txn, &readers, actor),
    }
}

/// Writes a new source policy read by `readers`, in `txn`, with one
/// `reader_added` event per reader. Answers its id.
pub(crate) fn create_source_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    readers: BTreeSet<EntityId>,
    open: bool,
    by: EntityId,
    at: u64,
) -> Result<EntityId> {
    let id = vault.store.clock.entity_id()?;
    let mut policy = SourceAudiencePolicy {
        kind: SourceAudienceKind::Source {
            readers: BTreeSet::new(),
            open: false,
        },
        created_by: Some(by),
        created_at: at,
        revision: 0,
    };
    POLICIES.put(&vault.store, txn, &id, &policy)?;
    policy = set_source_readers_row_in_txn(vault, txn, &id, policy, readers, by, at)?;
    if open {
        set_source_open_row_in_txn(vault, txn, &id, policy, true, by, at)?;
    }
    Ok(id)
}

/// Sets the readers of the source policy `id` to `readers`, in `txn`: one
/// event per person added or removed. A removed reader reads none of the
/// source's rows from this commit on, its earlier ones included.
pub(crate) fn set_source_readers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    readers: BTreeSet<EntityId>,
    by: EntityId,
    at: u64,
) -> Result<()> {
    let policy = POLICIES
        .get(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    set_source_readers_row_in_txn(vault, txn, id, policy, readers, by, at).map(|_| ())
}

/// Stands the source policy `id` open to the vault, or closes it, in `txn`.
/// A change records one event; a request that changes nothing records none.
pub(crate) fn set_source_open_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    open: bool,
    by: EntityId,
    at: u64,
) -> Result<()> {
    let policy = POLICIES
        .get(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    set_source_open_row_in_txn(vault, txn, id, policy, open, by, at).map(|_| ())
}

fn set_source_readers_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    mut policy: SourceAudiencePolicy,
    readers: BTreeSet<EntityId>,
    by: EntityId,
    at: u64,
) -> Result<SourceAudiencePolicy> {
    let SourceAudienceKind::Source {
        readers: current,
        open,
    } = &policy.kind
    else {
        return Err(Error::InvalidConfig(
            "a thread policy has no readers of its own".into(),
        ));
    };
    let open = *open;
    let added: Vec<EntityId> = readers.difference(current).copied().collect();
    let removed: Vec<EntityId> = current.difference(&readers).copied().collect();
    let changed = !added.is_empty() || !removed.is_empty();
    for (op, person) in added
        .into_iter()
        .map(|person| (SourceAudienceOp::ReaderAdded, person))
        .chain(
            removed
                .into_iter()
                .map(|person| (SourceAudienceOp::ReaderRemoved, person)),
        )
    {
        policy.revision += 1;
        EVENTS.put(
            &vault.store,
            txn,
            &(*id, policy.revision),
            &SourceAudienceEvent {
                op,
                person: Some(person),
                by: Some(by),
                at,
            },
        )?;
    }
    policy.kind = SourceAudienceKind::Source { readers, open };
    POLICIES.put(&vault.store, txn, id, &policy)?;
    // Every window the policy rides takes the change (fix list row 17203).
    if changed {
        wake::wake_policy_in_txn(vault, txn, id)?;
    }
    Ok(policy)
}

fn set_source_open_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    mut policy: SourceAudiencePolicy,
    open: bool,
    by: EntityId,
    at: u64,
) -> Result<SourceAudiencePolicy> {
    let SourceAudienceKind::Source {
        readers,
        open: current,
    } = &policy.kind
    else {
        return Err(Error::InvalidConfig(
            "a thread policy stands open only through its source".into(),
        ));
    };
    if *current == open {
        return Ok(policy);
    }
    let readers = readers.clone();
    policy.revision += 1;
    EVENTS.put(
        &vault.store,
        txn,
        &(*id, policy.revision),
        &SourceAudienceEvent {
            op: if open {
                SourceAudienceOp::Opened
            } else {
                SourceAudienceOp::Closed
            },
            person: None,
            by: Some(by),
            at,
        },
    )?;
    policy.kind = SourceAudienceKind::Source { readers, open };
    POLICIES.put(&vault.store, txn, id, &policy)?;
    wake::wake_policy_in_txn(vault, txn, id)?;
    Ok(policy)
}

/// The thread policy of the thread `thread_key` of the source policy
/// `source`, written in `txn` the first time a row of that thread lands.
/// Every later row of the same thread lands under the same policy, so a
/// share of the thread reaches its later messages too.
pub(crate) fn thread_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
    thread_key: &str,
    by: EntityId,
    at: u64,
) -> Result<EntityId> {
    match POLICIES.get(&vault.store, txn, source)? {
        Some(SourceAudiencePolicy {
            kind: SourceAudienceKind::Source { .. },
            ..
        }) => {}
        Some(_) => {
            return Err(Error::InvalidConfig(
                "a thread policy hangs under a source policy".into(),
            ));
        }
        None => return Err(Error::EntityNotFound),
    }
    let key = (*source, *blake3::hash(thread_key.as_bytes()).as_bytes());
    if let Some(id) = THREADS.get(&vault.store, txn, &key)? {
        return Ok(id);
    }
    let id = vault.store.clock.entity_id()?;
    POLICIES.put(
        &vault.store,
        txn,
        &id,
        &SourceAudiencePolicy {
            kind: SourceAudienceKind::Thread {
                source: *source,
                thread: key.1,
                shared_with: BTreeSet::new(),
            },
            created_by: Some(by),
            created_at: at,
            revision: 0,
        },
    )?;
    THREADS.put(&vault.store, txn, &key, &id)?;
    Ok(id)
}

/// Binds the row `record` to `policy` at its birth, in the writer that
/// lands it. A row bound already stays where it was born: a second bind to
/// the same policy changes nothing, and one to another policy is refused.
pub(crate) fn bind_record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    policy: &EntityId,
) -> Result<()> {
    if POLICIES.get(&vault.store, txn, policy)?.is_none() {
        return Err(Error::EntityNotFound);
    }
    match RECORDS.get(&vault.store, txn, record)? {
        Some(bound) if bound == *policy => Ok(()),
        Some(_) => Err(Error::InvalidConfig(
            "a row stays under the source audience it was born under".into(),
        )),
        None => RECORDS.put(&vault.store, txn, record, policy),
    }
}

/// Shares the thread policy `thread` with `person` (`share`), or withdraws
/// that share, in `txn`, as `by`'s explicit act. Answers whether anything
/// changed; a change records one event.
pub(crate) fn share_thread_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    thread: &EntityId,
    person: EntityId,
    share: bool,
    by: EntityId,
    at: u64,
) -> Result<bool> {
    let mut policy = POLICIES
        .get(&vault.store, txn, thread)?
        .ok_or(Error::EntityNotFound)?;
    let SourceAudienceKind::Thread { shared_with, .. } = &mut policy.kind else {
        return Err(Error::InvalidConfig(
            "only a thread is shared; a source's readers are its connection's".into(),
        ));
    };
    let changed = if share {
        shared_with.insert(person)
    } else {
        shared_with.remove(&person)
    };
    if !changed {
        return Ok(false);
    }
    policy.revision += 1;
    EVENTS.put(
        &vault.store,
        txn,
        &(*thread, policy.revision),
        &SourceAudienceEvent {
            op: if share {
                SourceAudienceOp::Shared
            } else {
                SourceAudienceOp::Unshared
            },
            person: Some(person),
            by: Some(by),
            at,
        },
    )?;
    POLICIES.put(&vault.store, txn, thread, &policy)?;
    wake::wake_policy_in_txn(vault, txn, thread)?;
    Ok(true)
}

/// The people a thread policy was shared with, and its source policy.
pub(crate) fn thread_shares_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    thread: &EntityId,
) -> Result<Option<(EntityId, BTreeSet<EntityId>)>> {
    Ok(match POLICIES.get(&vault.store, txn, thread)? {
        Some(SourceAudiencePolicy {
            kind:
                SourceAudienceKind::Thread {
                    source,
                    shared_with,
                    ..
                },
            ..
        }) => Some((source, shared_with)),
        _ => None,
    })
}

/// The thread policies of the source policy `source` that `actor` reads by
/// a share: how a reader finds the threads of a mailbox it does not read.
pub(crate) fn threads_shared_with_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    actor: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut shared = BTreeSet::new();
    for row in THREADS.iter_from(&vault.store, txn, source.as_bytes())? {
        let (_, thread) = row?;
        if let Some((_, shared_with)) = thread_shares_in(vault, txn, &thread)?
            && !shared_with.is_empty()
            && names_reader_in(vault, txn, &shared_with, actor)?
        {
            shared.insert(thread);
        }
    }
    Ok(shared)
}

/// One change to a policy's readers, as its receipt list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAudienceEventView {
    pub revision: u64,
    pub op: SourceAudienceOp,
    /// The person the change names, 32-hex; absent for an open or a close,
    /// or once that person was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_ref: Option<String>,
    /// Who made the change, 32-hex; absent once that actor was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_ref: Option<String>,
    pub at: u64,
}

/// Every change to `policy`'s readers, oldest first.
pub(crate) fn events_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Vec<SourceAudienceEventView>> {
    EVENTS
        .iter_from(&vault.store, txn, policy.as_bytes())?
        .map(|row| {
            let ((_, revision), event) = row?;
            Ok(SourceAudienceEventView {
                revision,
                op: event.op,
                person_ref: event.person.map(|id| id.to_hex()),
                by_ref: event.by.map(|id| id.to_hex()),
                at: event.at,
            })
        })
        .collect()
}

/// Every receipt of `policy`'s changes, by the revision each made: what
/// travels beside the policy (fix list row 17205).
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn events_of_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Vec<(u64, SourceAudienceEvent)>> {
    EVENTS
        .iter_from(&vault.store, txn, policy.as_bytes())?
        .map(|row| {
            let ((_, revision), event) = row?;
            Ok((revision, event))
        })
        .collect()
}

/// An actor's erase takes its id out of every policy and event (FIX 3520):
/// out of a source's readers and a thread's shares, so the erased person
/// reads nothing, and out of each `created_by` and event field. A policy it
/// changes takes its next revision, so a replica that has not heard of the
/// erase takes the redaction as the newer policy, not as a conflict; and
/// every window this vault stores drops the revisions that named the actor.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let policies = POLICIES.scan(&vault.store, wtxn)?;
    for (id, mut policy) in policies {
        let mut changed = false;
        if policy.created_by == Some(*actor) {
            policy.created_by = None;
            changed = true;
        }
        match &mut policy.kind {
            SourceAudienceKind::Source { readers, .. } => changed |= readers.remove(actor),
            SourceAudienceKind::Thread { shared_with, .. } => {
                changed |= shared_with.remove(actor);
            }
        }
        if changed {
            policy.revision = replica::next_revision(policy.revision)?;
            POLICIES.put(&vault.store, wtxn, &id, &policy)?;
            wake::wake_policy_in_txn(vault, wtxn, &id)?;
        }
    }
    let events = EVENTS.scan(&vault.store, wtxn)?;
    for (key, mut event) in events {
        let mut changed = false;
        if event.person == Some(*actor) {
            event.person = None;
            changed = true;
        }
        if event.by == Some(*actor) {
            event.by = None;
            changed = true;
        }
        if changed {
            EVENTS.put(&vault.store, wtxn, &key, &event)?;
            wake::wake_policy_in_txn(vault, wtxn, &key.0)?;
        }
    }
    // Every stored window's revisions naming the actor go with them; each
    // changed policy's successor rides in their place.
    #[cfg(feature = "sync")]
    crate::sync::source_audiences::erase_carriers_in_txn(vault, wtxn, actor)?;
    Ok(())
}
