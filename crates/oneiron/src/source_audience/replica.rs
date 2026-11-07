//! Source audiences on a replica (Engine A, 6 Nov 03:46): a binding and its
//! policy travel with their row on the owner-grade full-window lane only, the
//! lane room facts ride. A policy's highest revision wins; two unequal copies
//! of one revision conflict and neither replaces the other; a binding never
//! changes once set. A policy names no actor this vault erased: an incoming
//! copy is redacted on arrival, under a revision of its own above the
//! sender's, so the redaction is never mistaken for the sender's bytes. No
//! source-authority signature is asked for in this slice: the lane is the
//! authority (a signed slice is a FIX row).

use super::{
    EVENTS, POLICIES, RECORDS, SourceAudienceEvent, SourceAudienceKind, SourceAudiencePolicy,
    THREADS,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// What one replicated binding or policy did here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicaMerge {
    /// Nothing changed: the held copy stands (equal, or higher).
    Held,
    /// The incoming copy, or its redaction, is the canonical one now.
    Written,
    /// What it needs (a policy, or a thread's source) has not arrived: it
    /// stays carried, and its row stays refused.
    Pending,
    /// It contradicts what is held: refused, never merged.
    Conflict,
}

/// Merges one incoming copy of the policy `id` into the canonical policy, in
/// `txn`. The held head is first redacted against this vault's erased
/// actors; then a higher incoming revision wins, an equal equal one holds,
/// and an equal unequal one, or one of another identity, conflicts.
///
/// # Errors
///
/// Storage and codec failures; a revision past `u64::MAX`.
pub(crate) fn merge_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    incoming: &SourceAudiencePolicy,
) -> Result<ReplicaMerge> {
    let held = normalized_head_in_txn(vault, txn, id)?;
    let mut accepted = without_erased_actors(vault, txn, incoming)?;
    if let Some(held) = &held
        && !same_identity(held, &accepted)
    {
        return Ok(ReplicaMerge::Conflict);
    }
    // A thread merged here is filed where its source's threads are found
    // (fix list row 17204), whichever revision stands.
    index_thread_in_txn(vault, txn, id, &accepted)?;
    if let Some(held) = &held {
        if accepted.revision < held.revision {
            return Ok(ReplicaMerge::Held);
        }
        if accepted.revision == held.revision {
            return Ok(if accepted == *held {
                ReplicaMerge::Held
            } else {
                ReplicaMerge::Conflict
            });
        }
    }
    if accepted != *incoming {
        // A redaction is this vault's own successor, not the sender's bytes.
        accepted.revision = next_revision(accepted.revision)?;
    }
    POLICIES.put(&vault.store, txn, id, &accepted)?;
    // Every window the policy rides takes the newer revision (fix list row
    // 17203).
    super::wake::wake_policy_in_txn(vault, txn, id)?;
    Ok(ReplicaMerge::Written)
}

/// Files the thread policy `id` in its source's thread index, in `txn`:
/// how a replica finds the threads of a source, and how a later landing of
/// the thread here finds the policy its rows were born under. The thread's
/// own key takes the first policy filed for it. Another install's policy
/// for the same thread, minted before the two met, keeps its own bindings
/// and shares, so it is filed beside the first under a key of its own, and
/// a scan of the source finds it too. A source policy files nothing.
fn index_thread_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    policy: &SourceAudiencePolicy,
) -> Result<()> {
    let SourceAudienceKind::Thread { source, thread, .. } = &policy.kind else {
        return Ok(());
    };
    let key = match THREADS.get(&vault.store, txn, &(*source, *thread))? {
        None => (*source, *thread),
        Some(first) if first == *id => return Ok(()),
        Some(_) => {
            let mut beside = blake3::Hasher::new();
            beside.update(thread);
            beside.update(id.as_bytes());
            (*source, *beside.finalize().as_bytes())
        }
    };
    if THREADS.get(&vault.store, txn, &key)?.is_none() {
        THREADS.put(&vault.store, txn, &key, id)?;
    }
    Ok(())
}

/// Merges one incoming receipt of the change that made revision `revision`
/// of `policy`, in `txn` (fix list row 17205): one this vault does not hold
/// is kept, without any actor this vault erased. A receipt changes only by
/// losing an actor, when a vault erases one: two copies that differ
/// otherwise conflict, the held one standing, and two that agree leave
/// their meet, each actor either copy lost taken out ([`event_meet`]).
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn merge_event_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    policy: &EntityId,
    revision: u64,
    incoming: &SourceAudienceEvent,
) -> Result<ReplicaMerge> {
    let accepted = event_without_erased_actors(vault, txn, incoming)?;
    let key = (*policy, revision);
    let merged = match EVENTS.get(&vault.store, txn, &key)? {
        None => accepted,
        Some(held) => match event_meet(&held, &accepted) {
            None => return Ok(ReplicaMerge::Conflict),
            Some(meet) if meet == held => return Ok(ReplicaMerge::Held),
            Some(meet) => meet,
        },
    };
    EVENTS.put(&vault.store, txn, &key, &merged)?;
    super::wake::wake_policy_in_txn(vault, txn, policy)?;
    Ok(ReplicaMerge::Written)
}

/// Whether the receipt `incoming` of the change that made revision
/// `revision` of `policy` contradicts the one this vault holds: it tells
/// another change, not the same one with an actor taken out.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn event_conflicts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
    revision: u64,
    incoming: &SourceAudienceEvent,
) -> Result<bool> {
    Ok(EVENTS
        .get(&vault.store, txn, &(*policy, revision))?
        .is_some_and(|held| event_meet(&held, incoming).is_none()))
}

/// Two receipts of one change as all they tell: each actor either names.
/// `None` when they tell different changes. Admission folds a range's
/// copies of one receipt this way: a redacted copy between two that name
/// two people never hides the contradiction.
pub(crate) fn event_join(
    one: &SourceAudienceEvent,
    other: &SourceAudienceEvent,
) -> Option<SourceAudienceEvent> {
    let actor = |left: Option<EntityId>, right: Option<EntityId>| match (left, right) {
        (Some(left), Some(right)) if left != right => None,
        (Some(named), _) | (None, Some(named)) => Some(Some(named)),
        (None, None) => Some(None),
    };
    if one.op != other.op || one.at != other.at {
        return None;
    }
    Some(SourceAudienceEvent {
        op: one.op,
        person: actor(one.person, other.person)?,
        by: actor(one.by, other.by)?,
        at: one.at,
    })
}

/// Two receipts of one change as one: the change both tell, without each
/// actor either lost to an erase. `None` when they tell different changes.
fn event_meet(
    one: &SourceAudienceEvent,
    other: &SourceAudienceEvent,
) -> Option<SourceAudienceEvent> {
    // Each actor field: kept where both tell it, out where either lost it,
    // and no meet where they tell two people.
    let actor = |left: Option<EntityId>, right: Option<EntityId>| match (left, right) {
        (Some(left), Some(right)) if left != right => None,
        (Some(left), Some(_)) => Some(Some(left)),
        _ => Some(None),
    };
    if one.op != other.op || one.at != other.at {
        return None;
    }
    Some(SourceAudienceEvent {
        op: one.op,
        person: actor(one.person, other.person)?,
        by: actor(one.by, other.by)?,
        at: one.at,
    })
}

/// Whether the change receipt `event` names an actor this vault erased.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn event_names_erased_actor_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &SourceAudienceEvent,
) -> Result<bool> {
    Ok(event_without_erased_actors(vault, txn, event)? != *event)
}

/// `event` with every actor this vault erased taken out of it.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn event_without_erased_actors(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &SourceAudienceEvent,
) -> Result<SourceAudienceEvent> {
    let mut normal = event.clone();
    if let Some(person) = normal.person
        && vault.carrier_actor_erased_in_txn(txn, &person)?
    {
        normal.person = None;
    }
    if let Some(by) = normal.by
        && vault.carrier_actor_erased_in_txn(txn, &by)?
    {
        normal.by = None;
    }
    Ok(normal)
}

/// Binds the replicated row `record` to `policy`, in `txn`, once the
/// policy's closure resolves: a thread policy needs its source's. A row
/// bound already stays where it was born: the same binding holds, another
/// conflicts. A binding on a row held here whose own bytes carry no valid
/// obligation conflicts too (fix list row 16256): only a stamped row is
/// born bound.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn bind_replicated_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    policy: &EntityId,
) -> Result<ReplicaMerge> {
    match RECORDS.get(&vault.store, txn, record)? {
        Some(bound) if bound == *policy => return Ok(ReplicaMerge::Held),
        Some(_) => return Ok(ReplicaMerge::Conflict),
        None => {}
    }
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, record)?
        && super::obligation::row_obligation(&raw)
            != crate::store::source_audience_obligation::SourceAudienceObligation::Required
    {
        return Ok(ReplicaMerge::Conflict);
    }
    if policy_closure_in(vault, txn, policy)?.is_none() {
        return Ok(ReplicaMerge::Pending);
    }
    RECORDS.put(&vault.store, txn, record, policy)?;
    Ok(ReplicaMerge::Written)
}

/// The policies `policy` resolves through, as held: a source policy alone,
/// or a thread policy and then its source's. `None` while any is absent, or
/// for a thread whose source is no source policy: such a closure denies.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn policy_closure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Option<Vec<(EntityId, SourceAudiencePolicy)>>> {
    let Some(row) = POLICIES.get(&vault.store, txn, policy)? else {
        return Ok(None);
    };
    let parent = match &row.kind {
        SourceAudienceKind::Source { .. } => None,
        SourceAudienceKind::Thread { source, .. } => Some(*source),
    };
    let mut closure = vec![(*policy, row)];
    if let Some(source) = parent {
        match POLICIES.get(&vault.store, txn, &source)? {
            Some(
                parent @ SourceAudiencePolicy {
                    kind: SourceAudienceKind::Source { .. },
                    ..
                },
            ) => closure.push((source, parent)),
            _ => return Ok(None),
        }
    }
    Ok(Some(closure))
}

/// Whether a row bound to `policy` may travel with it: its closure
/// resolves here and names no actor this vault erased.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn publishable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<bool> {
    let Some(closure) = policy_closure_in(vault, txn, policy)? else {
        return Ok(false);
    };
    for (_, held) in &closure {
        if names_erased_actor_in(vault, txn, held)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The closure a carrier publishes for `policy` ([`policy_closure_in`]),
/// each policy already free of erased actors: the erase writer and every
/// merge keep them so. `None` while it does not resolve.
///
/// # Errors
///
/// Storage and codec failures; a held policy that still names an erased
/// actor (its erase owes a successor).
pub(crate) fn published_closure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &EntityId,
) -> Result<Option<Vec<(EntityId, SourceAudiencePolicy)>>> {
    let Some(closure) = policy_closure_in(vault, txn, policy)? else {
        return Ok(None);
    };
    for (_, held) in &closure {
        // A head an erase reached before it learned to bump the revision is
        // never published with the erased actor in it.
        if names_erased_actor_in(vault, txn, held)? {
            return Err(Error::InvalidConfig(
                "a source audience policy still names an erased actor; its erase owes a successor"
                    .into(),
            ));
        }
    }
    Ok(Some(closure))
}

/// Whether `policy` names an actor this vault erased: a reader, a share or
/// its creator.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn names_erased_actor_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &SourceAudiencePolicy,
) -> Result<bool> {
    Ok(without_erased_actors(vault, txn, policy)? != *policy)
}

/// Whether `incoming` contradicts the held head of `id`, both free of
/// erased actors: another identity, or the same revision with other
/// contents. A lower or a higher revision of the same policy does not.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn policy_conflicts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    incoming: &SourceAudiencePolicy,
) -> Result<bool> {
    let Some(held) = POLICIES.get(&vault.store, txn, id)? else {
        return Ok(false);
    };
    let held = without_erased_actors(vault, txn, &held)?;
    let incoming = without_erased_actors(vault, txn, incoming)?;
    Ok(
        !same_identity(&held, &incoming)
            || (incoming.revision == held.revision && incoming != held),
    )
}

/// The source policy of the thread policy `id`, as held; `None` for a
/// source policy or one not held.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn thread_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    Ok(match POLICIES.get(&vault.store, txn, id)? {
        Some(SourceAudiencePolicy {
            kind: SourceAudienceKind::Thread { source, .. },
            ..
        }) => Some(source),
        _ => None,
    })
}

/// The policy `id` as held.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn policy_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SourceAudiencePolicy>> {
    POLICIES.get(&vault.store, txn, id)
}

/// `policy` with every actor this vault erased taken out, as its own next
/// revision: the successor a recovery restores in place of a revision that
/// names one.
///
/// # Errors
///
/// Storage failures; a revision past `u64::MAX`.
pub(crate) fn redacted_successor_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &SourceAudiencePolicy,
) -> Result<SourceAudiencePolicy> {
    let mut redacted = without_erased_actors(vault, txn, policy)?;
    redacted.revision = next_revision(policy.revision)?;
    Ok(redacted)
}

/// The held head of `id`, redacted against this vault's erased actors and
/// stored as its own successor revision when that changed it.
fn normalized_head_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<SourceAudiencePolicy>> {
    let Some(held) = POLICIES.get(&vault.store, txn, id)? else {
        return Ok(None);
    };
    let mut normal = without_erased_actors(vault, txn, &held)?;
    if normal == held {
        return Ok(Some(held));
    }
    normal.revision = next_revision(held.revision)?;
    POLICIES.put(&vault.store, txn, id, &normal)?;
    super::wake::wake_policy_in_txn(vault, txn, id)?;
    Ok(Some(normal))
}

/// `policy` with every actor this vault erased taken out: out of a source's
/// readers and a thread's shares, and out of `created_by`. Its revision is
/// left as it was.
fn without_erased_actors(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &SourceAudiencePolicy,
) -> Result<SourceAudiencePolicy> {
    let erased = |actor: &EntityId| vault.carrier_actor_erased_in_txn(txn, actor);
    let mut normal = policy.clone();
    if let Some(by) = normal.created_by
        && erased(&by)?
    {
        normal.created_by = None;
    }
    let people = match &mut normal.kind {
        SourceAudienceKind::Source { readers, .. } => readers,
        SourceAudienceKind::Thread { shared_with, .. } => shared_with,
    };
    let mut gone = Vec::new();
    for person in people.iter() {
        if erased(person)? {
            gone.push(*person);
        }
    }
    for person in gone {
        people.remove(&person);
    }
    Ok(normal)
}

/// Whether two copies are of one policy: the same kind, for a thread the
/// same source, and the same birth. Readers, shares, revision and the
/// erasable creator may differ between its revisions.
fn same_identity(held: &SourceAudiencePolicy, incoming: &SourceAudiencePolicy) -> bool {
    let kind = match (&held.kind, &incoming.kind) {
        (SourceAudienceKind::Source { .. }, SourceAudienceKind::Source { .. }) => true,
        (
            SourceAudienceKind::Thread {
                source: held,
                thread: held_thread,
                ..
            },
            SourceAudienceKind::Thread {
                source: incoming,
                thread: incoming_thread,
                ..
            },
        ) => held == incoming && held_thread == incoming_thread,
        _ => false,
    };
    kind && held.created_at == incoming.created_at
}

/// The revision after `revision`.
pub(super) fn next_revision(revision: u64) -> Result<u64> {
    revision
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("source audience policy revision"))
}
