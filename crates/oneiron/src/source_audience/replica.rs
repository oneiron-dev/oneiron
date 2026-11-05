//! Source audiences on a replica (Engine A, 6 Nov 03:46): a binding and its
//! policy travel with their row on the owner-grade full-window lane only, the
//! lane room facts ride. A policy's highest revision wins; two unequal copies
//! of one revision conflict and neither replaces the other; a binding never
//! changes once set. A policy names no actor this vault erased: an incoming
//! copy is redacted on arrival, under a revision of its own above the
//! sender's, so the redaction is never mistaken for the sender's bytes. No
//! source-authority signature is asked for in this slice: the lane is the
//! authority (a signed slice is a FIX row).

use super::{POLICIES, RECORDS, SourceAudienceKind, SourceAudiencePolicy};
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
    if let Some(held) = &held {
        if !same_identity(held, &accepted) {
            return Ok(ReplicaMerge::Conflict);
        }
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
    Ok(ReplicaMerge::Written)
}

/// Binds the replicated row `record` to `policy`, in `txn`, once the
/// policy's closure resolves: a thread policy needs its source's. A row
/// bound already stays where it was born: the same binding holds, another
/// conflicts.
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
            SourceAudienceKind::Thread { source: held, .. },
            SourceAudienceKind::Thread {
                source: incoming, ..
            },
        ) => held == incoming,
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
