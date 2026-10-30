//! Custody work in the fold (WILL L04 row 04): the revision a custody
//! request's `seen` is over, and the terminal knowledge an admitted revoke
//! leaves for its secret's id.
//!
//! A custody request has effect only on the revision it saw: its `seen` is
//! [`act_revision`] under [`CUSTODY_WORK_REVISION_CONTEXT`] over its
//! secret's live custody requests at its parents, compared before it joins
//! them (CALLS CUSTODY_REVISION). The writer states it from the same heads,
//! and names each among the request's parents.
//!
//! An admitted revoke is terminal for its id on every replica that folds it
//! (CALLS CUSTODY_CONCURRENT_ACTIVE): an active change after it is without
//! effect, and one concurrent with it loses to it, however the heads move.
//! That knowledge is the fold's, rebuilt with it: never a queue, and never
//! an empty record for an id this vault does not hold.

use super::*;

/// The heads a custody request's revision is over (CALLS CUSTODY_REVISION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRevisionHeads {
    /// The live custody request heads of the secret at the request's
    /// parents, each one admitted with effect; zero for the first. The
    /// request is never one of its own heads, so no request makes itself
    /// stale, and its executor checks only that it still has effect.
    PriorCountedRequestHeads,
}

const CUSTODY_REVISION: CustodyRevisionHeads = CustodyRevisionHeads::PriorCountedRequestHeads;

/// How an active custody change meets an admitted revoke of its secret
/// (CALLS CUSTODY_CONCURRENT_ACTIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyConcurrentActive {
    /// The revoke is terminal for the id. An active change whose parents
    /// hold it is without effect; one concurrent with it is never done, as
    /// its executor refuses it as stale.
    ConflictRevokeTerminal,
}

const CUSTODY_CONCURRENT_ACTIVE: CustodyConcurrentActive =
    CustodyConcurrentActive::ConflictRevokeTerminal;

/// One custody value the fold proves an install holds: the enacted request
/// that proves it, its secret, the generation it approves and its executor.
struct EnactedCustodyValue<'a> {
    request: &'a AuthorityEntryHash,
    secret: EntityId,
    generation: u32,
    holder: EntityId,
}

impl AuthorityFold {
    /// The revision a custody request on `secret` states as its `seen`
    /// (CALLS CUSTODY_REVISION): [`act_revision`] over the secret's live
    /// custody request heads, which the fold of the request's parents
    /// carries.
    pub(crate) fn custody_work_revision(&self, secret: EntityId) -> [u8; 32] {
        match CUSTODY_REVISION {
            CustodyRevisionHeads::PriorCountedRequestHeads => act_revision(
                CUSTODY_WORK_REVISION_CONTEXT,
                self.owner_work
                    .heads
                    .get(&(OwnerWorkKind::Custody, secret))
                    .into_iter()
                    .flatten()
                    .copied(),
            ),
        }
    }

    /// The secret's live custody requests, each with its entry hash: what
    /// its next request replaces, the permits a rotate keeps, and the request
    /// a surface's resent protected input already names.
    pub(crate) fn custody_heads(
        &self,
        secret: EntityId,
    ) -> Vec<(AuthorityEntryHash, &OwnerWorkRequest)> {
        self.owner_work
            .heads
            .get(&(OwnerWorkKind::Custody, secret))
            .into_iter()
            .flatten()
            .filter_map(|hash| {
                self.owner_work_request(hash)
                    .map(|request| (*hash, request))
            })
            .collect()
    }

    /// Whether an admitted custody revoke names `secret`: terminal for it
    /// here (CALLS CUSTODY_CONCURRENT_ACTIVE). It reads admitted history,
    /// not this install's removal race: a revoke only narrows, and once
    /// admitted it stays.
    pub(crate) fn custody_revoked(&self, secret: &EntityId) -> bool {
        self.owner_work.revoked.contains(secret)
    }

    /// The installs that hold `secret`'s value at `generation`, as the fold
    /// proves it (FIX 4624(b)): the executor of each counted custody
    /// register, rotate or rewrap of it at that generation whose result is
    /// enacted, those of the secret's live heads first, each group by
    /// machine id. A permitted recipient is a candidate, never a holder: a
    /// value sealed to it proves no delivery. A kit request names no
    /// machine.
    pub(crate) fn custody_value_holders(&self, secret: EntityId, generation: u32) -> Vec<EntityId> {
        let heads = self.owner_work.heads.get(&(OwnerWorkKind::Custody, secret));
        let (mut live, mut earlier) = (BTreeSet::new(), BTreeSet::new());
        for held in self.enacted_custody_values() {
            if held.secret != secret || held.generation != generation {
                continue;
            }
            if heads.is_some_and(|heads| heads.contains(held.request)) {
                live.insert(held.holder);
            } else {
                earlier.insert(held.holder);
            }
        }
        let mut holders: Vec<EntityId> = live.iter().copied().collect();
        holders.extend(earlier.difference(&live).copied());
        holders
    }

    /// Each secret whose value the fold proves an install holds, at the
    /// highest generation it proves one does (FIX 11844): what an owner
    /// export names for its holders when no custody row here holds the
    /// secret. A secret an admitted revoke ended is left out, as its record
    /// would be.
    pub(crate) fn custody_held_generations(&self) -> BTreeMap<EntityId, u32> {
        let mut held = BTreeMap::new();
        for value in self.enacted_custody_values() {
            if self.custody_revoked(&value.secret) {
                continue;
            }
            held.entry(value.secret)
                .and_modify(|at: &mut u32| *at = (*at).max(value.generation))
                .or_insert(value.generation);
        }
        held
    }

    /// Each counted custody register, rotate or rewrap whose result is
    /// enacted and whose executor is a machine: the one place
    /// [`Self::custody_value_holders`] and [`Self::custody_held_generations`]
    /// read a holder from.
    fn enacted_custody_values(&self) -> impl Iterator<Item = EnactedCustodyValue<'_>> + '_ {
        self.owner_work
            .requests
            .iter()
            .filter_map(move |(hash, folded)| {
                let OwnerWorkBody::Custody {
                    change, generation, ..
                } = &folded.request.work
                else {
                    return None;
                };
                let enacted = matches!(
                    self.owner_work
                        .results
                        .get(hash)
                        .map(|answer| &answer.outcome),
                    Some(OwnerWorkOutcome::Enacted { .. })
                );
                let holder = folded.request.executor_machine()?;
                (folded.counts && *change != CustodyChange::Revoke && enacted).then_some(
                    EnactedCustodyValue {
                        request: hash,
                        secret: folded.request.act.target,
                        generation: *generation,
                        holder,
                    },
                )
            })
    }

    /// Every secret id an admitted custody revoke names, ascending.
    pub(crate) fn custody_revoked_ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.owner_work.revoked.iter().copied()
    }
}

/// Whether a custody request has effect on `work`, the state at its parents:
/// its `seen` is its secret's revision there, and no admitted revoke of the
/// secret precedes it unless it is a revoke itself. Any other request has.
pub(super) fn custody_request_lands(work: &OwnerWorkState, request: &OwnerWorkRequest) -> bool {
    let OwnerWorkBody::Custody { change, .. } = &request.work else {
        return true;
    };
    let secret = request.act.target;
    let seen = match CUSTODY_REVISION {
        CustodyRevisionHeads::PriorCountedRequestHeads => act_revision(
            CUSTODY_WORK_REVISION_CONTEXT,
            work.heads
                .get(&(OwnerWorkKind::Custody, secret))
                .into_iter()
                .flat_map(|heads| heads.live.iter().copied()),
        ),
    };
    let terminal = match CUSTODY_CONCURRENT_ACTIVE {
        CustodyConcurrentActive::ConflictRevokeTerminal => {
            *change != CustodyChange::Revoke && work.revoked.contains(&secret)
        }
    };
    seen == request.act.seen && !terminal
}

/// Keeps the secret an admitted custody revoke names as terminal.
pub(super) fn note_custody_revoke(work: &mut OwnerWorkState, request: &OwnerWorkRequest) {
    if matches!(
        request.work,
        OwnerWorkBody::Custody {
            change: CustodyChange::Revoke,
            ..
        }
    ) {
        work.revoked.insert(request.act.target);
    }
}
