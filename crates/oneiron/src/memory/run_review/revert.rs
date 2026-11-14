//! Owner revert of a run's reviewed changes, with their compensation.
//! `Memory::revert_run_as_owner` is its call surface.
//! `memory::run_review` defines the review and settlement records.

use super::changes::JournalKey;
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::identity_topology::{IdentityOpOutcome, IdentityOpWrite, TopologySeal};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};

impl Memory<'_> {
    /// Compensates the selected changes (all when absent). Each member's
    /// currency, owner proof, inverse and receipt share its write transaction.
    /// Earlier successful members remain durable if a later storage call fails.
    /// A settled run's members are its settlement's; a run nobody settled
    /// takes its members from its change journal, which keeps each
    /// compensation (ruling RUNCHANGES-REVERT-UNSETTLED = A, 13 Nov).
    pub fn revert_run_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RevertRunRequest,
    ) -> MemoryResult<RevertRunOutcome> {
        let run = run_key(&input.run_id)?;
        // Each member, with its journal key when the journal holds it.
        let members: Vec<(Option<JournalKey>, StoredChange)> = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            require_owner(self, &txn, owner)?;
            match SETTLEMENTS.get(&self.vault().store, &txn, &run)? {
                Some(stored) => stored.changes.into_iter().map(|m| (None, m)).collect(),
                None => {
                    let journal = super::changes::journal_members_in_txn(self, &txn, &run)?;
                    if journal.is_empty() {
                        return Err(MemoryError::not_found(
                            "no run settlement or run change has that handle",
                        ));
                    }
                    journal.into_iter().map(|(key, m)| (Some(key), m)).collect()
                }
            }
        };
        let all: std::collections::BTreeSet<_> =
            members.iter().map(|(_, m)| m.member.change()).collect();
        let selected: std::collections::BTreeSet<_> = input
            .changes
            .as_ref()
            .map(|changes| changes.iter().cloned().collect())
            .unwrap_or_else(|| all.clone());
        if !selected.is_subset(&all) {
            return Err(MemoryError::bad_request(
                "selection names a change outside this run",
            ));
        }
        let mut outcome = RevertRunOutcome {
            run_id: run.clone(),
            compensated: Vec::new(),
            not_undone: Vec::new(),
        };
        // Reverse explicit membership order, so a dependent child listed
        // after its input can be compensated before that input.
        for (key, member) in members.iter().rev() {
            let change = member.member.change();
            if !selected.contains(&change) {
                if let Some(receipt) = &member.compensation {
                    outcome.compensated.push(RunCompensation {
                        change,
                        receipt: receipt.clone(),
                    });
                    outcome
                        .not_undone
                        .extend(member.unrestored.iter().map(|change| RunNotUndone {
                            change: change.clone(),
                            reason: RunNotUndoneReason::Dependent,
                        }));
                } else {
                    outcome.not_undone.push(RunNotUndone {
                        change,
                        reason: RunNotUndoneReason::NotSelected,
                    });
                }
                continue;
            }
            let result = self.with_verified_actor_write_txn(|txn| {
                let actor = require_owner(self, txn, owner)?;
                if let Some(key) = key {
                    return super::changes::undo_journal_member_in_txn(
                        self, txn, owner, actor, key,
                    );
                }
                let mut journal = SETTLEMENTS
                    .get(&self.vault().store, txn, &run)?
                    .ok_or_else(|| MemoryError::not_found("run settlement is absent"))?;
                let row = journal
                    .changes
                    .iter_mut()
                    .find(|row| row.member.change() == change)
                    .ok_or_else(|| MemoryError::bad_request("change left the run"))?;
                let fresh = row.compensation.is_none();
                let undone = undo_member_in_txn(self, txn, owner, actor, row)?;
                if fresh && undone.is_ok() {
                    SETTLEMENTS.put(&self.vault().store, txn, &run, &journal)?;
                }
                Ok(undone)
            })?;
            match result {
                Ok((receipt, unrestored)) => {
                    outcome
                        .compensated
                        .push(RunCompensation { change, receipt });
                    outcome
                        .not_undone
                        .extend(unrestored.into_iter().map(|change| RunNotUndone {
                            change,
                            reason: RunNotUndoneReason::Dependent,
                        }));
                }
                Err(reason) => outcome.not_undone.push(RunNotUndone { change, reason }),
            }
        }
        self.produced_from(
            members
                .iter()
                .map(|(_, m)| m.member.rows())
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(outcome)
    }
}

/// Takes back one member in the caller's write: its compensating write, then
/// the owner's compensation decision, whose receipt the member keeps. A
/// member compensated before answers with that same receipt and writes
/// nothing; the caller stores a fresh compensation where the member lives.
pub(super) fn undo_member_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    actor: WriteActor,
    row: &mut StoredChange,
) -> MemoryResult<Result<(String, Vec<String>), RunNotUndoneReason>> {
    if let Some(receipt) = &row.compensation {
        return Ok(Ok((receipt.clone(), row.unrestored.clone())));
    }
    if row.verdict != RunChangeVerdict::Landed {
        return Ok(Err(RunNotUndoneReason::NotLanded));
    }
    let now = memory.vault().store.clock.now_recorded_at();
    let receipt = match &row.member {
        RunReviewChange::ExternalEffect { .. } | RunReviewChange::Erase { .. } => {
            return Ok(Err(RunNotUndoneReason::OneWay));
        }
        // Its author was erased since it landed (FIX 4727).
        _ if matches!(row.inverse, Some(RunInverse::AuthorErased)) => {
            return Ok(Err(RunNotUndoneReason::OneWay));
        }
        RunReviewChange::Delete { entity_ref } => {
            let hard = memory.vault().store.port_deletion_marked(
                txn,
                crate::ports::DeletionMarker::HardDelete,
                &EntityId::from_hex(entity_ref)?,
            )?;
            return Ok(Err(if hard {
                RunNotUndoneReason::OneWay
            } else {
                RunNotUndoneReason::BackupOnly
            }));
        }
        _ => compensate(memory, txn, owner, actor, row, now)?,
    };
    let Some((inverse_receipt, unrestored)) = receipt else {
        return Ok(Err(RunNotUndoneReason::Dependent));
    };
    let record = super::super::authorship::decision(
        actor,
        "run_compensation",
        "approved",
        "gate.run.revert.compensated",
        row.member.rows()?.first().copied(),
        serde_json::to_vec(&(&inverse_receipt, &unrestored))
            .map_err(|_| MemoryError::bad_request("compensation receipt cannot be encoded"))?,
        now,
    );
    memory
        .vault()
        .store
        .append_gate_decision_in_txn(txn, &record)?;
    let receipt = format!("gate:{}", record.decision_id.to_hex());
    row.compensation = Some(receipt.clone());
    row.unrestored = unrestored.clone();
    Ok(Ok((receipt, unrestored)))
}

fn compensate(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    actor: WriteActor,
    row: &StoredChange,
    now: u64,
) -> MemoryResult<Option<(String, Vec<String>)>> {
    let vault = memory.vault();
    match row.inverse.as_ref() {
        Some(RunInverse::Authored {
            author,
            fingerprint: expected,
        }) => {
            let id = EntityId::from_hex(&row.member.change())?;
            let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                return Ok(None);
            };
            if body.lifecycle != ClaimLifecycleStatus::Active
                || fingerprint(&snapshot::binding(memory, txn, &row.member)?.0) != *expected
                || has_live_dependent(vault, txn, &id)?
            {
                return Ok(None);
            }
            let reverted = crate::dreamer_consolidation::revert_authored_change_in_txn(
                vault,
                txn,
                id,
                EntityId::from_hex(author)?,
                actor,
                // That inverse takes milliseconds; `now` is the store
                // clock's Unix seconds.
                now.saturating_mul(1_000),
            )?;
            let unrestored = reverted
                .left_closed
                .into_iter()
                .map(|id| id.to_hex())
                .chain(reverted.left_alone)
                .collect();
            Ok(Some((id.to_hex(), unrestored)))
        }
        Some(RunInverse::Restored {
            fingerprint: expected,
        }) => {
            let id = EntityId::from_hex(&row.member.change())?;
            let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                return Ok(None);
            };
            if body.lifecycle != ClaimLifecycleStatus::Active
                || fingerprint(&super::restore_group::restored_binding(vault, txn, &id)?)
                    != *expected
                || has_live_dependent(vault, txn, &id)?
            {
                return Ok(None);
            }
            vault.retract_claim_in_txn_as(txn, &id, now, Some(actor))?;
            Ok(Some((id.to_hex(), Vec::new())))
        }
        Some(RunInverse::Note(undo)) => crate::note::revert_run_note_in_txn(memory, txn, undo)
            .map(|receipt| receipt.map(|receipt| (receipt, Vec::new()))),
        Some(RunInverse::Topology { event }) => {
            let event = EntityId::from_hex(event)?;
            // Where his request reached this install, as the host bound it
            // (FIX 4650): audit only.
            let seal = TopologySeal::decision(crate::authority::ActAuthority::Owner(
                owner.clone(),
                memory.owner_surface(),
            ));
            let write = IdentityOpWrite {
                source: crate::claim::ClaimSource::UserStated,
                approval: ClaimApprovalStatus::Approved,
                confidence: 1.0,
                actor: Some(actor),
            };
            match vault.undo_identity_topology_event_in_txn(txn, &event, &write, &seal, now) {
                Ok(IdentityOpOutcome::Applied { event, .. }) => {
                    Ok(Some((event.to_hex(), Vec::new())))
                }
                Err(crate::Error::Sync(crate::error::SyncError::IdentityTopologyRejected(
                    crate::identity_topology::IdentityTopologyRejection::NotCurrent { .. },
                ))) => Ok(None),
                Err(error) => Err(error.into()),
                _ => Err(MemoryError::bad_request(
                    "topology compensation did not apply",
                )),
            }
        }
        Some(RunInverse::AuthorErased) | None => Ok(None),
    }
}

/// Whether a live later claim cites, derives from or supersedes the change
/// `id`, or any live row of another type links to it so: the change is then
/// left standing with its input, never retracted under it.
fn has_live_dependent(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<bool> {
    for kind in [
        crate::edge::EdgeKind::DerivedFrom,
        crate::edge::EdgeKind::Supersedes,
        crate::edge::EdgeKind::Supports,
    ] {
        for peer in vault.port_edge_peers(txn, id, EdgeDirection::In, kind)? {
            let peer = peer?;
            let Some(record) = vault.store.port_entity_record(txn, &peer)? else {
                continue;
            };
            let state = vault.store.port_deletion_state(txn, &peer)?;
            if state.deleted || state.archived {
                continue;
            }
            if record.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                return Ok(true);
            }
            if vault.get_claim_in_txn(txn, &peer)?.is_some_and(|body| {
                body.lifecycle == ClaimLifecycleStatus::Active
                    && body.approval != ClaimApprovalStatus::Rejected
            }) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
