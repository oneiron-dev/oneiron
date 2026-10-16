//! Live admission of a PROJECT write: direct, batch and typed doors. Replay
//! never reaches this check; the read fold judges replicated rows instead.
use super::fold::{ProjectDisposition, ProjectEffective, ProjectRank};
use super::history_policy::PROJECT_FROZEN_APPLIED;
use super::read::{ProjectReader, ProjectVerdict, stored};
use super::revision::{ProjectRevision, REVISIONS, revisions_of_row};
use super::*;
use crate::authority::{CapabilitySlip, authority_fold_readonly_for_store_in_txn};
use crate::store::Store;

fn refused(reason: &'static str) -> Error {
    RecordError::InvalidProjectBody(reason).into()
}

fn unresolved(project: EntityId, reason: &'static str) -> Error {
    RecordError::ProjectAuthorityUnresolved { project, reason }.into()
}

pub(crate) fn validate_transition(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    bytes: &[u8],
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let next: ProjectRecord = decode(bytes).map_err(|_| refused("invalid project body"))?;
    let prior = stored(store, txn, id, kind)?;
    if let Some(old) = &prior {
        // Membership, goal and ask edits keep the authority and its proof.
        if old.authority() == next.authority() && old.write_proof == next.write_proof {
            return Ok(());
        }
        if next.write_proof.is_none() {
            return Err(refused("project authority change needs a signed proof"));
        }
    } else if REVISIONS
        .iter_from(store, txn, id.as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        // Decision 10: a deleted project's history still stands at its id.
        return Err(unresolved(id, "project id already holds signed history"));
    }
    let reader = ProjectReader::new(store, txn, posture)?.ok_or_else(invalid)?;
    let Some(proof) = &next.write_proof else {
        // An owner-door birth: main's stored-row rule.
        return match reader.judge_stored(id, &next)? {
            ProjectVerdict::Visible => Ok(()),
            ProjectVerdict::Pending(reason) | ProjectVerdict::Quarantined(reason) => {
                Err(refused(reason))
            }
        };
    };
    // A fresh proof is verified live here; only such a revision may be held
    // past the history budget, as a replicated one is.
    let fresh = prior
        .as_ref()
        .is_none_or(|old| old.write_proof.as_ref() != Some(proof));
    if fresh {
        verify_live(store, txn, id, &next, proof, posture)?;
    }
    if prior.is_none() && proof.anchor.is_some() {
        return Err(refused("a new project has no earlier authority"));
    }
    let chain = revisions_of_row(id, &next)?;
    let Some((candidate, _)) = chain.last() else {
        return Err(refused("invalid project write proof"));
    };
    let candidate = *candidate;
    let parent = chain.last().and_then(|(_, revision)| revision.parent());
    let current = reader.frontier(id)?;
    if current.as_ref().is_some_and(|current| {
        current.disposition == ProjectDisposition::Settled
            && current.witness.as_ref().map(|witness| witness.head) == Some(candidate)
    }) {
        // The row returns to the head the fold already serves.
        return Ok(());
    }
    // The trial folds the row and its chain with every project its
    // parents tie it to, as a read of the written state would.
    let trial = reader.with_write(id, next.clone(), chain)?;
    let held = trial.held_of(id)?;
    let cx = trial.door_cx(id, &held)?;
    if let Some(current) = &current {
        match &current.disposition {
            ProjectDisposition::Unsigned | ProjectDisposition::Settled => {
                if parent != current.witness.as_ref().map(|witness| witness.head) {
                    return Err(refused("project write must build on its current authority"));
                }
            }
            ProjectDisposition::ParentCycle { forks, .. } => {
                // A board fork the cycle leaves open settles only through
                // `resolve_project_fork`, whose envelope this transaction
                // holds; its anchor may be undefined in the served labels, so
                // the trial below, which installs `next` only where every
                // world does, judges it (ruling (a)). Any other write builds
                // on the served state.
                let board_fork = parent.filter(|parent| {
                    (forks.iter())
                        .any(|fork| fork.anchor == *parent && fork.rank == ProjectRank::Board)
                });
                match board_fork {
                    Some(anchor) => {
                        let named = held.resolutions_at(&anchor).any(|hash| match cx.row(hash) {
                            Some(ProjectRevision::Resolution { resolution, .. }) => {
                                resolution.next == candidate
                            }
                            _ => false,
                        });
                        if !named {
                            return Err(unresolved(id, "a board fork needs a board resolution"));
                        }
                    }
                    None => {
                        if parent != current.witness.as_ref().map(|witness| witness.head) {
                            return Err(refused(
                                "project write must build on its current authority",
                            ));
                        }
                    }
                }
            }
            ProjectDisposition::Fork {
                anchor,
                rank: ProjectRank::Leader,
                ..
            } => {
                if parent != Some(*anchor) {
                    return Err(unresolved(
                        id,
                        "a leader fork installs only a board sibling over its anchor",
                    ));
                }
            }
            ProjectDisposition::Fork {
                anchor,
                rank: ProjectRank::Board,
                ..
            } => {
                // Only `resolve_project_fork`, whose envelope this
                // transaction already holds, names the candidate: a valid
                // resolution of this fork's anchor (Sol #1434 r11 F1).
                let mut named = false;
                for hash in held.resolutions_at(anchor) {
                    if let Some(ProjectRevision::Resolution { resolution, .. }) = cx.row(hash)
                        && resolution.next == candidate
                        && cx.verdict(*hash)? == ProjectVerdict::Visible
                    {
                        named = true;
                        break;
                    }
                }
                if !named {
                    return Err(unresolved(id, "a board fork needs a board resolution"));
                }
            }
            ProjectDisposition::ConflictingBirths { .. }
            | ProjectDisposition::ConflictingSeals { .. } => {
                return Err(unresolved(
                    id,
                    "conflicting project roots need the owner's seal",
                ));
            }
            ProjectDisposition::Pending { .. } | ProjectDisposition::Unauthorized { .. } => {
                return Err(match current.disposition.verdict() {
                    ProjectVerdict::Pending(reason) | ProjectVerdict::Quarantined(reason) => {
                        refused(reason)
                    }
                    ProjectVerdict::Visible => invalid(),
                });
            }
            ProjectDisposition::OverBudget { state, .. } => {
                // Ruling F2 condition 1: past the budget a valid descendant
                // of the frozen head lands, as a narrowing meet. Any other
                // authenticated revision is held beside the frozen frontier,
                // as a replicated one is, and the owner is asked (OF-520):
                // the wire never refuses for count.
                let descends = parent.is_some_and(|parent| {
                    Some(parent) == state.frozen_head
                        || PROJECT_FROZEN_APPLIED
                            .contains(store, txn, &(id, parent))
                            .unwrap_or(false)
                });
                if !fresh && (!descends || cx.verdict(candidate)? != ProjectVerdict::Visible) {
                    return Err(RecordError::ProjectHistoryOverBudget {
                        project: id,
                        held: state.held,
                        max: state.max_revisions,
                    }
                    .into());
                }
                return Ok(());
            }
        }
    }
    let frontier = trial.frontier(id)?.ok_or_else(invalid)?;
    if fresh && matches!(frontier.disposition, ProjectDisposition::OverBudget { .. }) {
        // This write crosses the budget: it is held, and the batch-end
        // refresh freezes the project and opens the owner's question.
        return Ok(());
    }
    let installed = matches!(frontier.disposition, ProjectDisposition::Settled)
        && frontier.witness.as_ref().map(|witness| witness.head) == Some(candidate);
    let Some(effective) = frontier.effective.clone().filter(|_| installed) else {
        return Err(match cx.verdict(candidate)? {
            ProjectVerdict::Pending(reason) | ProjectVerdict::Quarantined(reason) => {
                refused(reason)
            }
            ProjectVerdict::Visible => match frontier.disposition.verdict() {
                ProjectVerdict::Pending(reason) | ProjectVerdict::Quarantined(reason) => {
                    refused(reason)
                }
                ProjectVerdict::Visible => {
                    refused("project write must build on its current authority")
                }
            },
        });
    };
    if prior.is_some() {
        refuse_stranded_children(&reader, id, kind, &effective)?;
    }
    Ok(())
}

/// A new signature is a live act: its slip must be live at this door's
/// clock as well as at its signed time, and it may not be dated ahead.
fn verify_live(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    next: &ProjectRecord,
    proof: &ProjectWriteProof,
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let slip = CapabilitySlip::from_token(&proof.slip_wire)
        .map_err(|_| refused("invalid project write slip"))?;
    let fold = authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mint = fold
        .slips
        .mints
        .get(&slip.claims.slip_id)
        .ok_or_else(|| refused("project write slip not minted"))?;
    let floor = crate::authority::AUTHORITY_FIRST_SEEN
        .get_lenient(
            store,
            txn,
            &crate::authority::authority_first_seen_clock_key(),
        )?
        .unwrap_or(0);
    let now =
        crate::authority::authority_observation_secs(store, floor, store.clock.now_recorded_at());
    if proof.signed_at > now {
        return Err(refused("project write proof is dated ahead"));
    }
    let challenge = next
        .authority()
        .write_challenge(id, proof.version, proof.signed_at, proof.anchor.as_deref())
        .map_err(|_| refused("invalid project write proof"))?;
    slip.verify_with_host_key(
        &mint.signer,
        &fold,
        now,
        &challenge,
        &proof.holder_signature,
    )
    .map_err(|_| refused("invalid project write proof"))?;
    Ok(())
}

/// Narrowing a live parent may not leave a signed subproject wider than it:
/// each child compares by its effective view against the candidate's.
fn refuse_stranded_children(
    reader: &ProjectReader<'_, '_>,
    id: EntityId,
    kind: u8,
    next: &ProjectEffective,
) -> Result<()> {
    let parent = id.to_hex();
    for row in reader
        .store()
        .type_index
        .prefix_iter(reader.txn(), &[kind])?
    {
        let (key, _) = row?;
        let child = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project type index"))?,
        )?;
        if child == id {
            continue;
        }
        if let Some(view) = reader.effective(child)?
            && view.bound_by_parents
            && view.parents.contains(&parent)
            && !view.fits_under(next)
        {
            return Err(refused("narrowing would strand a wider subproject"));
        }
    }
    Ok(())
}
