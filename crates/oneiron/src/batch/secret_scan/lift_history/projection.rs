//! The lift sweep's state as a caller toward one destination may read it (FIX 8165): its
//! proposals and their counts, without those filed from a row a world withheld from there keeps.
//! `secret_lift_as_owner_toward` and `status_where` are its call surface.
//! The lift root defines `SecretLiftStatus` and the side tables read here.

use std::collections::BTreeSet;

use super::{
    LiftCauseCount, PROPOSALS, RECEIPTS, RUN, STATUS_PROPOSALS, SecretLiftHistoryProposal,
    SecretLiftProgress, SecretLiftRequest, SecretLiftStatus, SecretScanMode, hex,
    live_owner_in_txn, secret_lift_as_owner, secret_scan_mode_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::settings::ReadDestination;

/// [`secret_lift_as_owner`] for a caller whose rows go to `destination`
/// (FIX 8165). The close and the start the input asks for run as there, and
/// stay committed. On this device the state is the same. Off it, a proposal
/// filed from a record a world withheld from that destination keeps is left
/// out of the proposals shown and of every proposal count, as if it were
/// never filed. A typed-body document carrier names that same source entity
/// in its row key and is narrowed too. Other side rows and carriers remain
/// unknown and stay, as do the run's and the last receipt's family totals,
/// whose contributors the sweep does not keep: unknown never withholds.
///
/// # Errors
/// As [`secret_lift_as_owner`].
pub fn secret_lift_as_owner_toward(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SecretLiftRequest,
    destination: &ReadDestination,
) -> Result<SecretLiftStatus> {
    if !destination.is_off_device() {
        return secret_lift_as_owner(vault, owner, input);
    }
    if let Some(close) = &input.close {
        vault.close_secret_lift_proposal(owner, &close.proposal, close.reason)?;
    }
    if input.start {
        vault.start_secret_lift(owner, vault.now_recorded_at())?;
    } else {
        let txn = vault.store.env.read_txn()?;
        live_owner_in_txn(vault, owner, &txn)?;
    }
    let withheld = withheld_sources(vault, destination)?;
    status_where(vault, &|proposal| {
        proposal_source(proposal).is_none_or(|record| !withheld.contains(&record))
    })
}

/// The source entity a path actually names. A typed-body document's row key
/// is that document's entity id, including earlier-frontier proposals filed
/// by `frontier::keys_of`. Other carrier and side-row keys remain unknown.
fn proposal_source(proposal: &SecretLiftHistoryProposal) -> Option<EntityId> {
    let path = &proposal.proposal.path;
    if let Some(hex) = path.strip_prefix("record:") {
        return EntityId::from_hex(hex).ok();
    }
    let (table, hex) = path.strip_prefix("carrier:")?.split_once(':')?;
    if table != crate::side_table::TYPED_BODY_DOC.name {
        return None;
    }
    EntityId::from_hex(hex).ok()
}

/// The records some proposal was filed from that a world withheld from
/// `destination` keeps now, judged in one read.
fn withheld_sources(vault: &Vault, destination: &ReadDestination) -> Result<BTreeSet<EntityId>> {
    let records: BTreeSet<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        let mut records = BTreeSet::new();
        for row in PROPOSALS.iter_from(&vault.store, &txn, &[])? {
            let (_, proposal) = row?;
            records.extend(proposal_source(&proposal));
        }
        records
    };
    let readable: BTreeSet<EntityId> = vault
        .off_device_readable_for(records.iter().copied().collect(), destination)?
        .into_iter()
        .collect();
    Ok(records.difference(&readable).copied().collect())
}

/// The lift sweep's state, of the proposals `keep` admits: the run in
/// progress, the last receipt, the proposals still open and the counts of
/// open and closed proposals, each counting only the kept ones.
pub(super) fn status_where(
    vault: &Vault,
    keep: &dyn Fn(&SecretLiftHistoryProposal) -> bool,
) -> Result<SecretLiftStatus> {
    // Every result body is pinned before the snapshot opens (FIX 7201).
    let _bodies = vault.pin_all_result_bodies();
    let txn = vault.store.env.read_txn()?;
    let mode = secret_scan_mode_in_txn(&vault.store, &txn)?;
    let running = RUN
        .get_lenient(&vault.store, &txn, &())?
        .map(|run| SecretLiftProgress {
            run_id: run.run_id.to_hex(),
            trigger: run.trigger,
            requested_at: run.requested_at,
            family: run.family,
            retrying: u64::try_from(run.retry.len()).unwrap_or(u64::MAX),
            counts: run.counts,
        });
    let last = RECEIPTS
        .iter_rev_from(&vault.store, &txn, &[])?
        .next()
        .transpose()?
        .map(|(_, receipt)| receipt);
    let mut open_proposals = 0_u64;
    let mut closed_proposals = 0_u64;
    let mut open_by_cause: Vec<LiftCauseCount> = Vec::new();
    let mut proposals = Vec::new();
    for row in PROPOSALS.iter_from(&vault.store, &txn, &[])? {
        let (key, mut proposal) = row?;
        if !keep(&proposal) {
            continue;
        }
        if !proposal.is_open() {
            closed_proposals += 1;
            continue;
        }
        open_proposals += 1;
        match open_by_cause
            .iter_mut()
            .find(|count| count.cause == proposal.cause)
        {
            Some(count) => count.open += 1,
            None => open_by_cause.push(LiftCauseCount {
                cause: proposal.cause,
                open: 1,
            }),
        }
        if proposals.len() < STATUS_PROPOSALS {
            proposal.id = hex(&key);
            proposals.push(proposal);
        }
    }
    Ok(SecretLiftStatus {
        paused: mode == SecretScanMode::Off && running.is_some(),
        mode,
        running,
        last,
        open_proposals,
        open_by_cause,
        closed_proposals,
        proposals,
    })
}
