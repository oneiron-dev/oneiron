//! The lift sweep's state as a caller toward one destination may read it (FIX 8165): its
//! proposals and their counts, without those filed from a row a world withheld from there keeps.
//! `secret_lift_as_owner_toward` and `status_where` are its call surface.
//! The lift root defines `SecretLiftStatus` and the side tables read here.

use std::collections::BTreeSet;

use super::{
    LiftCauseCount, PROPOSALS, RECEIPTS, RUN, STATUS_PROPOSALS, SecretLiftHistoryProposal,
    SecretLiftProgress, SecretLiftRequest, SecretLiftStatus, SecretScanMode, accounting, hex,
    live_owner_in_txn, secret_lift_as_owner, secret_scan_mode_in_txn,
};
use heed::RoTxn;

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
/// never filed. A typed-body document carrier also names its source in its
/// row key. Other side rows and carriers stay unknown. Run, receipt and retry counts omit only
/// contributors whose actual source entity is known and withheld. Unknown
/// sources never withhold.
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
    status_where(vault, Some(destination))
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
fn withheld_sources(
    vault: &Vault,
    txn: &RoTxn<'_>,
    destination: &ReadDestination,
) -> Result<BTreeSet<EntityId>> {
    let mut records = BTreeSet::new();
    for row in PROPOSALS.iter_from(&vault.store, txn, &[])? {
        let (_, proposal) = row?;
        records.extend(proposal_source(&proposal));
    }
    if let Some(run) = RUN.get_lenient(&vault.store, txn, &())? {
        records.extend(accounting::sources(&vault.store, txn, run.run_id)?);
        for (family, key) in &run.retry {
            records.extend(accounting::source(*family, key));
        }
    }
    if let Some((_, receipt)) = RECEIPTS
        .iter_rev_from(&vault.store, txn, &[])?
        .next()
        .transpose()?
    {
        records.extend(accounting::sources(&vault.store, txn, receipt.run_id)?);
    }
    let flagged = crate::settings::device_local_worlds_for(vault, txn, destination)?;
    let mut withheld = BTreeSet::new();
    for record in records {
        if crate::settings::device_local_keeps_among(&vault.store, txn, &flagged, &record)? {
            withheld.insert(record);
        }
    }
    Ok(withheld)
}

/// The lift sweep's state as `destination` admits: the run in
/// progress, the last receipt, the proposals still open and the counts of
/// open and closed proposals, each counting only the kept ones.
pub(super) fn status_where(
    vault: &Vault,
    destination: Option<&ReadDestination>,
) -> Result<SecretLiftStatus> {
    // Every result body is pinned before the snapshot opens (FIX 7201).
    let _bodies = vault.pin_all_result_bodies();
    let txn = vault.store.env.read_txn()?;
    let mode = secret_scan_mode_in_txn(&vault.store, &txn)?;
    // Collect and project the same content snapshot, so a newly committed
    // row cannot enter the output without its source being judged.
    let withheld = destination
        .map(|destination| withheld_sources(vault, &txn, destination))
        .transpose()?
        .unwrap_or_default();
    let keep_source = |source| !withheld.contains(&source);
    let running = RUN
        .get_lenient(&vault.store, &txn, &())?
        .map(|run| -> Result<SecretLiftProgress> {
            Ok(SecretLiftProgress {
                run_id: run.run_id.to_hex(),
                trigger: run.trigger,
                requested_at: run.requested_at,
                family: run.family,
                retrying: u64::try_from(
                    run.retry
                        .iter()
                        .filter(|(family, key)| {
                            accounting::source(*family, key).is_none_or(&keep_source)
                        })
                        .count(),
                )
                .unwrap_or(u64::MAX),
                counts: accounting::counts(&vault.store, &txn, run.run_id, false, &keep_source)?,
            })
        })
        .transpose()?;
    let last = RECEIPTS
        .iter_rev_from(&vault.store, &txn, &[])?
        .next()
        .transpose()?
        .map(|(_, receipt)| receipt.project(vault, &txn, &keep_source))
        .transpose()?;
    let mut open_proposals = 0_u64;
    let mut closed_proposals = 0_u64;
    let mut open_by_cause: Vec<LiftCauseCount> = Vec::new();
    let mut proposals = Vec::new();
    for row in PROPOSALS.iter_from(&vault.store, &txn, &[])? {
        let (key, mut proposal) = row?;
        if proposal_source(&proposal).is_some_and(|source| !keep_source(source)) {
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
