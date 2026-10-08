//! Read-time own-proposal outcomes and connector changes for one session.
//!
//! Nothing here is pushed. The proposal door already writes the actor's
//! submission receipt in its own transaction, and settlement rewrites the
//! claim; a board read folds both. Hosts acknowledge only what they deliver.

use super::read_set::{
    ChangedDelivery, ChangedEvent, ConnectorChange, ConnectorMount, ProposalChange, ProposalReason,
    lifecycle_line,
};
use super::{ChangedLine, MAX_BOARD_ROW_BYTES, SessionReadSet};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::connector_key::ConnectorKeyStatus;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONNECTOR_KEY};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// Recent submissions a session's first fold reads. Their outcomes are
/// delivered too: a session never assumes it already knew one.
const BASELINE_SUBMISSIONS: u64 = 64;
/// New submissions one fold reads; later ones wait for the next fold.
const SUBMISSIONS_PER_FOLD: usize = 256;
/// The rider's header and overflow lines.
const RIDER_FRAME_BYTES: usize = 128;

/// A settled own proposal, before its answer is looked up.
struct Settled {
    id: String,
    claim: EntityId,
    to: &'static str,
}

impl SessionReadSet {
    /// Fold this session's own proposal outcomes and connector changes into
    /// `line`. One count cap covers them and the lifecycle rows, and the whole
    /// rider, install receipts included, fits the one board row a STREAM
    /// delta joins it into. Rejections come first. The fold is read-only:
    /// what it delivers moves only on `acknowledge`.
    pub fn fold_own_changes(
        &self,
        vault: &Vault,
        actor: Option<EntityId>,
        line: &mut ChangedLine,
        cap: usize,
    ) -> Result<()> {
        let txn = vault.store.env.read_txn()?;
        let mut delivery = ChangedDelivery {
            generation: self.delivery_generation(),
            ..ChangedDelivery::default()
        };
        let mut settled = Vec::new();
        let mut connectors = Vec::new();
        if let Some(actor) = actor {
            let (seen, watched) = self.own_proposals();
            let after = match seen {
                Some(seen) => seen,
                None => crate::gate::proposal_observation::submission_count_in_txn(
                    &vault.store,
                    &txn,
                    actor,
                )?
                .saturating_sub(BASELINE_SUBMISSIONS),
            };
            let fresh = crate::gate::proposal_observation::submissions_after_in_txn(
                &vault.store,
                &txn,
                actor,
                after,
                SUBMISSIONS_PER_FOLD,
            )?;
            delivery.proposal_count = Some(fresh.last().map_or(after, |(at, _)| *at));
            let mut read = BTreeSet::new();
            for (at, id) in fresh {
                if read.insert(id.clone()) {
                    delivery.opened.push((at, id));
                }
            }
            for id in read
                .iter()
                .chain(watched.iter().filter(|id| !read.contains(*id)))
            {
                if let Some((claim, to)) = proposal_state(vault, &txn, id)? {
                    settled.push(Settled {
                        id: id.clone(),
                        claim,
                        to,
                    });
                }
            }
            let mounts = connector_mounts(vault, &txn, actor)?;
            if let Some(prefix) = self.prefix_connectors() {
                connectors = connector_changes(prefix, &mounts);
            }
            delivery.mounts = Some(mounts);
        }
        // Rejections first, so no tail of other outcomes keeps a diagnostic
        // off the next wake. Answers are looked up only for what can ride.
        settled.sort_by_key(|proposal| proposal.to != "rejected");
        let mut held = settled.len().saturating_sub(cap);
        settled.truncate(cap);
        let mut events = settled
            .into_iter()
            .map(|proposal| {
                Ok(ChangedEvent::Proposal {
                    change: proposal_answer(vault, &txn, proposal.claim, proposal.to)?,
                    id: proposal.id,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        events.extend(connectors);

        let mut budget = MAX_BOARD_ROW_BYTES.saturating_sub(RIDER_FRAME_BYTES);
        let mut fits = |row: &str| {
            let size = row.len() + 1;
            let fits = size <= budget;
            if fits {
                budget -= size;
            }
            fits
        };
        let mut kept = Vec::new();
        for event in events {
            if kept.len() < cap && fits(&event.line()) {
                match &event {
                    ChangedEvent::Proposal { id, .. } => delivery.settled.push(id.clone()),
                    ChangedEvent::Connector { id, mount, .. } => {
                        delivery.connectors.push((id.clone(), mount.clone()));
                    }
                }
                kept.push(event);
            } else {
                held += 1;
            }
        }
        // Install receipts keep their own rows and cap, inside the same row.
        let mut installs = Vec::new();
        for receipt in std::mem::take(&mut line.install_rows) {
            let single = ChangedLine {
                install_rows: vec![receipt.clone()],
                ..ChangedLine::default()
            };
            if single.render().get(1).is_some_and(|row| fits(row)) {
                installs.push(receipt);
            } else {
                line.install_overflow += 1;
            }
        }
        line.install_rows = installs;
        let rows = cap.saturating_sub(kept.len());
        let mut fitted = Vec::new();
        for (id, state) in std::mem::take(&mut line.rows) {
            if fitted.len() < rows && fits(&lifecycle_line(&id, &state)) {
                fitted.push((id, state));
            } else {
                held += 1;
            }
        }
        line.rows = fitted;
        line.overflow += held;
        line.events = kept;
        line.delivery = delivery;
        Ok(())
    }
}

/// An own proposal's settled state, or `None` while it is still open.
fn proposal_state(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &str,
) -> Result<Option<(EntityId, &'static str)>> {
    // Only claim proposals carry submission receipts today.
    let Some(id) = proposal
        .strip_prefix("claim:")
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let body = vault
        .store
        .port_entity_record(txn, &id)?
        .filter(|record| record.entity_type == ENTITY_TYPE_CLAIM)
        .and_then(|record| crate::claim::decode_claim_body(&record.body, true).ok());
    let Some(body) = body else {
        return Ok(Some((id, "erased")));
    };
    Ok(Some((
        id,
        match (body.approval, body.lifecycle) {
            (ClaimApprovalStatus::Rejected, _) => "rejected",
            (_, ClaimLifecycleStatus::Retracted) => "retracted",
            (_, ClaimLifecycleStatus::Superseded) => "superseded",
            (ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto, _) => "approved",
            (ClaimApprovalStatus::Proposed, ClaimLifecycleStatus::Active) => return Ok(None),
        },
    )))
}

/// Who or what answered a settled proposal, by reference: the owner's
/// resolution when one decided it, the policy row it cites, or the receipt.
/// The answer is the newest receipt that records this settlement. A later
/// write under the same id that the gate refused or held leaves the body as
/// it was, so its receipt never answers for it.
fn proposal_answer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
    to: &'static str,
) -> Result<ProposalChange> {
    let decision = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())?
        .into_iter()
        .rev()
        .find(|decision| settles(&decision.outcome, to));
    let reason = decision.as_ref().map(|decision| {
        if let Some(resolution) = decision
            .grant_ref
            .as_deref()
            .filter(|grant| grant.starts_with("bundle:"))
        {
            return ProposalReason::PersonWord(resolution.to_owned());
        }
        decision
            .receipt_reasons
            .iter()
            .find_map(|reason| reason.strip_prefix("policy_row_"))
            .map_or_else(
                || ProposalReason::Receipt(format!("gate:{}", decision.decision_id.to_hex())),
                |row| ProposalReason::RuleRow(row.to_owned()),
            )
    });
    let diagnostic = (to == "rejected").then(|| match &decision {
        Some(decision) if !decision.reason_codes.is_empty() => decision.reason_codes.join(","),
        Some(_) => "rejected with no reason code".to_owned(),
        None => "rejected with no settling receipt".to_owned(),
    });
    Ok(ProposalChange {
        to: to.to_owned(),
        reason,
        diagnostic,
    })
}

/// Whether a receipt with `outcome` records a settlement to `to`. Approval
/// is an admitted write or an owner's acceptance; rejection is only ever an
/// owner's decline; a retraction or supersession is an admitted write.
fn settles(outcome: &str, to: &str) -> bool {
    match to {
        "approved" => matches!(
            outcome,
            "allow" | "approved" | crate::edit_distance::delta::OUTCOME_APPROVED_AMENDED
        ),
        "rejected" => outcome == "rejected",
        _ => outcome == "allow",
    }
}

/// The live connector mounts that govern `actor`, by connector. Each
/// connector resolves to its governing key exactly as effect admission does;
/// it is a mount only while that key is active.
fn connector_mounts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<BTreeMap<String, ConnectorMount>> {
    let mut connectors = BTreeSet::new();
    for row in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CONNECTOR_KEY, None)?
    {
        let Some(record) = vault.store.port_entity_record(txn, &row?)? else {
            continue;
        };
        let record = crate::connector_key::decode_connector_key_body(&record.body)?;
        if record.actor_entity_ref.is_none_or(|bound| bound == actor) {
            connectors.insert(record.connector);
        }
    }
    let mut mounts = BTreeMap::new();
    for connector in connectors {
        let Some((key, record)) = crate::connector_key::governing_connector_key(
            &vault.store,
            txn,
            &connector,
            Some(&actor),
        )?
        else {
            continue;
        };
        if record.status != ConnectorKeyStatus::Active {
            continue;
        }
        mounts.insert(
            connector,
            ConnectorMount {
                key: key.to_hex(),
                fingerprint: connector_terms(vault, txn, record)?,
            },
        );
    }
    Ok(mounts)
}

/// A fingerprint of the terms a call runs under: the retained manifest, any
/// drift that holds tools for confirmation, the live slate, protocol and
/// admission revisions, charter and budgets. Bookkeeping that cannot change
/// a call (status clocks, custody rotation, suggestions, staged candidates)
/// stays out.
fn connector_terms(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut record: crate::connector_key::ConnectorKeyRecord,
) -> Result<String> {
    let drift = record
        .pending_manifest
        .take()
        .map(|pending| serde_json::to_vec(&pending.drift))
        .transpose()
        .map_err(|_| crate::Error::InvalidConfig("connector drift encoding".into()))?;
    let slate = record
        .slate_ref
        .map(|slate| crate::connector_key::read_connector_slate_in_txn(vault, txn, slate))
        .transpose()?
        .flatten()
        .map(|slate| (slate.revision(), slate.manifest_hash()));
    record.status_changed_at = None;
    record.suspended_reason = None;
    record.key_generation = 0;
    record.secret_ref = None;
    record.suggested_budgets.clear();
    record.pending_charter = None;
    record.consent_required = false;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&crate::connector_key::encode_connector_key_body(&record)?);
    if let Some(drift) = drift {
        hasher.update(b"drift");
        hasher.update(&drift);
    }
    if let Some((revision, manifest)) = slate {
        hasher.update(b"slate");
        hasher.update(&revision.to_be_bytes());
        hasher.update(&manifest);
    }
    Ok(hasher.finalize().to_hex()[..16].to_owned())
}

/// Installs, changes and removals against the mounts the prefix carries.
fn connector_changes(
    prefix: &BTreeMap<String, ConnectorMount>,
    mounts: &BTreeMap<String, ConnectorMount>,
) -> Vec<ChangedEvent> {
    let mut events = Vec::new();
    for (connector, mount) in mounts {
        let change = match prefix.get(connector) {
            None => ConnectorChange::Installed,
            Some(held) if held != mount => ConnectorChange::Changed,
            Some(_) => continue,
        };
        events.push(ChangedEvent::Connector {
            id: connector.clone(),
            change,
            mount: Some(mount.clone()),
        });
    }
    for connector in prefix.keys().filter(|id| !mounts.contains_key(*id)) {
        events.push(ChangedEvent::Connector {
            id: connector.clone(),
            change: ConnectorChange::Removed,
            mount: None,
        });
    }
    events
}
