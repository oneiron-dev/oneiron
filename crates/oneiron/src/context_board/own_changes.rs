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
use std::collections::BTreeMap;

/// Recent submissions a session's first fold scans for proposals still open.
const BASELINE_SUBMISSIONS: u64 = 64;
/// New submissions one fold reads; later ones wait for the next fold.
const SUBMISSIONS_PER_FOLD: usize = 256;
/// The rider's header and overflow lines.
const RIDER_FRAME_BYTES: usize = 64;

impl SessionReadSet {
    /// Fold this session's own proposal outcomes and connector changes into
    /// `line`. They render ahead of its lifecycle rows and share `cap` with
    /// them, and every row of the rider stays inside the board row-byte limit.
    /// The fold is read-only: what it delivers moves only on `acknowledge`.
    pub fn fold_own_changes(
        &self,
        vault: &Vault,
        actor: Option<EntityId>,
        line: &mut ChangedLine,
        cap: usize,
    ) -> Result<()> {
        let txn = vault.store.env.read_txn()?;
        let mut events = Vec::new();
        let mut delivery = ChangedDelivery::default();
        if let Some(actor) = actor {
            let (seen, watched) = self.own_proposals();
            let (count, fresh) = match seen {
                // A session's first fold sets its baseline and only picks up
                // the recent proposals still open, never old outcomes.
                None => {
                    let count = crate::gate::proposal_observation::submission_count_in_txn(
                        &vault.store,
                        &txn,
                        actor,
                    )?;
                    crate::gate::proposal_observation::submissions_after_in_txn(
                        &vault.store,
                        &txn,
                        actor,
                        count.saturating_sub(BASELINE_SUBMISSIONS),
                        BASELINE_SUBMISSIONS as usize,
                    )?
                }
                Some(seen) => crate::gate::proposal_observation::submissions_after_in_txn(
                    &vault.store,
                    &txn,
                    actor,
                    seen,
                    SUBMISSIONS_PER_FOLD,
                )?,
            };
            delivery.proposal_count = Some(match seen {
                None => count,
                Some(seen) => count.min(seen.saturating_add(SUBMISSIONS_PER_FOLD as u64)),
            });
            for id in &fresh {
                match proposal_outcome(vault, &txn, id)? {
                    Some(change) if seen.is_some() => {
                        delivery.opened.push(id.clone());
                        events.push(ChangedEvent::Proposal {
                            id: id.clone(),
                            change,
                        });
                    }
                    Some(_) => {}
                    None => delivery.opened.push(id.clone()),
                }
            }
            let fresh_ids: std::collections::BTreeSet<&String> = fresh.iter().collect();
            for id in watched.iter().filter(|id| !fresh_ids.contains(id)) {
                if let Some(change) = proposal_outcome(vault, &txn, id)? {
                    events.push(ChangedEvent::Proposal {
                        id: id.clone(),
                        change,
                    });
                }
            }
            let mounts = connector_mounts(vault, &txn, actor)?;
            if let Some(prefix) = self.prefix_connectors() {
                events.extend(connector_changes(prefix, &mounts));
            }
            delivery.mounts = Some(mounts);
        }
        events.sort_by_key(ChangedEvent::rank);

        // One count cap for the whole rider, and one row-byte budget: a STREAM
        // delta joins every rendered line into a single row. Install receipts
        // keep their own rows; the header and overflow lines are reserved.
        let installs = ChangedLine {
            install_rows: line.install_rows.clone(),
            install_overflow: line.install_overflow,
            ..ChangedLine::default()
        };
        let reserved = RIDER_FRAME_BYTES
            + installs
                .render()
                .iter()
                .map(|row| row.len() + 1)
                .sum::<usize>();
        let mut budget = MAX_BOARD_ROW_BYTES.saturating_sub(reserved);
        let mut held = 0;
        let mut kept = Vec::new();
        for event in events {
            let size = event.line().len() + 1;
            if kept.len() < cap && size <= budget {
                budget -= size;
                kept.push(event);
            } else {
                held += 1;
            }
        }
        for event in &kept {
            if let ChangedEvent::Proposal { id, .. } = event {
                delivery.settled.push(id.clone());
            }
        }
        let rows = cap.saturating_sub(kept.len());
        let mut fitted = Vec::new();
        for (id, state) in std::mem::take(&mut line.rows) {
            let size = lifecycle_line(&id, &state).len() + 1;
            if fitted.len() < rows && size <= budget {
                budget -= size;
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

/// The settled outcome of one own proposal, or `None` while it is still open.
fn proposal_outcome(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &str,
) -> Result<Option<ProposalChange>> {
    // Only claim proposals carry submission receipts today.
    let Some(id) = proposal
        .strip_prefix("claim:")
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let erased = || ProposalChange {
        to: "erased".to_owned(),
        reason: None,
        diagnostic: None,
    };
    let Some(record) = vault.store.port_entity_record(txn, &id)? else {
        return Ok(Some(erased()));
    };
    if record.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(Some(erased()));
    }
    let Ok(body) = crate::claim::decode_claim_body(&record.body, true) else {
        return Ok(Some(erased()));
    };
    let to = match (body.approval, body.lifecycle) {
        (ClaimApprovalStatus::Rejected, _) => "rejected",
        (_, ClaimLifecycleStatus::Retracted) => "retracted",
        (_, ClaimLifecycleStatus::Superseded) => "superseded",
        (ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto, _) => "approved",
        (ClaimApprovalStatus::Proposed, ClaimLifecycleStatus::Active) => return Ok(None),
    };
    // The newest claim-bound receipt answered it: the policy row it cites,
    // or the receipt itself, which names who decided.
    let decision = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, id.as_bytes())?
        .pop();
    let reason = decision.as_ref().map(|decision| {
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
        None => "rejected with no gate receipt".to_owned(),
    });
    Ok(Some(ProposalChange {
        to: to.to_owned(),
        reason,
        diagnostic,
    }))
}

/// The live connector mounts that govern `actor`, by connector: an exact
/// actor key wins over an actor-agnostic one, as in effect admission.
fn connector_mounts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<BTreeMap<String, ConnectorMount>> {
    let mut mounts: BTreeMap<String, (bool, ConnectorMount)> = BTreeMap::new();
    for row in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CONNECTOR_KEY, None)?
    {
        let key = row?;
        let Some(record) = vault.store.port_entity_record(txn, &key)? else {
            continue;
        };
        let mut record = crate::connector_key::decode_connector_key_body(&record.body)?;
        let exact = match record.actor_entity_ref {
            Some(bound) if bound == actor => true,
            Some(_) => continue,
            None => false,
        };
        if record.status != ConnectorKeyStatus::Active
            || mounts
                .get(&record.connector)
                .is_some_and(|(held, _)| *held && !exact)
        {
            continue;
        }
        // The terms a call runs under, without bookkeeping that moves while
        // they hold: status clocks, rotation, suggestions and pending stages.
        record.status_changed_at = None;
        record.suspended_reason = None;
        record.key_generation = 0;
        record.suggested_budgets.clear();
        record.pending_charter = None;
        record.pending_manifest = None;
        record.consent_required = false;
        let terms = crate::connector_key::encode_connector_key_body(&record)?;
        let fingerprint = blake3::hash(&terms).to_hex()[..16].to_owned();
        mounts.insert(
            record.connector.clone(),
            (
                exact,
                ConnectorMount {
                    key: key.to_hex(),
                    fingerprint,
                },
            ),
        );
    }
    Ok(mounts
        .into_iter()
        .map(|(connector, (_, mount))| (connector, mount))
        .collect())
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
