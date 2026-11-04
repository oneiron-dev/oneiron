//! Erasure scrub of fan-out recipients (FIX 4699, Engine ruling 13:2x).
//! Entry: `erase_launch_recipient_in_txn`.
//! Stored launch vocabulary stays in `fanout_launch`.

use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;
use serde::{Deserialize, Serialize};

/// Truthful erasure-scrub marker: what recipient erasures scrubbed from one
/// launch, and the FIRST pre-scrub digest for audit. `None` on the row means
/// never scrubbed; old rows read as none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::task_verb) struct FanoutRecipientScrub {
    /// Vault seconds of the latest scrub.
    pub scrubbed_at: u64,
    /// FIRST pre-scrub digest (audit only, never a ruling binding).
    pub prior_digest: [u8; 32],
    /// Wave tasks whose assignee went default (`None`).
    pub wave_assignees: u32,
    /// `Ask.holders` entries removed.
    pub ask_holders: u32,
    /// `AdmittedAsk.recipients` entries removed.
    pub ask_recipients: u32,
    /// Consults merged into the `"erased"` plan bucket.
    pub erased_peer_count: u32,
    /// Unanswered width-check row retired by the scrub, kept as history;
    /// `None` when no check retired (held, answered, or none).
    pub retired_check_row: Option<String>,
}

/// Drops `actor`'s `per_peer` entries (order preserved) and rewrites the
/// `unpriced_parts` patterns naming it. `consult_count` stays frozen as
/// stated: `per_peer` mixes consult and ordinary TASK deliveries with no
/// per-entry provenance (REVIEW-4453 P1-2), so subtracting would zero a
/// surviving peer's consults. `true` when anything named it.
pub(in crate::task_verb) fn scrub_statement_for(
    statement: &mut FanoutStatement,
    actor: &EntityId,
) -> bool {
    let mut dropped = false;
    statement.per_peer.retain(|entry| {
        if entry.peer == *actor {
            dropped = true;
            false
        } else {
            true
        }
    });
    let hex = actor.to_hex();
    let assignee = format!("assignee={hex}");
    let consult = format!("consult peer={hex}");
    let agent = format!("agent={hex}");
    let mut renamed = false;
    for part in &mut statement.unpriced_parts {
        if part.contains(&assignee) {
            *part = part.replace(&assignee, &format!("assignee={ERASED_CALL_IDENTITY}"));
            renamed = true;
        }
        if part.contains(&consult) {
            *part = part.replace(&consult, &format!("consult peer={ERASED_CALL_IDENTITY}"));
            renamed = true;
        }
        if part.contains(&agent) {
            *part = part.replace(&agent, &format!("agent={ERASED_CALL_IDENTITY}"));
            renamed = true;
        }
    }
    dropped || renamed
}

/// Rewrites an erased actor's refs in pause/check pathology evidence
/// (REVIEW-4453 round 2): a rate-spike `peer_ref` or a consult-cycle
/// `peer_path` entry naming it becomes the erased identity, so receipts
/// and meter rows stop emitting the exact id after erasure.
pub(in crate::task_verb) fn scrub_pathology_for(
    pathology: Option<&mut crate::outbound_chokepoint::FanoutPathology>,
    hex: &str,
) -> bool {
    use crate::outbound_chokepoint::FanoutPathology;
    let Some(pathology) = pathology else {
        return false;
    };
    match pathology {
        FanoutPathology::PerPeerRateSpike { peer_ref, .. } => {
            if peer_ref == hex {
                *peer_ref = ERASED_CALL_IDENTITY.to_owned();
                true
            } else {
                false
            }
        }
        FanoutPathology::ConsultCycle { peer_path } => {
            let mut renamed = false;
            for peer in peer_path.iter_mut() {
                if peer == hex {
                    *peer = ERASED_CALL_IDENTITY.to_owned();
                    renamed = true;
                }
            }
            renamed
        }
    }
}

/// Rebuilds the scrubbed plan from the scrubbed payload plus the total
/// `"erased"` bucket count: the single implementation the scrub transaction
/// and the ack/resume re-proof share, so a mismatch detects corruption, not
/// drift. `stored` supplies the actor, brief and mode the scrub never
/// touches; the payload supplies the ref hash and the fresh edges, with
/// `total_erased` moved (wave, out of the default bucket) or added (ask,
/// restoring the judged total) as one `"erased"` edge.
fn scrubbed_plan_for(
    payload: &LaunchPayload,
    launch_ref: EntityId,
    stored: &FanoutPlan,
    total_erased: u32,
) -> Result<FanoutPlan> {
    // Dummy actor: overwritten with `stored` below; the payload hash and the
    // fresh edges never depend on it.
    let mut plan = payload.plan(launch_ref, launch_ref, stored.mode)?;
    plan.actor_ref = stored.actor_ref.clone();
    plan.brief_ref = stored.brief_ref.clone();
    if total_erased == 0 {
        return Ok(plan);
    }
    let root = match payload {
        LaunchPayload::Wave { cut, .. } => cut.epic_task_ref.to_hex(),
        LaunchPayload::Ask { group_ref, .. } | LaunchPayload::AdmittedAsk { group_ref, .. } => {
            group_ref.to_hex()
        }
    };
    if matches!(payload, LaunchPayload::Wave { .. }) {
        // A scrubbed assignee reads as the default realization in the fresh
        // edges; move the erased share back into `"erased"`.
        if let Some(slot) = plan
            .edges
            .iter_mut()
            .find(|edge| edge.to_peer_ref == WAVE_DEFAULT_REALIZATION)
        {
            slot.count = slot.count.saturating_sub(total_erased);
        }
        plan.edges.retain(|edge| edge.count != 0);
        plan.edges.push(FanoutPlanEdge {
            from_peer_ref: root,
            to_peer_ref: ERASED_CALL_IDENTITY.to_owned(),
            count: total_erased,
        });
    } else {
        plan.edges.push(FanoutPlanEdge {
            from_peer_ref: root,
            to_peer_ref: ERASED_CALL_IDENTITY.to_owned(),
            count: total_erased,
        });
    }
    Ok(plan)
}

impl StoredLaunch {
    /// Scrubs `actor` as a recipient: payload holders/recipients/assignees,
    /// plan edges into one `"erased"` bucket, rebuilt estimate, statement,
    /// pause/check rows and the marker. `true` when the row named the
    /// recipient and was rewritten; held rows stay listed under the new
    /// digest, dispatched+unanswered checks retire.
    pub(in crate::task_verb) fn scrub_recipient_in(
        &mut self,
        actor: &EntityId,
        now: u64,
    ) -> Result<bool> {
        let (wave_cut, ask_cut, admitted_cut) = match &mut self.payload {
            LaunchPayload::Wave { cut, .. } => {
                let mut cut_count = 0u32;
                for task in &mut cut.tasks {
                    if task.assignee_ref == Some(*actor) {
                        task.assignee_ref = None;
                        cut_count = cut_count.saturating_add(1);
                    }
                }
                (cut_count, 0, 0)
            }
            LaunchPayload::Ask { holders, .. } => {
                let before = holders.len();
                holders.retain(|holder| holder != actor);
                let cut = u32::try_from(before - holders.len()).unwrap_or(u32::MAX);
                (0, cut, 0)
            }
            LaunchPayload::AdmittedAsk { recipients, .. } => {
                let before = recipients.len();
                recipients.retain(|recipient| recipient != actor);
                let cut = u32::try_from(before - recipients.len()).unwrap_or(u32::MAX);
                (0, 0, cut)
            }
        };
        if wave_cut == 0 && ask_cut == 0 && admitted_cut == 0 {
            return Ok(false);
        }
        let hex = actor.to_hex();
        let mut newly_erased: u32 = 0;
        for edge in &self.plan.edges {
            if edge.to_peer_ref == hex {
                newly_erased = newly_erased.saturating_add(edge.count);
            }
        }
        let prior = self.recipient_scrub.clone();
        let total_erased = prior.as_ref().map_or(newly_erased, |marker| {
            marker.erased_peer_count.saturating_add(newly_erased)
        });
        let old_digest = self.estimate.plan_digest;
        let scrubbed = scrubbed_plan_for(&self.payload, self.launch_ref, &self.plan, total_erased)?;
        let estimate = fanout_estimate(&scrubbed)?;
        self.plan = scrubbed;
        self.estimate = estimate.clone();
        scrub_statement_for(&mut self.statement, actor);
        if let Some(row) = self.pause.as_mut() {
            row.plan_digest = estimate.plan_digest;
            row.estimate = estimate.clone();
            row.statement = Some(self.statement.clone());
            scrub_pathology_for(row.pathology.as_mut(), &hex);
        }
        if let Some(row) = self.check_row.as_mut() {
            row.plan_digest = estimate.plan_digest;
            row.estimate = estimate.clone();
            row.statement = Some(self.statement.clone());
            scrub_pathology_for(row.pathology.as_mut(), &hex);
        }
        let retired = prior
            .as_ref()
            .and_then(|marker| marker.retired_check_row.clone())
            .or_else(|| {
                (self.dispatched_at.is_some()
                    && self.check_row.is_some()
                    && self.choice_receipt_ref.is_none())
                .then(|| self.check_row.as_ref().map(|row| row.row_ref.clone()))
                .flatten()
            });
        self.recipient_scrub = Some(FanoutRecipientScrub {
            scrubbed_at: now,
            prior_digest: prior
                .as_ref()
                .map_or(old_digest, |marker| marker.prior_digest),
            wave_assignees: prior.as_ref().map_or(wave_cut, |marker| {
                marker.wave_assignees.saturating_add(wave_cut)
            }),
            ask_holders: prior
                .as_ref()
                .map_or(ask_cut, |marker| marker.ask_holders.saturating_add(ask_cut)),
            ask_recipients: prior.as_ref().map_or(admitted_cut, |marker| {
                marker.ask_recipients.saturating_add(admitted_cut)
            }),
            erased_peer_count: total_erased,
            retired_check_row: retired,
        });
        Ok(true)
    }
}

/// Re-proves a scrubbed launch against its scrubbed state: the scrub
/// transaction's rebuild, compared to the stored row. Returns the stored
/// scrubbed plan for the existing width-check/resume doors.
pub(in crate::task_verb) fn verify_scrubbed_launch(launch: &StoredLaunch) -> Result<FanoutPlan> {
    let marker = launch
        .recipient_scrub
        .as_ref()
        .ok_or(Error::CorruptedIndex("fan-out scrub marker missing"))?;
    let rebuild = scrubbed_plan_for(
        &launch.payload,
        launch.launch_ref,
        &launch.plan,
        marker.erased_peer_count,
    )?;
    if rebuild != launch.plan {
        return Err(Error::CorruptedIndex("fan-out scrubbed plan mismatch"));
    }
    if fanout_plan_digest(&rebuild)? != launch.estimate.plan_digest {
        return Err(Error::CorruptedIndex("fan-out scrubbed digest mismatch"));
    }
    let payload_hash = blake3::hash(&encode(&launch.payload)?).to_hex().to_string();
    let expected_ref = format!("{}:{payload_hash}", launch.launch_ref.to_hex());
    if launch.plan.plan_ref != expected_ref {
        return Err(Error::CorruptedIndex("fan-out scrubbed plan ref mismatch"));
    }
    Ok(launch.plan.clone())
}

/// Erases `actor` as a recipient from every surviving fan-out launch: the
/// recipient pass of `erase_launch_actor_in_txn`, over rows the launcher
/// pass kept. One scan; each touched row is scrubbed and rewritten in the
/// same transaction.
pub(in crate::task_verb) fn erase_launch_recipient_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let now = vault.now_recorded_at();
    let mut touched = Vec::new();
    for (key, mut launch) in FANOUT_LAUNCHES.scan(&vault.store, wtxn)? {
        if launch.scrub_recipient_in(actor, now)? {
            touched.push((key, launch));
        }
    }
    for (key, launch) in touched {
        FANOUT_LAUNCHES.put(&vault.store, wtxn, &key, &launch)?;
    }
    Ok(())
}
