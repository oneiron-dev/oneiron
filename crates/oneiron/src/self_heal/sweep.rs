//! The Coach's scheduled tier-1 sweep (ARCH-0066 §4) and its proposed-only
//! repair bridge. The sweep runs the receipt tripwires over the last day of
//! Gate receipts, one tripwire window at a time, and the served-signal
//! detectors over the stored retrieval runs, call receipts and the whole
//! pending consent tray, as the signed scheduled detector instance. Each accepted firing a closed-form
//! repair answers gets one repair intent, every one of them in the same
//! pass (OF-418 L8), filed through the production healer host for the owner
//! to review and counted by the healer oversight receipts under its
//! diagnostic's id. Nothing here applies a repair.

use super::{
    DiagnosticEventClass, RepairActor, RepairOperation, RepairProposal,
    decode_diagnostic_event_body,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::{ClaimSource, EntityId, Result, Vault};

/// The sweep's working-set scope.
pub const TIER1_SWEEP_SCOPE: &str = "vault";
/// How far back one sweep reads: the nightly cadence.
const SWEEP_SPAN_SECS: u64 = 86_400;

/// What one sweep stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tier1Sweep {
    pub diagnostics: Vec<EntityId>,
    pub repairs: Vec<EntityId>,
}

impl Vault {
    /// Runs every receipt tripwire over the last day, window by window, then
    /// files every repair its firings ask for. Each window reads every Gate
    /// receipt it holds, never a newest top-N. A manifest that forces
    /// tripwires closed silences the sweep.
    pub fn run_tier1_sweep(&self, now: u64) -> Result<Tier1Sweep> {
        // Resolved once: every window, leg and signed run of the pass reads
        // this one policy (FIX 10096).
        let Some(policy) = self.resolved_tripwire_bounds()? else {
            return Ok(Tier1Sweep::default());
        };
        let window = policy.bounds.window_secs.max(1);
        let start = now.saturating_sub(SWEEP_SPAN_SECS);
        let mut diagnostics = Vec::new();
        let mut end = now;
        while end > start {
            let query = ReceiptQuery {
                kinds: [ReceiptKind::Gate].into(),
                start_at: Some(end.saturating_sub(window)),
                end_at: Some(end),
                limit: usize::MAX,
                ..ReceiptQuery::default()
            };
            diagnostics.extend(self.run_receipt_tripwires_under(
                TIER1_SWEEP_SCOPE,
                query.clone(),
                end,
                &policy,
            )?);
            diagnostics.extend(self.run_consent_denied_detector(TIER1_SWEEP_SCOPE, query)?);
            end = end.saturating_sub(window);
        }
        diagnostics.extend(self.run_served_signal_detectors_under(now, Some(&policy))?);
        diagnostics.sort();
        diagnostics.dedup();
        let repairs = self.propose_tier1_repairs(&diagnostics, now)?;
        Ok(Tier1Sweep {
            diagnostics,
            repairs,
        })
    }

    /// The Coach's deterministic healer: one repair intent per signed tier-1
    /// diagnostic whose class a closed-form repair answers. A retrieval miss
    /// (a point miss or the windowed regression) asks for a reindex of its
    /// scope; a Dreamer consolidation the Gate refused and a degenerate
    /// Dreamer run each ask for a retry of their run, only once their replay
    /// coordinate verifies as that ended Dreamer attempt
    /// (`ended_dreamer_attempt`), a refused one as failed. A refusal whose
    /// coordinate is its Gate receipt's id names no run, so it stays a
    /// diagnostic. A consent refusal is the owner's answer, not a
    /// malfunction, drift is the owner's policy to narrow, and a refused MCP
    /// call is the boundary working, so those stay diagnostics. A diagnostic
    /// already answered is skipped. Every eligible diagnostic is filed in
    /// this call, however many there are. Each intent filed is counted as
    /// proposed in the healer oversight receipts under its diagnostic's id,
    /// where the host's review door settles it.
    pub fn propose_tier1_repairs(
        &self,
        diagnostics: &[EntityId],
        now: u64,
    ) -> Result<Vec<EntityId>> {
        let coach = self.coach_authority()?;
        let healer = self.register_prod_healer(coach.clone());
        let actor = RepairActor {
            actor_class: coach.actor_class().gate_actor_class().to_owned(),
            actor_ref: coach.entity_ref(),
        };
        let run = format!("tier1:{}", now / SWEEP_SPAN_SECS);
        let mut filed = Vec::new();
        for id in diagnostics {
            if !self.is_signed_tripwire(id)? {
                continue;
            }
            let Some(raw) = self.get_raw(id)? else {
                continue;
            };
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if header.entity_type != crate::registry::ENTITY_TYPE_DIAGNOSTIC
                || raw.len() <= ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            let event = decode_diagnostic_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let (target_predicate, operation) = match event.event_class {
                DiagnosticEventClass::RetrievalMiss => (
                    "retrieval.index",
                    RepairOperation::Reindex {
                        scope_ref: "retrieval".into(),
                    },
                ),
                DiagnosticEventClass::ConsolidationError if event.actor_ref.is_none() => {
                    let run_ref = event.replay.run_ref.as_deref();
                    let ended = self.ended_dreamer_attempt(run_ref)?;
                    let Some((run_ref, AttemptState::Failed)) = ended else {
                        continue;
                    };
                    ("dreamer.consolidation", RepairOperation::Retry { run_ref })
                }
                DiagnosticEventClass::DreamerRunDegenerate => {
                    let run_ref = event.replay.run_ref.as_deref();
                    let Some((run_ref, _)) = self.ended_dreamer_attempt(run_ref)? else {
                        continue;
                    };
                    ("dreamer.run", RepairOperation::Retry { run_ref })
                }
                _ => continue,
            };
            let proposal_id = crate::codebase::entity_id_from_hash_material(
                b"oneiron:self-heal:tier1-repair:v1",
                &[id.as_bytes()],
            )?;
            if self.healer_proposal(&proposal_id)?.is_some() {
                continue;
            }
            // Counted under the diagnostic's id in the write that files it.
            healer.submit_counted(
                &run,
                "coach.tripwires",
                RepairProposal {
                    proposal_id,
                    diagnostic_refs: vec![*id],
                    actor: actor.clone(),
                    source: ClaimSource::Generated,
                    target_predicate: target_predicate.into(),
                    operation,
                    session_tag: String::new(),
                },
                &id.to_hex(),
                now,
            )?;
            filed.push(proposal_id);
        }
        Ok(filed)
    }

    /// The Dreamer attempt a diagnostic's replay coordinate names, as 32 hex,
    /// with the state it ended in: a stored queue row whose payload is a
    /// Dreamer job's and which is failed or completed. `None` for anything
    /// else, a Gate receipt's id among them: a receipt is never a run to
    /// retry.
    fn ended_dreamer_attempt(
        &self,
        run_ref: Option<&str>,
    ) -> Result<Option<(String, AttemptState)>> {
        let Some(Ok(id)) = run_ref.map(EntityId::from_hex) else {
            return Ok(None);
        };
        let attempt = AttemptId::from_bytes(id.as_bytes())?;
        let Some(record) = AttemptQueue::new(self).get(attempt)? else {
            return Ok(None);
        };
        if crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).is_err()
            || !matches!(record.state, AttemptState::Failed | AttemptState::Completed)
        {
            return Ok(None);
        }
        Ok(Some((id.to_hex(), record.state)))
    }
}
