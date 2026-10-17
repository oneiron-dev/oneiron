//! The Coach's scheduled tier-1 sweep (ARCH-0066 §4) and its proposed-only
//! repair bridge. The sweep runs the receipt tripwires over the last day of
//! Gate receipts, one tripwire window at a time, and the served-signal
//! detectors over the stored retrieval runs and call receipts, as the
//! signed scheduled detector instance. Each accepted firing a closed-form
//! repair answers gets one bounded repair intent, filed through the
//! production healer host for the owner to review and counted by the
//! healer oversight receipts under its diagnostic's id. Nothing here
//! applies a repair.

use super::{
    DiagnosticEventClass, MAX_EVENTS_PER_RUN, RepairActor, RepairOperation, RepairProposal,
    decode_diagnostic_event_body,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::{ClaimSource, EntityId, Result, Vault};

/// The sweep's working-set scope.
pub const TIER1_SWEEP_SCOPE: &str = "vault";
/// How far back one sweep reads: the nightly cadence.
const SWEEP_SPAN_SECS: u64 = 86_400;
/// At most this many repair intents per call, so a storm of firings cannot
/// flood the owner's review tray.
const MAX_REPAIRS_PER_SWEEP: usize = 64;

/// What one sweep stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tier1Sweep {
    pub diagnostics: Vec<EntityId>,
    pub repairs: Vec<EntityId>,
}

impl Vault {
    /// Runs every receipt tripwire over the last day, window by window, then
    /// files the bounded repairs. A manifest that forces tripwires closed
    /// silences the sweep.
    pub fn run_tier1_sweep(&self, now: u64) -> Result<Tier1Sweep> {
        let Some(bounds) = self.tripwire_bounds()? else {
            return Ok(Tier1Sweep::default());
        };
        let window = bounds.window_secs.max(1);
        let start = now.saturating_sub(SWEEP_SPAN_SECS);
        let mut diagnostics = Vec::new();
        let mut end = now;
        while end > start {
            let query = ReceiptQuery {
                kinds: [ReceiptKind::Gate].into(),
                start_at: Some(end.saturating_sub(window)),
                end_at: Some(end),
                limit: MAX_EVENTS_PER_RUN,
                ..ReceiptQuery::default()
            };
            diagnostics.extend(self.run_receipt_tripwires(
                TIER1_SWEEP_SCOPE,
                query.clone(),
                end,
            )?);
            diagnostics.extend(self.run_consent_denied_detector(TIER1_SWEEP_SCOPE, query)?);
            end = end.saturating_sub(window);
        }
        diagnostics.extend(self.run_served_signal_detectors(now)?);
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
    /// Dreamer run each ask for a retry of their run. A consent refusal is
    /// the owner's answer, not a malfunction, drift is the owner's policy to
    /// narrow, and a refused MCP call is the boundary working, so those stay
    /// diagnostics. A diagnostic already answered is skipped. Each intent
    /// filed is counted as proposed in the healer oversight receipts under
    /// its diagnostic's id, where the host's review door settles it.
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
            if filed.len() == MAX_REPAIRS_PER_SWEEP {
                tracing::warn!(
                    left = diagnostics.len(),
                    "tier-1 repair intents capped for this sweep"
                );
                break;
            }
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
                    let Some(run_ref) = event.replay.run_ref.clone() else {
                        continue;
                    };
                    ("dreamer.consolidation", RepairOperation::Retry { run_ref })
                }
                DiagnosticEventClass::DreamerRunDegenerate => {
                    let Some(run_ref) = event.replay.run_ref.clone() else {
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
            healer.submit(
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
            )?;
            self.with_write_txn_grouped(|txn| {
                crate::failure_ladder::oversight::proposed_in_txn(self, txn, &id.to_hex(), now)
            })?;
            filed.push(proposal_id);
        }
        Ok(filed)
    }
}
