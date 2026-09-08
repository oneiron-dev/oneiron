//! Decision core: ceilings, source-trust, and gate evaluation.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::write_envelope::SourceLineage;

use super::manifest_types::{CommOptOutPosture, PolicyManifestResolution};
use crate::gate::ceiling::{
    DelegationGrantRecord, PolicyApprovalCeiling, PolicyCriticality, check_source_trust,
};
use crate::gate::decision::{GateDecision, GateReasonCode, external_effect_receipt_reasons};
use crate::gate::grants::external_effect_grant_matches;
use crate::gate::input::{GateContentKind, GateEvaluatorInput, consent_ladder_reasons};

#[cfg_attr(not(test), allow(dead_code))]
impl PolicyManifestResolution {
    #[must_use]
    pub(crate) fn actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> PolicyApprovalCeiling {
        if self.is_fail_closed() {
            return PolicyApprovalCeiling::Proposed;
        }

        let mut ceiling: Option<PolicyApprovalCeiling> = None;
        for row in &self.actor_ceilings {
            if row.actor_class != actor_class {
                continue;
            }
            match (&row.actor_ref, actor_ref) {
                (None, _) => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                (Some(row_ref), Some(request_ref)) if row_ref == request_ref => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                _ => {}
            }
        }
        ceiling.unwrap_or(PolicyApprovalCeiling::Proposed)
    }

    pub(crate) fn has_matching_actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> bool {
        self.actor_ceilings.iter().any(|row| {
            row.actor_class == actor_class
                && match (&row.actor_ref, actor_ref) {
                    (None, _) => true,
                    (Some(row_ref), Some(request_ref)) => row_ref == request_ref,
                    _ => false,
                }
        })
    }

    /// Effective `actor_ceilings` value from rows bound to THIS actor ref.
    ///
    /// Class-wide rows are deliberately excluded. ONE-1686 uses this narrower
    /// fold for transcript recording: class-wide ceilings govern claim
    /// admission, while only a row that names one writer may clamp that
    /// writer's ordinary transcript rows or authorize its elevated `system`
    /// authorship. Multiple exact rows still combine by the ordinary
    /// most-restrictive rule.
    pub(crate) fn actor_bound_ceiling(
        &self,
        actor_class: &str,
        actor_ref: &str,
    ) -> Option<PolicyApprovalCeiling> {
        self.actor_ceilings
            .iter()
            .filter(|row| {
                row.actor_class == actor_class && row.actor_ref.as_deref() == Some(actor_ref)
            })
            .fold(None, |ceiling, row| {
                Some(
                    ceiling.map_or(row.ceiling, |existing: PolicyApprovalCeiling| {
                        existing.restrict(row.ceiling)
                    }),
                )
            })
    }

    fn actor_ceiling_allows_auto_for_content(&self, input: &GateEvaluatorInput) -> bool {
        // ONE-1686 (RT-04): witness MESSAGE ingress is transcript RECORDING,
        // not claim admission. It has no proposed lane — a refused row is a
        // turn that never happened — so "this vault wrote no ceiling row for
        // the writer" must not silently end its ability to record ordinary
        // conversations. An `actor_ceilings` row that NAMES the writer is the
        // owner's lever and clamps here; no row keeps ordinary recording
        // available. Authority for the elevated `system` bucket is a separate,
        // fail-closed question the witness door's floor answers
        // (`gate::witness_message`). The AGENT_DEF self-limit is deliberately
        // not read here: a `Proposed`
        // definition means an agent's CLAIMS need review, not that it may not
        // be recorded speaking.
        if input.content_kind == GateContentKind::WitnessMessage {
            let actor_class = input.actor.actor_class.trim();
            return input.actor.actor_ref.as_deref().is_none_or(|actor_ref| {
                self.actor_bound_ceiling(actor_class, actor_ref)
                    .is_none_or(|ceiling| ceiling == PolicyApprovalCeiling::Auto)
            });
        }

        // A payload-aware scoped MCP grant is the one external-effect path
        // that dissolves the Proposed fork: store-backed matching already
        // proved server, tool, endpoint, and data-class scope. Blind grants
        // and every non-effect write retain the authored clamp below.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
            return input.content_kind == GateContentKind::ExternalEffect
                && input.external_effect.as_ref().is_some_and(|effect| {
                    effect.scoped_mcp_call.is_some() && effect.scoped_mcp_grant_authorized
                });
        }
        let actor_class = input.actor.actor_class.trim();
        if self.actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            == PolicyApprovalCeiling::Auto
        {
            return true;
        }

        // The edge-provenance no-matching-row auto exception is suppressed
        // for ANY definition-bound actor (B2 resolution 2026-07-10): an Auto
        // definition ceiling means "does not self-limit", not "inherits the
        // no-row exception" — no row → Proposed holds as written for
        // definition-bound actors.
        input.content_kind == GateContentKind::EdgeProvenanceClaim
            && matches!(actor_class, "agent" | "system")
            && !self.has_matching_actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            && input.agent_definition_ceiling.is_none()
    }

    fn dreamer_auto_grant_requires_manifest_signature(&self, input: &GateEvaluatorInput) -> bool {
        input.content_kind == GateContentKind::Claim
            && input.actor.actor_class.trim() == "agent"
            && input.provenance.dreamer_run_id.is_some()
            && self.actor_ceiling(
                input.actor.actor_class.trim(),
                input.actor.actor_ref.as_deref(),
            ) == PolicyApprovalCeiling::Auto
    }

    #[must_use]
    pub(crate) fn evaluate_gate(&self, input: &GateEvaluatorInput) -> GateDecision {
        self.evaluate_gate_with_lineage(input, None)
    }

    /// Envelope-bearing evaluation preserves the observed source members.
    /// Each restricted member needs its own applicable permit; the declared
    /// source cannot vouch for the rest. Doors without an envelope keep using
    /// [`Self::evaluate_gate`], which passes no lineage.
    #[must_use]
    pub(crate) fn evaluate_gate_with_lineage(
        &self,
        input: &GateEvaluatorInput,
        lineage: Option<&SourceLineage>,
    ) -> GateDecision {
        let actor_class = input.actor.actor_class.trim();
        if actor_class.is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorClass);
        }
        if input.provenance.actor_entity_ref.is_none() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorProvenance);
        }
        if input.policy_manifest_version.trim().is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingPolicyManifestVersion);
        }
        let external_effect = if input.content_kind == GateContentKind::ExternalEffect {
            input.external_effect.as_ref()
        } else {
            None
        };
        // ONE-1752 (ARCH-0057 §3.1). The folded opt-out bit is unchanged — CA
        // owns how it is computed — and only its CONSEQUENCE moved. A
        // counterparty's suppression is a fact about the counterparty; refusing
        // the owner outright made their own instrument answer for it. So:
        //
        // * a matching `comm.send_override` falls through to ordinary
        //   evaluation, and `external_effect_receipt_reasons` pins WHICH
        //   override decided it;
        // * `allow_with_receipt` falls through immediately, keeping the opt-out
        //   receipt trail;
        // * `escalate` (the default) holds the send as a PENDING owner
        //   decision, carrying the same receipt reasons the deny carried.
        //
        // The override never deletes `comm.opt_out`, `comm.do_not_contact`, or a
        // contact-level opt-out claim; CLEAR remains its own op.
        if let Some(effect) = external_effect
            && effect.counterparty_opted_out
        {
            match (
                effect.counterparty_send_override,
                self.comm_opt_out_posture(),
            ) {
                (Some(_), _) | (None, CommOptOutPosture::AllowWithReceipt) => {}
                (None, CommOptOutPosture::Escalate) => {
                    return GateDecision::pending(vec![GateReasonCode::PendingCounterpartyOptOut])
                        .with_receipt_reasons(external_effect_receipt_reasons(effect));
                }
            }
        }
        if self.is_fail_closed() {
            if input.content_kind == GateContentKind::ExternalEffect {
                let decision =
                    GateDecision::pending(vec![GateReasonCode::PendingExternalEffectAuthority]);
                return if let Some(effect) = external_effect {
                    decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
                } else {
                    decision
                };
            }
            return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
        }

        let mut pending = Vec::new();
        let mut actor_ceiling_allows_auto = self.actor_ceiling_allows_auto_for_content(input);
        if let Some(grant_ref) = input.actor.delegation_grant_ref.as_deref() {
            let bound = self
                .delegation_fold
                .records
                .get(grant_ref)
                .and_then(|r| match r {
                    DelegationGrantRecord::Grant {
                        actor_class,
                        actor_ref,
                        ..
                    } => Some((actor_class, actor_ref)),
                    _ => None,
                });
            let matches = bound.is_some_and(|(class, reference)| {
                class.trim() == actor_class
                    && reference.as_deref() == input.actor.actor_ref.as_deref()
            });
            actor_ceiling_allows_auto = actor_ceiling_allows_auto
                && matches
                && self.delegation_fold.effective_ceiling(grant_ref)
                    == Some(PolicyApprovalCeiling::Auto);
        }
        if !actor_ceiling_allows_auto {
            pending.push(GateReasonCode::PendingActorCeiling);
        }

        /* actor ceiling is already restrictive; delegated authority can only narrow it. */
        if actor_ceiling_allows_auto
            && self.dreamer_auto_grant_requires_manifest_signature(input)
            && self.signatures.is_empty()
        {
            pending.push(GateReasonCode::PendingPolicyManifestAuthority);
        }

        if !self.source_trust_allows_auto_with_lineage(
            input.source,
            input.sensitivity_band,
            input.actor.actor_ref.as_deref(),
            lineage,
        ) {
            pending.push(GateReasonCode::PendingSourceTrust);
        }

        // DEC-0006 write-side residual: `Critical` is a composed-effect SIGNAL,
        // not an unconditional gate. It contributes to the consent ladder
        // below (via `ConsentGateContext`), and the closed catastrophe set is
        // the only always-gate (invariant 7). The legacy unconditional floor
        // survives only where no consent context was composed, so a caller
        // that has not yet been moved onto the DEC-0006 path keeps its
        // pre-existing behaviour rather than silently losing a gate.
        if input.criticality == PolicyCriticality::Critical && input.consent.is_none() {
            pending.push(GateReasonCode::PendingCriticalityFloor);
        }

        pending.extend(consent_ladder_reasons(input.consent.as_ref()));

        match input.content_kind {
            // The witness door's own floor (`gate::witness_message`) carries the
            // envelope-shaped part of this content kind's verdict; what the
            // evaluator contributes is the actor/provenance floor, the
            // fail-closed manifest checks, and the ceiling clamp above.
            GateContentKind::Claim
            | GateContentKind::EdgeProvenanceClaim
            | GateContentKind::Repair
            | GateContentKind::WitnessMessage => {}
            GateContentKind::PolicyManifest => {
                pending.push(GateReasonCode::PendingPolicyManifestAuthority);
            }
            GateContentKind::ExternalEffect => {
                if !self.external_effect_allows_auto(input) {
                    pending.push(GateReasonCode::PendingExternalEffectAuthority);
                }
            }
        }

        let decision = if pending.is_empty() {
            GateDecision::allow()
        } else {
            GateDecision::pending(pending)
        };

        if let Some(effect) = external_effect {
            decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
        } else {
            decision
        }
    }

    /// Declared-source-only evaluation for doors without an envelope.
    // The declared-only form's one production caller is the federated
    // admission path, which exists only under `sync`.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn source_trust_allows_auto(
        &self,
        source: Option<ClaimSource>,
        sensitivity: Option<u8>,
        actor_ref: Option<&str>,
    ) -> bool {
        self.source_trust_allows_auto_with_lineage(source, sensitivity, actor_ref, None)
    }

    /// Use the same per-member rule for gate decisions and final Auto checks.
    /// A restricted lineage member never borrows the declared source's row.
    pub(crate) fn source_trust_allows_auto_with_lineage(
        &self,
        source: Option<ClaimSource>,
        sensitivity: Option<u8>,
        actor_ref: Option<&str>,
        lineage: Option<&SourceLineage>,
    ) -> bool {
        check_source_trust(
            source,
            ClaimApprovalStatus::Auto,
            sensitivity,
            actor_ref,
            &self.source_trust,
            lineage,
        )
        .is_ok()
    }

    fn external_effect_allows_auto(&self, input: &GateEvaluatorInput) -> bool {
        let Some(effect) = input.external_effect.as_ref() else {
            return false;
        };
        if effect.verb.trim().is_empty() || effect.channel.trim().is_empty() {
            return false;
        }
        // Payload-aware scoped grants are the only safe MCP auto path. The
        // boolean is set only by the store-backed four-axis match below; a
        // caller-supplied standing-grant reference has no authority here.
        // Only the typed scoped-MCP call path enters this branch. Ordinary
        // connectors may use an `mcp:` channel (including exact-shaped
        // capability lookalikes), but their text carries no capability
        // authority and must continue through ordinary policy matching.
        if effect.scoped_mcp_call.is_some() {
            return effect.scoped_mcp_grant_authorized;
        }
        if !effect.has_permission {
            return false;
        }

        // Blind/non-scoped grants keep the Proposed-ceiling restriction. A
        // scoped MCP grant reaches the return above only after all axes pass.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
            return false;
        }
        if effect.standing_grant_ref.is_some() {
            return true;
        }
        if !effect.has_opted_in {
            return false;
        }

        self.scoped_grants().iter().any(|grant| {
            grant.budget.is_none() && external_effect_grant_matches(grant, &input.actor, effect)
        })
    }
}
