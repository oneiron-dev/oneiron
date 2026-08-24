//! Acting on a verdict.
//!
//! There is exactly one invariant here, and every arm below is written to keep
//! it: `final_content` is either the caller's original string or nothing. No
//! path in this file authors, substitutes, or edits content on the caller's
//! behalf, so a reader who receives content receives what was actually
//! written.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::llm::{BudgetLease, LlmBackend};
use crate::store::GateSystemNoticeRecord;

use super::classify::OwnerPlanePass;
use super::notice::{
    POLICY_MODEL_HELP_MESSAGE, default_system_notice, policy_model_rationale_notice, policy_notice,
};
use super::planes::PolicyPlane;
use super::receipt::policy_model_reason_codes;
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{PolicyClassifyDecision, PolicyClassifyVerdict, PolicyVerdictCategory};

/// The manifest moved out from under the pass twice running, so no verdict
/// could be pinned to the policy in force.
pub(crate) const OWNER_PLANE_STALE_MANIFEST_REASON: &str = "gate.policy_model.stale_manifest";
/// ...and the sovereign plane let the content through rather than enforce a
/// rule it could not name.
pub(crate) const OWNER_PLANE_FAIL_OPEN_REASON: &str = "gate.policy_model.owner_plane_fail_open";

/// Whether this door is the one that records the decision it is acting on.
///
/// A policy decision gets exactly ONE row. The classify-and-enforce entries
/// mint the verdict they act on, so they own its row and write it.
/// [`Vault::enforce_policy_model_verdict`] receives a verdict another door
/// produced — and that door already receipted it — so it acts on the decision
/// without recording it a second time under a second outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionLedger {
    /// This door minted the verdict; it writes the row.
    Record,
    /// The door that minted the verdict wrote the row.
    AlreadyRecorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementAction {
    Allow,
    Warn,
    Block,
    RouteToHelp,
}

impl PolicyEnforcementAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }

    const fn for_decision(decision: PolicyClassifyDecision) -> Self {
        match decision {
            PolicyClassifyDecision::Allow => Self::Allow,
            PolicyClassifyDecision::Warn => Self::Warn,
            PolicyClassifyDecision::Block => Self::Block,
            PolicyClassifyDecision::RouteToHelp => Self::RouteToHelp,
        }
    }

    /// Whether the caller must not deliver the content. `Warn` delivers.
    #[must_use]
    pub const fn halts(self) -> bool {
        matches!(self, Self::Block | Self::RouteToHelp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementVoice {
    Persona,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBargeInKill {
    pub cancel_tts: bool,
    pub flush_playout_buffer: bool,
    pub cancel_llm: bool,
}

impl PolicyBargeInKill {
    const fn full_flush() -> Self {
        Self {
            cancel_tts: true,
            flush_playout_buffer: true,
            cancel_llm: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHelpRouting {
    pub category: PolicyVerdictCategory,
    pub message: String,
    pub diagnosis: Option<String>,
    pub persona_present: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyModelEnforcement {
    pub action: PolicyEnforcementAction,
    pub verdict: PolicyClassifyVerdict,
    /// The caller's original content, or nothing. Never a substitute.
    pub final_content: Option<String>,
    pub outbound_halted: bool,
    pub receipt_ref: Option<String>,
    pub system_notice: Option<String>,
    pub notice_voice: Option<PolicyEnforcementVoice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_notices: Vec<GateSystemNoticeRecord>,
    pub help_routing: Option<PolicyHelpRouting>,
    pub classify_trace: Vec<PolicyClassifyVerdict>,
    pub pre_display_block: bool,
    pub barge_in_kill: Option<PolicyBargeInKill>,
    /// The owner plane did not get to run: its safeguard model was down.
    pub custom_tier_skipped: bool,
}

impl Vault {
    pub fn enforce_policy_model(
        &self,
        request: PolicyClassifyRequest,
    ) -> Result<PolicyModelEnforcement> {
        self.enforce_policy_model_with_config(request, &PolicyModelConfig::default())
    }

    pub fn enforce_policy_model_with_config(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelEnforcement> {
        // The receipt-less pass, not the public classify door: that door now
        // writes the row for the verdicts it hands out bare, and this flow
        // records its own below. Routing through it would ledger one decision
        // twice.
        let verdict = self.owner_pattern_only_pass(&request, config)?;
        self.enforcement_from_verdict(request, config, verdict, false, DecisionLedger::Record)
    }

    /// Enforce with the owner's safeguard model available.
    ///
    /// A downed model, an unreadable answer and an unwritten policy document
    /// all read as "the owner plane did not run" rather than as a failure —
    /// nothing below the owner plane exists to fall back to, so the content
    /// passes through and `custom_tier_skipped` records the fact.
    ///
    /// # The manifest can move while the model is answering
    ///
    /// The pass snapshots the manifest, then AWAITS a network round trip. An
    /// owner who changes a row from `Warn` to `Block` during that await would
    /// otherwise have the pre-change verdict enforced against post-change
    /// policy — the engine acting on a rule that no longer exists. So the
    /// verdict is checked against what is in force before it is acted on, and
    /// a stale one is derived again, ONCE.
    ///
    /// If the second derivation is stale too, the manifest is moving faster
    /// than a pass can be taken and the owner plane does what it always does
    /// when it cannot answer: it fails OPEN, because it is sovereign and
    /// nothing sits beneath it. That outcome is receipted rather than silent.
    pub async fn enforce_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyModelEnforcement> {
        let safeguard = Some((backend, lease));
        let mut pass = self.owner_plane_pass(&request, config, safeguard).await?;
        if self.policy_model_verdict_is_stale_with_config(&pass.verdict, &request, config)? {
            pass = self.owner_plane_pass(&request, config, safeguard).await?;
            if self.policy_model_verdict_is_stale_with_config(&pass.verdict, &request, config)? {
                return self.stale_owner_plane_fail_open(request, config);
            }
        }
        let OwnerPlanePass {
            verdict,
            model_skipped,
        } = pass;
        self.enforcement_from_verdict(
            request,
            config,
            verdict,
            model_skipped,
            DecisionLedger::Record,
        )
    }

    /// The owner plane could not pin a verdict to the policy in force, so it
    /// enforces nothing and says so. Sovereign planes fail open; what they do
    /// not do is enforce a rule they cannot name.
    fn stale_owner_plane_fail_open(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelEnforcement> {
        let binding = self.policy_model_context(&request, config)?.binding;
        let verdict = PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::OwnerPolicy);
        let receipt_ref = self.append_policy_model_gate_receipt(
            &request,
            &verdict,
            "owner_plane_stale_fail_open",
            vec![
                OWNER_PLANE_STALE_MANIFEST_REASON.to_owned(),
                OWNER_PLANE_FAIL_OPEN_REASON.to_owned(),
            ],
            Vec::new(),
        )?;
        Ok(PolicyModelEnforcement {
            action: PolicyEnforcementAction::Allow,
            classify_trace: vec![verdict.clone()],
            verdict,
            final_content: Some(request.content),
            outbound_halted: false,
            receipt_ref: Some(receipt_ref),
            system_notice: None,
            notice_voice: None,
            system_notices: Vec::new(),
            help_routing: None,
            pre_display_block: false,
            barge_in_kill: None,
            // The plane did not get to decide, which is the fact this flag
            // carries — the model answered, but against a manifest that had
            // already moved on.
            custom_tier_skipped: true,
        })
    }

    /// Turns a verdict this vault already produced into the enforcement a
    /// caller acts on — the owner half of a [`DualPlanePass`], say, which
    /// arrives as a bare verdict with no enforcement attached.
    ///
    /// `custom_tier_skipped` is the caller's to supply: it is
    /// [`DualPlanePass::owner_model_skipped`] for that pass, and `false` for a
    /// verdict a model answered.
    ///
    /// # The producing door owns the ledger row
    ///
    /// This door does NOT receipt. A policy decision gets one row, written by
    /// the door that made it: [`Vault::classify_both_planes`] writes the owner
    /// plane's row on the way through, the classify-and-enforce entries write
    /// their own, and the BARE classify doors
    /// ([`Vault::classify_policy_model`] and its siblings) write theirs at
    /// mint — which is what makes this door's silence safe rather than a hole.
    /// A verdict reaching here has a row already, whichever door produced it.
    /// Recording again would put the SAME decision in the ledger twice under
    /// two different outcomes — once as `owner_plane_block`, again as
    /// `block` — and the pattern-tuning counts a substrate owner reads those
    /// rows for would count it twice.
    ///
    /// So [`PolicyModelEnforcement::receipt_ref`] is `None` from this door.
    /// The row is the producing call's.
    ///
    /// # The verdict must be THIS request's, under the policy in force
    ///
    /// Everything else here arrives from one call: request, config and verdict
    /// are settled together by the door that classified. Here they are three
    /// independent arguments, and nothing about the signature stops a caller
    /// pairing a verdict with another request — a stale one it cached, or one
    /// about entirely different content. Enforced as-is that verdict would
    /// halt or release THIS request's content on another question's answer.
    ///
    /// So the pairing is checked rather than assumed, with the predicate that
    /// already knows both halves:
    /// [`Vault::policy_model_verdict_is_stale_with_config`] recomputes this
    /// request's content binding and compares it, compares the safeguard
    /// selector, and re-checks the manifest frontier. Any of the three failing
    /// is [`Error::PolicyVerdictNotInForce`] — a refusal, not a fail-open.
    /// This door cannot re-derive (it has no model), so the honest answer is
    /// to send the caller back for a verdict that fits, not to act on one that
    /// does not.
    ///
    /// [`DualPlanePass`]: super::relay::DualPlanePass
    /// [`DualPlanePass::owner_model_skipped`]: super::relay::DualPlanePass::owner_model_skipped
    pub fn enforce_policy_model_verdict(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        verdict: PolicyClassifyVerdict,
        custom_tier_skipped: bool,
    ) -> Result<PolicyModelEnforcement> {
        // A verdict from the HOSTED plane is not this door's to enforce, and
        // the staleness check cannot tell: both halves of a `DualPlanePass`
        // answer the SAME request, so a hosted verdict carries the same
        // binding, the same selector and the same frontier as the owner one.
        // Handed `pass.relay` instead of `pass.owner` — one field apart — this
        // door would enforce a hosted service's `Block` as the vault owner's
        // own, attributing it to a plane that never decided it.
        //
        // Two plane markers, kept as DEFENCE IN DEPTH rather than as the
        // load-bearing check — and it is worth being exact about which is
        // which, because the comment that stood here was wrong.
        //
        // The claim was that the staleness check below cannot tell the planes
        // apart, since both halves of a `DualPlanePass` answer the same
        // request. That is true of a verdict built by copying the owner's and
        // stamping it hosted, which is what the test did. It is NOT true of a
        // verdict the relay actually mints: the two planes bind against
        // DIFFERENT documents and frontiers, so a real `pass.relay` verdict
        // fails the staleness check on its binding. Verified by disabling both
        // markers below — the door still refuses a production-minted hosted
        // `Block`.
        //
        // The markers are kept anyway. They are two comparisons, they state
        // the plane rule at the door that owns it instead of leaving it as an
        // emergent property of how bindings happen to be derived, and if a
        // later change ever gave the two planes a shared binding, they are
        // what would still hold. The attestation catches a verified
        // vault-side verdict; the category catches every hosted verdict that
        // decided anything, since `hosted_row_verdict` stamps it. Neither
        // catches a hosted clean allow, which carries no category and no
        // attestation — and enforcing one yields an allow, so there is no
        // wrong action behind that gap.
        if verdict.hosted_attestation.is_some()
            || matches!(verdict.category, PolicyVerdictCategory::HostedLegal { .. })
        {
            return Err(Error::PolicyVerdictNotInForce);
        }
        if self.policy_model_verdict_is_stale_with_config(&verdict, &request, config)? {
            return Err(Error::PolicyVerdictNotInForce);
        }
        self.enforcement_from_verdict(
            request,
            config,
            verdict,
            custom_tier_skipped,
            DecisionLedger::AlreadyRecorded,
        )
    }

    fn enforcement_from_verdict(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        verdict: PolicyClassifyVerdict,
        custom_tier_skipped: bool,
        ledger: DecisionLedger,
    ) -> Result<PolicyModelEnforcement> {
        let action = PolicyEnforcementAction::for_decision(verdict.decision);
        let classify_trace = vec![verdict.clone()];
        // An allow that learned nothing carries no signal and is not
        // receipted. An allow that DID learn something — a pattern fired and
        // the model overruled it, say — is exactly the row the substrate owner
        // needs, so it is.
        if action == PolicyEnforcementAction::Allow && verdict.audit.is_none() {
            return Ok(PolicyModelEnforcement {
                action,
                verdict,
                final_content: Some(request.content),
                outbound_halted: false,
                receipt_ref: None,
                system_notice: None,
                notice_voice: None,
                system_notices: Vec::new(),
                help_routing: None,
                classify_trace,
                pre_display_block: false,
                barge_in_kill: None,
                custom_tier_skipped,
            });
        }

        // The vault-egress path only ever sees owner-plane verdicts, so there
        // is no hosted policy to attribute against here.
        let mut system_notices = policy_notice(verdict.decision, &verdict.category, None, config)
            .into_iter()
            .collect::<Vec<_>>();
        // Appended last so it can never become the single surfaced body. The
        // vault-egress path is the owner plane by construction, so it says so
        // rather than leaving a clean allow's rationale unattributed.
        system_notices.extend(policy_model_rationale_notice(
            &verdict,
            PolicyPlane::OwnerPolicy,
            None,
        ));
        let receipt_ref = match ledger {
            DecisionLedger::Record => Some(self.append_policy_model_gate_receipt(
                &request,
                &verdict,
                action.as_str(),
                policy_model_reason_codes(&verdict),
                system_notices.clone(),
            )?),
            DecisionLedger::AlreadyRecorded => None,
        };
        let halts = action.halts();
        Ok(PolicyModelEnforcement {
            help_routing: (action == PolicyEnforcementAction::RouteToHelp).then(|| {
                PolicyHelpRouting {
                    category: verdict.category.clone(),
                    message: POLICY_MODEL_HELP_MESSAGE.to_owned(),
                    diagnosis: None,
                    persona_present: true,
                }
            }),
            action,
            verdict,
            // `Warn` hands back exactly what the caller passed in.
            final_content: (!halts).then_some(request.content),
            outbound_halted: halts,
            receipt_ref,
            system_notice: default_system_notice(&system_notices),
            notice_voice: Some(PolicyEnforcementVoice::System),
            system_notices,
            classify_trace,
            pre_display_block: halts,
            barge_in_kill: halts.then(PolicyBargeInKill::full_flush),
            custom_tier_skipped,
        })
    }
}
