//! Acting on a verdict.
//!
//! There is exactly one invariant here, and every arm below is written to keep
//! it: `final_content` is either the caller's original string or nothing. No
//! path in this file authors, substitutes, or edits content on the caller's
//! behalf, so a reader who receives content receives what was actually
//! written.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::Result;
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
        let verdict = self.classify_policy_model_with_config(request.clone(), config)?;
        self.enforcement_from_verdict(request, config, verdict, false)
    }

    /// Enforce with the owner's safeguard model available.
    ///
    /// A downed model, an unreadable answer and an unwritten policy document
    /// all read as "the owner plane did not run" rather than as a failure —
    /// nothing below the owner plane exists to fall back to, so the content
    /// passes through and `custom_tier_skipped` records the fact.
    pub async fn enforce_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyModelEnforcement> {
        let OwnerPlanePass {
            verdict,
            model_skipped,
        } = self
            .owner_plane_pass(&request, config, Some((backend, lease)))
            .await?;
        self.enforcement_from_verdict(request, config, verdict, model_skipped)
    }

    fn enforcement_from_verdict(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        verdict: PolicyClassifyVerdict,
        custom_tier_skipped: bool,
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
        let receipt_ref = self.append_policy_model_gate_receipt(
            &request,
            &verdict,
            action.as_str(),
            policy_model_reason_codes(&verdict),
            system_notices.clone(),
        )?;
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
            receipt_ref: Some(receipt_ref),
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
