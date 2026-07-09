//! OF-333 policy-model classify verb.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::gate::{self, PolicyManifestResolution};
use crate::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_SAFEGUARD_MODEL_BINDING, DeterministicFallback, LlmBackend, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, ModelTierRef, ResponseFormat, SafeguardModelBinding,
};
use crate::store::{
    GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GateDecisionId, GateDecisionRecord, GateSystemNoticeAction,
    GateSystemNoticeRecord,
};

pub const POLICY_MODEL_REWORD_RETRY_BUDGET: usize = 2;
const POLICY_MODEL_SAFE_GENERIC_PERSONA_REPLY: &str =
    "I can keep this safe and general without using that detail.";
const POLICY_MODEL_BLOCK_NOTICE: &str =
    "Oneiron blocked this outbound content before display or action.";
const POLICY_MODEL_OWNER_BLOCK_THIRD_PARTY_NOTICE: &str =
    "Oneiron blocked this outbound content under the vault owner's policy.";
const POLICY_MODEL_OWNER_BLOCK_NOTICE: &str =
    "Oneiron blocked this outbound content because one of your policy settings asked it to.";
const POLICY_MODEL_HELP_CARD_NOTICE: &str =
    "Oneiron routed this turn to a help card with EF-304 handoff.";
const POLICY_MODEL_HELP_MESSAGE: &str =
    "Support resources should be offered alongside the reply without diagnosing the person.";
const SYSTEM_NOTICE_CHANNEL_EF196_OF221: &str = "EF-196/OF-221";
const SYSTEM_NOTICE_VOICE_SYSTEM: &str = "system";
const SYSTEM_NOTICE_AUDIENCE_ALL: &str = "all";
const SYSTEM_NOTICE_AUDIENCE_OWNER: &str = "owner";
const SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY: &str = "third_party";
const SYSTEM_NOTICE_TYPE_BLOCK: &str = "policy_block";
const SYSTEM_NOTICE_TYPE_HELP_CARD: &str = "policy_help_card";
const OWNER_POLICY_SETTINGS_DEEP_LINK: &str = "oneiron://settings/policy/b11-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClassifySubject {
    OutboundContent,
    Action,
}

impl PolicyClassifySubject {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundContent => "outbound_content",
            Self::Action => "action",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAgeTier {
    #[default]
    Unverified,
    Minor,
    Adult,
}

impl PolicyAgeTier {
    #[must_use]
    pub const fn permits_adult_content(self) -> bool {
        matches!(self, Self::Adult)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Minor => "minor",
            Self::Adult => "adult",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyRequest {
    pub subject: PolicyClassifySubject,
    pub content: String,
    pub account_jurisdiction: Option<String>,
    pub age_tier: PolicyAgeTier,
    pub world_ref: Option<String>,
    pub caller_ref: Option<String>,
}

impl PolicyClassifyRequest {
    #[must_use]
    pub fn outbound_content(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::OutboundContent,
            content: content.into(),
            account_jurisdiction: None,
            age_tier: PolicyAgeTier::Unverified,
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn action(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::Action,
            content: content.into(),
            account_jurisdiction: None,
            age_tier: PolicyAgeTier::Unverified,
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn with_age_tier(mut self, age_tier: PolicyAgeTier) -> Self {
        self.age_tier = age_tier;
        self
    }

    #[must_use]
    pub fn with_world_ref(mut self, world_ref: impl Into<String>) -> Self {
        self.world_ref = Some(world_ref.into());
        self
    }

    #[must_use]
    pub fn with_account_jurisdiction(mut self, account_jurisdiction: impl Into<String>) -> Self {
        self.account_jurisdiction = Some(account_jurisdiction.into());
        self
    }

    #[must_use]
    pub fn with_caller_ref(mut self, caller_ref: impl Into<String>) -> Self {
        self.caller_ref = Some(caller_ref.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyModelConfig {
    pub safeguard_binding: SafeguardModelBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyClassifyDecision {
    Allow,
    Block,
    RouteToHelp,
    RewordRetry,
}

impl PolicyClassifyDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::RouteToHelp => "route-to-help",
            Self::RewordRetry => "reword-retry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "category", content = "sub", rename_all = "snake_case")]
pub enum PolicyVerdictCategory {
    None,
    LegalFloor(LegalFloorSubclass),
    Crisis(CrisisSubclass),
    AgeGate(AgeGateSubclass),
    OwnerPolicy { row_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalFloorSubclass {
    MinorSexualization,
    Ncii,
    SeriousCrime,
    Jurisdiction { row_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrisisSubclass {
    SelfHarm,
    Medical,
    HarmToOthers,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeGateSubclass {
    AdultContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHedgeBucket {
    Certain,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfidence {
    pub calibrated: f32,
    pub hedge_bucket: PolicyHedgeBucket,
}

impl PolicyConfidence {
    const CERTAIN: Self = Self {
        calibrated: 1.0,
        hedge_bucket: PolicyHedgeBucket::Certain,
    };

    const HIGH: Self = Self {
        calibrated: 0.92,
        hedge_bucket: PolicyHedgeBucket::High,
    };

    const MEDIUM: Self = Self {
        calibrated: 0.75,
        hedge_bucket: PolicyHedgeBucket::Medium,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyContentBinding {
    pub content_hash: [u8; 32],
    pub read_frontier_hash: [u8; 32],
}

impl PolicyContentBinding {
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.content_hash)
    }

    #[must_use]
    pub fn read_frontier_hash_hex(&self) -> String {
        bytes_to_hex_lower(&self.read_frontier_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyClassifyVerdict {
    pub decision: PolicyClassifyDecision,
    pub category: PolicyVerdictCategory,
    pub confidence: PolicyConfidence,
    pub binding: PolicyContentBinding,
    pub safeguard_binding: String,
}

impl PolicyClassifyVerdict {
    #[must_use]
    pub fn decision_str(&self) -> &'static str {
        self.decision.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementAction {
    Allow,
    Block,
    RouteToHelp,
    RewordRetry,
}

impl PolicyEnforcementAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
            Self::RewordRetry => "reword_retry",
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRewordFeedback {
    pub category: PolicyVerdictCategory,
    pub row_ref: Option<String>,
    pub instruction: String,
    pub visible_to_user: bool,
    pub voice: PolicyEnforcementVoice,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyModelEnforcement {
    pub action: PolicyEnforcementAction,
    pub verdict: PolicyClassifyVerdict,
    pub final_content: Option<String>,
    pub outbound_halted: bool,
    pub receipt_ref: Option<String>,
    pub system_notice: Option<String>,
    pub notice_voice: Option<PolicyEnforcementVoice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_notices: Vec<GateSystemNoticeRecord>,
    pub help_routing: Option<PolicyHelpRouting>,
    pub reword_attempts: usize,
    pub reword_feedbacks: Vec<PolicyRewordFeedback>,
    pub classify_trace: Vec<PolicyClassifyVerdict>,
    pub pre_display_block: bool,
    pub barge_in_kill: Option<PolicyBargeInKill>,
    pub custom_tier_skipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyPrompt {
    pub system: String,
    pub user: String,
    pub rubric_rows: Vec<PolicyRubricRow>,
}

impl PolicyClassifyPrompt {
    #[must_use]
    pub fn llm_request(&self, config: &PolicyModelConfig) -> LlmRequest {
        let selector = config.safeguard_binding.selector();
        let mut params = BTreeMap::new();
        params.insert("temperature".to_owned(), json!(0));
        params.insert("max_output_tokens".to_owned(), json!(96));

        let mut provider_options = BTreeMap::new();
        provider_options.insert("safeguard_binding".to_owned(), json!(selector));
        provider_options.insert("factory_taxonomy".to_owned(), json!("suppressed"));

        LlmRequest {
            model: config.safeguard_binding.llm_model_id(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Other {
                    name: "policy_model_classify".to_owned(),
                },
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: "policy_model_deterministic_tripwire".to_owned(),
                        config: Some(json!({ "scope": "floor_only" })),
                    },
                },
                tier: crate::llm::TierPrecedence {
                    per_call: None,
                    vault_policy: Some(config.safeguard_binding.tier_ref()),
                    purpose_default: Some(ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned())),
                    global_default: ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: classify_response_schema(),
                },
                locality: config.safeguard_binding.locality(),
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: self.system.clone(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: self.user.clone(),
                    }],
                },
            ],
            tools: Vec::new(),
            params,
            provider_options,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRubricRow {
    pub row_ref: String,
    pub layer: PolicyRubricLayer,
    pub category: String,
    pub action: PolicyClassifyDecision,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyRubricLayer {
    EngineFloor,
    VaultFloor,
    OwnerPolicy,
}

/// B11-2 / ONE-WIRE-2 R9 trust domain for a relay-boundary floor pass.
///
/// The floor runs where OUR infrastructure touches content, once per trust
/// domain. The hosted relay / connector edge (the caller) MUST derive this from
/// the connection's infrastructure trust domain, NEVER from a vault-attested
/// "already classified" receipt — a sovereign machine owns its box, so its
/// receipt is not evidence (R9).
///
/// Intentionally `Serialize` but NOT `Deserialize`: this must never be decoded
/// from the wire. A future protocol carrying `"trust_domain":"cloud_vault"`
/// parsed from vault-supplied bytes would be exactly the vault-attested-receipt
/// bypass in a different coat — the trust domain is established by our
/// infrastructure, so it is emitted (receipts/logs) but never accepted inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayTrustDomain {
    /// Cloud vault: content was floor-classified vault-side on our infra; the
    /// relay trusts that pass and does not re-run.
    CloudVault,
    /// Local/self-host vault whose outbound transits an Oneiron-hosted connector
    /// (shared Slack app, push relay, hosted email sender). Our infra relays the
    /// content, so the relay runs a FLOOR-ONLY pass at the boundary.
    LocalViaHostedConnector,
    /// Local/self-host vault using its own BYO connector: nothing transits us.
    LocalViaByoConnector,
}

impl RelayTrustDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudVault => "cloud_vault",
            Self::LocalViaHostedConnector => "local_via_hosted_connector",
            Self::LocalViaByoConnector => "local_via_byo_connector",
        }
    }
}

/// Why a hosted-relay floor pass degraded off the safeguard-model tier. A
/// degraded pass fell back to the Rung-1 deterministic result (never below it);
/// the marker keeps a degraded `Allow` distinguishable from a model-confirmed
/// `Allow` in receipts and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayFloorDegrade {
    /// The safeguard model was unavailable (transport/backend error).
    SafeguardModelUnavailable,
    /// The safeguard model responded but the response was unusable (unparseable,
    /// or an off-floor verdict such as a hallucinated owner-policy row that has
    /// no floor rubric row to bind to).
    SafeguardModelResponseUnusable,
}

impl RelayFloorDegrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeguardModelUnavailable => "safeguard_model_unavailable",
            Self::SafeguardModelResponseUnusable => "safeguard_model_response_unusable",
        }
    }
}

/// Outcome of a relay-boundary FLOOR pass (B11-2 / R9). Advisory only — this
/// classifies, it does not itself halt the relay; the caller must honor
/// [`RelayFloorPass::must_halt_relay`].
///
/// `FloorClassified` is the only variant that ran a classify pass, and its
/// verdict is FLOOR ONLY — the owner custom tier is never assembled at the
/// relay, so the verdict category can never be
/// [`PolicyVerdictCategory::OwnerPolicy`].
///
/// Intentionally `Serialize` but NOT `Deserialize` (same reason as
/// [`RelayTrustDomain`]): a relay outcome is emitted for receipts/logs, never
/// reconstructed from untrusted bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayFloorPass {
    /// Cloud vault: already classified vault-side; the relay trusts it.
    TrustedVaultSide,
    /// BYO connector: nothing transits our infra; nothing ran.
    NotRelayedByUs,
    /// Hosted connector on a local vault: OUR infra ran a floor-only pass.
    /// `degraded` is set when the pass fell back to the Rung-1 result because
    /// the safeguard-model tier failed.
    FloorClassified {
        verdict: PolicyClassifyVerdict,
        #[serde(skip_serializing_if = "Option::is_none")]
        degraded: Option<RelayFloorDegrade>,
    },
}

impl RelayFloorPass {
    /// The floor verdict, present only when OUR infra ran a relay classify pass.
    #[must_use]
    pub fn floor_verdict(&self) -> Option<&PolicyClassifyVerdict> {
        match self {
            Self::FloorClassified { verdict, .. } => Some(verdict),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether OUR infra ran a classify pass at the relay boundary. False for a
    /// cloud vault (trusted vault-side) and BYO (never transits us).
    #[must_use]
    pub fn ran_relay_classify(&self) -> bool {
        matches!(self, Self::FloorClassified { .. })
    }

    /// The degradation marker, if the safeguard-model tier failed and the pass
    /// fell back to the Rung-1 deterministic result.
    #[must_use]
    pub fn degraded(&self) -> Option<RelayFloorDegrade> {
        match self {
            Self::FloorClassified { degraded, .. } => *degraded,
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether the caller edge must NOT relay this content. True only when a
    /// floor pass ran and returned a non-`Allow` verdict: every non-`Allow`
    /// verdict — `Block`, `RouteToHelp`, and `RewordRetry` alike — means
    /// do-not-relay as-is at an edge (this API is advisory; the edge enforces).
    /// A trusted cloud pass and an untouched BYO path never halt the relay.
    #[must_use]
    pub fn must_halt_relay(&self) -> bool {
        self.floor_verdict()
            .is_some_and(|verdict| verdict.decision != PolicyClassifyDecision::Allow)
    }
}

impl Vault {
    pub fn classify_policy_model(
        &self,
        request: PolicyClassifyRequest,
    ) -> Result<PolicyClassifyVerdict> {
        self.classify_policy_model_with_config(request, &PolicyModelConfig::default())
    }

    pub fn classify_policy_model_with_config(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyVerdict> {
        let context = self.policy_model_context(&request, config)?;
        let binding = context.binding;
        let verdict = if let Some(local) = classify_from_local_floor(&request) {
            local
        } else {
            if context.owner_policy_rows_dropped {
                return Err(dropped_owner_policy_rows_error());
            }
            classify_without_backend_from_rubric(&context.prompt.rubric_rows, binding, config)
        };
        Ok(PolicyClassifyVerdict {
            binding,
            safeguard_binding: config.safeguard_binding.selector(),
            ..verdict
        })
    }

    pub async fn classify_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyClassifyVerdict> {
        let context = self.policy_model_context(&request, config)?;
        let binding = context.binding;
        if let Some(local) = classify_from_local_floor(&request) {
            return Ok(PolicyClassifyVerdict {
                binding,
                safeguard_binding: config.safeguard_binding.selector(),
                ..local
            });
        }
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }

        let response = backend
            .generate(context.prompt.llm_request(config), lease)
            .await
            .map_err(|error| {
                Error::InvalidConfig(format!("policy model classify failed: {error}"))
            })?;
        parse_policy_model_response(&response, &context.prompt.rubric_rows, binding, config)
    }

    pub fn enforce_policy_model(
        &self,
        request: PolicyClassifyRequest,
    ) -> Result<PolicyModelEnforcement> {
        self.enforce_policy_model_with_rewriter(
            request,
            &PolicyModelConfig::default(),
            default_policy_rewrite_candidate,
        )
    }

    pub fn enforce_policy_model_with_rewriter(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        rewriter: impl FnMut(&PolicyRewordFeedback, &str) -> String,
    ) -> Result<PolicyModelEnforcement> {
        let first = self.classify_policy_model_with_config(request.clone(), config)?;
        self.enforce_policy_model_from_verdict(request, config, first, rewriter, false)
    }

    pub async fn enforce_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
        rewriter: impl FnMut(&PolicyRewordFeedback, &str) -> String,
    ) -> Result<PolicyModelEnforcement> {
        let backend_context = PolicyBackendEnforcement {
            config,
            backend,
            lease,
        };
        let (first, custom_tier_skipped) = self
            .classify_policy_model_for_enforcement_with_backend(&request, &backend_context)
            .await?;
        self.enforce_policy_model_from_verdict_with_backend(
            request,
            first,
            rewriter,
            custom_tier_skipped,
            &backend_context,
        )
        .await
    }

    fn enforce_policy_model_from_verdict(
        &self,
        mut request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        first: PolicyClassifyVerdict,
        mut rewriter: impl FnMut(&PolicyRewordFeedback, &str) -> String,
        custom_tier_skipped: bool,
    ) -> Result<PolicyModelEnforcement> {
        let mut verdict = first;
        let mut trace = vec![verdict.clone()];
        let mut feedbacks = Vec::new();
        let mut reword_attempts = 0;

        loop {
            match verdict.decision {
                PolicyClassifyDecision::Allow => {
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::Allow,
                        verdict,
                        final_content: Some(request.content),
                        outbound_halted: false,
                        receipt_ref: None,
                        system_notice: None,
                        notice_voice: None,
                        system_notices: Vec::new(),
                        help_routing: None,
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: false,
                        barge_in_kill: None,
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::Block => {
                    let system_notices = block_system_notices(&verdict);
                    let receipt_ref = self.append_policy_model_gate_receipt(
                        &request,
                        &verdict,
                        "block",
                        policy_model_reason_codes(&verdict),
                        system_notices.clone(),
                    )?;
                    let system_notice = default_system_notice(&system_notices);
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::Block,
                        verdict,
                        final_content: None,
                        outbound_halted: true,
                        receipt_ref: Some(receipt_ref),
                        system_notice,
                        notice_voice: Some(PolicyEnforcementVoice::System),
                        system_notices,
                        help_routing: None,
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: true,
                        barge_in_kill: Some(PolicyBargeInKill::full_flush()),
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::RouteToHelp => {
                    let system_notices = vec![route_to_help_system_notice()];
                    let receipt_ref = self.append_policy_model_gate_receipt(
                        &request,
                        &verdict,
                        "route_to_help",
                        policy_model_reason_codes(&verdict),
                        system_notices.clone(),
                    )?;
                    let system_notice = default_system_notice(&system_notices);
                    let routing = PolicyHelpRouting {
                        category: verdict.category.clone(),
                        message: POLICY_MODEL_HELP_MESSAGE.to_owned(),
                        diagnosis: None,
                        persona_present: true,
                    };
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::RouteToHelp,
                        verdict,
                        final_content: Some(request.content),
                        outbound_halted: false,
                        receipt_ref: Some(receipt_ref),
                        system_notice,
                        notice_voice: Some(PolicyEnforcementVoice::System),
                        system_notices,
                        help_routing: Some(routing),
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: false,
                        barge_in_kill: None,
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::RewordRetry => {
                    if reword_attempts >= POLICY_MODEL_REWORD_RETRY_BUDGET {
                        let final_content = reword_exhaustion_content(&verdict).map(str::to_owned);
                        return Ok(PolicyModelEnforcement {
                            action: PolicyEnforcementAction::RewordRetry,
                            verdict,
                            final_content,
                            outbound_halted: false,
                            receipt_ref: None,
                            system_notice: None,
                            notice_voice: Some(PolicyEnforcementVoice::Persona),
                            system_notices: Vec::new(),
                            help_routing: None,
                            reword_attempts,
                            reword_feedbacks: feedbacks,
                            classify_trace: trace,
                            pre_display_block: false,
                            barge_in_kill: None,
                            custom_tier_skipped,
                        });
                    }

                    let feedback = reword_feedback_for_verdict(&verdict);
                    let rewritten = rewriter(&feedback, &request.content);
                    feedbacks.push(feedback);
                    reword_attempts += 1;
                    request.content = rewritten;
                    verdict = if custom_tier_skipped {
                        self.policy_model_floor_or_allow_verdict(&request, config)?
                    } else {
                        self.classify_policy_model_with_config(request.clone(), config)?
                    };
                    trace.push(verdict.clone());
                }
            }
        }
    }

    async fn enforce_policy_model_from_verdict_with_backend(
        &self,
        mut request: PolicyClassifyRequest,
        first: PolicyClassifyVerdict,
        mut rewriter: impl FnMut(&PolicyRewordFeedback, &str) -> String,
        mut custom_tier_skipped: bool,
        backend_context: &PolicyBackendEnforcement<'_>,
    ) -> Result<PolicyModelEnforcement> {
        let mut verdict = first;
        let mut trace = vec![verdict.clone()];
        let mut feedbacks = Vec::new();
        let mut reword_attempts = 0;

        loop {
            match verdict.decision {
                PolicyClassifyDecision::Allow => {
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::Allow,
                        verdict,
                        final_content: Some(request.content),
                        outbound_halted: false,
                        receipt_ref: None,
                        system_notice: None,
                        notice_voice: None,
                        system_notices: Vec::new(),
                        help_routing: None,
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: false,
                        barge_in_kill: None,
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::Block => {
                    let system_notices = block_system_notices(&verdict);
                    let receipt_ref = self.append_policy_model_gate_receipt(
                        &request,
                        &verdict,
                        "block",
                        policy_model_reason_codes(&verdict),
                        system_notices.clone(),
                    )?;
                    let system_notice = default_system_notice(&system_notices);
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::Block,
                        verdict,
                        final_content: None,
                        outbound_halted: true,
                        receipt_ref: Some(receipt_ref),
                        system_notice,
                        notice_voice: Some(PolicyEnforcementVoice::System),
                        system_notices,
                        help_routing: None,
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: true,
                        barge_in_kill: Some(PolicyBargeInKill::full_flush()),
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::RouteToHelp => {
                    let system_notices = vec![route_to_help_system_notice()];
                    let receipt_ref = self.append_policy_model_gate_receipt(
                        &request,
                        &verdict,
                        "route_to_help",
                        policy_model_reason_codes(&verdict),
                        system_notices.clone(),
                    )?;
                    let system_notice = default_system_notice(&system_notices);
                    let routing = PolicyHelpRouting {
                        category: verdict.category.clone(),
                        message: POLICY_MODEL_HELP_MESSAGE.to_owned(),
                        diagnosis: None,
                        persona_present: true,
                    };
                    return Ok(PolicyModelEnforcement {
                        action: PolicyEnforcementAction::RouteToHelp,
                        verdict,
                        final_content: Some(request.content),
                        outbound_halted: false,
                        receipt_ref: Some(receipt_ref),
                        system_notice,
                        notice_voice: Some(PolicyEnforcementVoice::System),
                        system_notices,
                        help_routing: Some(routing),
                        reword_attempts,
                        reword_feedbacks: feedbacks,
                        classify_trace: trace,
                        pre_display_block: false,
                        barge_in_kill: None,
                        custom_tier_skipped,
                    });
                }
                PolicyClassifyDecision::RewordRetry => {
                    if reword_attempts >= POLICY_MODEL_REWORD_RETRY_BUDGET {
                        let final_content = reword_exhaustion_content(&verdict).map(str::to_owned);
                        return Ok(PolicyModelEnforcement {
                            action: PolicyEnforcementAction::RewordRetry,
                            verdict,
                            final_content,
                            outbound_halted: false,
                            receipt_ref: None,
                            system_notice: None,
                            notice_voice: Some(PolicyEnforcementVoice::Persona),
                            system_notices: Vec::new(),
                            help_routing: None,
                            reword_attempts,
                            reword_feedbacks: feedbacks,
                            classify_trace: trace,
                            pre_display_block: false,
                            barge_in_kill: None,
                            custom_tier_skipped,
                        });
                    }

                    let feedback = reword_feedback_for_verdict(&verdict);
                    let rewritten = rewriter(&feedback, &request.content);
                    feedbacks.push(feedback);
                    reword_attempts += 1;
                    request.content = rewritten;
                    let (next, skipped) = self
                        .classify_policy_model_for_enforcement_with_backend(
                            &request,
                            backend_context,
                        )
                        .await?;
                    custom_tier_skipped |= skipped;
                    verdict = next;
                    trace.push(verdict.clone());
                }
            }
        }
    }

    async fn classify_policy_model_for_enforcement_with_backend(
        &self,
        request: &PolicyClassifyRequest,
        backend_context: &PolicyBackendEnforcement<'_>,
    ) -> Result<(PolicyClassifyVerdict, bool)> {
        let config = backend_context.config;
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        if let Some(local) = classify_from_local_floor(request) {
            return Ok((
                PolicyClassifyVerdict {
                    binding,
                    safeguard_binding: config.safeguard_binding.selector(),
                    ..local
                },
                false,
            ));
        }
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }

        let response = match backend_context
            .backend
            .generate(context.prompt.llm_request(config), backend_context.lease)
            .await
        {
            Ok(response) => response,
            Err(_error) => {
                return Ok((
                    self.policy_model_floor_or_allow_verdict(request, config)?,
                    true,
                ));
            }
        };
        Ok((
            parse_policy_model_response(&response, &context.prompt.rubric_rows, binding, config)?,
            false,
        ))
    }

    fn policy_model_floor_or_allow_verdict(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyVerdict> {
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        let verdict = classify_from_local_floor(request).unwrap_or_else(|| {
            verdict(
                PolicyClassifyDecision::Allow,
                PolicyVerdictCategory::None,
                PolicyConfidence::HIGH,
                binding,
                config,
            )
        });
        Ok(PolicyClassifyVerdict {
            binding,
            safeguard_binding: config.safeguard_binding.selector(),
            ..verdict
        })
    }

    /// B11-2 / R9 relay-boundary FLOOR pass, deterministic (Rung-1) tier only.
    ///
    /// Runs where OUR infrastructure touches a vault's outbound content, once
    /// per trust domain. `domain` MUST be derived by the caller (the hosted
    /// relay / connector edge) from the connection's infrastructure trust
    /// domain, NEVER from a vault-attested "already classified" receipt (R9).
    ///
    /// * [`RelayTrustDomain::CloudVault`] — trusts the vault-side floor pass; no
    ///   re-run ([`RelayFloorPass::TrustedVaultSide`]).
    /// * [`RelayTrustDomain::LocalViaHostedConnector`] — runs the Rung-1
    ///   deterministic floor tripwire on 100% of relayed content, FLOOR ONLY:
    ///   the owner custom tier is never assembled or evaluated here.
    /// * [`RelayTrustDomain::LocalViaByoConnector`] — nothing transits us; no
    ///   pass runs ([`RelayFloorPass::NotRelayedByUs`]).
    ///
    /// This never touches the input side and never runs the owner custom tier;
    /// it can only ADD floor coverage on the hosted-relay path, never weaken an
    /// existing floor or deny path.
    ///
    /// Advisory: this classifies but does not itself halt the relay — the caller
    /// must honor [`RelayFloorPass::must_halt_relay`]. Every relay decision that
    /// blocks or skips is recorded as an audit receipt (a clean, non-degraded
    /// `Allow` is not), so a relay block or a mis-labeled skip is never silent.
    /// A returned `Err` means infrastructure misuse only (unresolvable/malformed
    /// local policy state or a failed receipt write).
    pub fn relay_boundary_floor_pass(
        &self,
        request: PolicyClassifyRequest,
        domain: RelayTrustDomain,
    ) -> Result<RelayFloorPass> {
        self.relay_boundary_floor_pass_with_config(request, domain, &PolicyModelConfig::default())
    }

    pub fn relay_boundary_floor_pass_with_config(
        &self,
        request: PolicyClassifyRequest,
        domain: RelayTrustDomain,
        config: &PolicyModelConfig,
    ) -> Result<RelayFloorPass> {
        let pass = match domain {
            RelayTrustDomain::CloudVault => RelayFloorPass::TrustedVaultSide,
            RelayTrustDomain::LocalViaByoConnector => RelayFloorPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                // Deterministic tier only: needs the binding, not the model
                // prompt, so it never renders the floor rubric into a prompt.
                let binding = self.relay_floor_only_binding(&request, config)?;
                let verdict = relay_floor_rung1_verdict(&request, binding, config);
                RelayFloorPass::FloorClassified {
                    verdict,
                    degraded: None,
                }
            }
        };
        self.record_relay_floor_receipt(&request, domain, &pass, config)?;
        Ok(pass)
    }

    /// B11-2 / R9 relay-boundary FLOOR pass with the safeguard model available
    /// for a flagged span.
    ///
    /// **Caller contract:** invoke this ONLY for a span the connector edge has
    /// already flagged for model review. Rung-1 is not extended to emit flags
    /// (B11 R8.3), so the flag heuristic is the edge's responsibility (the
    /// out-of-scope connector lane) — this method does not re-derive it. Rung-1
    /// still runs deterministically on 100% of the hosted-relay path via
    /// [`relay_boundary_floor_pass`]; here it runs again as the backstop and the
    /// FLOOR-ONLY safeguard model adjudicates the flagged span only when Rung-1
    /// did not already resolve it. The owner custom tier is never assembled, so
    /// the model classifies against floor rows only and a relay verdict can
    /// never be [`PolicyVerdictCategory::OwnerPolicy`]; a model verdict whose
    /// fixed category was not assembled into the floor rubric is treated as an
    /// off-floor (unusable) response and degrades rather than taking effect.
    ///
    /// Failure is symmetric and never below the floor: if the safeguard model is
    /// unavailable OR its response is unusable (unparseable, or an off-floor
    /// verdict such as a hallucinated owner-policy row), the pass falls back to
    /// the Rung-1 deterministic result and marks itself `degraded`. A returned
    /// `Err` therefore means infrastructure misuse only — unresolvable/malformed
    /// local policy state or a failed receipt write — never a model outcome.
    ///
    /// `pub(crate)` by design (R6): this takes an arbitrary safeguard backend,
    /// and on our relay infrastructure the classifier binding must be OURS —
    /// swapping in a weak model there would weaken enforcement of our own legal
    /// duty. Model freedom is a local/self-host/BYO property, so only first-party
    /// code that pins our classifier may drive the model tier; the public relay
    /// API is the deterministic Rung-1 pass.
    ///
    /// Reserved crate API: no first-party caller exists yet (the connector-edge
    /// wiring is a follow-up ticket), so it is exercised only by tests today.
    #[allow(dead_code)]
    pub(crate) async fn relay_boundary_floor_pass_with_backend(
        &self,
        request: PolicyClassifyRequest,
        domain: RelayTrustDomain,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<RelayFloorPass> {
        let pass = match domain {
            RelayTrustDomain::CloudVault => RelayFloorPass::TrustedVaultSide,
            RelayTrustDomain::LocalViaByoConnector => RelayFloorPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                let context = self.policy_model_floor_only_context(&request, config)?;
                let binding = context.binding;
                if let Some(local) = classify_from_local_floor(&request) {
                    // Rung-1 caught it deterministically; the model tier is not consulted.
                    RelayFloorPass::FloorClassified {
                        verdict: PolicyClassifyVerdict {
                            binding,
                            safeguard_binding: config.safeguard_binding.selector(),
                            ..local
                        },
                        degraded: None,
                    }
                } else {
                    // Rung-1 is clean; the FLOOR-ONLY model is the flagged-span
                    // nuance layer. Any model failure degrades to the Rung-1
                    // result, marked -- never below the floor.
                    match backend
                        .generate(context.prompt.llm_request(config), lease)
                        .await
                    {
                        Ok(response) => match parse_policy_model_response(
                            &response,
                            &context.prompt.rubric_rows,
                            binding,
                            config,
                        ) {
                            // FLOOR ONLY: accept a fixed-category verdict only if
                            // that category was actually assembled into the floor
                            // rubric shown to the model. A closed-taxonomy
                            // category the floor never listed (e.g. crisis/medical
                            // with no vault floor row) is off-floor for this pass
                            // and is treated as unusable — the relay enforces the
                            // assembled floor, not the model's full taxonomy.
                            Ok(verdict)
                                if relay_category_in_floor_rubric(
                                    &verdict.category,
                                    &context.prompt.rubric_rows,
                                ) =>
                            {
                                RelayFloorPass::FloorClassified {
                                    verdict,
                                    degraded: None,
                                }
                            }
                            _off_floor_or_err => RelayFloorPass::FloorClassified {
                                verdict: relay_floor_clean_verdict(binding, config),
                                degraded: Some(RelayFloorDegrade::SafeguardModelResponseUnusable),
                            },
                        },
                        Err(_unavailable) => RelayFloorPass::FloorClassified {
                            verdict: relay_floor_clean_verdict(binding, config),
                            degraded: Some(RelayFloorDegrade::SafeguardModelUnavailable),
                        },
                    }
                }
            }
        };
        self.record_relay_floor_receipt(&request, domain, &pass, config)?;
        Ok(pass)
    }

    fn policy_model_floor_only_context(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelFloorOnlyContext> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "policy manifest is malformed for relay-boundary floor pass".to_owned(),
            ));
        }
        // FLOOR ONLY: owner-policy rows are never assembled here, so a dropped or
        // forged owner-rows manifest cannot block or misfire the floor pass.
        let prompt = build_policy_classify_prompt_floor_only(request, &policy)?;
        let binding = content_binding(request, &policy, config)?;
        Ok(PolicyModelFloorOnlyContext { prompt, binding })
    }

    /// Binding + fail-closed check for the deterministic (Rung-1) relay pass,
    /// without rendering the model prompt. The floor rows are still assembled and
    /// validated (so a malformed legal-floor row fails closed exactly as the
    /// model path does — no strictness is lost), but the prompt string is never
    /// built because the deterministic path does not call the model.
    fn relay_floor_only_binding(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyContentBinding> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "policy manifest is malformed for relay-boundary floor pass".to_owned(),
            ));
        }
        // Validate the floor rows (fail closed on a malformed legal-floor row)
        // without paying for the prompt render the deterministic path never uses.
        let _validated_floor_rows = rubric_rows_floor_only(&policy)?;
        content_binding(request, &policy, config)
    }

    /// Writes the B11-2 / R9 relay-boundary audit receipt. Called from both
    /// relay paths: a hosted-relay classify that blocks/routes/rewords or that
    /// degraded, and a trust-domain SKIP (trusted cloud, untouched BYO), are all
    /// recorded so a relay block or a mis-labeled skip is never silent. A clean,
    /// non-degraded relay `Allow` carries no enforcement signal and is not
    /// receipted (matching the vault-egress allow convention). The receipt
    /// records the trust domain, whether classify ran or was skipped, and the
    /// content binding.
    fn record_relay_floor_receipt(
        &self,
        request: &PolicyClassifyRequest,
        domain: RelayTrustDomain,
        pass: &RelayFloorPass,
        config: &PolicyModelConfig,
    ) -> Result<()> {
        // The gate decision ledger requires every reason code to be namespaced
        // under `gate.` (vet_gate_decision_record), so relay codes ride there.
        let mut reason_codes = vec![
            format!("gate.relay.trust_domain.{}", domain.as_str()),
            if pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
        ];
        if let Some(degrade) = pass.degraded() {
            reason_codes.push(format!("gate.relay.degraded.{}", degrade.as_str()));
        }
        let (outcome, receipt_verdict) = match pass {
            RelayFloorPass::FloorClassified { verdict, degraded } => {
                if verdict.decision == PolicyClassifyDecision::Allow && degraded.is_none() {
                    return Ok(());
                }
                reason_codes.extend(policy_model_reason_codes(verdict));
                (
                    format!("relay_floor_{}", relay_outcome_suffix(verdict.decision)),
                    verdict.clone(),
                )
            }
            RelayFloorPass::TrustedVaultSide => (
                "relay_trusted_vault_side".to_owned(),
                relay_skip_verdict(request, config),
            ),
            RelayFloorPass::NotRelayedByUs => (
                "relay_not_relayed".to_owned(),
                relay_skip_verdict(request, config),
            ),
        };
        self.append_policy_model_gate_receipt(
            request,
            &receipt_verdict,
            &outcome,
            reason_codes,
            Vec::new(),
        )?;
        Ok(())
    }

    fn append_policy_model_gate_receipt(
        &self,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        system_notices: Vec<GateSystemNoticeRecord>,
    ) -> Result<String> {
        let decision_id = GateDecisionId::now();
        let mut wtxn = self.store.env.write_txn()?;
        self.store.append_gate_decision_in_txn(
            &mut wtxn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at: crate::unix_seconds_now(),
                outcome: outcome.to_owned(),
                reason_codes,
                receipt_reasons: Vec::new(),
                system_notices,
                actor_class: "policy_model".to_owned(),
                actor_ref: request.caller_ref.clone(),
                content_kind: request.subject.as_str().to_owned(),
                policy_manifest_version: gate::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: None,
                diff_handle: verdict.binding.content_hash.to_vec(),
                read_frontier_hash: verdict.binding.read_frontier_hash,
            },
        )?;
        wtxn.commit()?;
        Ok(format!("gate:{}", decision_id.to_hex()))
    }

    pub fn policy_model_prompt(
        &self,
        request: &PolicyClassifyRequest,
    ) -> Result<PolicyClassifyPrompt> {
        self.policy_model_prompt_with_config(request, &PolicyModelConfig::default())
    }

    pub fn policy_model_prompt_with_config(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyPrompt> {
        let context = self.policy_model_context(request, config)?;
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }
        Ok(context.prompt)
    }

    fn policy_model_context(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelContext> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "policy manifest is malformed for policy model classify".to_owned(),
            ));
        }
        let prompt = build_policy_classify_prompt_for_policy(request, &policy)?;
        let binding = content_binding(request, &policy, config)?;
        Ok(PolicyModelContext {
            prompt,
            binding,
            owner_policy_rows_dropped: policy.owner_policy_rows_dropped(),
        })
    }

    pub fn policy_model_llm_request(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<LlmRequest> {
        Ok(self
            .policy_model_prompt_with_config(request, config)?
            .llm_request(config))
    }

    pub fn policy_model_verdict_is_stale(
        &self,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
    ) -> Result<bool> {
        self.policy_model_verdict_is_stale_with_config(
            verdict,
            request,
            &PolicyModelConfig::default(),
        )
    }

    pub fn policy_model_verdict_is_stale_with_config(
        &self,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed()
            || policy.owner_policy_rows_dropped()
        {
            return Ok(true);
        }
        Ok(
            verdict.binding != content_binding(request, &policy, config)?
                || verdict.safeguard_binding != config.safeguard_binding.selector(),
        )
    }
}

struct PolicyModelContext {
    prompt: PolicyClassifyPrompt,
    binding: PolicyContentBinding,
    owner_policy_rows_dropped: bool,
}

struct PolicyModelFloorOnlyContext {
    prompt: PolicyClassifyPrompt,
    binding: PolicyContentBinding,
}

struct PolicyBackendEnforcement<'a> {
    config: &'a PolicyModelConfig,
    backend: &'a dyn LlmBackend,
    lease: &'a BudgetLease,
}

fn dropped_owner_policy_rows_error() -> Error {
    Error::InvalidConfig(
        "policy manifest owner_policy_rows were dropped for policy model classify".to_owned(),
    )
}

fn policy_model_reason_codes(verdict: &PolicyClassifyVerdict) -> Vec<String> {
    let decision = match verdict.decision {
        PolicyClassifyDecision::Allow => "allow",
        PolicyClassifyDecision::Block => "block",
        PolicyClassifyDecision::RouteToHelp => "route_to_help",
        PolicyClassifyDecision::RewordRetry => "reword_retry",
    };
    let mut reasons = vec![format!("gate.policy_model.{decision}")];
    reasons.push(policy_model_category_reason(&verdict.category).to_owned());
    reasons
}

fn policy_model_category_reason(category: &PolicyVerdictCategory) -> &'static str {
    match category {
        PolicyVerdictCategory::None => "gate.policy_model.category.none",
        PolicyVerdictCategory::LegalFloor(_) => "gate.policy_model.category.legal_floor",
        PolicyVerdictCategory::Crisis(_) => "gate.policy_model.category.crisis",
        PolicyVerdictCategory::AgeGate(_) => "gate.policy_model.category.age_gate",
        PolicyVerdictCategory::OwnerPolicy { .. } => "gate.policy_model.category.owner_policy",
    }
}

fn default_system_notice(notices: &[GateSystemNoticeRecord]) -> Option<String> {
    notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        .or_else(|| {
            notices
                .iter()
                .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_ALL)
        })
        .or_else(|| notices.first())
        .map(|notice| notice.body.clone())
}

fn block_system_notices(verdict: &PolicyClassifyVerdict) -> Vec<GateSystemNoticeRecord> {
    match &verdict.category {
        PolicyVerdictCategory::OwnerPolicy { row_ref } => {
            let owner_notice_row_ref = safe_system_notice_row_ref(row_ref);
            let owner_notice_body = owner_notice_row_ref
                .as_deref()
                .map(|row_ref| {
                    format!(
                        "Oneiron blocked this outbound content because your policy row {row_ref} asked it to."
                    )
                })
                .unwrap_or_else(|| POLICY_MODEL_OWNER_BLOCK_NOTICE.to_owned());
            vec![
                system_notice(
                    SYSTEM_NOTICE_TYPE_BLOCK,
                    SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY,
                    POLICY_MODEL_OWNER_BLOCK_THIRD_PARTY_NOTICE.to_owned(),
                    None,
                    None,
                ),
                system_notice(
                    SYSTEM_NOTICE_TYPE_BLOCK,
                    SYSTEM_NOTICE_AUDIENCE_OWNER,
                    owner_notice_body,
                    owner_notice_row_ref,
                    Some(GateSystemNoticeAction {
                        label: "Change policy setting".to_owned(),
                        target: OWNER_POLICY_SETTINGS_DEEP_LINK.to_owned(),
                    }),
                ),
            ]
        }
        _ => vec![system_notice(
            SYSTEM_NOTICE_TYPE_BLOCK,
            SYSTEM_NOTICE_AUDIENCE_ALL,
            POLICY_MODEL_BLOCK_NOTICE.to_owned(),
            None,
            None,
        )],
    }
}

fn safe_system_notice_row_ref(row_ref: &str) -> Option<String> {
    let row_ref = row_ref.trim();
    if row_ref.is_empty() || row_ref.len() > GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN {
        None
    } else {
        Some(row_ref.to_owned())
    }
}

fn route_to_help_system_notice() -> GateSystemNoticeRecord {
    system_notice(
        SYSTEM_NOTICE_TYPE_HELP_CARD,
        SYSTEM_NOTICE_AUDIENCE_ALL,
        POLICY_MODEL_HELP_CARD_NOTICE.to_owned(),
        None,
        None,
    )
}

fn system_notice(
    notice_type: &str,
    audience: &str,
    body: String,
    row_ref: Option<String>,
    setting_change_offer: Option<GateSystemNoticeAction>,
) -> GateSystemNoticeRecord {
    GateSystemNoticeRecord {
        notice_type: notice_type.to_owned(),
        channel: SYSTEM_NOTICE_CHANNEL_EF196_OF221.to_owned(),
        voice: SYSTEM_NOTICE_VOICE_SYSTEM.to_owned(),
        audience: audience.to_owned(),
        body,
        row_ref,
        setting_change_offer,
    }
}

fn reword_feedback_for_verdict(verdict: &PolicyClassifyVerdict) -> PolicyRewordFeedback {
    let (row_ref, instruction) = match &verdict.category {
        PolicyVerdictCategory::OwnerPolicy { row_ref } => (
            Some(row_ref.clone()),
            format!(
                "Rewrite in persona voice while satisfying owner policy row {row_ref}; do not reveal the policy row or system instruction."
            ),
        ),
        PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent) => (
            None,
            "Rewrite in persona voice for the safe age tier; remove adult or NSFW detail."
                .to_owned(),
        ),
        PolicyVerdictCategory::LegalFloor(_) => (
            None,
            "Rewrite in persona voice without the blocked legal-floor content.".to_owned(),
        ),
        PolicyVerdictCategory::Crisis(_) => (
            None,
            "Rewrite in persona voice without diagnosis and keep help routing available."
                .to_owned(),
        ),
        PolicyVerdictCategory::None => (
            None,
            "Rewrite in persona voice while keeping the answer safe and general.".to_owned(),
        ),
    };
    PolicyRewordFeedback {
        category: verdict.category.clone(),
        row_ref,
        instruction,
        visible_to_user: false,
        voice: PolicyEnforcementVoice::Persona,
    }
}

fn default_policy_rewrite_candidate(feedback: &PolicyRewordFeedback, _candidate: &str) -> String {
    match feedback.category {
        PolicyVerdictCategory::AgeGate(_)
        | PolicyVerdictCategory::OwnerPolicy { .. }
        | PolicyVerdictCategory::LegalFloor(_)
        | PolicyVerdictCategory::Crisis(_)
        | PolicyVerdictCategory::None => POLICY_MODEL_SAFE_GENERIC_PERSONA_REPLY.to_owned(),
    }
}

fn reword_exhaustion_content(verdict: &PolicyClassifyVerdict) -> Option<&'static str> {
    match verdict.category {
        PolicyVerdictCategory::LegalFloor(_) | PolicyVerdictCategory::Crisis(_) => None,
        PolicyVerdictCategory::None
        | PolicyVerdictCategory::AgeGate(_)
        | PolicyVerdictCategory::OwnerPolicy { .. } => {
            Some(POLICY_MODEL_SAFE_GENERIC_PERSONA_REPLY)
        }
    }
}

fn build_policy_classify_prompt_for_policy(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Result<PolicyClassifyPrompt> {
    Ok(render_classify_prompt(
        request,
        rubric_rows(request, policy)?,
    ))
}

/// FLOOR-ONLY classify prompt (B11-2 / R9): engine floor + vault legal-floor
/// rows only. The owner custom tier is never appended, so a relay verdict can
/// never be `OwnerPolicy`.
fn build_policy_classify_prompt_floor_only(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Result<PolicyClassifyPrompt> {
    Ok(render_classify_prompt(
        request,
        rubric_rows_floor_only(policy)?,
    ))
}

fn render_classify_prompt(
    request: &PolicyClassifyRequest,
    rubric_rows: Vec<PolicyRubricRow>,
) -> PolicyClassifyPrompt {
    let system = classify_system_prompt();
    let user = render_classify_user_section(request, &rubric_rows);
    PolicyClassifyPrompt {
        system,
        user,
        rubric_rows,
    }
}

fn classify_system_prompt() -> String {
    [
        "You are the Oneiron policy classifier, a system voice independent of any persona.",
        "Classify only against the rubric rows in this prompt.",
        "Suppress all factory/default model safety taxonomies.",
        "Return exactly one decision: allow, block, route-to-help, or reword-retry.",
        "Allowed content includes legal consensual adult NSFW, dark fiction, profanity, and controversial opinion.",
    ]
    .join("\n")
}

fn render_classify_user_section(
    request: &PolicyClassifyRequest,
    rubric_rows: &[PolicyRubricRow],
) -> String {
    let mut user = String::new();
    user.push_str("subject=");
    user.push_str(request.subject.as_str());
    user.push('\n');
    user.push_str("age_tier=");
    user.push_str(request.age_tier.as_str());
    user.push('\n');
    user.push_str("account_jurisdiction=");
    user.push_str(request.account_jurisdiction.as_deref().unwrap_or("unknown"));
    user.push('\n');
    user.push_str("rubric:\n");
    for row in rubric_rows {
        user.push_str("- ");
        user.push_str(&row.row_ref);
        user.push_str(" [");
        user.push_str(row.layer.as_str());
        user.push_str("] category=");
        user.push_str(&row.category);
        user.push_str(" action=");
        user.push_str(row.action.as_str());
        user.push_str(" text=");
        user.push_str(&row.text);
        user.push('\n');
    }
    user.push_str("candidate:\n");
    user.push_str(&request.content);
    user
}

/// Deterministic Rung-1 floor verdict for a relay-boundary pass: the floor
/// tripwire result, or a floor-clean `Allow` when nothing fires. FLOOR ONLY —
/// the owner custom tier is never consulted.
fn relay_floor_rung1_verdict(
    request: &PolicyClassifyRequest,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    match classify_from_local_floor(request) {
        Some(local) => PolicyClassifyVerdict {
            binding,
            safeguard_binding: config.safeguard_binding.selector(),
            ..local
        },
        None => relay_floor_clean_verdict(binding, config),
    }
}

/// A floor-clean relay verdict (`Allow`/`None`): Rung-1 found nothing, or a
/// degraded model tier fell back to the deterministic result.
fn relay_floor_clean_verdict(
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    verdict(
        PolicyClassifyDecision::Allow,
        PolicyVerdictCategory::None,
        PolicyConfidence::HIGH,
        binding,
        config,
    )
}

/// Synthetic receipt verdict for a trust-domain SKIP. A skip never classifies
/// against the manifest, so the receipt binds to a content-only hash with a zero
/// policy frontier — an honest "did not run against policy state" marker.
fn relay_skip_verdict(
    request: &PolicyClassifyRequest,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    relay_floor_clean_verdict(relay_skip_content_binding(request), config)
}

fn relay_skip_content_binding(request: &PolicyClassifyRequest) -> PolicyContentBinding {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.policy_model.relay.skip.content.v1");
    hash_binding_str(&mut hasher, "subject", request.subject.as_str());
    hash_binding_str(&mut hasher, "content", &request.content);
    PolicyContentBinding {
        content_hash: hasher.finalize().into(),
        read_frontier_hash: [0; 32],
    }
}

fn relay_outcome_suffix(decision: PolicyClassifyDecision) -> &'static str {
    match decision {
        PolicyClassifyDecision::Allow => "allow",
        PolicyClassifyDecision::Block => "block",
        PolicyClassifyDecision::RouteToHelp => "route_to_help",
        PolicyClassifyDecision::RewordRetry => "reword_retry",
    }
}

/// Whether a relay model verdict's category was actually assembled into the
/// floor-only rubric shown to the model. `None` (allow) needs no row; an owner
/// verdict is never valid on the floor-only path. A fixed category is honored
/// only when a rubric row carries it — engine-floor categories always qualify
/// (they are in every rubric), while a closed-taxonomy category the floor did
/// not list (e.g. `crisis/medical`/`crisis/harm_to_others` with no vault floor
/// row) does not, so the relay never enforces a verdict outside its floor.
fn relay_category_in_floor_rubric(
    category: &PolicyVerdictCategory,
    rubric_rows: &[PolicyRubricRow],
) -> bool {
    let key = match category {
        PolicyVerdictCategory::None => return true,
        PolicyVerdictCategory::OwnerPolicy { .. } => return false,
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization) => {
            "legal_floor/minor_sexualization"
        }
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::Ncii) => "legal_floor/ncii",
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime) => {
            "legal_floor/serious_crime"
        }
        PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::Jurisdiction { .. }) => {
            "legal_floor/jurisdiction"
        }
        PolicyVerdictCategory::Crisis(CrisisSubclass::SelfHarm) => "crisis/self_harm",
        PolicyVerdictCategory::Crisis(CrisisSubclass::Medical) => "crisis/medical",
        PolicyVerdictCategory::Crisis(CrisisSubclass::HarmToOthers) => "crisis/harm_to_others",
        PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent) => "age_gate/adult_content",
    };
    rubric_rows.iter().any(|row| row.category == key)
}

impl PolicyRubricLayer {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EngineFloor => "engine_floor",
            Self::VaultFloor => "vault_floor",
            Self::OwnerPolicy => "owner_policy",
        }
    }
}

fn rubric_rows(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Result<Vec<PolicyRubricRow>> {
    let mut rows = rubric_rows_floor_only(policy)?;
    for row in policy.active_owner_policy_rows(request.world_ref.as_deref()) {
        rows.push(PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            layer: PolicyRubricLayer::OwnerPolicy,
            category: "owner_policy".to_owned(),
            action: if row.block {
                PolicyClassifyDecision::Block
            } else {
                PolicyClassifyDecision::RewordRetry
            },
            text: row.text.clone(),
        });
    }
    Ok(rows)
}

/// The floor rubric only — engine floor + active vault legal-floor rows, no
/// owner custom tier. Shared by the vault-egress classify and the B11-2 relay
/// floor pass so the two never drift apart.
fn rubric_rows_floor_only(policy: &PolicyManifestResolution) -> Result<Vec<PolicyRubricRow>> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for row in engine_floor_rows() {
        seen.insert(row.row_ref.clone());
        rows.push(row);
    }
    for row in policy.legal_floor_rows().iter().filter(|row| row.active) {
        if seen.insert(row.row_ref.clone()) {
            let category = combined_floor_category(&row.category, &row.subcategory)?;
            let action = action_from_manifest(&row.action)?;
            validate_fixed_category_action(&category, action)?;
            rows.push(PolicyRubricRow {
                row_ref: row.row_ref.clone(),
                layer: PolicyRubricLayer::VaultFloor,
                category,
                action,
                text: row.text.clone(),
            });
        }
    }
    Ok(rows)
}

fn engine_floor_rows() -> Vec<PolicyRubricRow> {
    vec![
        PolicyRubricRow {
            row_ref: "engine:minor-sexualization".to_owned(),
            layer: PolicyRubricLayer::EngineFloor,
            category: "legal_floor/minor_sexualization".to_owned(),
            action: PolicyClassifyDecision::Block,
            text: "Block sexual content involving minors or realistic depictions of real minors."
                .to_owned(),
        },
        PolicyRubricRow {
            row_ref: "engine:ncii".to_owned(),
            layer: PolicyRubricLayer::EngineFloor,
            category: "legal_floor/ncii".to_owned(),
            action: PolicyClassifyDecision::Block,
            text: "Block non-consensual intimate imagery or deepfakes of a real person.".to_owned(),
        },
        PolicyRubricRow {
            row_ref: "engine:serious-crime".to_owned(),
            layer: PolicyRubricLayer::EngineFloor,
            category: "legal_floor/serious_crime".to_owned(),
            action: PolicyClassifyDecision::Block,
            text: "Block credible facilitation of serious violence, weapons, explosives, or mass harm."
                .to_owned(),
        },
        PolicyRubricRow {
            row_ref: "engine:self-harm".to_owned(),
            layer: PolicyRubricLayer::EngineFloor,
            category: "crisis/self_harm".to_owned(),
            action: PolicyClassifyDecision::RouteToHelp,
            text: "Route credible imminent self-harm or suicide risk to help.".to_owned(),
        },
        PolicyRubricRow {
            row_ref: "engine:adult-content-age-gate".to_owned(),
            layer: PolicyRubricLayer::EngineFloor,
            category: "age_gate/adult_content".to_owned(),
            action: PolicyClassifyDecision::RewordRetry,
            text: "Reword adult or NSFW output when the account age tier does not permit it."
                .to_owned(),
        },
    ]
}

fn combined_floor_category(category: &str, subcategory: &str) -> Result<String> {
    let combined = format!("{category}/{subcategory}");
    if fixed_category(&combined).is_some() {
        Ok(combined)
    } else {
        Err(Error::InvalidConfig(format!(
            "unsupported policy model floor category {combined}"
        )))
    }
}

fn action_from_manifest(action: &str) -> Result<PolicyClassifyDecision> {
    match action {
        "block" => Ok(PolicyClassifyDecision::Block),
        "route_to_help" | "route-to-help" => Ok(PolicyClassifyDecision::RouteToHelp),
        "reword_retry" | "reword-retry" => Ok(PolicyClassifyDecision::RewordRetry),
        other => Err(Error::InvalidConfig(format!(
            "unsupported policy model row action {other}"
        ))),
    }
}

fn validate_fixed_category_action(category: &str, action: PolicyClassifyDecision) -> Result<()> {
    let Some((_, expected)) = fixed_category(category) else {
        return Err(Error::InvalidConfig(format!(
            "unsupported policy model category {category}"
        )));
    };
    if action != expected {
        return Err(Error::InvalidConfig(format!(
            "policy model category {category} requires action {} but manifest used {}",
            expected.as_str(),
            action.as_str()
        )));
    }
    Ok(())
}

fn classify_from_local_floor(request: &PolicyClassifyRequest) -> Option<PolicyClassifyVerdict> {
    let normalized = normalize(&request.content);
    if is_minor_sexualization(&normalized) {
        return Some(local_verdict(
            PolicyClassifyDecision::Block,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization),
            PolicyConfidence::CERTAIN,
        ));
    }
    if contains_any(
        &normalized,
        &[
            "non consensual intimate",
            "non-consensual intimate",
            "revenge porn",
            "leaked nude",
            "deepfake nude",
        ],
    ) {
        return Some(local_verdict(
            PolicyClassifyDecision::Block,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::Ncii),
            PolicyConfidence::CERTAIN,
        ));
    }
    if contains_any(
        &normalized,
        &[
            "build a bomb",
            "make a bomb",
            "make explosives",
            "mass harm",
            "terrorist attack",
            "3d print a ghost gun",
        ],
    ) {
        return Some(local_verdict(
            PolicyClassifyDecision::Block,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime),
            PolicyConfidence::CERTAIN,
        ));
    }
    if contains_any(
        &normalized,
        &[
            "kill myself",
            "end my life",
            "suicide plan",
            "hurt myself tonight",
        ],
    ) {
        return Some(local_verdict(
            PolicyClassifyDecision::RouteToHelp,
            PolicyVerdictCategory::Crisis(CrisisSubclass::SelfHarm),
            PolicyConfidence::HIGH,
        ));
    }
    if is_adult_content(&normalized) && !request.age_tier.permits_adult_content() {
        return Some(local_verdict(
            PolicyClassifyDecision::RewordRetry,
            PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent),
            PolicyConfidence::HIGH,
        ));
    }
    None
}

fn local_verdict(
    decision: PolicyClassifyDecision,
    category: PolicyVerdictCategory,
    confidence: PolicyConfidence,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict {
        decision,
        category,
        confidence,
        binding: PolicyContentBinding {
            content_hash: [0; 32],
            read_frontier_hash: [0; 32],
        },
        safeguard_binding: String::new(),
    }
}

fn classify_without_backend_from_rubric(
    rubric_rows: &[PolicyRubricRow],
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    if let Some(row) = rubric_rows
        .iter()
        .find(|row| row.layer == PolicyRubricLayer::OwnerPolicy)
    {
        return verdict(
            row.action,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: row.row_ref.clone(),
            },
            PolicyConfidence::MEDIUM,
            binding,
            config,
        );
    }
    verdict(
        PolicyClassifyDecision::Allow,
        PolicyVerdictCategory::None,
        PolicyConfidence::HIGH,
        binding,
        config,
    )
}

fn verdict(
    decision: PolicyClassifyDecision,
    category: PolicyVerdictCategory,
    confidence: PolicyConfidence,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict {
        decision,
        category,
        confidence,
        binding,
        safeguard_binding: config.safeguard_binding.selector(),
    }
}

fn is_minor_sexualization(normalized: &str) -> bool {
    normalized.contains("csam")
        || (contains_any(
            normalized,
            &[
                "minor",
                "minors",
                "child",
                "children",
                "underage",
                "kid",
                "kids",
                "teen",
                "13 year old",
                "14 year old",
                "15 year old",
            ],
        ) && contains_any(
            normalized,
            &[
                "sex", "sexual", "nude", "nudes", "explicit", "erotic", "porn", "nsfw",
            ],
        ))
}

fn is_adult_content(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "consensual adult nsfw",
            "adult nsfw",
            "explicit sex",
            "erotic",
            "porn",
            "nude",
            "sexual roleplay",
        ],
    )
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn content_binding(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
    config: &PolicyModelConfig,
) -> Result<PolicyContentBinding> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.policy_model.classify.content.v1");
    hash_binding_str(&mut hasher, "subject", request.subject.as_str());
    hash_binding_str(&mut hasher, "content", &request.content);
    hash_binding_str(&mut hasher, "age_tier", request.age_tier.as_str());
    hash_binding_opt_str(
        &mut hasher,
        "account_jurisdiction",
        request.account_jurisdiction.as_deref(),
    );
    hash_binding_opt_str(&mut hasher, "world_ref", request.world_ref.as_deref());
    hash_binding_str(
        &mut hasher,
        "safeguard_binding",
        &config.safeguard_binding.selector(),
    );
    Ok(PolicyContentBinding {
        content_hash: hasher.finalize().into(),
        read_frontier_hash: policy.read_frontier_hash()?,
    })
}

fn hash_binding_opt_str(hasher: &mut Sha256, label: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_binding_str(hasher, label, "some");
            hash_binding_str(hasher, label, value);
        }
        None => hash_binding_str(hasher, label, "none"),
    }
}

fn hash_binding_str(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(value.len().to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.update([0xff]);
}

#[derive(Debug, Deserialize)]
struct PolicyModelResponseWire {
    decision: PolicyClassifyDecision,
    category: String,
    #[serde(default)]
    row_ref: Option<String>,
    confidence: f32,
    hedge_bucket: PolicyHedgeBucket,
}

fn parse_policy_model_response(
    response: &LlmResponse,
    rubric_rows: &[PolicyRubricRow],
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> Result<PolicyClassifyVerdict> {
    let text = response_text(response).ok_or_else(|| {
        Error::InvalidConfig("policy model response contained no text part".to_owned())
    })?;
    let wire: PolicyModelResponseWire = serde_json::from_str(strip_json_fence(text))
        .map_err(|error| Error::InvalidConfig(format!("invalid policy model JSON: {error}")))?;
    if !wire.confidence.is_finite() || !(0.0..=1.0).contains(&wire.confidence) {
        return Err(Error::InvalidConfig(
            "policy model confidence must be finite and in [0, 1]".to_owned(),
        ));
    }

    let category = model_category(&wire, rubric_rows)?;
    Ok(verdict(
        wire.decision,
        category,
        PolicyConfidence {
            calibrated: wire.confidence,
            hedge_bucket: wire.hedge_bucket,
        },
        binding,
        config,
    ))
}

fn response_text(response: &LlmResponse) -> Option<&str> {
    response.message.content.iter().find_map(|part| match part {
        ContentPart::Text { text } if !text.trim().is_empty() => Some(text.as_str()),
        _ => None,
    })
}

fn strip_json_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_fence) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let after_header = after_fence
        .split_once('\n')
        .map_or(after_fence, |(_, rest)| rest);
    after_header
        .strip_suffix("```")
        .map_or(after_header, str::trim)
}

fn model_category(
    wire: &PolicyModelResponseWire,
    rubric_rows: &[PolicyRubricRow],
) -> Result<PolicyVerdictCategory> {
    if let Some((category, expected_action)) = fixed_category(&wire.category) {
        if wire.row_ref.is_some() {
            return Err(Error::InvalidConfig(format!(
                "policy model {} category must not include row_ref",
                wire.category
            )));
        }
        if wire.decision != expected_action {
            return Err(Error::InvalidConfig(format!(
                "policy model {} category requires decision {} but response used {}",
                wire.category,
                expected_action.as_str(),
                wire.decision.as_str()
            )));
        }
        return Ok(category);
    }
    match wire.category.as_str() {
        "owner_policy" => owner_policy_category(wire, rubric_rows),
        other => Err(Error::InvalidConfig(format!(
            "unknown policy model category {other}"
        ))),
    }
}

fn fixed_category(category: &str) -> Option<(PolicyVerdictCategory, PolicyClassifyDecision)> {
    match category {
        "none" => Some((PolicyVerdictCategory::None, PolicyClassifyDecision::Allow)),
        "legal_floor/minor_sexualization" => Some((
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization),
            PolicyClassifyDecision::Block,
        )),
        "legal_floor/ncii" => Some((
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::Ncii),
            PolicyClassifyDecision::Block,
        )),
        "legal_floor/serious_crime" => Some((
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::SeriousCrime),
            PolicyClassifyDecision::Block,
        )),
        "crisis/self_harm" => Some((
            PolicyVerdictCategory::Crisis(CrisisSubclass::SelfHarm),
            PolicyClassifyDecision::RouteToHelp,
        )),
        "crisis/medical" => Some((
            PolicyVerdictCategory::Crisis(CrisisSubclass::Medical),
            PolicyClassifyDecision::RouteToHelp,
        )),
        "crisis/harm_to_others" => Some((
            PolicyVerdictCategory::Crisis(CrisisSubclass::HarmToOthers),
            PolicyClassifyDecision::RouteToHelp,
        )),
        "age_gate/adult_content" => Some((
            PolicyVerdictCategory::AgeGate(AgeGateSubclass::AdultContent),
            PolicyClassifyDecision::RewordRetry,
        )),
        _ => None,
    }
}

fn owner_policy_category(
    wire: &PolicyModelResponseWire,
    rubric_rows: &[PolicyRubricRow],
) -> Result<PolicyVerdictCategory> {
    let row_ref = wire
        .row_ref
        .as_deref()
        .ok_or_else(|| Error::InvalidConfig("owner_policy verdict missing row_ref".to_owned()))?;
    let row = rubric_rows
        .iter()
        .find(|row| row.layer == PolicyRubricLayer::OwnerPolicy && row.row_ref == row_ref)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "owner_policy verdict referenced inactive or absent row {row_ref}"
            ))
        })?;
    if wire.decision != row.action {
        return Err(Error::InvalidConfig(format!(
            "owner_policy verdict for {row_ref} used action {} but row action is {}",
            wire.decision.as_str(),
            row.action.as_str()
        )));
    }
    Ok(PolicyVerdictCategory::OwnerPolicy {
        row_ref: row_ref.to_owned(),
    })
}

fn classify_response_schema() -> JsonValue {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["decision", "category", "row_ref", "confidence", "hedge_bucket"],
        "properties": {
            "decision": {
                "type": "string",
                "enum": ["allow", "block", "route-to-help", "reword-retry"]
            },
            "category": {
                "type": "string",
                "enum": [
                    "none",
                    "legal_floor/minor_sexualization",
                    "legal_floor/ncii",
                    "legal_floor/serious_crime",
                    "crisis/self_harm",
                    "crisis/medical",
                    "crisis/harm_to_others",
                    "age_gate/adult_content",
                    "owner_policy"
                ]
            },
            "row_ref": { "type": ["string", "null"] },
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
            "hedge_bucket": {
                "type": "string",
                "enum": ["certain", "high", "medium", "low"]
            }
        }
    })
}

#[cfg(test)]
mod tests;
