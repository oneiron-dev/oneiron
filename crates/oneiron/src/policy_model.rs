//! OF-333 policy-model classify verb.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate::{self, PolicyManifestResolution};
use crate::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_SAFEGUARD_MODEL_BINDING, DeterministicFallback, LlmBackend, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, ModelTierRef, ResponseFormat, SafeguardModelBinding,
};
use crate::types::bytes_to_hex_lower;

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

fn dropped_owner_policy_rows_error() -> Error {
    Error::InvalidConfig(
        "policy manifest owner_policy_rows were dropped for policy model classify".to_owned(),
    )
}

fn build_policy_classify_prompt_for_policy(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Result<PolicyClassifyPrompt> {
    let rubric_rows = rubric_rows(request, policy)?;
    let system = [
        "You are the Oneiron policy classifier, a system voice independent of any persona.",
        "Classify only against the rubric rows in this prompt.",
        "Suppress all factory/default model safety taxonomies.",
        "Return exactly one decision: allow, block, route-to-help, or reword-retry.",
        "Allowed content includes legal consensual adult NSFW, dark fiction, profanity, and controversial opinion.",
    ]
    .join("\n");

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
    for row in &rubric_rows {
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

    Ok(PolicyClassifyPrompt {
        system,
        user,
        rubric_rows,
    })
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
mod tests {
    use super::*;

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use rmpv::Value;
    use tempfile::TempDir;

    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::error::Result;
    use crate::llm::{
        BudgetLease, FatalLlmError, FinishReason, LlmGenerateFuture, LlmInputUsage, LlmOutputUsage,
        LlmResponse, LlmStreamResult, LlmUsage,
    };
    use crate::store::Store;
    use crate::types::{ENTITY_ID_LEN, ENTITY_TYPE_POLICY_MANIFEST, EntityId, VaultConfig};

    fn temp_vault() -> (TempDir, Vault) {
        let tmp = tempfile::tempdir().expect("temp vault dir");
        let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open temp vault");
        (tmp, vault)
    }

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("valid test id")
    }

    fn base_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut entries = vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("policy-model-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (Value::from("rules"), Value::Array(Vec::new())),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("human")),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
        ];
        entries.extend(extra_entries);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
        out
    }

    fn owner_rows(rows: Vec<Value>) -> (Value, Value) {
        (
            Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
            Value::Array(rows),
        )
    }

    fn legal_floor_rows(rows: Vec<Value>) -> (Value, Value) {
        (
            Value::from(gate::POLICY_LEGAL_FLOOR_ROWS_KEY),
            Value::Array(rows),
        )
    }

    fn legal_floor_row(
        row_ref: &str,
        category: &str,
        subcategory: &str,
        action: &str,
        text: &str,
    ) -> Value {
        Value::Map(vec![
            (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
            (
                Value::from(gate::POLICY_ROW_CATEGORY_KEY),
                Value::from(category),
            ),
            (
                Value::from(gate::POLICY_ROW_SUBCATEGORY_KEY),
                Value::from(subcategory),
            ),
            (
                Value::from(gate::POLICY_ROW_ACTION_KEY),
                Value::from(action),
            ),
            (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
            (
                Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                Value::Boolean(true),
            ),
        ])
    }

    fn owner_row(row_ref: &str, text: &str) -> Value {
        Value::Map(vec![
            (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
            (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
            (
                Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                Value::Boolean(true),
            ),
        ])
    }

    fn owner_row_with_action(row_ref: &str, text: &str, action: &str) -> Value {
        Value::Map(vec![
            (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
            (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
            (
                Value::from(gate::POLICY_ROW_ACTION_KEY),
                Value::from(action),
            ),
            (
                Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                Value::Boolean(true),
            ),
        ])
    }

    fn scoped_owner_row(row_ref: &str, text: &str, world_ref: &str) -> Value {
        Value::Map(vec![
            (Value::from(gate::POLICY_ROW_REF_KEY), Value::from(row_ref)),
            (Value::from(gate::POLICY_ROW_TEXT_KEY), Value::from(text)),
            (
                Value::from(gate::POLICY_ROW_WORLD_REF_KEY),
                Value::from(world_ref),
            ),
            (
                Value::from(gate::POLICY_ROW_ACTIVE_KEY),
                Value::Boolean(true),
            ),
        ])
    }

    fn put_policy_manifest_bytes(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = test_id(seed);
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    struct StaticPolicyBackend {
        body: &'static str,
    }

    impl LlmBackend for StaticPolicyBackend {
        fn generate<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            Box::pin(async move {
                Ok(LlmResponse {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![ContentPart::Text {
                            text: self.body.to_owned(),
                        }],
                    },
                    usage: LlmUsage {
                        input: LlmInputUsage::default(),
                        output: LlmOutputUsage::default(),
                        raw_provider: JsonValue::Null,
                    },
                    finish_reason: FinishReason::Stop,
                })
            })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }

    struct RecordingPolicyBackend {
        body: &'static str,
        seen_model: Arc<Mutex<Option<String>>>,
    }

    impl LlmBackend for RecordingPolicyBackend {
        fn generate<'a>(
            &'a self,
            request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            let body = self.body.to_owned();
            *self.seen_model.lock().expect("record model") =
                Some(request.model.as_str().to_owned());
            Box::pin(async move {
                Ok(LlmResponse {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![ContentPart::Text { text: body }],
                    },
                    usage: LlmUsage {
                        input: LlmInputUsage::default(),
                        output: LlmOutputUsage::default(),
                        raw_provider: JsonValue::Null,
                    },
                    finish_reason: FinishReason::Stop,
                })
            })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}

        fn raw_waker() -> RawWaker {
            RawWaker::new(
                std::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
        }

        // SAFETY: the noop waker never dereferences the null data pointer.
        unsafe { Waker::from_raw(raw_waker()) }
    }

    #[test]
    fn classify_returns_one_of_four() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let cases = [
            (
                "consensual adult nsfw between verified adults",
                PolicyAgeTier::Adult,
            ),
            ("sexualized minor nude request", PolicyAgeTier::Adult),
            ("I might kill myself tonight", PolicyAgeTier::Adult),
            ("adult nsfw reply", PolicyAgeTier::Unverified),
        ];
        for (content, age_tier) in cases {
            let verdict = vault.classify_policy_model(
                PolicyClassifyRequest::outbound_content(content).with_age_tier(age_tier),
            )?;
            assert!(
                matches!(
                    verdict.decision_str(),
                    "allow" | "block" | "route-to-help" | "reword-retry"
                ),
                "unexpected decision {:?}",
                verdict.decision
            );
        }
        Ok(())
    }

    #[test]
    fn policy_as_rubric_allows_legal_adult_nsfw_and_blocks_minor_sexualization() -> Result<()> {
        let (_tmp, vault) = temp_vault();

        let adult = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content(
                "consensual adult nsfw scene between verified adults",
            )
            .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(adult.decision, PolicyClassifyDecision::Allow);
        assert_eq!(adult.category, PolicyVerdictCategory::None);

        let minor = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content("explicit sexual image of an underage minor")
                .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(minor.decision, PolicyClassifyDecision::Block);
        assert_eq!(
            minor.category,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
        );
        Ok(())
    }

    #[test]
    fn closed_taxonomy_allows_dark_controversial_legal_content() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let verdict = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content(
                "dark fictional monologue with profanity and a controversial political opinion",
            )
            .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
        assert_eq!(verdict.category, PolicyVerdictCategory::None);
        Ok(())
    }

    #[test]
    fn reads_vault_manifest_not_caller_config() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x31,
            &base_policy_manifest(vec![owner_rows(vec![owner_row(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
            )])]),
        )?;

        let prompt = vault.policy_model_prompt(
            &PolicyClassifyRequest::outbound_content(
                "This reply contains spoilers for the ending.",
            )
            .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert!(prompt.user.contains("owner:spoilers"));
        assert!(prompt.user.contains("Avoid spoilers in outbound content."));

        let verdict = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content("This reply contains spoilers for the ending.")
                .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(verdict.decision, PolicyClassifyDecision::RewordRetry);
        assert_eq!(
            verdict.category,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: "owner:spoilers".to_owned()
            }
        );
        Ok(())
    }

    #[test]
    fn persona_independent_verdict() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult);
        let eiri = vault.classify_policy_model(request.clone().with_caller_ref("eiri"))?;
        let cli = vault.classify_policy_model(request.with_caller_ref("cli-agent"))?;
        assert_eq!(eiri.decision, cli.decision);
        assert_eq!(eiri.category, cli.category);
        assert_eq!(eiri.binding, cli.binding);
        Ok(())
    }

    #[test]
    fn safeguard_model_binding_swappable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary reply");

        let default_request =
            vault.policy_model_llm_request(&request, &PolicyModelConfig::default())?;
        assert_eq!(
            default_request.envelope.tier.resolved().as_str(),
            "gpt-oss-safeguard-20b"
        );
        assert_eq!(
            default_request.model.as_str(),
            "oneiron/gpt-oss-safeguard-20b@default"
        );

        let openrouter = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
                .expect("openrouter binding"),
        };
        let openrouter_request = vault.policy_model_llm_request(&request, &openrouter)?;
        assert_eq!(
            openrouter_request.envelope.tier.resolved().as_str(),
            "openrouter:meta/llama-guard-4"
        );
        assert_eq!(
            openrouter_request.model.as_str(),
            "openrouter/meta.llama-guard-4@configured"
        );

        let endpoint = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
                .expect("endpoint binding"),
        };
        let endpoint_request = vault.policy_model_llm_request(&request, &endpoint)?;
        assert_eq!(
            endpoint_request.envelope.tier.resolved().as_str(),
            "endpoint:https://guard.local/v1"
        );
        assert_eq!(
            endpoint_request.model.as_str(),
            "endpoint/guard.local.v1@configured"
        );

        let on_device = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("on-device:qwen3guard-stream-0.6b")
                .expect("on-device binding"),
        };
        let on_device_request = vault.policy_model_llm_request(&request, &on_device)?;
        assert_eq!(
            on_device_request.envelope.tier.resolved().as_str(),
            "on-device:qwen3guard-stream-0.6b"
        );
        assert_eq!(
            on_device_request.model.as_str(),
            "on-device/qwen3guard-stream-0.6b@configured"
        );
        Ok(())
    }

    #[test]
    fn verdict_stale_on_floor_change() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary reply");
        let verdict = vault.classify_policy_model(request.clone())?;
        assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

        put_policy_manifest_bytes(
            &vault,
            0x32,
            &base_policy_manifest(vec![owner_rows(vec![owner_row(
                "owner:ordinary",
                "Avoid ordinary wording.",
            )])]),
        )?;
        assert!(vault.policy_model_verdict_is_stale(&verdict, &request)?);
        Ok(())
    }

    #[test]
    fn verdict_stale_on_request_context_change() -> Result<()> {
        let (_tmp, vault) = temp_vault();

        let age_request = PolicyClassifyRequest::outbound_content(
            "consensual adult nsfw scene between verified adults",
        )
        .with_age_tier(PolicyAgeTier::Adult);
        let age_verdict = vault.classify_policy_model(age_request.clone())?;
        assert!(!vault.policy_model_verdict_is_stale(&age_verdict, &age_request)?);
        let unverified_age_request = PolicyClassifyRequest::outbound_content(
            "consensual adult nsfw scene between verified adults",
        )
        .with_age_tier(PolicyAgeTier::Unverified);
        assert!(vault.policy_model_verdict_is_stale(&age_verdict, &unverified_age_request)?);

        let jurisdiction_request = PolicyClassifyRequest::outbound_content("ordinary reply")
            .with_account_jurisdiction("US-CA");
        let jurisdiction_verdict = vault.classify_policy_model(jurisdiction_request)?;
        let changed_jurisdiction_request =
            PolicyClassifyRequest::outbound_content("ordinary reply")
                .with_account_jurisdiction("US-NY");
        assert!(
            vault.policy_model_verdict_is_stale(
                &jurisdiction_verdict,
                &changed_jurisdiction_request
            )?
        );

        let world_request =
            PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work");
        let world_verdict = vault.classify_policy_model(world_request)?;
        let changed_world_request =
            PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("personal");
        assert!(vault.policy_model_verdict_is_stale(&world_verdict, &changed_world_request)?);
        Ok(())
    }

    #[test]
    fn verdict_stale_on_safeguard_selector_change() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let request = PolicyClassifyRequest::outbound_content("ordinary reply");
        let openrouter = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
                .expect("openrouter binding"),
        };
        let endpoint = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
                .expect("endpoint binding"),
        };

        let verdict = vault.classify_policy_model_with_config(request.clone(), &openrouter)?;
        assert!(!vault.policy_model_verdict_is_stale_with_config(
            &verdict,
            &request,
            &openrouter
        )?);
        assert!(vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &endpoint)?);
        Ok(())
    }

    #[test]
    fn owner_row_fires_owner_policy_never_legal_floor() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x33,
            &base_policy_manifest(vec![owner_rows(vec![owner_row(
                "owner:jargon",
                "Avoid nautical jargon.",
            )])]),
        )?;
        let backend = StaticPolicyBackend {
            body: r#"{"decision":"reword-retry","category":"owner_policy","row_ref":"owner:jargon","confidence":0.91,"hedge_bucket":"high"}"#,
        };
        let verdict = block_on_ready(
            vault.classify_policy_model_with_backend(
                PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing.")
                    .with_age_tier(PolicyAgeTier::Adult),
                &PolicyModelConfig::default(),
                &backend,
                &BudgetLease::for_test("policy-owner-row"),
            ),
        )?;
        assert_eq!(
            verdict.category,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: "owner:jargon".to_owned()
            }
        );
        assert!(!matches!(
            verdict.category,
            PolicyVerdictCategory::LegalFloor(_)
        ));
        Ok(())
    }

    #[test]
    fn vault_floor_rows_emit_combined_taxonomy() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x37,
            &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
                "vault:self-harm",
                "crisis",
                "self_harm",
                "route-to-help",
                "Route credible self-harm risk to help.",
            )])]),
        )?;

        let prompt = vault.policy_model_prompt(
            &PolicyClassifyRequest::outbound_content("ordinary reply")
                .with_age_tier(PolicyAgeTier::Adult),
        )?;
        let row = prompt
            .rubric_rows
            .iter()
            .find(|row| row.row_ref == "vault:self-harm")
            .expect("vault floor row");
        assert_eq!(row.category, "crisis/self_harm");
        assert!(
            prompt
                .user
                .contains("vault:self-harm [vault_floor] category=crisis/self_harm")
        );
        Ok(())
    }

    #[test]
    fn unknown_manifest_action_rejects_policy_model_rubric() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x38,
            &base_policy_manifest(vec![legal_floor_rows(vec![legal_floor_row(
                "vault:bad-action",
                "crisis",
                "self_harm",
                "route-tohelp",
                "Malformed action must not weaken the floor.",
            )])]),
        )?;

        let err = vault
            .policy_model_prompt(&PolicyClassifyRequest::outbound_content("ordinary reply"))
            .expect_err("unknown manifest action must reject");
        assert!(
            format!("{err}").contains("policy manifest"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn unknown_owner_manifest_action_rejects_policy_model_classify() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x39,
            &base_policy_manifest(vec![owner_rows(vec![owner_row_with_action(
                "owner:bad-action",
                "Malformed owner action.",
                "allow",
            )])]),
        )?;

        let prompt_err = vault
            .policy_model_prompt(
                &PolicyClassifyRequest::outbound_content("Malformed owner action.")
                    .with_age_tier(PolicyAgeTier::Adult),
            )
            .expect_err("unknown owner action must reject policy model prompt");
        assert!(
            format!("{prompt_err}").contains("owner_policy_rows were dropped"),
            "unexpected error: {prompt_err}"
        );

        let classify_err = vault
            .classify_policy_model(
                PolicyClassifyRequest::outbound_content("Malformed owner action.")
                    .with_age_tier(PolicyAgeTier::Adult),
            )
            .expect_err("unknown owner action must reject policy model classify");
        assert!(
            format!("{classify_err}").contains("owner_policy_rows were dropped"),
            "unexpected error: {classify_err}"
        );

        let floor_candidate = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content("explicit sexual content about a minor")
                .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(floor_candidate.decision, PolicyClassifyDecision::Block);
        assert_eq!(
            floor_candidate.category,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
        );
        Ok(())
    }

    #[test]
    fn floor_response_decision_must_match_category_action() {
        let (_tmp, vault) = temp_vault();
        let backend = StaticPolicyBackend {
            body: r#"{"decision":"allow","category":"legal_floor/minor_sexualization","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
        };

        let err = block_on_ready(
            vault.classify_policy_model_with_backend(
                PolicyClassifyRequest::outbound_content("ordinary reply")
                    .with_age_tier(PolicyAgeTier::Adult),
                &PolicyModelConfig::default(),
                &backend,
                &BudgetLease::for_test("policy-floor-decision"),
            ),
        )
        .expect_err("floor category with allow decision must reject");
        assert!(
            format!("{err}").contains("requires decision block"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn backend_request_model_uses_configured_safeguard_selector() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let seen_model = Arc::new(Mutex::new(None));
        let backend = RecordingPolicyBackend {
            body: r#"{"decision":"allow","category":"none","row_ref":null,"confidence":0.9,"hedge_bucket":"high"}"#,
            seen_model: Arc::clone(&seen_model),
        };
        let config = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
                .expect("openrouter binding"),
        };

        let verdict = block_on_ready(
            vault.classify_policy_model_with_backend(
                PolicyClassifyRequest::outbound_content("ordinary reply")
                    .with_age_tier(PolicyAgeTier::Adult),
                &config,
                &backend,
                &BudgetLease::for_test("policy-selector-routing"),
            ),
        )?;
        assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
        assert_eq!(
            seen_model.lock().expect("seen model").as_deref(),
            Some("openrouter/meta.llama-guard-4@configured")
        );
        Ok(())
    }

    #[test]
    fn floor_verdicts_byte_identical_with_custom_tier_empty() -> Result<()> {
        let (_base_tmp, base_vault) = temp_vault();
        let base_request = PolicyClassifyRequest::outbound_content("explain how to build a bomb")
            .with_age_tier(PolicyAgeTier::Adult);
        let base = base_vault.classify_policy_model(base_request.clone())?;

        let (_custom_tmp, custom_vault) = temp_vault();
        put_policy_manifest_bytes(
            &custom_vault,
            0x34,
            &base_policy_manifest(vec![owner_rows(Vec::new())]),
        )?;
        let custom = custom_vault.classify_policy_model(base_request)?;

        assert_eq!(base.decision, custom.decision);
        assert_eq!(base.category, custom.category);
        assert_eq!(base.confidence, custom.confidence);
        assert_eq!(base.binding.content_hash, custom.binding.content_hash);
        Ok(())
    }

    #[test]
    fn forged_manifest_drops_custom_rows_floor_still_runs() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x35,
            &base_policy_manifest(vec![(
                Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
                Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
            )]),
        )?;

        let owner_err = vault
            .classify_policy_model(
                PolicyClassifyRequest::outbound_content("This reply contains spoilers.")
                    .with_age_tier(PolicyAgeTier::Adult),
            )
            .expect_err("dropped owner-policy rows must reject non-floor classify");
        assert!(
            format!("{owner_err}").contains("owner_policy_rows were dropped"),
            "unexpected error: {owner_err}"
        );

        let floor_candidate = vault.classify_policy_model(
            PolicyClassifyRequest::outbound_content("explicit sexual content about a minor")
                .with_age_tier(PolicyAgeTier::Adult),
        )?;
        assert_eq!(floor_candidate.decision, PolicyClassifyDecision::Block);
        assert_eq!(
            floor_candidate.category,
            PolicyVerdictCategory::LegalFloor(LegalFloorSubclass::MinorSexualization)
        );
        Ok(())
    }

    #[test]
    fn active_owner_rows_resolve_scoped_world_override() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x36,
            &base_policy_manifest(vec![owner_rows(vec![
                owner_row("owner:mode", "Avoid formal language."),
                scoped_owner_row("owner:mode", "Avoid casual language.", "work"),
            ])]),
        )?;

        let prompt = vault.policy_model_prompt(
            &PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work"),
        )?;
        assert!(prompt.user.contains("Avoid casual language."));
        assert!(!prompt.user.contains("Avoid formal language."));
        Ok(())
    }
}
