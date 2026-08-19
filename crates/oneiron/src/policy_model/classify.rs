//! Vault-egress classification, which is the owner plane and nothing else.
//!
//! A vault classifies its own outbound content against the rows its owner
//! wrote. If the owner never turned the plane on, this path does no work at
//! all: no rubric, no safeguard-model call, no verdict beyond `Allow`.

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate::{self, PolicyManifestResolution};
use crate::llm::{BudgetLease, LlmBackend, LlmRequest};

use super::binding::{PolicyContentBinding, content_binding};
use super::planes::{PolicyPlane, PolicyRubricRow, owner_rubric_rows};
use super::prompt::{PolicyClassifyPrompt, parse_policy_model_response, render_classify_prompt};
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyVerdictCategory,
};

pub(crate) struct PolicyModelContext {
    pub(crate) prompt: PolicyClassifyPrompt,
    pub(crate) binding: PolicyContentBinding,
    pub(crate) owner_policy_enabled: bool,
    pub(crate) owner_policy_rows_dropped: bool,
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
        if !context.owner_policy_enabled {
            return Ok(PolicyClassifyVerdict::clean_allow(context.binding, config));
        }
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }
        Ok(classify_from_owner_rubric(
            &context.prompt.rubric_rows,
            context.binding,
            config,
        ))
    }

    pub async fn classify_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyClassifyVerdict> {
        let context = self.policy_model_context(&request, config)?;
        if !context.owner_policy_enabled {
            return Ok(PolicyClassifyVerdict::clean_allow(context.binding, config));
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
        // `hosted: None` on purpose: the vault-egress path has no hosted legal
        // policy in play, so a hosted verdict from the model cannot resolve
        // and is rejected instead of being attributed to the owner.
        parse_policy_model_response(
            &response,
            &context.prompt.rubric_rows,
            None,
            context.binding,
            config,
        )
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

    pub(crate) fn policy_model_context(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelContext> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        policy_model_context_for_policy(request, config, &policy)
    }
}

fn policy_model_context_for_policy(
    request: &PolicyClassifyRequest,
    config: &PolicyModelConfig,
    policy: &PolicyManifestResolution,
) -> Result<PolicyModelContext> {
    if policy.diagnostics().loaded_manifest_forces_fail_closed() {
        return Err(Error::InvalidConfig(
            "policy manifest is malformed for policy model classify".to_owned(),
        ));
    }
    let rows = owner_rubric_rows(request, policy);
    Ok(PolicyModelContext {
        prompt: render_classify_prompt(request, rows),
        binding: content_binding(request, policy, config)?,
        owner_policy_enabled: policy.owner_policy_enabled(),
        owner_policy_rows_dropped: policy.owner_policy_rows_dropped(),
    })
}

/// The backend-free stand-in for the owner plane: the MOST SEVERE active owner
/// row governs (`Block` over `RouteToHelp` over `Warn`), with manifest order
/// breaking ties. It exists so a vault with no safeguard model still honors its
/// owner's rows deterministically rather than silently allowing everything —
/// and taking the first row instead of the strictest would let a `Warn` written
/// above a `Block` swallow the owner's strictest instruction.
pub(crate) fn classify_from_owner_rubric(
    rubric_rows: &[PolicyRubricRow],
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    match rubric_rows
        .iter()
        .filter(|row| row.plane == PolicyPlane::OwnerPolicy)
        .reduce(|governing, row| {
            if owner_row_severity(row.action) > owner_row_severity(governing.action) {
                row
            } else {
                governing
            }
        }) {
        Some(row) => PolicyClassifyVerdict::new(
            row.action,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: row.row_ref.clone(),
            },
            PolicyConfidence::MEDIUM,
            binding,
            config,
        ),
        None => PolicyClassifyVerdict::clean_allow(binding, config),
    }
}

/// How strict an owner row is. Ordering only — the numbers are never stored,
/// never emitted, and exist solely so two rows can be compared.
const fn owner_row_severity(decision: PolicyClassifyDecision) -> u8 {
    match decision {
        PolicyClassifyDecision::Allow => 0,
        PolicyClassifyDecision::Warn => 1,
        PolicyClassifyDecision::RouteToHelp => 2,
        PolicyClassifyDecision::Block => 3,
    }
}

pub(crate) fn dropped_owner_policy_rows_error() -> Error {
    Error::InvalidConfig(
        "policy manifest owner_policy_rows were dropped for policy model classify".to_owned(),
    )
}
