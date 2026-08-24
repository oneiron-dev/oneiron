//! Vault-egress classification, which is the owner plane and nothing else.
//!
//! A vault classifies its own outbound content against the policy its owner
//! wrote. If the owner never turned the plane on, this path does no work at
//! all: no patterns, no safeguard-model call, no verdict beyond `Allow`. If
//! they turned it on but wrote no policy document, the plane is INACTIVE for
//! model classification — the engine has nothing to send, and it will not
//! invent one.
//!
//! The owner's plane is sovereign, so it fails OPEN: a model that is down, an
//! answer the engine cannot read, or a document that was never written all
//! leave the content flowing. There is nothing underneath the owner's own
//! policy to fall back to.

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate::{self, PolicyManifestResolution};
use crate::llm::{BudgetLease, LlmBackend, LlmRequest};

use super::binding::{PolicyContentBinding, content_binding};
use super::contract::PolicyOutputContract;
use super::pattern::{
    CompiledPatternRule, CompiledPatternRules, PatternEvaluation, PolicyPatternRole,
    PolicyPatternRule, compile_pattern_rules,
};
use super::planes::{PolicyRubricRow, owner_rubric_rows};
use super::prompt::{
    AnswerPlane, PolicyClassifyPrompt, render_classify_prompt, resolve_policy_model_response,
};
use super::request::{PolicyClassifyRequest, PolicyModelConfig, RelayClassifierMode};
use super::verdict::{
    PolicyClassifyVerdict, PolicyConfidence, PolicyPassAudit, PolicyVerdictCategory,
};

/// The owner's policy document and the answer shape it asked for. Both or
/// neither: a document nobody declared a contract for is an answer the engine
/// cannot read.
pub(crate) struct OwnerPolicyDocument {
    pub(crate) text: String,
    pub(crate) contract: PolicyOutputContract,
}

pub(crate) struct PolicyModelContext {
    pub(crate) binding: PolicyContentBinding,
    pub(crate) owner_policy_enabled: bool,
    pub(crate) owner_policy_rows_dropped: bool,
    pub(crate) rubric_rows: Vec<PolicyRubricRow>,
    pub(crate) patterns: CompiledPatternRules,
    pub(crate) document: Option<OwnerPolicyDocument>,
}

impl PolicyModelContext {
    /// The prompt for this pass, or `None` when the plane has no document to
    /// send.
    pub(crate) fn prompt(&self, request: &PolicyClassifyRequest) -> Option<PolicyClassifyPrompt> {
        let document = self.document.as_ref()?;
        Some(render_classify_prompt(
            request,
            &document.text,
            self.rubric_rows.clone(),
            document.contract,
        ))
    }

    /// Which of the owner's rules may act: only those naming a row that is
    /// active for this request.
    fn acts(&self) -> impl Fn(&CompiledPatternRule) -> bool + '_ {
        |rule| {
            self.rubric_rows
                .iter()
                .any(|row| row.row_ref == rule.category())
        }
    }

    fn evaluate(&self, content: &str) -> PatternEvaluation<'_> {
        self.patterns.evaluate_where(content, &self.acts())
    }
}

impl Vault {
    /// Classify with no safeguard model in reach.
    ///
    /// Only the owner's `Decide` pattern rules can conclude anything here —
    /// they are the coverage the owner declared hard enough to stand without a
    /// model. Everything else allows, because an unexamined guess is not a
    /// verdict.
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
        let Some(context) = self.live_owner_context(context, config)? else {
            return Ok(PolicyClassifyVerdict::clean_allow(binding, config));
        };
        let evaluation = context.evaluate(&request.content);
        Ok(owner_pattern_only_verdict(
            &context,
            &evaluation,
            config,
            binding,
        ))
    }

    /// Classify with a safeguard model available.
    ///
    /// Never returns a model failure as an error: an unavailable model, an
    /// unreadable answer and an unwritten document all resolve to `Allow` with
    /// the pass audited, because the owner's plane is sovereign and fails open.
    pub async fn classify_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyClassifyVerdict> {
        Ok(self
            .owner_plane_pass(&request, config, Some((backend, lease)))
            .await?
            .verdict)
    }

    /// The owner plane's full pass, model included. Shared by the classify
    /// entry, the enforcement entry and the both-planes entry so the three can
    /// never drift.
    pub(crate) async fn owner_plane_pass(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<(&dyn LlmBackend, &BudgetLease)>,
    ) -> Result<OwnerPlanePass> {
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        let Some(context) = self.live_owner_context(context, config)? else {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config),
                model_skipped: false,
            });
        };
        let evaluation = context.evaluate(&request.content);
        let mut audit = pass_audit(&evaluation);

        if evaluation.acting_role() == Some(PolicyPatternRole::Decide) {
            return Ok(OwnerPlanePass {
                verdict: owner_pattern_only_verdict(&context, &evaluation, config, binding),
                model_skipped: false,
            });
        }
        if !wants_model(config.owner_classifier_mode, evaluation.acting_role()) {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
                model_skipped: false,
            });
        }
        let (Some((backend, lease)), Some(prompt)) = (safeguard, context.prompt(request)) else {
            // No model to reach, or no document to send it: the plane is
            // inactive for model classification. Sovereign, so it fails open.
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
                model_skipped: true,
            });
        };
        let Ok(response) = backend.generate(prompt.llm_request(config), lease).await else {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
                model_skipped: true,
            });
        };
        let Ok(resolved) = resolve_policy_model_response(&response, &prompt, &AnswerPlane::Owner)
        else {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
                model_skipped: true,
            });
        };
        audit.model_rule_ids = resolved.answer.rule_ids;
        audit.model_rule_ids_dropped = resolved.dropped_rule_ids;
        audit.model_confidence = resolved.answer.confidence;
        audit.model_rationale = resolved.answer.rationale;
        Ok(OwnerPlanePass {
            verdict: PolicyClassifyVerdict::new(
                resolved.decision,
                resolved.category,
                PolicyConfidence::MEDIUM,
                binding,
                config,
            )
            .with_audit(audit),
            model_skipped: false,
        })
    }

    /// The prompt this vault would send for `request`, or `None` when the owner
    /// wrote no policy document. Returns the substrate owner's own text — the
    /// engine contributes no words to it.
    pub fn policy_model_prompt(
        &self,
        request: &PolicyClassifyRequest,
    ) -> Result<Option<PolicyClassifyPrompt>> {
        self.policy_model_prompt_with_config(request, &PolicyModelConfig::default())
    }

    pub fn policy_model_prompt_with_config(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<Option<PolicyClassifyPrompt>> {
        let context = self.policy_model_context(request, config)?;
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }
        Ok(context.prompt(request))
    }

    pub fn policy_model_llm_request(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<Option<LlmRequest>> {
        Ok(self
            .policy_model_prompt_with_config(request, config)?
            .map(|prompt| prompt.llm_request(config)))
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

    /// Whether the manifest has moved out from under a verdict, so a caller
    /// about to act on it should derive a fresh one first.
    ///
    /// Two things can go stale, and they are asked about separately.
    ///
    /// The CONTENT half of the binding — subject, content, world, safeguard
    /// selector — is about the question. A verdict for other content, another
    /// world or another classifier is not this verdict, whatever the plane is
    /// doing.
    ///
    /// The FRONTIER half is about the manifest the plane decided against, and
    /// it is only asked of a plane that is ON. A disabled plane decides
    /// nothing, so an edit elsewhere in the manifest cannot invalidate its
    /// clean allow — and reporting it stale only sends the caller to re-derive
    /// its way back to the identical clean allow. Mirrors the same
    /// short-circuit the live-context resolver already applies.
    ///
    /// That short-circuit is about the CLEAN ALLOW, not about the plane. A
    /// plane that is off returns the inert clean allow and can return nothing
    /// else, so any other verdict in a caller's hand was minted while the
    /// plane was ON and the owner has since opted out. Reporting that one
    /// fresh would let a `Block` the owner switched off keep blocking, which
    /// is the owner-sovereignty violation this whole predicate exists to
    /// prevent — so the ON to OFF transition reads STALE.
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
        let fresh = content_binding(request, &policy, config)?;
        if verdict.binding.content_hash != fresh.content_hash
            || verdict.safeguard_binding != config.safeguard_binding.selector()
        {
            return Ok(true);
        }
        if policy.owner_policy_enabled() {
            return Ok(verdict.binding.read_frontier_hash != fresh.read_frontier_hash);
        }
        Ok(!verdict.is_inert_clean_allow())
    }

    /// `None` when the owner plane is off; `Err` when it is on but its
    /// configuration cannot be read, which is a defect the caller must see
    /// rather than a verdict.
    fn live_owner_context(
        &self,
        context: PolicyModelContext,
        _config: &PolicyModelConfig,
    ) -> Result<Option<PolicyModelContext>> {
        if !context.owner_policy_enabled {
            return Ok(None);
        }
        if context.owner_policy_rows_dropped {
            return Err(dropped_owner_policy_rows_error());
        }
        Ok(Some(context))
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

/// What the owner plane concluded, plus whether its model got to speak.
pub(crate) struct OwnerPlanePass {
    pub(crate) verdict: PolicyClassifyVerdict,
    /// The plane wanted a model verdict and did not get one. Not a failure —
    /// the owner's plane is sovereign — but the caller is owed the fact.
    pub(crate) model_skipped: bool,
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
    let owner_policy_enabled = policy.owner_policy_enabled();
    // The owner's rules are READ ONLY once the plane is on. A plane that is
    // off promises an inert clean allow, and compiling its patterns first
    // turned a rule that would not compile into a configuration error for a
    // plane nobody switched on — a defect surfaced by machinery that was never
    // going to run.
    let patterns = if owner_policy_enabled {
        owner_compiled_patterns(policy)?
    } else {
        CompiledPatternRules::default()
    };
    let document = owner_policy_document(policy)?;
    Ok(PolicyModelContext {
        binding: content_binding(request, policy, config)?,
        owner_policy_enabled,
        owner_policy_rows_dropped: policy.owner_policy_rows_dropped(),
        rubric_rows: owner_rubric_rows(request, policy),
        patterns,
        document,
    })
}

/// The owner's pattern rules, validated and compiled. Only ever called for a
/// plane that is switched on.
fn owner_compiled_patterns(policy: &PolicyManifestResolution) -> Result<CompiledPatternRules> {
    if policy.owner_policy_patterns_dropped() {
        return Err(Error::InvalidConfig(
            "policy manifest owner_policy_patterns were dropped for policy model classify"
                .to_owned(),
        ));
    }
    let known_row_ref = |category: &str| policy.owner_policy_row_refs().contains(&category);
    let rules: Vec<PolicyPatternRule> = policy
        .owner_policy_patterns()
        .iter()
        .map(|row| PolicyPatternRule {
            id: row.id.clone(),
            pattern: row.pattern.clone(),
            category: row.category.clone(),
            role: row
                .role
                .as_deref()
                .map_or(Some(PolicyPatternRole::Escalate), PolicyPatternRole::parse)
                // An unparseable role is caught below; the placeholder never acts.
                .unwrap_or(PolicyPatternRole::Escalate),
        })
        .collect();
    if policy.owner_policy_patterns().iter().any(|row| {
        row.role
            .as_deref()
            .is_some_and(|role| PolicyPatternRole::parse(role).is_none())
    }) {
        return Err(Error::InvalidConfig(
            "policy manifest owner_policy_patterns named a role the engine does not have"
                .to_owned(),
        ));
    }
    compile_pattern_rules(&rules, &known_row_ref).map_err(|defect| {
        Error::InvalidConfig(format!(
            "policy manifest owner pattern rule {} {}",
            defect.field, defect.reason
        ))
    })
}

/// Both halves or neither. A document with no declared contract is refused
/// rather than guessed at: the engine would be inventing the answer shape the
/// owner's own text asked for.
fn owner_policy_document(policy: &PolicyManifestResolution) -> Result<Option<OwnerPolicyDocument>> {
    match (
        policy.owner_policy_document(),
        policy.owner_policy_output_contract(),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(Error::InvalidConfig(
            "policy manifest must carry an owner policy document and its output contract together"
                .to_owned(),
        )),
        (Some(text), Some(contract)) => {
            let contract = PolicyOutputContract::parse(contract).ok_or_else(|| {
                Error::InvalidConfig(
                    "policy manifest owner_policy_output_contract names a contract the engine does not have"
                        .to_owned(),
                )
            })?;
            Ok(Some(OwnerPolicyDocument {
                text: text.to_owned(),
                contract,
            }))
        }
    }
}

/// The verdict a pass reaches with no model answer: a `Decide` rule's row, or
/// a clean allow. Every matched id is audited either way.
fn owner_pattern_only_verdict(
    context: &PolicyModelContext,
    evaluation: &PatternEvaluation<'_>,
    config: &PolicyModelConfig,
    binding: PolicyContentBinding,
) -> PolicyClassifyVerdict {
    let audit = pass_audit(evaluation);
    let decided = evaluation
        .acting
        .filter(|rule| rule.role() == PolicyPatternRole::Decide)
        .and_then(|rule| {
            context
                .rubric_rows
                .iter()
                .find(|row| row.row_ref == rule.category())
        });
    match decided {
        Some(row) => PolicyClassifyVerdict::new(
            row.action,
            PolicyVerdictCategory::OwnerPolicy {
                row_ref: row.row_ref.clone(),
            },
            PolicyConfidence::CERTAIN,
            binding,
            config,
        )
        .with_audit(audit),
        None => PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
    }
}

/// Whether a pass with this acting role should call the model.
pub(crate) fn wants_model(mode: RelayClassifierMode, acting: Option<PolicyPatternRole>) -> bool {
    match mode {
        RelayClassifierMode::ClassifyAll => true,
        RelayClassifierMode::PatternGated => acting == Some(PolicyPatternRole::Escalate),
    }
}

pub(crate) fn pass_audit(evaluation: &PatternEvaluation<'_>) -> PolicyPassAudit {
    PolicyPassAudit {
        matched_pattern_ids: evaluation
            .matched_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect(),
        acting_pattern_role: evaluation.acting_role(),
        ..PolicyPassAudit::default()
    }
}

pub(crate) fn dropped_owner_policy_rows_error() -> Error {
    Error::InvalidConfig(
        "policy manifest owner_policy_rows were dropped for policy model classify".to_owned(),
    )
}
