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
//! policy to fall back to. What flows is never called clean, though: a plane
//! that wanted a model answer and has none returns
//! [`PolicyClassifyDecision::Skipped`], never an `Allow`.

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate::{self, PolicyManifestResolution};
use crate::llm::{BudgetGuard, BudgetLease, LlmBackend, LlmRequest};
use crate::store::GateSystemNoticeRecord;

use super::binding::{PolicyContentBinding, content_binding};
use super::contract::PolicyOutputContract;
use super::decide::{SafeguardModel, safeguard_verdict};
use super::notice::{policy_model_rationale_notice, policy_notice};
use super::pattern::{
    CompiledPatternRule, CompiledPatternRules, PatternEvaluation, PolicyPatternRole,
    PolicyPatternRule, compile_pattern_rules,
};
use super::planes::{PolicyPlane, PolicyRubricRow, owner_rubric_rows};
use super::prompt::{AnswerPlane, PolicyClassifyPrompt, render_classify_prompt};
use super::receipt::policy_model_reason_codes;
use super::request::{PolicyClassifyRequest, PolicyModelConfig, RelayClassifierMode};
use super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyPassAudit,
    PolicySkipReason, PolicyVerdictCategory,
};
use crate::error::RelayError;

/// The owner's policy document and the answer shape it asked for. Both or
/// neither: a document nobody declared a contract for is an answer the engine
/// cannot read.
struct OwnerPolicyDocument {
    pub(crate) text: String,
    pub(crate) contract: PolicyOutputContract,
}

pub(super) struct PolicyModelContext {
    pub(crate) binding: PolicyContentBinding,
    pub(crate) owner_policy_enabled: bool,
    pub(crate) owner_policy_rows_dropped: bool,
    pub(crate) rubric_rows: Vec<PolicyRubricRow>,
    pub(crate) patterns: CompiledPatternRules,
    document: Option<OwnerPolicyDocument>,
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

    /// Whether the owner wrote a document a model could classify against.
    fn has_document(&self) -> bool {
        self.document.is_some()
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
    /// model. Content the owner's dial wants a model to read comes back
    /// [`PolicyClassifyDecision::Skipped`]: an unexamined guess is not a
    /// verdict, and neither is an unexamined `Allow`.
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
        let verdict = self.owner_pattern_only_pass(&request, config)?;
        self.record_bare_classify_receipt(&request, &verdict, config)
    }

    /// The model-less owner pass, WITHOUT a ledger row.
    ///
    /// Shared by the bare classify door above and
    /// [`Vault::enforce_policy_model_with_config`], which records its own row
    /// at enforcement — the same division
    /// [`Vault::owner_plane_pass`] keeps for the with-model pair. The receipt
    /// deliberately does not live here: a row written in the shared pass would
    /// give the enforce flow two for one decision.
    pub(super) fn owner_pattern_only_pass(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyVerdict> {
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        let Some(context) = self.live_owner_context(context, config)? else {
            return Ok(PolicyClassifyVerdict::clean_allow(
                binding,
                config,
                PolicyPlane::OwnerPolicy,
            ));
        };
        let evaluation = context.evaluate(&request.content);
        if evaluation.acting_role() != Some(PolicyPatternRole::Decide)
            && wants_model(config.owner_classifier_mode, evaluation.acting_role())
            && let Some(decisions) = config.owner_decisions.as_deref()
            && let Some(prompt) = context.prompt(request)
        {
            return decisions.classify(
                request,
                &prompt,
                AnswerPlane::Owner,
                binding,
                config,
                pass_audit(&evaluation),
            );
        }
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
    /// unreadable answer and an unwritten document all resolve to
    /// [`PolicyClassifyDecision::Skipped`] with the pass audited, because the
    /// owner's plane is sovereign and fails open — but never to an `Allow`.
    /// Nor does a manifest that moved while the model answered: a stale
    /// verdict is derived again, once, and a manifest still moving after that
    /// is [`PolicySkipReason::PolicyMoving`].
    pub async fn classify_policy_model_with_backend(
        &self,
        request: PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<PolicyClassifyVerdict> {
        let pass = self
            .owner_plane_pass_pinned(&request, config, Some((backend, lease)))
            .await?;
        self.record_bare_classify_receipt(&request, &pass.verdict, config)
    }

    /// The ledger row a BARE classify door owes for the verdict it just
    /// minted.
    ///
    /// # Why the bare doors receipt at all
    ///
    /// One policy decision gets one row, written by the door that MADE it.
    /// [`Vault::enforce_policy_model_verdict`] deliberately writes none — it
    /// enforces a decision someone else already made and recording again
    /// would double-count it. That is right, and it leaves a hole: a host that
    /// classifies through one of these doors and then enforces through that
    /// one produced an audited `Block` with NO row anywhere. Filling it here
    /// is the same rule read the other way round — these doors are the
    /// producing door, so the row is theirs.
    ///
    /// # Why here and not in the shared pass
    ///
    /// [`Vault::owner_plane_pass`] is shared with
    /// [`Vault::enforce_policy_model_with_backend`], which records its own row
    /// at enforcement. A receipt in the shared pass would give those flows two
    /// rows for one decision — precisely the double-ledger this design already
    /// removed once. So it sits in the public doors that would otherwise leave
    /// nothing behind.
    ///
    /// The silence rule is the enforcement path's, unchanged: an `Allow` that
    /// learned nothing carries no signal and writes nothing. Anything else —
    /// a warn, a block, a route, or an allow with an audit a pattern or the
    /// model contributed to — is a row.
    ///
    /// A pass whose model did not answer is a SOVEREIGN PLANE FALLING OPEN,
    /// which is the fact the owner is most owed. Its verdict is
    /// [`PolicyClassifyDecision::Skipped`], so the silence rule never drops it.
    ///
    /// Returns the verdict the row records, which is the one the door hands
    /// back: see the frontier check below for when that differs.
    fn record_bare_classify_receipt(
        &self,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyVerdict> {
        #[cfg(test)]
        super::in_force::before_settling(super::in_force::SettlingDoor::BareClassify);
        // F107's window, on the doors F94 and F99 built: the verdict was bound
        // to a policy frontier, and the door hands it out after a LATER
        // transaction. The silence rule only drops an Allow that still
        // answers the policy in force; anything else is settled in the row's
        // own transaction (see `owner_verdict_in_force_in_txn`).
        if verdict.decision == PolicyClassifyDecision::Allow
            && verdict.audit.is_none()
            && !self.policy_model_verdict_is_stale_with_config(verdict, request, config)?
        {
            return Ok(verdict.clone());
        }
        let mut wtxn = self.store.env.write_txn()?;
        let (recorded, moved) =
            self.owner_verdict_in_force_in_txn(&wtxn, verdict, request, config)?;
        let verdict = &recorded;
        // The vault-egress path is the owner plane by construction, so there
        // is no hosted policy to attribute against.
        let mut system_notices: Vec<_> =
            policy_notice(verdict.decision, &verdict.category, None, config)
                .into_iter()
                .collect();
        // Appended last, as everywhere: an audit row must never become the
        // single body a caller surfaces.
        system_notices.extend(policy_model_rationale_notice(
            verdict,
            PolicyPlane::OwnerPolicy,
            None,
        ));
        let mut reason_codes = policy_model_reason_codes(verdict);
        // Which dial produced the decision is configuration-significant since
        // the planes split their modes, and the dual-plane owner path already
        // records it. These rows are newly written — a bare classify used to
        // leave none — so without this a ledger consumer cannot tell whether
        // a decision was reached under `ClassifyAll` or `PatternGated`, and
        // the two mean different things about what was NOT examined.
        reason_codes.push(format!(
            "gate.policy_model.owner_plane.classifier_mode.{}",
            config.owner_classifier_mode.as_str()
        ));
        if verdict.decision.skip_reason().is_some() {
            reason_codes.push(super::enforce::OWNER_PLANE_MODEL_SKIPPED_REASON.to_owned());
            reason_codes.push(super::enforce::OWNER_PLANE_FAIL_OPEN_REASON.to_owned());
        }
        if moved {
            reason_codes.push(super::enforce::OWNER_PLANE_FRONTIER_MOVED_REASON.to_owned());
        }
        self.append_policy_model_gate_receipt_in_txn(
            &mut wtxn,
            request,
            verdict,
            &format!("owner_plane_{}", verdict.decision.ledger_str()),
            reason_codes,
            system_notices,
        )?;
        wtxn.commit()?;
        Ok(recorded)
    }

    /// [`Self::owner_plane_pass`] for a door that hands its verdict out.
    ///
    /// The pass snapshots the manifest, then awaits the model. A verdict for
    /// a manifest that moved in that window answers a policy no longer in
    /// force, so it is derived again, ONCE; a manifest still moving after
    /// that yields [`PolicySkipReason::PolicyMoving`] bound to the frontier in
    /// force now, never the old policy's answer.
    pub(super) async fn owner_plane_pass_pinned(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<(&dyn LlmBackend, &BudgetLease)>,
    ) -> Result<OwnerPlanePass> {
        for _ in 0..2 {
            let pass = self.owner_plane_pass(request, config, safeguard).await?;
            if !self.policy_model_verdict_is_stale_with_config(&pass.verdict, request, config)? {
                return Ok(pass);
            }
        }
        let binding = self.policy_model_context(request, config)?.binding;
        Ok(OwnerPlanePass {
            verdict: PolicyClassifyVerdict::skipped(
                PolicySkipReason::PolicyMoving,
                binding,
                config,
                PolicyPlane::OwnerPolicy,
            ),
        })
    }

    /// The owner plane's full pass, model included. Shared by the classify
    /// entry, the enforcement entry and the both-planes entry so the three can
    /// never drift.
    pub(super) async fn owner_plane_pass(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<(&dyn LlmBackend, &BudgetLease)>,
    ) -> Result<OwnerPlanePass> {
        self.owner_plane_pass_with_safeguard(
            request,
            config,
            safeguard.map(|(backend, lease)| SafeguardModel::Leased { backend, lease }),
        )
        .await
    }

    /// Admit one lease at the moment the classifier actually needs a model.
    /// Pattern-only and disabled owner-policy passes reserve nothing.
    pub(super) async fn owner_plane_pass_with_budget(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        budget: &BudgetGuard,
    ) -> Result<OwnerPlanePass> {
        self.owner_plane_pass_with_safeguard(
            request,
            config,
            Some(SafeguardModel::Budgeted { backend, budget }),
        )
        .await
    }

    async fn owner_plane_pass_with_safeguard(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<SafeguardModel<'_>>,
    ) -> Result<OwnerPlanePass> {
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        let Some(context) = self.live_owner_context(context, config)? else {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(
                    binding,
                    config,
                    PolicyPlane::OwnerPolicy,
                ),
            });
        };
        let evaluation = context.evaluate(&request.content);
        let audit = pass_audit(&evaluation);

        if evaluation.acting_role() == Some(PolicyPatternRole::Decide) {
            return Ok(OwnerPlanePass {
                verdict: owner_pattern_only_verdict(&context, &evaluation, config, binding),
            });
        }
        if !wants_model(config.owner_classifier_mode, evaluation.acting_role()) {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(
                    binding,
                    config,
                    PolicyPlane::OwnerPolicy,
                )
                .with_audit(audit),
            });
        }
        let skipped = |reason: PolicySkipReason, audit: PolicyPassAudit| OwnerPlanePass {
            verdict: PolicyClassifyVerdict::skipped(
                reason,
                binding,
                config,
                PolicyPlane::OwnerPolicy,
            )
            .with_audit(audit),
        };
        // No document to send, or no model to reach: the plane is inactive for
        // model classification. Sovereign, so it fails open — as a skip.
        let Some(prompt) = context.prompt(request) else {
            return Ok(skipped(PolicySkipReason::NoDocument, audit));
        };
        if let Some(decisions) = config.owner_decisions.as_deref() {
            return Ok(OwnerPlanePass {
                verdict: decisions.classify(
                    request,
                    &prompt,
                    AnswerPlane::Owner,
                    binding,
                    config,
                    audit,
                )?,
            });
        }
        let Some(safeguard) = safeguard else {
            return Ok(skipped(PolicySkipReason::NoBackend, audit));
        };
        // A budgeted call gets its own admission, even on a stale-policy
        // retry. A denied admission is a skipped sovereign classifier pass,
        // not a free invocation on an old lease.
        Ok(OwnerPlanePass {
            verdict: safeguard_verdict(
                safeguard,
                request,
                &prompt,
                &AnswerPlane::Owner,
                crate::vault::embedded_owner_actor_id()?,
                binding,
                config,
                audit,
            )
            .await?,
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

    pub(super) fn policy_model_context(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyModelContext> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        policy_model_context_for_policy(request, config, &policy)
    }
}

/// Evaluate the owner policy for a traceless chat turn. Only the policy manifest
/// is read. In particular, the ordinary classify/enforce doors are NOT used:
/// they append durable gate receipts even when a turn is withheld.
/// A moving policy is retried once, then refused without releasing content.
pub(crate) async fn stateless_owner_classification(
    vault: &Vault,
    content: &str,
    config: &PolicyModelConfig,
    backend: &dyn LlmBackend,
    budget: &BudgetGuard,
) -> Result<(PolicyClassifyDecision, Vec<GateSystemNoticeRecord>)> {
    let request = PolicyClassifyRequest::outbound_content(content);
    for _ in 0..2 {
        let pass = vault
            .owner_plane_pass_with_budget(&request, config, backend, budget)
            .await?;
        #[cfg(test)]
        super::in_force::before_settling(super::in_force::SettlingDoor::AnonymousChat);
        if !vault.policy_model_verdict_is_stale_with_config(&pass.verdict, &request, config)? {
            let verdict = pass.verdict;
            // A human hold needs a durable queue. This route cannot create
            // one, so it returns a blocking notice, never a phantom hold.
            let notice_decision = if verdict.decision == PolicyClassifyDecision::Hold {
                PolicyClassifyDecision::Block
            } else {
                verdict.decision
            };
            let notices = policy_notice(notice_decision, &verdict.category, None, config)
                .into_iter()
                .collect();
            return Ok((verdict.decision, notices));
        }
    }
    Err(Error::ConcurrentWrite(
        "anonymous chat policy changed during classification",
    ))
}

/// What the owner plane concluded. A pass whose model did not get to speak
/// says so in the verdict itself ([`PolicyClassifyDecision::Skipped`]), so no
/// caller can drop the fact on the way out.
pub(super) struct OwnerPlanePass {
    pub(crate) verdict: PolicyClassifyVerdict,
}

impl OwnerPlanePass {
    /// The plane wanted a model verdict and did not get one. Not a failure —
    /// the owner's plane is sovereign — but the caller is owed the fact.
    pub(crate) fn model_skipped(&self) -> bool {
        self.verdict.decision.skip_reason().is_some()
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
    let rubric_rows = owner_rubric_rows(request, policy);
    if rubric_rows
        .iter()
        .any(|row| row.action == PolicyClassifyDecision::Reword)
    {
        super::reword::validate_reword_notice(config)?;
    }
    Ok(PolicyModelContext {
        binding: content_binding(request, policy, config)?,
        owner_policy_enabled,
        owner_policy_rows_dropped: policy.owner_policy_rows_dropped(),
        rubric_rows,
        patterns,
        document,
    })
}

/// The owner's pattern rules, validated and compiled. Only ever called for a
/// plane that is switched on.
fn owner_compiled_patterns(policy: &PolicyManifestResolution) -> Result<CompiledPatternRules> {
    if policy.owner_policy_patterns_dropped() {
        return Err(Error::Relay(RelayError::PolicyManifestInvalid {
            field: "owner_policy_patterns",
            reason: "were dropped by manifest decode",
        }));
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
        Error::Relay(RelayError::PolicyManifestInvalid {
            field: defect.field,
            reason: defect.reason,
        })
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
        (Some(_), None) | (None, Some(_)) => Err(Error::Relay(RelayError::PolicyManifestInvalid {
            field: "owner_policy_output_contract",
            reason: "must be declared with the owner policy document",
        })),
        (Some(text), Some(contract)) => {
            let contract = PolicyOutputContract::parse(contract).ok_or(Error::Relay(
                RelayError::PolicyManifestInvalid {
                    field: "owner_policy_output_contract",
                    reason: "names a contract the engine does not have",
                },
            ))?;
            Ok(Some(OwnerPolicyDocument {
                text: text.to_owned(),
                contract,
            }))
        }
    }
}

/// The verdict a pass reaches with no model answer: a `Decide` rule's row; a
/// skip where the owner's dial wanted a model to read the content; otherwise a
/// clean allow. Every matched id is audited either way.
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
            PolicyPlane::OwnerPolicy,
        )
        .with_audit(audit),
        // A request no owner row applies to has nothing a model could judge.
        None if !context.rubric_rows.is_empty()
            && wants_model(config.owner_classifier_mode, evaluation.acting_role()) =>
        {
            let reason = if context.has_document() {
                PolicySkipReason::NoBackend
            } else {
                PolicySkipReason::NoDocument
            };
            PolicyClassifyVerdict::skipped(reason, binding, config, PolicyPlane::OwnerPolicy)
                .with_audit(audit)
        }
        None => PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::OwnerPolicy)
            .with_audit(audit),
    }
}

/// Whether a pass with this acting role should call the model.
pub(super) fn wants_model(mode: RelayClassifierMode, acting: Option<PolicyPatternRole>) -> bool {
    match mode {
        RelayClassifierMode::ClassifyAll => true,
        RelayClassifierMode::PatternGated => acting == Some(PolicyPatternRole::Escalate),
    }
}

pub(super) fn pass_audit(evaluation: &PatternEvaluation<'_>) -> PolicyPassAudit {
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

pub(super) fn dropped_owner_policy_rows_error() -> Error {
    Error::Relay(RelayError::PolicyManifestInvalid {
        field: "owner_policy_rows",
        reason: "were dropped by manifest decode",
    })
}
