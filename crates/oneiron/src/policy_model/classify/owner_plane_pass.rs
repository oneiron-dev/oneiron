//! The owner plane's with-model pass: the pinned retry, the budgeted
//! admission, and the safeguard verdict they share.

use super::*;

impl Vault {
    /// [`Self::owner_plane_pass`] for a door that hands its verdict out.
    ///
    /// The pass snapshots the manifest, then awaits the model. A verdict for
    /// a manifest that moved in that window answers a policy no longer in
    /// force, so it is derived again, ONCE; a manifest still moving after
    /// that yields [`PolicySkipReason::PolicyMoving`] bound to the frontier in
    /// force now, never the old policy's answer. Every derivation spends the
    /// caller's one `clock` (FIX 10034).
    pub(in crate::policy_model) async fn owner_plane_pass_pinned(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<(&dyn LlmBackend, &BudgetLease)>,
        clock: &PolicyCallClock,
    ) -> Result<OwnerPlanePass> {
        for _ in 0..2 {
            let pass = self
                .owner_plane_pass(request, config, safeguard, clock)
                .await?;
            if !self.policy_model_verdict_is_stale_with_config(&pass.verdict, request, config)? {
                return Ok(pass);
            }
        }
        self.policy_moving_verdict(request, config)
    }

    /// The owner plane's typed fail-open for a policy still moving after its
    /// retry: [`PolicySkipReason::PolicyMoving`], bound to the frontier in
    /// force now. A pure read: it writes no row, so the traceless chat turn
    /// uses it too (FIX 10033).
    pub(super) fn policy_moving_verdict(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<OwnerPlanePass> {
        let context = self.policy_model_context(request, config)?;
        Ok(OwnerPlanePass {
            verdict: PolicyClassifyVerdict::skipped(
                PolicySkipReason::PolicyMoving,
                context.binding,
                config,
                PolicyPlane::OwnerPolicy,
            ),
            examined: context.owner_policy_enabled,
        })
    }

    /// The owner plane's full pass, model included. Shared by the classify
    /// entry, the enforcement entry and the both-planes entry so the three can
    /// never drift.
    pub(in crate::policy_model) async fn owner_plane_pass(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<(&dyn LlmBackend, &BudgetLease)>,
        clock: &PolicyCallClock,
    ) -> Result<OwnerPlanePass> {
        self.owner_plane_pass_with_safeguard(
            request,
            config,
            safeguard.map(|(backend, lease)| SafeguardModel::Leased { backend, lease }),
            clock,
        )
        .await
    }

    /// Admit one lease at the moment the classifier actually needs a model.
    /// Pattern-only and disabled owner-policy passes reserve nothing.
    pub(in crate::policy_model) async fn owner_plane_pass_with_budget(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        budget: &BudgetGuard,
        clock: &PolicyCallClock,
    ) -> Result<OwnerPlanePass> {
        self.owner_plane_pass_with_safeguard(
            request,
            config,
            Some(SafeguardModel::Budgeted { backend, budget }),
            clock,
        )
        .await
    }

    async fn owner_plane_pass_with_safeguard(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        safeguard: Option<SafeguardModel<'_>>,
        clock: &PolicyCallClock,
    ) -> Result<OwnerPlanePass> {
        let context = self.policy_model_context(request, config)?;
        let binding = context.binding;
        let examined = context.owner_policy_enabled;
        let Some(context) = self.live_owner_context(context, config)? else {
            return Ok(OwnerPlanePass {
                verdict: PolicyClassifyVerdict::clean_allow(
                    binding,
                    config,
                    PolicyPlane::OwnerPolicy,
                ),
                examined,
            });
        };
        let evaluation = context.evaluate(&request.content);
        let audit = pass_audit(&evaluation);

        if evaluation.acting_role() == Some(PolicyPatternRole::Decide) {
            return Ok(OwnerPlanePass {
                verdict: owner_pattern_only_verdict(&context, &evaluation, config, binding),
                examined,
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
                examined,
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
            examined,
        };
        // No document to send, or no model to reach: the plane is inactive for
        // model classification. Sovereign, so it fails open — as a skip.
        let Some(prompt) = context.prompt(request) else {
            return Ok(skipped(PolicySkipReason::NoDocument, audit));
        };
        if let Some(decisions) = config.owner_decisions.as_deref() {
            return Ok(OwnerPlanePass {
                verdict: decisions.classify(
                    self,
                    request,
                    &prompt,
                    AnswerPlane::Owner,
                    binding,
                    config,
                    audit,
                    clock,
                )?,
                examined,
            });
        }
        let Some(safeguard) = safeguard else {
            return Ok(skipped(PolicySkipReason::NoBackend, audit));
        };
        // A budgeted call gets its own admission, even on a stale-policy
        // retry. A denied admission is a skipped sovereign classifier pass,
        // not a free invocation on an old lease.
        let verdict = safeguard_verdict(
            safeguard,
            request,
            &prompt,
            &AnswerPlane::Owner,
            crate::vault::embedded_owner_actor_id()?,
            binding,
            config,
            audit,
            clock,
        )
        .await?;
        // The guard refused the pass or its notes: `host.budget.hit` on its line.
        if let SafeguardModel::Budgeted { budget, .. } = safeguard
            && (verdict.decision.skip_reason() == Some(PolicySkipReason::BudgetExhausted)
                || verdict
                    .audit
                    .as_deref()
                    .is_some_and(|audit| audit.model_notes_budget_exhausted))
        {
            let line = budget.read().attempt_id;
            self.budget_denied_hooks(
                &oneiron_model::llm::BudgetDenied::Exhausted,
                budget,
                &line,
                None,
                None,
            );
        }
        Ok(OwnerPlanePass { verdict, examined })
    }
}
