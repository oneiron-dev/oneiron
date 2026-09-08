//! Hosted classification engine: single hosted pass with mid-pass re-check and CloudVault receipt verification.

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate;

use super::super::binding::{PolicyContentBinding, content_binding, relay_verify_content_binding};
use super::super::classify::{pass_audit, wants_model};
use super::super::pattern::{CompiledPatternRule, CompiledPatternRules, PolicyPatternRole};
use super::super::planes::{HostedLegalPolicy, PolicyPlane, hosted_rubric_rows};
use super::super::prompt::{AnswerPlane, render_classify_prompt, resolve_policy_model_response};
use super::super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyVerdictCategory,
};
use super::boundary::malformed_relay_policy_error;
use super::outcome::{
    CloudVaultPassOrFallback, RelayBoundaryDegrade, RelayBoundaryPass, RelayResolution,
    RelaySafeguardTier, VaultSideVerdictSource, degraded_hosted_pass, log_only_or_gated,
    pass_audit_of,
};

impl Vault {
    /// The hosted pass, plus the re-check its await window requires.
    ///
    /// # The manifest can move while the model is answering
    ///
    /// A pass binds its verdict to the vault's policy state, then AWAITS a
    /// network round trip. Policy state that moves during that await leaves
    /// the pass holding a verdict bound to a frontier that is no longer in
    /// force — and the relay would receipt it under that dead binding, so a
    /// later CloudVault verification recomputing the hash locally would find a
    /// receipt attesting policy state nobody could reproduce.
    ///
    /// This is the hole the owner plane closed at its own enforcement door: the
    /// verdict is checked against what is in force before it is acted on, and
    /// a stale one is derived again, ONCE.
    ///
    /// Where the two planes part is what happens when the second derivation is
    /// stale too. The owner plane is sovereign and fails OPEN. The hosted plane
    /// is fail-CLOSED — its rows are prose only a model can read, and relaying
    /// on a verdict it cannot pin to a policy is the unexamined allow the whole
    /// plane exists to refuse. So it DEGRADES, which is what makes
    /// [`RelayBoundaryPass::must_halt_relay`] stop the relay.
    ///
    /// With no hosted policy bound to the attested identity there is nothing to
    /// pin and no model call to pin it across, so the re-check is skipped
    /// whole.
    pub(super) async fn hosted_relay_pass(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        patterns: Option<&CompiledPatternRules>,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
    ) -> Result<RelayBoundaryPass> {
        let pass = self
            .hosted_relay_pass_once(request, hosted, patterns, config, safeguard)
            .await?;
        if hosted.is_none() || !self.relay_binding_moved(request, config, &pass)? {
            return Ok(pass);
        }
        let pass = self
            .hosted_relay_pass_once(request, hosted, patterns, config, safeguard)
            .await?;
        if !self.relay_binding_moved(request, config, &pass)? {
            return Ok(pass);
        }
        // Reached only when `hosted.is_some()` — the guard above returns
        // early otherwise — so a hosted policy is bound by construction.
        Ok(degraded_hosted_pass(
            self.relay_policy_binding(request, config)?,
            config,
            pass_audit_of(&pass),
            RelayBoundaryDegrade::PolicyBindingMovedMidPass,
            true,
        ))
    }
}

impl Vault {
    /// Whether the policy state a pass bound its verdict to is still the state
    /// in force. A pass that produced no verdict bound nothing, so nothing of
    /// it can have gone stale.
    fn relay_binding_moved(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        pass: &RelayBoundaryPass,
    ) -> Result<bool> {
        let Some(verdict) = pass.boundary_verdict() else {
            return Ok(false);
        };
        Ok(verdict.binding != self.relay_policy_binding(request, config)?)
    }
}

impl Vault {
    async fn hosted_relay_pass_once(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        patterns: Option<&CompiledPatternRules>,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
    ) -> Result<RelayBoundaryPass> {
        let binding = self.relay_policy_binding(request, config)?;
        let Some(policy) = hosted else {
            // No hosted policy in play: there is nothing to classify against,
            // so the model is never called and nothing can degrade.
            return Ok(RelayBoundaryPass::classified(
                PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal),
                None,
                false,
                RelayResolution::NoPolicyInPlay,
            ));
        };
        let empty = CompiledPatternRules::default();
        let patterns = patterns.unwrap_or(&empty);
        let evaluation = patterns
            .evaluate_where(&request.content, &|rule: &CompiledPatternRule| {
                policy.row_for_category(rule.category()).is_some()
            });
        let audit = pass_audit(&evaluation);

        if evaluation.acting_role() == Some(PolicyPatternRole::Decide) {
            // A hard rule the substrate owner wrote. It is the verdict, the
            // model is not consulted, and this is the coverage that survives an
            // outage.
            let row = evaluation
                .acting
                .and_then(|rule| policy.row_for_category(rule.category()));
            if let Some(row) = row {
                return Ok(RelayBoundaryPass::classified(
                    hosted_row_verdict(row, policy, binding, config).with_audit(audit),
                    None,
                    true,
                    RelayResolution::PatternDecided,
                ));
            }
        }
        if !wants_model(config.hosted_classifier_mode, evaluation.acting_role()) {
            return Ok(RelayBoundaryPass::classified(
                PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal)
                    .with_audit(audit),
                None,
                true,
                log_only_or_gated(&evaluation),
            ));
        }
        let Some(safeguard) = safeguard else {
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::SafeguardModelTierAbsent,
                true,
            ));
        };
        let Some(contract) = policy.output_contract else {
            // Registration refuses this, so reaching it means the registry was
            // bypassed. Fail closed rather than guess the answer shape — and
            // say WHICH gap it was: there is a model here, what is missing is
            // the shape of the answer.
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::OutputContractUndeclared,
                true,
            ));
        };
        let prompt = render_classify_prompt(
            request,
            &policy.policy_document,
            hosted_rubric_rows(policy),
            contract,
        );
        let response = match safeguard
            .backend
            .generate(prompt.llm_request(config), safeguard.lease)
            .await
        {
            Ok(response) => response,
            Err(_unavailable) => {
                return Ok(degraded_hosted_pass(
                    binding,
                    config,
                    audit,
                    RelayBoundaryDegrade::SafeguardModelUnavailable,
                    true,
                ));
            }
        };
        let Ok(resolved) =
            resolve_policy_model_response(&response, &prompt, &AnswerPlane::Hosted(policy))
        else {
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::SafeguardModelResponseUnusable,
                true,
            ));
        };
        let mut audit = audit;
        audit.model_rule_ids = resolved.answer.rule_ids;
        audit.model_rule_ids_dropped = resolved.dropped_rule_ids;
        audit.model_confidence = resolved.answer.confidence;
        audit.model_rationale = resolved.answer.rationale;
        Ok(RelayBoundaryPass::classified(
            PolicyClassifyVerdict::new(
                resolved.decision,
                resolved.category,
                PolicyConfidence::MEDIUM,
                binding,
                config,
                PolicyPlane::HostedLegal,
            )
            .with_audit(audit),
            None,
            true,
            RelayResolution::ModelDecided,
        ))
    }
}

impl Vault {
    /// Verifies a CloudVault receipt produced by our vault-side runner. The
    /// receipt lookup and every comparison are over locally derived values.
    ///
    /// Content and read-frontier hashes plus the safeguard selector establish
    /// that the receipt describes THIS content under THIS policy state. They do
    /// not, on their own, establish that the hosted legal plane ever ran: a
    /// vault-side pass evaluates the OWNER plane, and a clean owner-plane
    /// `Allow` verified this far would otherwise skip the relay entirely — the
    /// hosted service's own legal duty silently discharged by the vault's
    /// verdict about a different question. So with a hosted policy in play the
    /// receipt must additionally carry hosted evidence naming that policy's
    /// version and hash — and since the hash now covers the policy DOCUMENT,
    /// that evidence names the exact text that was in force.
    ///
    /// A receipt without it is not an ERROR, it is simply not evidence of a
    /// hosted pass: it falls through to the hosted pass like any other
    /// untrusted receipt, and the breach is audited.
    ///
    /// The check sits BEFORE the decision branch on purpose. A stored non-Allow
    /// verdict is returned verbatim, and `Warn` does not halt — so trusting an
    /// unattested `Warn` would relay the content with the hosted plane never
    /// consulted, which is the same hole in a milder coat.
    pub(in super::super) fn cloud_vault_verified_trust(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayBoundaryPass> {
        let binding = self.relay_verify_binding(request, config)?;
        let Some(receipt) = verdicts.latest_boundary_verdict(&binding.content_hash)? else {
            return Err(Error::RelayVaultReceiptUntrusted { reason: "missing" });
        };
        if receipt.binding.content_hash != binding.content_hash
            || receipt.binding.read_frontier_hash != binding.read_frontier_hash
        {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "binding_mismatch",
            });
        }
        if receipt.safeguard_binding != config.safeguard_binding.selector() {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "safeguard_binding_mismatch",
            });
        }
        // The dial gets the same treatment as the selector beside it, and for
        // the same reason: the receipt is only evidence while the
        // configuration that produced it is the configuration in force. It is
        // the OWNER dial, because the pass this receipt records is a
        // vault-side one — the hosted dial governs the pass the relay would
        // run instead, not the pass it is deciding whether to trust. A receipt
        // recording no dial at all predates the field and is not trusted.
        if receipt.classifier_mode != Some(config.owner_classifier_mode) {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "classifier_mode_mismatch",
            });
        }
        if let Some(policy) = hosted
            && !receipt.attests_hosted_plane(policy, config)
        {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "hosted_plane_unattested",
            });
        }
        if receipt.decision != PolicyClassifyDecision::Allow {
            // Returned as it stands, and recorded as exactly that. The relay
            // verified WHAT was judged; it has no evidence of HOW, and with no
            // hosted policy bound the attestation check that would narrow it
            // never even ran.
            return Ok(RelayBoundaryPass::classified(
                receipt,
                None,
                hosted.is_some(),
                RelayResolution::VaultSideDecided,
            ));
        }
        Ok(RelayBoundaryPass::TrustedVaultSide)
    }
}

impl Vault {
    /// Shares CloudVault verification and breach capture between relay entry
    /// points.
    pub(super) fn cloud_vault_pass_or_hosted_fallback(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<CloudVaultPassOrFallback> {
        match self.cloud_vault_verified_trust(request, hosted, config, verdicts) {
            Ok(pass) => Ok(CloudVaultPassOrFallback::Pass(pass)),
            Err(Error::RelayVaultReceiptUntrusted { reason }) => {
                Ok(CloudVaultPassOrFallback::HostedFallback {
                    receipt_breach: reason,
                })
            }
            Err(error) => Err(error),
        }
    }
}

impl Vault {
    pub(in super::super) fn relay_verify_binding(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyContentBinding> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(malformed_relay_policy_error());
        }
        let _ = config; // Kept in the seam alongside the sibling relay binding.
        relay_verify_content_binding(request, &policy)
    }
}

impl Vault {
    /// Binding plus fail-closed check for a relay pass. The vault's own policy
    /// state never decides a hosted verdict, but it does bind the receipt, so
    /// an unreadable manifest still fails the pass closed.
    fn relay_policy_binding(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyContentBinding> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(malformed_relay_policy_error());
        }
        content_binding(request, &policy, config)
    }
}

fn hosted_row_verdict(
    row: &super::planes::HostedLegalRow,
    policy: &HostedLegalPolicy,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict::new(
        row.action.decision(),
        PolicyVerdictCategory::HostedLegal {
            category: row.category.clone(),
            jurisdiction: policy.jurisdiction.clone(),
            policy_version: policy.version.clone(),
            row_ref: row.row_ref.clone(),
        },
        PolicyConfidence::CERTAIN,
        binding,
        config,
        PolicyPlane::HostedLegal,
    )
}
