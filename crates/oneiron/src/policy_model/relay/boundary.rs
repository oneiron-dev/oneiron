//! Relay entry points and ledger writes: trust-domain dispatch, dual-plane fan-out, binding-checked receipts.

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate;
use crate::store::GateSystemNoticeRecord;

use super::super::binding::{
    PolicyContentBinding, content_binding, relay_skip_content_binding, relay_verify_content_binding,
};
use super::super::classify::OwnerPlanePass;
use super::super::concurrent::join2;
use super::super::notice::{policy_model_rationale_notice, policy_notice};
use super::super::pattern::CompiledPatternRules;
use super::super::planes::{HostedLegalPolicy, PolicyPlane};
use super::super::receipt::policy_model_reason_codes;
use super::super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::super::verdict::{PolicyClassifyDecision, PolicyClassifyVerdict};
use super::outcome::{
    CloudVaultPassOrFallback, DualPlanePass, RelayBoundaryDegrade, RelayBoundaryPass,
    RelayReceiptRow, RelayResolution, RelaySafeguardTier, VaultSideVerdictSource,
    degraded_hosted_pass, pass_audit_of,
};
use super::registry::EdgeServiceRegistry;
use super::trust::{AttestedRelayDomain, RelayTrustDomain};
use crate::error::RelayError;

impl Vault {
    /// The relay-boundary pass over the hosted legal plane.
    ///
    /// Runs where OUR infrastructure touches a vault's outbound content, once
    /// per trust domain. `domain` is a sealed [`AttestedRelayDomain`] witness:
    /// the caller (the hosted relay / connector edge) mints it from an
    /// [`AuthenticatedConnectionIdentity`](crate::policy_model::AuthenticatedConnectionIdentity) its edge auth validated, NEVER from
    /// a vault-attested "already classified" receipt — the domain is evidence
    /// now, not a label the caller picks.
    ///
    /// The relaying service's legal policy is RESOLVED HERE, from `registry`
    /// keyed by the witness's own attested identity (see
    /// [`EdgeServiceRegistry::hosted_legal_policy`]) — there is deliberately no
    /// policy parameter, because a caller that could hand one in could choose
    /// the jurisdiction it is judged under. With no policy bound to that
    /// identity there is nothing to enforce and every pass is clean.
    ///
    /// * [`RelayTrustDomain::CloudVault`] — verifies the vault-side receipt
    ///   against locally recomputed hashes and, with a hosted policy in play,
    ///   against that policy's own attestation; a fully verified `Allow` is
    ///   trusted, a verified non-`Allow` is returned as it stands, and anything
    ///   untrusted falls back to the hosted pass with an audit receipt.
    /// * [`RelayTrustDomain::LocalViaHostedConnector`] — runs the hosted legal
    ///   plane. The owner plane is never assembled or evaluated here.
    /// * [`RelayTrustDomain::LocalViaByoConnector`] — nothing transits us; no
    ///   pass runs ([`RelayBoundaryPass::NotRelayedByUs`]).
    ///
    /// `safeguard` is optional so a deployment with no classifier can still
    /// call this — but a pass that NEEDED a model verdict and had none is
    /// degraded, and a degraded pass with a hosted policy in play halts the
    /// relay. Deterministic coverage during an outage is exactly and only the
    /// substrate owner's `Decide` pattern rules.
    ///
    /// Advisory: this classifies but does not itself halt the relay — the
    /// caller must honor [`RelayBoundaryPass::must_halt_relay`]. Every pass
    /// that carries a signal is receipted; the one pass that is not is a clean
    /// allow the model actually examined with nothing to say. A returned `Err`
    /// means infrastructure misuse only — unresolvable/malformed local policy
    /// state or a failed receipt write — never a model outcome.
    pub async fn relay_boundary_pass(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayBoundaryPass> {
        let verify_at = self.relay_verify_at(&request, domain, config)?;
        self.relay_boundary_pass_at(
            request, domain, registry, config, safeguard, verdicts, verify_at,
        )
        .await
    }

    /// The identity-free binding a CloudVault reuse is verified at, pinned
    /// by its door before the lookup, so the door's last transaction can tell
    /// whether the manifest moved since. No other domain reuses a verdict.
    fn relay_verify_at(
        &self,
        request: &PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        config: &PolicyModelConfig,
    ) -> Result<Option<PolicyContentBinding>> {
        match domain.domain() {
            RelayTrustDomain::CloudVault => self.relay_verify_binding(request, config).map(Some),
            RelayTrustDomain::LocalViaByoConnector | RelayTrustDomain::LocalViaHostedConnector => {
                Ok(None)
            }
        }
    }

    /// [`Self::relay_boundary_pass`], with a CloudVault reuse verified at
    /// `verify_at`, the binding its door pinned.
    #[expect(clippy::too_many_arguments)]
    async fn relay_boundary_pass_at(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
        verify_at: Option<PolicyContentBinding>,
    ) -> Result<RelayBoundaryPass> {
        let hosted = registry.hosted_legal_policy(domain.service_identity());
        let patterns = registry.compiled_patterns(domain.service_identity());
        let mut receipt_breach = None;
        let pass = match domain.domain() {
            RelayTrustDomain::CloudVault => {
                match self.cloud_vault_pass_or_hosted_fallback(
                    &request, hosted, config, verdicts, verify_at,
                )? {
                    CloudVaultPassOrFallback::Pass(pass) => pass,
                    CloudVaultPassOrFallback::HostedFallback {
                        receipt_breach: reason,
                    } => {
                        receipt_breach = Some(reason);
                        self.hosted_relay_pass(&request, hosted, patterns, config, safeguard)
                            .await?
                    }
                }
            }
            RelayTrustDomain::LocalViaByoConnector => RelayBoundaryPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                self.hosted_relay_pass(&request, hosted, patterns, config, safeguard)
                    .await?
            }
        };
        // The receipt write takes the LAST word on the policy binding, so a
        // move it catches replaces the pass the caller gets. Otherwise the
        // ledger would record a halt-worthy degrade against a pass whose
        // `must_halt_relay` is false, and the relay would proceed on an allow
        // its own receipt disowns.
        let recorded = self.record_relay_receipt(RelayReceipt {
            request: &request,
            domain,
            pass: &pass,
            receipt_breach,
            hosted,
            config,
            verify_at,
        })?;
        Ok(recorded.unwrap_or(pass))
    }
}

impl Vault {
    /// Both planes, one round trip.
    ///
    /// For content that BOTH leaves a vault under its owner's policy AND
    /// transits our relay under a hosted legal policy, the two model calls are
    /// independent — different documents, different rows, different machinery —
    /// so they are ISSUED CONCURRENTLY rather than one after the other. The
    /// latency of asking two planes is the latency of asking one.
    ///
    /// Each verdict is routed to its own plane: the hosted pass decides whether
    /// the relay may proceed, and the owner's verdict is the vault's to enforce.
    /// Neither is allowed to stand in for the other.
    ///
    /// BOTH planes are receipted, HERE, because this is the door that made
    /// both decisions. The relay pass writes its own row on the way through;
    /// the owner pass gets one under owner-plane keys, so a vault owner
    /// reading their own ledger finds their plane's verdict about their own
    /// content beside the hosted service's. A model that failed leaves a row
    /// too, saying the plane fell open.
    ///
    /// The owner verdict is handed back raw for the vault to enforce, and
    /// [`Vault::enforce_policy_model_verdict`] is where it goes. That door
    /// deliberately writes nothing: the decision is already in the ledger, and
    /// a second row for it under a second outcome would double every count
    /// read off those rows.
    pub async fn classify_both_planes(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<DualPlanePass> {
        let owner_safeguard = safeguard.map(|tier| (tier.backend, tier.lease));
        let verify_at = self.relay_verify_at(&request, domain, config)?;
        let (owner, relay) = join2(
            self.owner_plane_pass_pinned(&request, config, owner_safeguard),
            self.relay_boundary_pass_at(
                request.clone(),
                domain,
                registry,
                config,
                safeguard,
                verdicts,
                verify_at,
            ),
        )
        .await;
        let mut owner = owner?;
        let relay = relay?;
        // The owner half settled first and then waited on the hosted half,
        // so the manifest may have moved since it was pinned. Pin it again.
        if self.policy_model_verdict_is_stale_with_config(&owner.verdict, &request, config)? {
            owner = self
                .owner_plane_pass_pinned(&request, config, owner_safeguard)
                .await?;
        }
        // Both halves are settled against the policy in force in ONE final
        // transaction, which writes their rows: the owner half to its answer
        // there, the hosted half (run here or reused) to the halting
        // binding-moved degrade if its binding moved. Checked in two
        // transactions, an edit between them would leave one half answering
        // a policy already replaced. No retry — the degrade is the typed
        // answer to a policy that will not hold.
        #[cfg(test)]
        super::super::in_force::before_settling(super::super::in_force::SettlingDoor::DualPlane);
        let mut wtxn = self.store.env.write_txn()?;
        let owner = self.record_owner_plane_receipt_in_txn(&mut wtxn, &request, owner, config)?;
        let moved = self.relay_pass_moved_in_txn(
            &mut wtxn,
            &RelayReceipt {
                request: &request,
                domain,
                pass: &relay,
                receipt_breach: None,
                hosted: registry.hosted_legal_policy(domain.service_identity()),
                config,
                verify_at,
            },
        )?;
        wtxn.commit()?;
        let owner_model_skipped = owner.model_skipped();
        Ok(DualPlanePass {
            owner: owner.verdict,
            relay: moved.unwrap_or(relay),
            owner_model_skipped,
        })
    }
}

impl Vault {
    /// Writes the OWNER plane's row for a dual-plane pass.
    ///
    /// The relay side receipts itself; this is the other half of the same
    /// pass, written under owner-plane keys with the same conventions as the
    /// relay row — `gate.`-namespaced codes, model-supplied strings tokenized
    /// by [`policy_model_reason_codes`]. Enforcing the verdict afterwards adds
    /// no second row; see [`Vault::enforce_policy_model_verdict`].
    ///
    /// Same silence rule too: a clean allow that learned nothing and got the
    /// model it wanted has nothing to record. A pass whose model did NOT
    /// answer is the opposite — the sovereign plane fell open, and that is
    /// precisely the fact the owner is owed.
    ///
    /// Returns the pass the door hands out, settled against the policy in
    /// force in the door's final transaction, which writes the row.
    fn record_owner_plane_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: &PolicyClassifyRequest,
        pass: OwnerPlanePass,
        config: &PolicyModelConfig,
    ) -> Result<OwnerPlanePass> {
        let (verdict, moved) =
            self.owner_verdict_in_force_in_txn(wtxn, &pass.verdict, request, config)?;
        let pass = OwnerPlanePass { verdict };
        if pass.verdict.decision == PolicyClassifyDecision::Allow
            && pass.verdict.audit.is_none()
            && !moved
        {
            return Ok(pass);
        }
        let verdict = &pass.verdict;
        let mut reason_codes = vec![
            "gate.relay.owner_plane.classify.ran".to_owned(),
            format!(
                "gate.relay.owner_plane.classifier_mode.{}",
                config.owner_classifier_mode.as_str()
            ),
        ];
        if pass.model_skipped() {
            reason_codes.push("gate.relay.owner_plane.model_skipped".to_owned());
            reason_codes.push("gate.relay.owner_plane.fail_open".to_owned());
        }
        if moved {
            reason_codes.push("gate.relay.owner_plane.frontier_moved".to_owned());
        }
        reason_codes.extend(policy_model_reason_codes(verdict));
        let mut notices: Vec<_> = policy_notice(verdict.decision, &verdict.category, None, config)
            .into_iter()
            .collect();
        // Appended last, as everywhere: an audit row must never become the
        // single body a caller surfaces.
        notices.extend(policy_model_rationale_notice(
            verdict,
            PolicyPlane::OwnerPolicy,
            None,
        ));
        self.append_policy_model_gate_receipt_in_txn(
            wtxn,
            request,
            verdict,
            &format!("owner_plane_{}", verdict.decision.ledger_str()),
            reason_codes,
            notices,
        )?;
        Ok(pass)
    }
}

impl Vault {
    /// Writes the relay-boundary audit receipt.
    ///
    /// The rule is that a pass carrying ANY signal is recorded: a warn, block
    /// or route; a degrade; an untrusted vault receipt; a trust-domain skip;
    /// any substrate-owner pattern that matched — including one the model went
    /// on to overrule, which is precisely the data that tells the owner their
    /// pattern is too wide; and any resolution other than a clean one nobody
    /// needs told about.
    ///
    /// Exactly TWO pass shapes write nothing, and both are silent because there
    /// was nothing to say: the model looked at the content and found it clean
    /// ([`RelayResolution::ModelDecided`]), and no hosted policy was bound to
    /// the attested identity at all
    /// ([`RelayResolution::NoPolicyInPlay`]) — in the second case no question
    /// was ever asked, so there is no answer to record. Either way a degrade, a
    /// breach or a matched pattern puts the row back.
    /// Test-only door onto [`Self::record_relay_receipt`], which is private
    /// and takes a borrowed struct the test module cannot name a lifetime for
    /// otherwise. No production caller.
    #[cfg(test)]
    pub(in super::super) fn record_relay_receipt_for_test(
        &self,
        request: &PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        pass: &RelayBoundaryPass,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
    ) -> Result<Option<RelayBoundaryPass>> {
        self.record_relay_receipt(RelayReceipt {
            request,
            domain,
            pass,
            receipt_breach: None,
            hosted,
            config,
            verify_at: None,
        })
    }
}

impl Vault {
    fn record_relay_receipt(&self, receipt: RelayReceipt<'_>) -> Result<Option<RelayBoundaryPass>> {
        #[cfg(test)]
        super::super::in_force::before_settling(
            super::super::in_force::SettlingDoor::RelayBoundary,
        );
        let domain = receipt.domain.domain();
        // The gate decision ledger requires every reason code to be namespaced
        // under `gate.`, so relay codes ride there too. This row records the
        // HOSTED plane, so the dial it stamps is the hosted one; the owner
        // plane's row stamps its own under `gate.relay.owner_plane.`.
        let mut reason_codes = vec![
            format!("gate.relay.trust_domain.{}", domain.as_str()),
            format!(
                "gate.relay.classifier_mode.{}",
                receipt.config.hosted_classifier_mode.as_str()
            ),
            if receipt.pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
        ];
        if let Some(degrade) = receipt.pass.degraded() {
            reason_codes.push(format!("gate.relay.degraded.{}", degrade.as_str()));
            // WHICH degrade it was does not tell a reader what the relay then
            // did, because that depends on the host's outage policy and on
            // whether this degrade was an availability one. Say it outright.
            reason_codes.push(
                if receipt.pass.must_halt_relay() {
                    "gate.relay.degrade_halted"
                } else {
                    "gate.relay.degrade_proceeded"
                }
                .to_owned(),
            );
        }
        if let Some(resolution) = receipt.pass.resolution() {
            reason_codes.push(format!("gate.relay.resolution.{}", resolution.as_str()));
        }
        if let Some(reason) = receipt.receipt_breach {
            reason_codes.push(format!("gate.relay.vault_receipt_untrusted.{reason}"));
        }
        let mut notices = Vec::new();
        let (outcome, receipt_verdict) = match receipt.pass {
            RelayBoundaryPass::Classified(classified) => {
                let verdict = &classified.verdict;
                let signalless = verdict.decision == PolicyClassifyDecision::Allow
                    && classified.degraded.is_none()
                    && receipt.receipt_breach.is_none()
                    && matches!(
                        classified.resolution,
                        RelayResolution::ModelDecided | RelayResolution::NoPolicyInPlay
                    )
                    && verdict.audit.is_none();
                if signalless {
                    // A clean allow leaves no row — but it still has a pinned
                    // binding, and the relay is about to act on it. Skipping
                    // the re-check here would leave the commonest hosted
                    // result, an unaudited model allow, as the one path that
                    // can relay against policy state it can no longer pin.
                    // So the check still runs; it just writes nothing unless
                    // the binding moved, in which case the move IS the signal
                    // and earns its row.
                    return self.append_relay_receipt_binding_checked(
                        &receipt,
                        verdict,
                        &format!("relay_boundary_{}", verdict.decision.ledger_str()),
                        reason_codes,
                        Vec::new(),
                        RelayReceiptRow::OnlyIfBindingMoved,
                    );
                }
                reason_codes.extend(policy_model_reason_codes(verdict));
                notices.extend(policy_notice(
                    verdict.decision,
                    &verdict.category,
                    receipt.hosted,
                    receipt.config,
                ));
                // The relay boundary evaluates the hosted plane and nothing
                // else, so a rationale its verdict does not attribute — a
                // clean allow the model examined after a pattern fired — is
                // still a hosted-plane row.
                notices.extend(policy_model_rationale_notice(
                    verdict,
                    PolicyPlane::HostedLegal,
                    receipt.hosted.map(|hosted| hosted.version.as_str()),
                ));
                (
                    format!("relay_boundary_{}", verdict.decision.ledger_str()),
                    verdict.clone(),
                )
            }
            RelayBoundaryPass::TrustedVaultSide => (
                "relay_trusted_vault_side".to_owned(),
                relay_skip_verdict(receipt.request, receipt.config),
            ),
            RelayBoundaryPass::NotRelayedByUs => (
                "relay_not_relayed".to_owned(),
                relay_skip_verdict(receipt.request, receipt.config),
            ),
        };
        self.append_relay_receipt_binding_checked(
            &receipt,
            &receipt_verdict,
            &outcome,
            reason_codes,
            notices,
            RelayReceiptRow::Always,
        )
    }
}

impl Vault {
    /// Writes the relay row, re-checking the policy binding INSIDE the write
    /// transaction and recording a degrade instead if it moved.
    ///
    /// The pass re-checks its binding and then returns; this row is written in
    /// a separate transaction afterwards. That gap is the same window the
    /// mid-pass re-check closes one seam earlier, and it has the same
    /// consequence: a manifest that moves in it leaves the ledger asserting a
    /// verdict against policy state nobody can reproduce, which is exactly
    /// what a later CloudVault verification would fail on.
    ///
    /// So the last word is taken where the row is written. If the binding
    /// moved, the row records `PolicyBindingMovedMidPass` against the FRESH
    /// binding rather than the verdict's dead one — the pass's own audit rides
    /// along, because what the substrate owner's patterns matched is still
    /// true and should not be thrown away with the verdict it replaces.
    ///
    /// Which binding a pass is checked on, and when it is not checked at all,
    /// is [`Self::relay_pass_moved_in_txn`]'s; a CloudVault reuse is checked
    /// too, at the binding its door verified it at.
    ///
    /// Returns the degraded pass when the binding moved, so the CALLER's pass
    /// becomes the one the ledger describes. Writing a halt-worthy degrade row
    /// and then handing back the undegraded pass would make the ledger and the
    /// behaviour disagree: `must_halt_relay` would be false on a pass whose
    /// receipt says the relay stopped. A record nobody honours is worse than
    /// no record, because it reads as authoritative.
    #[expect(clippy::too_many_arguments)]
    pub(in super::super) fn append_relay_receipt_binding_checked_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &RelayReceipt<'_>,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        notices: Vec<GateSystemNoticeRecord>,
        row: RelayReceiptRow,
    ) -> Result<Option<RelayBoundaryPass>> {
        if let Some(moved) = self.relay_pass_moved_in_txn(wtxn, receipt)? {
            return Ok(Some(moved));
        }
        if row == RelayReceiptRow::Always {
            self.append_policy_model_gate_receipt_in_txn(
                wtxn,
                receipt.request,
                verdict,
                outcome,
                reason_codes,
                notices,
            )?;
        }
        Ok(None)
    }

    /// The `PolicyBindingMovedMidPass` degrade that replaces `receipt.pass`,
    /// with its row in `wtxn`, when the binding the pass answers is no longer
    /// the one in force there; otherwise `None`.
    ///
    /// A pass run here is compared on the `content_binding` it pinned. A
    /// CloudVault reuse (`TrustedVaultSide`, or a returned `VaultSideDecided`
    /// verdict) pinned no binding of its own: it was verified at `verify_at`,
    /// the identity-free binding its door pinned before the lookup, so it is
    /// compared on that, in that family. Comparing either family with the
    /// other would read every pass as moved. A reuse with no binding pinned
    /// is read as moved. A pass with no verdict and no reuse pinned nothing.
    ///
    /// And no hosted policy means no re-check at all, in PARITY with
    /// `hosted_relay_pass`: that seam skips its own comparison whenever
    /// `hosted.is_none()`, because with nothing bound to the attested
    /// identity there is nothing to pin and no model call to pin it
    /// across. Running the comparison here and not there would let the
    /// same event produce a degrade one seam later than it possibly could
    /// — and a `NoPolicyInPlay` fallback, reachable through a receipt
    /// breach, would come back HALTING on a hosted plane that was never in
    /// play.
    fn relay_pass_moved_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &RelayReceipt<'_>,
    ) -> Result<Option<RelayBoundaryPass>> {
        let reused = reuses_vault_side(receipt.pass);
        if receipt.hosted.is_none() || (!reused && receipt.pass.boundary_verdict().is_none()) {
            return Ok(None);
        }
        let policy = gate::resolve_policy_manifest(&self.store, wtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(malformed_relay_policy_error());
        }
        let fresh = content_binding(receipt.request, &policy, receipt.config)?;
        let unmoved = match (reused, receipt.verify_at) {
            (true, Some(verify_at)) => {
                relay_verify_content_binding(receipt.request, &policy)? == verify_at
            }
            (true, None) => false,
            (false, _) => receipt.pass.boundary_verdict().is_some_and(|verdict| {
                verdict.binding == fresh
                    && verdict.decision_binding
                        == receipt.config.decision_binding(PolicyPlane::HostedLegal)
            }),
        };
        if unmoved {
            return Ok(None);
        }
        self.append_binding_moved_row_in_txn(wtxn, receipt, fresh)
            .map(Some)
    }

    /// [`Self::append_relay_receipt_binding_checked_in_txn`] in a
    /// transaction of its own.
    pub(in super::super) fn append_relay_receipt_binding_checked(
        &self,
        receipt: &RelayReceipt<'_>,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        notices: Vec<GateSystemNoticeRecord>,
        row: RelayReceiptRow,
    ) -> Result<Option<RelayBoundaryPass>> {
        let mut wtxn = self.store.env.write_txn()?;
        let moved = self.append_relay_receipt_binding_checked_in_txn(
            &mut wtxn,
            receipt,
            verdict,
            outcome,
            reason_codes,
            notices,
            row,
        )?;
        wtxn.commit()?;
        Ok(moved)
    }

    /// Records the `PolicyBindingMovedMidPass` degrade that replaces a pass
    /// whose binding moved, against the FRESH binding, in the caller's
    /// transaction, and returns the replacement pass.
    fn append_binding_moved_row_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &RelayReceipt<'_>,
        fresh: PolicyContentBinding,
    ) -> Result<RelayBoundaryPass> {
        // Minted through the one constructor that raises a degrade,
        // so the halt is resolved against the host's outage policy
        // exactly as it would have been mid-pass — a binding move is
        // not an availability degrade, so it halts under either
        // setting, but the row says so rather than assuming it.
        //
        // And told what the ORIGINAL pass knew: whether a hosted
        // policy was bound at all. Hardcoding that true would make a
        // fallback with no hosted policy in play come back claiming a
        // plane it never had — and `must_halt_relay` reads exactly
        // that flag, so it would halt on it too. A reuse was trusted for
        // the hosted policy bound now, so that plane was in play.
        let moved_pass = degraded_hosted_pass(
            fresh,
            receipt.config,
            pass_audit_of(receipt.pass),
            RelayBoundaryDegrade::PolicyBindingMovedMidPass,
            receipt.pass.hosted_policy_in_play() || reuses_vault_side(receipt.pass),
        );
        let degraded = moved_pass
            .boundary_verdict()
            .ok_or(Error::CorruptedIndex("degraded relay pass without verdict"))?
            .clone();
        let mut codes = vec![
            format!(
                "gate.relay.trust_domain.{}",
                receipt.domain.domain().as_str()
            ),
            format!(
                "gate.relay.classifier_mode.{}",
                receipt.config.hosted_classifier_mode.as_str()
            ),
            if receipt.pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
            format!(
                "gate.relay.degraded.{}",
                RelayBoundaryDegrade::PolicyBindingMovedMidPass.as_str()
            ),
            if moved_pass.must_halt_relay() {
                "gate.relay.degrade_halted"
            } else {
                "gate.relay.degrade_proceeded"
            }
            .to_owned(),
            format!(
                "gate.relay.resolution.{}",
                RelayResolution::Unresolved.as_str()
            ),
        ];
        // The verdict is replaced; the EVIDENCE for why this pass ran
        // the way it did is not. An untrusted vault receipt is the
        // reason the hosted fallback happened at all, and rebuilding
        // the codes from scratch dropped it.
        if let Some(reason) = receipt.receipt_breach {
            codes.push(format!("gate.relay.vault_receipt_untrusted.{reason}"));
        }
        codes.extend(policy_model_reason_codes(&degraded));
        // Same rule, the other carrier. `pass_audit_of` copies the
        // model's rule ids and confidence into the replacement, but
        // the RATIONALE has no reason code — its only durable form is
        // the audit notice, and passing an empty notice list threw it
        // away. What the model said about the substrate owner's rules
        // is what the owner reads back to improve them; replacing the
        // verdict is no reason to lose it.
        let notices: Vec<GateSystemNoticeRecord> = policy_model_rationale_notice(
            &degraded,
            PolicyPlane::HostedLegal,
            receipt.hosted.map(|hosted| hosted.version.as_str()),
        )
        .into_iter()
        .collect();
        self.append_policy_model_gate_receipt_in_txn(
            wtxn,
            receipt.request,
            &degraded,
            // The outcome follows the replacement verdict, as every
            // other receipt row's does: a halted pass is no Allow.
            &format!("relay_boundary_{}", degraded.decision.ledger_str()),
            codes,
            notices,
        )?;
        Ok(moved_pass)
    }
}

pub(in crate::policy_model) struct RelayReceipt<'a> {
    pub(in super::super) request: &'a PolicyClassifyRequest,
    pub(in super::super) domain: &'a AttestedRelayDomain,
    pub(in super::super) pass: &'a RelayBoundaryPass,
    pub(in super::super) receipt_breach: Option<&'static str>,
    pub(in super::super) hosted: Option<&'a HostedLegalPolicy>,
    pub(in super::super) config: &'a PolicyModelConfig,
    /// The binding a CloudVault reuse was verified at; `None` elsewhere.
    pub(in super::super) verify_at: Option<PolicyContentBinding>,
}

/// A CloudVault reuse: a vault-side verdict trusted (`TrustedVaultSide`) or
/// returned as it stands (`VaultSideDecided`), not a pass run here.
fn reuses_vault_side(pass: &RelayBoundaryPass) -> bool {
    matches!(pass, RelayBoundaryPass::TrustedVaultSide)
        || pass.resolution() == Some(RelayResolution::VaultSideDecided)
}

/// Synthetic receipt verdict for a trust-domain SKIP. A skip never classifies
/// against policy state, so the receipt binds to a content-only hash with a
/// zero policy frontier — an honest "did not run" marker.
fn relay_skip_verdict(
    request: &PolicyClassifyRequest,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict::clean_allow(
        relay_skip_content_binding(request),
        config,
        PolicyPlane::HostedLegal,
    )
}

pub(super) fn malformed_relay_policy_error() -> Error {
    Error::Relay(RelayError::PolicyManifestInvalid {
        field: "policy_manifest",
        reason: "is malformed for relay-boundary pass",
    })
}

impl EdgeServiceRegistry {
    pub(super) fn compiled_patterns(
        &self,
        service_identity: &str,
    ) -> Option<&CompiledPatternRules> {
        Some(&self.entry(service_identity)?.patterns)
    }
}
