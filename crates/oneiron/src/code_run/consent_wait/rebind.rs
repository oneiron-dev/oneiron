//! Two-party rebind of an already admitted, unsettled code consent wait.

use crate::Vault;
use crate::consent::{AuthenticatedOwner, EffectDigest, approve_once_decision_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::binding::{binding_digest, put_code_consent_wait_in_txn, read_code_consent_wait_in_txn};
use super::browser::browser_facts_match_row;
use super::rebind_types::{
    CodeConsentRebind, CodeConsentRebindPrepared, CodeConsentRebindProposal,
    CodeConsentRebindTarget,
};
use super::settle::now_ms;
use super::types::{CodeConsentPrincipal, CodeConsentWaitRow};

impl Vault {
    /// Reuses this frozen intent's consumed approval under its current live binding.
    /// The send boundary holds the same writer; this admits and spends nothing.
    pub(crate) fn code_consent_retry_approval_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &crate::outbound_intent_ledger::IntentLedgerRecord,
        wait_id: EntityId,
    ) -> Result<bool> {
        let Some(row) = read_code_consent_wait_in_txn(self, txn, wait_id)? else {
            return Ok(false);
        };
        if !row.approved_unsettled()
            || row.consumption.is_some()
            || row
                .admission
                .as_ref()
                .is_none_or(|admission| admission.intent_id != record.id)
        {
            return Ok(false);
        }
        eligible(&row)?;
        let active = row.active_binding();
        if let Some(credential) = row.active_credential() {
            let verified = match self.invocation_slip_in_txn(txn, &credential.witness) {
                Ok(verified) => verified,
                Err(Error::Record(crate::error::RecordError::InvalidAuthorityLogBody(_))) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            let claims = verified.claims();
            if active
                .original
                .opener_slip
                .is_some_and(|slip| slip != claims.slip_id)
                || credential.instrument.as_ref().is_some_and(|instrument| {
                    crate::runtime_hooks::verb::verb_ask_instrument_slip(&instrument)
                        != Some(claims.slip_id)
                        || instrument.vault != claims.vault_id
                })
            {
                return Ok(false);
            }
        }
        let (effect, _) = match crate::outbound_consent::code_wait_rebind_effects_in_txn(
            self,
            txn,
            &row,
            &active.binding_digest,
            &active.binding_digest,
        ) {
            Ok(effects) => effects,
            Err(IntentLedgerError::InvalidInput(_)) => return Ok(false),
            Err(IntentLedgerError::Engine(error)) => return Err(error),
            Err(IntentLedgerError::InvalidRecord(reason)) => {
                return Err(Error::CorruptedIndex(reason));
            }
            Err(error) => return Err(Error::InvalidConfig(error.to_string())),
        };
        if effect.as_bytes() != &active.effect_digest {
            return Ok(false);
        }
        self.code_wait_consumed_approval_in_txn(txn, &row, &effect)
    }

    /// Keeps the original holder's actual successor request, with no authority change.
    pub(crate) fn prepare_code_consent_rebind(
        &self,
        target: &CodeConsentRebindTarget,
        principal: CodeConsentPrincipal,
        actor_class: &str,
    ) -> Result<CodeConsentRebindPrepared> {
        self.with_write_txn_grouped(|txn| {
            let mut row = read_code_consent_wait_in_txn(self, txn, target.wait_id)?
                .filter(|row| row.binding.original.actor_ref == principal.actor_ref)
                .ok_or(Error::EntityNotFound)?;
            check_target(&row, target)?;
            eligible(&row)?;
            let successor = principal.credential.as_ref().ok_or(Error::InvalidConfig(
                "a code consent wait rebind takes the holder's actual request-bound slip"
                    .to_owned(),
            ))?;
            let current = row.active_binding();
            let predecessor = current
                .original
                .credential
                .as_ref()
                .ok_or(Error::InvalidConfig(
                    "this code consent wait stands on no slip to rebind".to_owned(),
                ))?;
            let proof = self.rebind_invocation_slip_in_txn(
                txn,
                &predecessor.witness,
                &successor.witness,
                row.binding.original.actor_ref,
                actor_class,
            )?;
            let mut next = current.clone();
            next.original.credential = Some(successor.clone());
            next.original.opener_slip = Some(proof.successor);
            let next_binding = binding_digest(&next)?;
            let (previous, _) =
                effects_in_txn(self, txn, &row, &current.binding_digest, &next_binding)?;
            if row
                .consumed_approval()
                .is_none_or(|(digest, _)| digest != *previous.as_bytes())
            {
                return Err(Error::ConcurrentWrite(
                    "the code consent authorization changed",
                ));
            }
            let revision = row
                .revision
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("code consent wait revision"))?;
            let proposal = CodeConsentRebindProposal {
                id: self.store.clock.entity_id()?,
                target: target.clone(),
                prepared_revision: revision,
                requester: principal.actor_ref,
                actor_class: actor_class.to_owned(),
                predecessor: proof.predecessor,
                successor: proof.successor,
                credential: successor.clone(),
                prior_receipt: row.rebinds.last().map(|rebind| rebind.receipt),
                intent_id: row
                    .admission
                    .as_ref()
                    .ok_or(Error::EntityNotFound)?
                    .intent_id,
                proposed_at_ms: now_ms(),
            };
            let prepared = CodeConsentRebindPrepared {
                proposal_id: proposal.id,
                revision,
                predecessor: proof.predecessor,
                successor: proof.successor,
            };
            // An unconfirmed proposal is not authority and cannot lock out a newer request.
            row.rebind_proposal = Some(proposal);
            put_code_consent_wait_in_txn(
                self,
                txn,
                &mut row,
                crate::consent::CodeWaitCommand::PrepareRebind,
            )?;
            Ok(prepared)
        })
    }

    /// The separate owner's explicit act confirms one exact holder proposal.
    /// This changes only continuation authority, never the original admission.
    pub(crate) fn confirm_code_consent_rebind(
        &self,
        owner: &AuthenticatedOwner,
        target: &CodeConsentRebindTarget,
        proposal_id: EntityId,
    ) -> Result<(CodeConsentRebind, bool)> {
        let result = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut row = read_code_consent_wait_in_txn(self, txn, target.wait_id)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(prior) = row
                .rebinds
                .iter()
                .find(|rebind| rebind.proposal.id == proposal_id)
            {
                let digest = EffectDigest::from_bytes(prior.effect_digest);
                if prior.owner != actor
                    || confirmed_target(&prior.proposal) != *target
                    || row
                        .admission
                        .as_ref()
                        .is_none_or(|admission| admission.intent_id != prior.proposal.intent_id)
                    || approve_once_decision_in_txn(&self.store, txn, &digest)?
                        != Some(prior.marker_decision)
                {
                    return Err(Error::ConcurrentWrite(
                        "the code consent rebind identity changed",
                    ));
                }
                // A duplicate reads the first act; it does not authorize or reopen work.
                return Ok((prior.clone(), true));
            }
            check_target(&row, target)?;
            eligible(&row)?;
            let proposal = row
                .rebind_proposal
                .as_ref()
                .filter(|proposal| {
                    proposal.id == proposal_id && confirmed_target(proposal) == *target
                })
                .cloned()
                .ok_or(Error::ConcurrentWrite(
                    "the code consent rebind proposal changed",
                ))?;
            if proposal.requester != row.binding.original.actor_ref
                || proposal.prior_receipt != row.rebinds.last().map(|rebind| rebind.receipt)
                || row
                    .admission
                    .as_ref()
                    .is_none_or(|admission| admission.intent_id != proposal.intent_id)
            {
                return Err(Error::ConcurrentWrite("the code consent admission changed"));
            }
            let current = row.active_binding();
            let predecessor = current
                .original
                .credential
                .as_ref()
                .ok_or(Error::InvalidConfig(
                    "this code consent wait stands on no slip to rebind".to_owned(),
                ))?;
            let proof = self.rebind_invocation_slip_in_txn(
                txn,
                &predecessor.witness,
                &proposal.credential.witness,
                row.binding.original.actor_ref,
                &proposal.actor_class,
            )?;
            if proof.predecessor != proposal.predecessor || proof.successor != proposal.successor {
                return Err(Error::ConcurrentWrite(
                    "the proposed credential succession changed",
                ));
            }
            let mut lineage = row
                .binding
                .original
                .opener_slip
                .into_iter()
                .collect::<Vec<_>>();
            for rebind in &row.rebinds {
                lineage.extend([rebind.proposal.predecessor, rebind.proposal.successor]);
            }
            lineage.extend([proof.predecessor, proof.successor]);
            lineage.sort_unstable();
            lineage.dedup();
            if owner.answers_from_slip_lineage_in_txn(self, txn, &lineage)? {
                return Err(Error::Gate(GateError::ConsentUnauthenticatedActor(
                    "the opener lineage never authorizes its own code consent rebind",
                )));
            }
            let mut next = current.clone();
            next.original.credential = Some(proposal.credential.clone());
            next.original.opener_slip = Some(proof.successor);
            let next_binding = binding_digest(&next)?;
            let (previous, successor) =
                effects_in_txn(self, txn, &row, &current.binding_digest, &next_binding)?;
            let (_, previous_decision) = row.consumed_approval().ok_or(Error::EntityNotFound)?;
            let principal_ref = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let receipt =
                self.record_code_wait_rebind_in_txn(txn, owner, &row, previous, successor)?;
            let rebind = CodeConsentRebind {
                proposal,
                binding_digest: next_binding,
                effect_digest: *successor.as_bytes(),
                prior_effect_digest: *previous.as_bytes(),
                prior_decision: previous_decision,
                original_approval: row.answer.as_ref().ok_or(Error::EntityNotFound)?.decision,
                owner: actor,
                principal_ref,
                authentication: owner.decision_id(),
                receipt: receipt.decision_id(),
                marker_decision: if previous == successor {
                    previous_decision
                } else {
                    receipt.decision_id()
                },
                confirmed_at_ms: now_ms(),
            };
            row.rebind_proposal = None;
            row.rebinds.push(rebind.clone());
            put_code_consent_wait_in_txn(
                self,
                txn,
                &mut row,
                crate::consent::CodeWaitCommand::ConfirmRebind,
            )?;
            Ok((rebind, false))
        })?;
        if !result.1 {
            self.signal_code_owned_call_asks();
            self.store.notify_proactivity_changes();
        }
        Ok(result)
    }
}

fn confirmed_target(proposal: &CodeConsentRebindProposal) -> CodeConsentRebindTarget {
    let mut target = proposal.target.clone();
    target.revision = proposal.prepared_revision;
    target
}

fn check_target(row: &CodeConsentWaitRow, target: &CodeConsentRebindTarget) -> Result<()> {
    let sealed = row.checkpoint.as_ref().ok_or(Error::EntityNotFound)?;
    if row.binding.run_id != target.run_id
        || row.binding.wait_id != target.wait_id
        || sealed.wait_generation != target.generation
        || sealed.step_hash != target.step_hash
        || row.binding.effect_digest != target.effect_digest
        || row.revision != target.revision
    {
        return Err(Error::ConcurrentWrite(
            "the sealed code consent rebind target changed",
        ));
    }
    Ok(())
}

fn eligible(row: &CodeConsentWaitRow) -> Result<()> {
    if !row.approved_unsettled() || row.admission.is_none() || row.consumption.is_some() {
        return Err(Error::InvalidConfig(
            "only an admitted, unsettled code consent wait can rebind".to_owned(),
        ));
    }
    if binding_digest(&row.binding)? != row.binding.binding_digest {
        return Err(Error::CorruptedIndex("code consent original binding"));
    }
    let active = row.active_binding();
    if binding_digest(&active)? != active.binding_digest {
        return Err(Error::CorruptedIndex("code consent active binding"));
    }
    Ok(())
}

fn effects_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CodeConsentWaitRow,
    current: &[u8; 32],
    successor: &[u8; 32],
) -> Result<(EffectDigest, EffectDigest)> {
    if row.binding.pending.connector_call().is_some() {
        return crate::outbound_consent::code_wait_rebind_effects_in_txn(
            vault, txn, row, current, successor,
        )
        .map_err(|error| match error {
            IntentLedgerError::Engine(error) => error,
            IntentLedgerError::InvalidRecord(reason) => Error::CorruptedIndex(reason),
            other => Error::InvalidConfig(other.to_string()),
        });
    }
    if !browser_facts_match_row(&row.binding) {
        return Err(Error::ConcurrentWrite(
            "the admitted browser consent target changed",
        ));
    }
    let digest = EffectDigest::from_bytes(row.binding.effect_digest);
    Ok((digest, digest))
}
