//! Hold-time code-consent policy and action evidence; neither is a grant.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::gate::ExternalEffectGateInput;
use crate::gate::code_consent_settlement::ResolvedCodeConsentSettlement;
use crate::{EntityId, Error, Result, Vault};

use super::{ActionClass, ActionEnvelope, ActorBound, BoundClass, BoundEnvelope, GrantBound};

/// Minted from the producer's real gate input, then covered by the wait's
/// binding digest. Deserialization is data only, never holder authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FrozenCodeConsentSettlement {
    pub(crate) policy: ResolvedCodeConsentSettlement,
    effect_bound: Vec<u8>,
    pub(crate) holders: BTreeSet<EntityId>,
    browser_scope: Option<FrozenCodeConsentBrowserScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FrozenCodeConsentBrowserScope {
    pub(super) project: Option<EntityId>,
    pub(super) audience: Option<String>,
}

impl FrozenCodeConsentSettlement {
    pub(crate) fn action_requirement(&self) -> Result<GrantBound> {
        let mut cursor = std::io::Cursor::new(&self.effect_bound);
        let value = rmpv::decode::read_value(&mut cursor)
            .map_err(|_| Error::InvalidConfig("invalid frozen code-consent action".to_owned()))?;
        if cursor.position() != self.effect_bound.len() as u64 {
            return Err(Error::InvalidConfig(
                "trailing frozen code-consent action".to_owned(),
            ));
        }
        super::codec::decode_bound_value(&value)
    }
}

impl Vault {
    /// Freeze BEFORE the connector/browser producer drops its native effect
    /// input. The caller binds this exact value into its immutable wait row.
    pub(crate) fn freeze_code_consent_settlement_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        effect: &ExternalEffectGateInput,
    ) -> Result<Option<FrozenCodeConsentSettlement>> {
        self.freeze_code_consent_settlement_for_scope_in_txn(txn, effect, None)
    }

    pub(super) fn freeze_code_consent_settlement_for_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        effect: &ExternalEffectGateInput,
        browser_scope: Option<FrozenCodeConsentBrowserScope>,
    ) -> Result<Option<FrozenCodeConsentSettlement>> {
        let Some(required) =
            crate::gate::code_consent_settlement::code_consent_action_requirement(effect)
        else {
            return Ok(None);
        };
        let resolution = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let Some(policy) = resolution.code_consent_settlement.clone() else {
            return Ok(None);
        };
        let (BoundClass::Action(class), BoundEnvelope::Action(envelope)) =
            (required.class(), required.envelope())
        else {
            return Ok(None);
        };
        let mut holders = BTreeSet::new();
        if !policy.conflicting_authored_rows {
            let browser_holders = browser_scope
                .as_ref()
                .map(|scope| self.code_consent_browser_holder_powers_in_txn(txn, class, scope))
                .transpose()?;
            let candidates = match &browser_holders {
                Some(powers) => powers.keys().copied().collect(),
                None => self.ask_authority_holders_in_txn(txn, class, envelope)?,
            };
            for holder in candidates {
                let covered = match &browser_holders {
                    Some(powers) => powers.contains_key(&holder),
                    None => self
                        .code_consent_holder_power_in_txn(txn, holder, class, envelope)?
                        .is_some(),
                };
                if covered
                    && policy.eligible.admits(holder)
                    && super::doors::person_is_live_for_store_in_txn(&self.store, txn, &holder)?
                {
                    holders.insert(holder);
                }
            }
        }
        let mut effect_bound = Vec::new();
        rmpv::encode::write_value(
            &mut effect_bound,
            &super::codec::encode_bound_value(&required)?,
        )
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        Ok(Some(FrozenCodeConsentSettlement {
            policy,
            effect_bound,
            holders,
            browser_scope,
        }))
    }

    /// Only an action bound to THIS PERSON covers their settlement power;
    /// the opener and a granting owner's identity are not substitutes.
    pub(crate) fn code_consent_holder_power_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        class: &ActionClass,
        envelope: &ActionEnvelope,
    ) -> Result<Option<String>> {
        let required = GrantBound::action(
            ActorBound::new(person.to_hex())?.with_actor_class("human")?,
            class.clone(),
            envelope.clone(),
        )?;
        for grant in self.active_standing_consent_grants_in_txn(txn)? {
            let super::StandingConsentGrant::Action(action) = grant else {
                continue;
            };
            if !action.bound().contains(&required) {
                continue;
            }
            let reference = action.bound().digest().to_hex();
            if self
                .consent_grant_in_txn(txn, &reference)?
                .is_some_and(|row| row.is_active())
            {
                return Ok(Some(reference));
            }
        }
        Ok(None)
    }
}

/// Same-snapshot person, policy and power evidence. This alone cannot mint an
/// approve-once marker or turn a holder into an Owner.
pub(crate) struct CodeConsentHolderPolicy {
    pub(crate) actor: EntityId,
    pub(crate) principal_ref: String,
    pub(crate) authentication: crate::store::GateDecisionId,
    pub(crate) grant_ref: String,
    pub(crate) policy: ResolvedCodeConsentSettlement,
    pub(crate) policy_frontier: [u8; 32],
}

impl Vault {
    /// The final effect writer calls this only after it has proved the wait's
    /// immutable binding, target, original authority and first-answer state.
    pub(crate) fn code_consent_holder_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &super::AuthenticatedOwner,
        frozen: &FrozenCodeConsentSettlement,
    ) -> Result<Option<CodeConsentHolderPolicy>> {
        let actor = holder.revalidate_person_in_txn(self, txn)?;
        if !frozen.holders.contains(&actor)
            || frozen.policy.conflicting_authored_rows
            || !frozen.policy.eligible.admits(actor)
        {
            return Ok(None);
        }
        let resolution = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if resolution.code_consent_settlement.as_ref() != Some(&frozen.policy) {
            return Ok(None);
        }
        let required = frozen.action_requirement()?;
        let (BoundClass::Action(class), BoundEnvelope::Action(envelope)) =
            (required.class(), required.envelope())
        else {
            return Ok(None);
        };
        let grant_ref = match &frozen.browser_scope {
            Some(scope) => self
                .code_consent_browser_holder_powers_in_txn(txn, class, scope)?
                .get(&actor)
                .cloned(),
            None => self.code_consent_holder_power_in_txn(txn, actor, class, envelope)?,
        };
        let Some(grant_ref) = grant_ref else {
            return Ok(None);
        };
        Ok(Some(CodeConsentHolderPolicy {
            actor,
            principal_ref: holder.person_principal_ref_in_txn(self, txn)?.to_owned(),
            authentication: holder.decision_id(),
            grant_ref,
            policy: frozen.policy.clone(),
            policy_frontier: resolution.read_frontier_hash()?,
        }))
    }
}

/// Historical attribution, not a credential or authority to approve an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentHolderAttribution {
    pub(crate) actor: EntityId,
    pub(crate) principal_ref: String,
    pub(crate) authentication: crate::store::GateDecisionId,
    pub(crate) grant_ref: String,
    pub(crate) policy: ResolvedCodeConsentSettlement,
    pub(crate) policy_frontier: [u8; 32],
}

/// The receipt and historical basis of one proved held-effect act.
pub(crate) struct CodeConsentHolderDecision {
    pub(crate) receipt: super::ConsentReceipt,
    pub(crate) attribution: CodeConsentHolderAttribution,
}

impl CodeConsentHolderPolicy {
    pub(crate) fn attribution(&self) -> CodeConsentHolderAttribution {
        CodeConsentHolderAttribution {
            actor: self.actor,
            principal_ref: self.principal_ref.clone(),
            authentication: self.authentication,
            grant_ref: self.grant_ref.clone(),
            policy: self.policy.clone(),
            policy_frontier: self.policy_frontier,
        }
    }
}

impl Vault {
    /// Records the authenticated holder without an Owner stamp. The caller
    /// has already claimed the exact wait's act in this writer, or is recording
    /// that act's later settlement. Attribution alone authorizes neither.
    pub(crate) fn append_code_consent_holder_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attribution: &CodeConsentHolderAttribution,
        receipt: &super::ConsentReceipt,
    ) -> Result<()> {
        let reason = match receipt {
            super::ConsentReceipt::Approved {
                grant: super::ConsentGrant::ApproveOnce(_),
                ..
            } => "gate.consent.code_holder.approved",
            // Self-heal's Owner-denial detector does not check actor class.
            // A holder's word must not enter its Owner-only denial stream.
            super::ConsentReceipt::Denied { .. } => "gate.consent.code_holder.denied",
            super::ConsentReceipt::CodeWaitSettled { .. } => receipt.reason_code(),
            _ => {
                return Err(Error::InvalidConfig(
                    "not a held code-consent holder receipt".to_owned(),
                ));
            }
        };
        let mut reason_codes = vec![reason.to_owned()];
        for source in &attribution.policy.sources {
            reason_codes.push(format!(
                "gate.policy_manifest:{}:{}@{}",
                source.manifest_ref,
                crate::gate::code_consent_settlement::KEY,
                source.version,
            ));
        }
        let record = crate::store::GateDecisionRecord {
            version: crate::store::GATE_DECISION_LEDGER_VERSION,
            decision_id: receipt.decision_id(),
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: receipt.gate_outcome().to_owned(),
            reason_codes,
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "human".to_owned(),
            actor_ref: Some(attribution.actor.to_hex()),
            content_kind: super::grant::CONSENT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(attribution.grant_ref.clone()),
            diff_handle: crate::consent::consent_receipt_diff_handle(&receipt),
            read_frontier_hash: attribution.policy_frontier,
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)
    }
}
