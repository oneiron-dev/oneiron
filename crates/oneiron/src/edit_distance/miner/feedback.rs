//! Immutable, owner-bound decisions used by the preference miner.
//! Inbox consent and explicit measured-amendment intake share this audience binding.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::store::{decode_row, encode_row};
use super::target::CompilationTarget;
use crate::Vault;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::GateDecisionRecord;

const LABEL: &str = "principal-bound inbox decision";

/// Immutable owner-bound decision on an inbox/amendment intake item, keyed by
/// receipt id.
const DECISION: SideTable<String, PrincipalDecision, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_PRINCIPAL_DECISION);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PrincipalDecision {
    v: u8,
    pub(super) receipt: String,
    #[serde(
        serialize_with = "super::stored_fields::serialize_opt_entity",
        deserialize_with = "super::stored_fields::deserialize_opt_entity"
    )]
    pub(super) claim: Option<EntityId>,
    #[serde(
        serialize_with = "super::stored_fields::serialize_entity",
        deserialize_with = "super::stored_fields::deserialize_entity"
    )]
    pub(super) principal: EntityId,
    #[serde(
        serialize_with = "super::stored_fields::serialize_entity",
        deserialize_with = "super::stored_fields::deserialize_entity"
    )]
    pub(super) actor: EntityId,
    #[serde(
        serialize_with = "super::stored_fields::serialize_opt_entity",
        deserialize_with = "super::stored_fields::deserialize_opt_entity"
    )]
    pub(super) skill: Option<EntityId>,
    pub(super) target: CompilationTarget,
    pub(super) outcome: String,
    pub(super) predicate: String,
    #[serde(
        serialize_with = "super::stored_fields::serialize_opt_value",
        deserialize_with = "super::stored_fields::deserialize_opt_value"
    )]
    pub(super) reviewed_value: Option<Value>,
    /// Canonical reviewed claim identity, not caller-supplied text evidence.
    pub(super) fingerprint: String,
    pub(super) scope: String,
    pub(super) substitution: Option<(String, String)>,
    pub(super) at: u64,
}

/// Called only AFTER the content-bound inbox redemption produced its receipt,
/// and inside that transaction. The actor is from the reviewed write envelope;
/// the principal is the independently authenticated decider, never that actor.
pub(crate) fn record_inbox_learning_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &GateDecisionRecord,
    reviewed: &ClaimBody,
    principal: EntityId,
    target: &CompilationTarget,
) -> Result<()> {
    let Some(actor) = crate::claim::session_claim_producer(reviewed) else {
        // An unstamped generator earns no attribution.
        return Ok(());
    };
    // Do not recursively learn from acceptance of this learner's own output.
    if super::influence::is_mined_preference(&reviewed.predicate) {
        return Ok(());
    }
    let claim = record.claim_id.ok_or(Error::CorruptedIndex(LABEL))?;
    let claim = EntityId::from_bytes(claim).map_err(|_| Error::CorruptedIndex(LABEL))?;
    let receipt = crate::receipt::gate_decision_receipt(record).receipt_id;
    let fingerprint = crate::inbox::inbox_claim_hash(reviewed)?;
    let final_body = vault.get_claim_in_txn(txn, &claim)?;
    let substitution = if record.outcome == "approved_amended" {
        reviewed
            .value
            .as_str()
            .zip(final_body.as_ref().and_then(|body| body.value.as_str()))
            .and_then(|(before, after)| super::mining::substitution_pair(before, after))
            .map(|pair| (pair.from, pair.to))
    } else {
        None
    };
    let scope = crate::actor_claims::edit_cost_scope_name(reviewed.scope.as_ref()).map_or_else(
        || format!("claim:{}:{:?}", reviewed.predicate, reviewed.subject),
        str::to_owned,
    );
    let row = PrincipalDecision {
        v: 1,
        receipt: receipt.clone(),
        claim: Some(claim),
        principal,
        actor,
        skill: None,
        target: target.clone(),
        outcome: record.outcome.clone(),
        predicate: reviewed.predicate.clone(),
        reviewed_value: Some(reviewed.value.clone()),
        fingerprint: crate::entity_id::bytes_to_hex_lower(&fingerprint),
        scope,
        substitution,
        at: record.created_at,
    };
    if DECISION.contains(&vault.store, &*txn, &receipt)? {
        return Err(Error::InvariantViolation("inbox decision already captured"));
    }
    DECISION.put(&vault.store, txn, &receipt, &row)?;
    Ok(())
}

pub(super) fn principal_decision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<Option<PrincipalDecision>> {
    let Some(row) = DECISION.get(&vault.store, txn, &receipt.to_owned())? else {
        return Ok(None);
    };
    validate_decision(row, receipt).map(Some)
}

pub(super) fn principal_decisions(vault: &Vault) -> Result<Vec<PrincipalDecision>> {
    let txn = vault.store.env.read_txn()?;
    DECISION
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(receipt, row)| validate_decision(row, &receipt))
        .collect()
}

fn validate_decision(row: PrincipalDecision, receipt: &str) -> Result<PrincipalDecision> {
    if row.receipt != receipt
        || !matches!(
            row.outcome.as_str(),
            "approved" | "approved_amended" | "rejected"
        )
    {
        return Err(Error::CorruptedIndex(LABEL));
    }
    row.target.validate()?;
    Ok(row)
}

impl RawValue for PrincipalDecision {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_row(self, LABEL)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: PrincipalDecision = decode_row(bytes, LABEL)?;
        if row.v != 1 {
            return Err(CodecError::Value(Error::CorruptedIndex(LABEL)));
        }
        Ok(row)
    }
}

/// Scope passed through the ordinary claim decoder, including its principal
/// validator. No missing-principal default is invented here.
pub(super) fn preference_scope(scope: &str, principal: EntityId) -> Value {
    let mut entries = match crate::actor_claims::edit_cost_scope(scope) {
        Value::Map(entries) => entries,
        _ => Vec::new(),
    };
    entries.push((
        Value::from("principal"),
        Value::Binary(principal.as_bytes().to_vec()),
    ));
    Value::Map(entries)
}

/// Binds a measured amendment to its host-authenticated human decider.
///
/// Call at explicit decision intake after recording ED-01/ED-03 evidence.
/// The generator is read from that evidence; it is NEVER the principal.
/// Historical rows without this binding stay audit-only. A later caller cannot
/// relabel an existing binding, change its age, or give it another target.
pub fn bind_amendment_preference_principal(
    vault: &Vault,
    owner: crate::write_envelope::WriteActor,
    receipt: &str,
    target: &CompilationTarget,
) -> Result<()> {
    target.validate()?;
    vault.with_write_txn(|txn| {
        vault.verify_owner_write_actor_in_txn(txn, &owner)?;
        let evidence =
            crate::edit_distance::attribution::amendment_evidence_in_txn(vault, txn, receipt)?
                .ok_or(Error::InvalidClaimBody(
                    "preference binding requires measured amendment evidence",
                ))?;
        let row = PrincipalDecision {
            v: 1,
            receipt: receipt.to_owned(),
            claim: None,
            principal: owner.entity_ref(),
            actor: evidence.actor,
            skill: evidence.skill,
            target: target.clone(),
            outcome: "approved_amended".to_owned(),
            predicate: String::new(),
            reviewed_value: None,
            fingerprint: String::new(),
            scope: evidence.scope,
            substitution: None,
            at: evidence.at,
        };
        if let Some(existing) = principal_decision(vault, txn, receipt)? {
            if existing.principal == row.principal
                && existing.target == row.target
                && existing.actor == row.actor
                && existing.skill == row.skill
                && existing.scope == row.scope
                && existing.at == row.at
                && existing.outcome == row.outcome
            {
                return Ok(());
            }
            return Err(Error::InvalidClaimBody(
                "preference decision binding is immutable",
            ));
        }
        DECISION.put(&vault.store, txn, &receipt.to_owned(), &row)?;
        Ok(())
    })
}
