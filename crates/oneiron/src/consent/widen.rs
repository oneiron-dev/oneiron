//! Propose-only authority widening. Only the existing authenticated-owner door
//! can turn a frozen canonical delta into a standing grant.
use super::codec::{decode_bound_value, encode_bound_value};
use super::support::{invalid_row, normalized_ref};
use super::{
    AuthenticatedOwner, ConsentDomain, ConsentReceipt, GrantBound, bound_catastrophe_class,
};
use crate::error::GateError;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

const PREFIX: &[u8] = b"consent.widen.v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidenKind {
    Action,
    Disclosure,
    AutoConfirm,
}
impl WidenKind {
    fn label(self) -> &'static str {
        match self {
            Self::Action => "propose_action_widen",
            Self::Disclosure => "propose_disclosure_widen",
            Self::AutoConfirm => "propose_auto_confirm_widen",
        }
    }
    fn parse(text: &str) -> Option<Self> {
        match text {
            "propose_action_widen" => Some(Self::Action),
            "propose_disclosure_widen" => Some(Self::Disclosure),
            "propose_auto_confirm_widen" => Some(Self::AutoConfirm),
            _ => None,
        }
    }
}

/// A proposal receipt confers no authority. It is not a ConsentGrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenProposal {
    pub proposal_ref: String,
    pub canonical_delta: Vec<u8>,
    pub proposer: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub decision_id: [u8; 16],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProposal {
    version: u8,
    proposal: WidenProposal,
    resolved: bool,
}

pub fn canonical_widen_delta(kind: WidenKind, bound: &GrantBound) -> Result<Vec<u8>> {
    if (kind == WidenKind::Disclosure) != (bound.domain() == ConsentDomain::Disclosure) {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "widen kind crosses bound domain",
        )));
    }
    let value = Value::Array(vec![
        Value::from(1),
        Value::from(kind.label()),
        encode_bound_value(bound),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).map_err(|_| invalid_row())?;
    Ok(bytes)
}
fn decode_delta(bytes: &[u8]) -> Result<GrantBound> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_row());
    }
    let Value::Array(parts) = value else {
        return Err(invalid_row());
    };
    let [version, kind, bound] = parts.as_slice() else {
        return Err(invalid_row());
    };
    if version.as_u64() != Some(1) {
        return Err(invalid_row());
    }
    let kind = kind
        .as_str()
        .and_then(WidenKind::parse)
        .ok_or_else(invalid_row)?;
    let bound = decode_bound_value(bound)?;
    if canonical_widen_delta(kind, &bound)? != bytes {
        return Err(invalid_row());
    }
    Ok(bound)
}
fn proposal_ref(delta: &[u8], proposer: &str, owner: &str, created: u64, expires: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PREFIX);
    for field in [
        delta,
        proposer.as_bytes(),
        owner.as_bytes(),
        &created.to_be_bytes(),
        &expires.to_be_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}
fn key(reference: &str) -> Result<Vec<u8>> {
    if reference.len() != 64
        || !reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_row());
    }
    Ok([PREFIX, reference.as_bytes()].concat())
}
fn decode_row(bytes: &[u8], reference: &str) -> Result<StoredProposal> {
    let row: StoredProposal = serde_json::from_slice(bytes).map_err(|_| invalid_row())?;
    let p = &row.proposal;
    decode_delta(&p.canonical_delta)?;
    if row.version != 1
        || p.proposal_ref != reference
        || p.expires_at <= p.created_at
        || p.expires_at - p.created_at > 3600
        || crate::EntityId::from_hex(&p.proposer).is_err()
        || normalized_ref("widen owner", p.owner_ref.clone())? != p.owner_ref
        || proposal_ref(
            &p.canonical_delta,
            &p.proposer,
            &p.owner_ref,
            p.created_at,
            p.expires_at,
        ) != reference
    {
        return Err(invalid_row());
    }
    Ok(row)
}
impl Vault {
    /// Host-stamped agent admission. This parks a proposal and a pending receipt;
    /// it never writes a standing-grant row or changes an effective ceiling.
    pub fn propose_widen(
        &self,
        actor: WriteActor,
        kind: WidenKind,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        if actor.actor_class() != EdgeActorClass::Agent {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposer must be an agent",
            )));
        }
        let now = crate::unix_seconds_now();
        if expires_at <= now || expires_at - now > 3600 {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposal expiry must be within one hour",
            )));
        }
        if bound_catastrophe_class(&bound).is_some() {
            return Err(Error::Gate(GateError::ConsentCatastropheNotRememberable(
                "catastrophe widen is forbidden",
            )));
        }
        let owner_ref = normalized_ref("widen owner", owner_ref.to_owned())?;
        let canonical_delta = canonical_widen_delta(kind, &bound)?;
        let proposer = actor.entity_ref().to_hex();
        let reference = proposal_ref(&canonical_delta, &proposer, &owner_ref, now, expires_at);
        let key = key(&reference)?;
        self.with_write_txn(|txn| {
            if self
                .store
                .entities
                .get(&*txn, actor.entity_ref().as_bytes())?
                .is_none()
            {
                return Err(Error::EntityNotFound);
            }
            if let Some(raw) = self.store.vault_meta.get(&*txn, &key)? {
                return Ok(decode_row(&raw, &reference)?.proposal);
            }
            let proposal = WidenProposal {
                proposal_ref: reference,
                canonical_delta,
                proposer,
                owner_ref,
                created_at: now,
                expires_at,
                decision_id: GateDecisionId::now().as_bytes(),
            };
            let record = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::from_bytes(proposal.decision_id),
                created_at: now,
                outcome: "pending".into(),
                reason_codes: vec!["gate.consent.widen_proposed".into()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".into(),
                actor_ref: Some(proposal.proposer.clone()),
                content_kind: "consent_widen".into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: None,
                diff_handle: blake3::hash(&proposal.canonical_delta).as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            };
            self.store.append_gate_decision_in_txn(txn, &record)?;
            let row = StoredProposal {
                version: 1,
                proposal: proposal.clone(),
                resolved: false,
            };
            self.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&row).map_err(|_| invalid_row())?,
            )?;
            Ok(proposal)
        })
    }
    /// Resolve one frozen proposal. An approve-once receipt cannot be supplied
    /// here: the existing authenticated owner handle is the separate authority axis.
    pub fn accept_widen(
        &self,
        owner: &AuthenticatedOwner,
        reference: &str,
        expected_delta: &[u8],
    ) -> Result<ConsentReceipt> {
        let key = key(reference)?;
        self.with_write_txn(|txn| {
            let raw = self
                .store
                .vault_meta
                .get(&*txn, &key)?
                .ok_or_else(invalid_row)?;
            let mut row = decode_row(&raw, reference)?;
            let proposal = &row.proposal;
            if row.resolved
                || proposal.expires_at <= crate::unix_seconds_now()
                || proposal.owner_ref != owner.principal_ref()
                || proposal.canonical_delta != expected_delta
            {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "widen proposal is stale, changed, resolved, or bound to another owner",
                )));
            }
            let bound = decode_delta(&proposal.canonical_delta)?;
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            row.resolved = true;
            self.store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&row).map_err(|_| invalid_row())?,
            )?;
            Ok(receipt)
        })
    }
    pub fn widen_proposal(&self, reference: &str) -> Result<Option<WidenProposal>> {
        let key = key(reference)?;
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|raw| decode_row(&raw, reference).map(|row| row.proposal))
            .transpose()
    }
}
