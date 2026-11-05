//! The closed-purpose native SKILL state witness wire value.
//!
//! Decoding and signature verification authenticate bytes, not native admission.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::super::storage;
use crate::EntityId;
use crate::authority::{AuthorityEntryHash, NativeSkillCarrier};
use crate::claim::ClaimApprovalStatus;
use crate::error::{Error, Result};
use crate::skill::SkillLifecycle;

const FORMAT: u8 = 1;
const SIGNING_DOMAIN: &[u8] = b"oneiron.native.skill-state.v1\0";
const TOKEN_DOMAIN: &[u8] = b"oneiron.native.skill-state.token.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    lifecycle: String,
    approval: ClaimApprovalStatus,
}

impl State {
    fn lifecycle(&self) -> Result<SkillLifecycle> {
        SkillLifecycle::parse(&self.lifecycle).ok_or_else(malformed)
    }
}

/// The source coordinates at admission. The frontier and CORE fingerprint are
/// historical evidence, not the current local incarnation or a restore key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    entity: [u8; 16],
    document: [u8; 16],
    birth_at: u64,
    source_core: [u8; 32],
    source_frontier: Vec<u8>,
    event: [u8; 16],
    recorded_at: u64,
    ordinal: u64,
    previous: Option<AuthorityEntryHash>,
    prior: State,
    state: State,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Carrier {
    machine: [u8; 16],
    key: [u8; 32],
    heads: BTreeSet<AuthorityEntryHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    carrier: Carrier,
    signature: Vec<u8>,
}

/// A decoded witness, deliberately not an accepted state or a permission.
/// All fields and signing constructors remain inside the native publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SkillStateFact {
    format: u8,
    operation: Operation,
    attestation: Option<Attestation>,
}

fn malformed() -> Error {
    Error::CorruptedIndex("native SKILL state witness")
}

impl SkillStateFact {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let fact: Self = storage::decode(bytes)?;
        if fact.format != FORMAT
            || fact.operation.ordinal == 0
            || (fact.operation.ordinal == 1) != fact.operation.previous.is_none()
        {
            return Err(malformed());
        }
        EntityId::from_bytes(fact.operation.entity)?;
        EntityId::from_bytes(fact.operation.document)?;
        EntityId::from_bytes(fact.operation.event)?;
        super::super::document::decode_frontier(&fact.operation.source_frontier)?;
        fact.operation.prior.lifecycle()?;
        fact.operation.state.lifecycle()?;
        if let Some(attestation) = &fact.attestation {
            EntityId::from_bytes(attestation.carrier.machine)?;
            if attestation.signature.len() != 64 {
                return Err(malformed());
            }
        }
        Ok(fact)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| malformed())
    }

    fn transcript(&self) -> Result<Vec<u8>> {
        let carrier = self.attestation.as_ref().map(|signed| &signed.carrier);
        let payload = rmp_serde::to_vec_named(&(self.format, &self.operation, carrier))
            .map_err(|_| malformed())?;
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// A content-derived native token, independent of any fresh Loro op id.
    /// It becomes an ACK source only after native source validation too.
    pub(super) fn token(&self) -> Result<AuthorityEntryHash> {
        let mut hash = blake3::Hasher::new();
        hash.update(TOKEN_DOMAIN);
        hash.update(&self.transcript()?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Verifies only the attestation. The caller must still establish native
    /// admission, historical carrier standing and the actual source binding.
    /// An unsigned local witness never becomes peer standing through this API.
    pub(super) fn verified_carrier(&self) -> Result<Option<NativeSkillCarrier>> {
        let Some(attestation) = &self.attestation else {
            return Ok(None);
        };
        let signature: [u8; 64] = attestation
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| malformed())?;
        let key = VerifyingKey::from_bytes(&attestation.carrier.key).map_err(|_| malformed())?;
        key.verify_strict(&self.transcript()?, &Signature::from_bytes(&signature))
            .map_err(|_| malformed())?;
        Ok(Some(NativeSkillCarrier {
            heads: attestation.carrier.heads.clone(),
            machine: EntityId::from_bytes(attestation.carrier.machine)?,
            key: attestation.carrier.key,
            token: self.token()?,
        }))
    }

    pub(super) fn target_is(&self, entity: EntityId, document: EntityId, birth_at: u64) -> bool {
        self.operation.entity == *entity.as_bytes()
            && self.operation.document == *document.as_bytes()
            && self.operation.birth_at == birth_at
    }

    pub(super) fn state(&self) -> Result<(SkillLifecycle, ClaimApprovalStatus)> {
        Ok((
            self.operation.state.lifecycle()?,
            self.operation.state.approval,
        ))
    }

    /// Native order, not the operation id of a later text join or rewrite.
    /// Ordering is meaningful only among independently admitted witnesses.
    pub(super) fn order(&self) -> Result<(u64, AuthorityEntryHash)> {
        Ok((self.operation.ordinal, self.token()?))
    }
}
