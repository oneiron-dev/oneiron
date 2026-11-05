//! The closed-purpose native SKILL state witness wire value.
//!
//! Decoding and signature verification authenticate bytes, not native admission.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::super::storage;
use crate::EntityId;
use crate::authority::{AuthorityEntryHash, NativeSkillCarrier};
use crate::claim::ClaimApprovalStatus;
use crate::error::{Error, Result, SecretError};
use crate::provenance::ActorStamp;
use crate::skill::{SkillLifecycle, SkillRecord};

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
    fn of(record: &SkillRecord) -> Self {
        Self {
            lifecycle: record.lifecycle_status.as_str().to_owned(),
            approval: record.approval_status,
        }
    }

    fn lifecycle(&self) -> Result<SkillLifecycle> {
        SkillLifecycle::parse(&self.lifecycle).ok_or_else(malformed)
    }
}

/// The typed local operation and its historical successor source binding.
/// Decoding this descriptor does not establish that its source was admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Door {
    Update,
    Supersede {
        successor: [u8; 16],
        source_core: [u8; 32],
        logical_body: [u8; 32],
        document_pin: Option<([u8; 16], Vec<u8>)>,
    },
}

/// The original writer's erasable stamp and carried causal input. Resolving
/// its token now is neither historical authorization nor recipient admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalWriter {
    token: [u8; 16],
    class: u8,
    authority_frontier: Option<AuthorityEntryHash>,
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
    door: Door,
    writer: Option<OriginalWriter>,
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
    /// The dormant publisher accepts only the actual final builder input and
    /// its document from the same Store transaction, never provisional P4 data.
    #[cfg(feature = "sync")]
    pub(super) fn from_final_input(
        input: &crate::batch::NativeSkillFinalInput<'_>,
        txn: &mut heed::RwTxn<'_>,
        document: EntityId,
        source: &super::super::EntityDoc,
        previous: Option<&Self>,
    ) -> Result<(Self, Option<ActorStamp>)> {
        input.recheck_in_txn(txn)?;
        let entity = input.entity();
        let birth = source.birth();
        if birth.entity != entity.to_hex() {
            return Err(malformed());
        }
        let prior = State::of(input.snapshot().prior());
        if let Some(previous) = previous
            && (!previous.target_birth_is(entity, birth.at) || previous.operation.state != prior)
        {
            return Err(malformed());
        }
        let ordinal = previous.map_or(Ok(1), |previous| {
            previous
                .operation
                .ordinal
                .checked_add(1)
                .ok_or(Error::InvariantViolation(
                    "native SKILL state ordinal overflow",
                ))
        })?;
        // Mint only from the actual applying writer, in its transaction.
        // Return this same stamp for the document commit; a later cache lookup
        // need not return the same token when the writer carries a frontier.
        let writer = input
            .actor()
            .map(|actor| {
                crate::provenance::actor_stamp_in_txn(input.vault(), txn, actor)
                    .map(|stamp| (stamp, actor.authority_frontier()))
            })
            .transpose()?;
        let mut fact = Self {
            format: FORMAT,
            operation: Operation {
                entity: *entity.as_bytes(),
                document: *document.as_bytes(),
                birth_at: birth.at,
                source_core: input.snapshot().source_fingerprint(),
                source_frontier: source.frontier(),
                event: *EntityId::now().as_bytes(),
                recorded_at: input.recorded_at(),
                ordinal,
                previous: previous.map(Self::token).transpose()?,
                prior,
                state: State::of(input.record()),
                door: match input.superseding_revision() {
                    None => Door::Update,
                    Some(successor) => Door::Supersede {
                        successor: *successor.entity().as_bytes(),
                        source_core: successor.source_fingerprint(),
                        logical_body: successor.logical_body_fingerprint(),
                        document_pin: successor
                            .document_pin()
                            .map(|(id, frontier)| (*id.as_bytes(), frontier.to_vec())),
                    },
                },
                writer: writer.map(|(stamp, authority_frontier)| OriginalWriter {
                    token: *stamp.token.as_bytes(),
                    class: stamp.class as u8,
                    authority_frontier,
                }),
            },
            attestation: None,
        };
        // A legal local typed operation cannot acquire a new enrollment or
        // keystore requirement. An unavailable signer leaves no transferable
        // attestation; corruption and other errors are still errors.
        let signer = match crate::store::install_identity::machine_signer_in_txn(input.vault(), txn)
        {
            Ok(signer) => Some(signer),
            Err(Error::Secret(SecretError::KeystoreUnavailable(_))) => None,
            Err(error) => return Err(error),
        };
        if let Some((machine, key)) = signer {
            let store = &input.vault().store;
            let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
                store,
                store.privacy_posture,
                txn,
            )?;
            fact.attestation = Some(Attestation {
                carrier: Carrier {
                    machine: *machine.as_bytes(),
                    key: key.verifying_key().to_bytes(),
                    heads: crate::authority::act_heads(&fold, machine),
                },
                signature: Vec::new(),
            });
            let signature = key.sign(&fact.transcript()?).to_bytes().to_vec();
            fact.attestation.as_mut().ok_or_else(malformed)?.signature = signature;
        }
        Ok((fact, writer.map(|(stamp, _)| stamp)))
    }

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
        match &fact.operation.door {
            Door::Update => {
                if fact.operation.state.lifecycle()? == SkillLifecycle::Superseded
                    && fact.operation.prior.lifecycle()? != SkillLifecycle::Superseded
                {
                    return Err(malformed());
                }
            }
            Door::Supersede {
                successor,
                document_pin,
                ..
            } => {
                let successor = EntityId::from_bytes(*successor)?;
                if successor.as_bytes() == &fact.operation.entity
                    || fact.operation.prior.lifecycle()? != SkillLifecycle::Active
                    || fact.operation.state.lifecycle()? != SkillLifecycle::Superseded
                {
                    return Err(malformed());
                }
                if let Some((id, frontier)) = document_pin {
                    EntityId::from_bytes(*id)?;
                    super::super::document::decode_frontier(frontier)?;
                }
            }
        }
        if let Some(writer) = &fact.operation.writer {
            EntityId::from_bytes(writer.token)?;
            crate::edge::EdgeActorClass::try_from_u8(writer.class).ok_or_else(malformed)?;
        }
        if let Some(attestation) = &fact.attestation {
            EntityId::from_bytes(attestation.carrier.machine)?;
            if attestation.signature.len() != 64 {
                return Err(malformed());
            }
        }
        if fact.encode()?.as_slice() != bytes {
            return Err(malformed());
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

    /// A selected admitted source may have moved slots through SWITCH or
    /// restore. Its signed document coordinate stays historical.
    pub(super) fn target_birth_is(&self, entity: EntityId, birth_at: u64) -> bool {
        self.operation.entity == *entity.as_bytes() && self.operation.birth_at == birth_at
    }

    /// Pure projection can check the supplied birth, but has no Store/head
    /// context. Full document-id/source admission belongs to its real caller.
    pub(super) fn names_birth(&self, birth: &super::super::Birth) -> bool {
        birth.entity == crate::entity_id::bytes_to_hex_lower(&self.operation.entity)
            && birth.at == self.operation.birth_at
    }

    /// A provenance-use coordinate only. A missing token claim must never
    /// make the historical writer absent or invent fresh authority for it.
    pub(super) fn writer_token(&self) -> Result<Option<EntityId>> {
        self.operation
            .writer
            .as_ref()
            .map(|writer| EntityId::from_bytes(writer.token))
            .transpose()
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
