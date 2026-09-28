//! Replicable admission proof for a locally checked option-link bearer.
//!
//! The issuer's private key remains in local vault_meta. Only its public key
//! and signatures replicate; a token digest alone cannot authorize an answer.

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

/// Local ed25519 seed that signs one ask group's option-link words. Key: id16 (group).
const SIGNERS: SideTable<EntityId, [u8; 32], side_table::Raw> =
    SideTable::new(&side_table::TASK_ASK_LINK_SIGNER);
const TRANSCRIPT: &[u8] = b"oneiron.tasks.ask.link_answer.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinkProof {
    pub token_digest: [u8; 32],
    pub revision: u64,
    pub signature: Vec<u8>,
}

pub(in crate::task_verb) fn mint_key(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
) -> Result<[u8; 32]> {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    SIGNERS.put(&vault.store, txn, &group, &seed)?;
    Ok(signing.verifying_key().to_bytes())
}

fn transcript(
    group: EntityId,
    revision: u64,
    friend: EntityId,
    token_digest: &[u8; 32],
    word_ref: EntityId,
    order: u64,
    at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TRANSCRIPT.len() + 16 + 8 + 16 + 32 + 16 + 8 + 8);
    bytes.extend_from_slice(TRANSCRIPT);
    bytes.extend_from_slice(group.as_bytes());
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes.extend_from_slice(friend.as_bytes());
    bytes.extend_from_slice(token_digest);
    bytes.extend_from_slice(word_ref.as_bytes());
    bytes.extend_from_slice(&order.to_be_bytes());
    bytes.extend_from_slice(&at.to_be_bytes());
    bytes
}

pub(super) fn sign_link_word(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_id: EntityId,
    group: &AskGroup,
    word_ref: EntityId,
    fact: &AskAnswerFact,
    token_digest: [u8; 32],
) -> Result<LinkProof> {
    let seed = SIGNERS
        .get(&vault.store, txn, &group_id)?
        .ok_or_else(invalid)?;
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes() != group.link_verify_key {
        return Err(invalid());
    }
    let revision = group.effective.what.revision;
    let signature = signing
        .sign(&transcript(
            group_id,
            revision,
            fact.actor,
            &token_digest,
            word_ref,
            fact.order,
            fact.at,
        ))
        .to_bytes()
        .to_vec();
    Ok(LinkProof {
        token_digest,
        revision,
        signature,
    })
}

/// Called at the generic TASK put door and at evidence reads. No local secret,
/// token row, or sync arrival ordering is necessary to verify an issued word.
pub(super) fn validate_source(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    fact: &AskAnswerFact,
) -> Result<()> {
    if (fact.source == TaskAskSource::Inform) != fact.word.inform_for.is_some() {
        return Err(invalid());
    }
    if fact.source != TaskAskSource::ForeignStated {
        return if fact.link_proof.is_none() {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    let proof = fact.link_proof.as_ref().ok_or_else(invalid)?;
    if fact.word.inform_for.is_some()
        || proof.revision != group.effective.what.revision
        || !group
            .effective
            .what
            .options
            .contains_key(fact.word.option.as_ref().ok_or_else(invalid)?)
        || !group
            .members
            .iter()
            .any(|m| m.actor == fact.actor.to_hex() && m.task == fact.task.to_hex())
    {
        return Err(invalid());
    }
    let verifying = VerifyingKey::from_bytes(&group.link_verify_key).map_err(|_| invalid())?;
    let signature: [u8; 64] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    verifying
        .verify(
            &transcript(
                fact.group,
                proof.revision,
                fact.actor,
                &proof.token_digest,
                id,
                fact.order,
                fact.at,
            ),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| invalid())?;
    // A forged proof is refused above for good; a genuine word whose PERSON
    // row has not replicated yet stays retryable.
    let raw = store
        .entities
        .get(txn, fact.actor.as_bytes())?
        .ok_or(Error::Record(RecordError::AskDependencyPending))?;
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_PERSON)
    {
        return Err(invalid());
    }
    Ok(())
}

const SETTLEMENT_TRANSCRIPT: &[u8] = b"oneiron.tasks.ask.link_settlement.v1\0";

fn settlement_message(result: &super::super::TaskAskResult) -> Result<Vec<u8>> {
    let mut unsigned = result.clone();
    unsigned.settlement.link_result_proof = None;
    let body = rmp_serde::to_vec_named(&unsigned).map_err(|_| invalid())?;
    let mut message = Vec::with_capacity(SETTLEMENT_TRANSCRIPT.len() + body.len());
    message.extend_from_slice(SETTLEMENT_TRANSCRIPT);
    message.extend_from_slice(&body);
    Ok(message)
}

fn needs_settlement_proof(result: &super::super::TaskAskResult) -> bool {
    result
        .evidence
        .iter()
        .any(|entry| entry.source == TaskAskSource::ForeignStated)
}

pub(in crate::task_verb) fn sign_settlement(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_id: EntityId,
    group: &AskGroup,
    result: &super::super::TaskAskResult,
) -> Result<Option<Vec<u8>>> {
    if !needs_settlement_proof(result) {
        return Ok(None);
    }
    let seed = SIGNERS
        .get(&vault.store, txn, &group_id)?
        .ok_or_else(invalid)?;
    let signer = SigningKey::from_bytes(&seed);
    if signer.verifying_key().to_bytes() != group.link_verify_key
        || result.settlement.group_ref != group_id
    {
        return Err(invalid());
    }
    Ok(Some(
        signer
            .sign(&settlement_message(result)?)
            .to_bytes()
            .to_vec(),
    ))
}

pub(in crate::task_verb) fn verify_settlement(
    group: &AskGroup,
    result: &super::super::TaskAskResult,
) -> Result<()> {
    let Some(proof) = &result.settlement.link_result_proof else {
        return if needs_settlement_proof(result) {
            Err(invalid())
        } else {
            Ok(())
        };
    };
    if !needs_settlement_proof(result) {
        return Err(invalid());
    }
    let key = VerifyingKey::from_bytes(&group.link_verify_key).map_err(|_| invalid())?;
    let bytes: [u8; 64] = proof.as_slice().try_into().map_err(|_| invalid())?;
    key.verify(&settlement_message(result)?, &Signature::from_bytes(&bytes))
        .map_err(|_| invalid())
}
