//! Typed policy reads, owner edits and inert untrusted contributions.
//! The owner writer is the same one `install_owner_policy_manifest` takes;
//! composition and validation remain the existing manifest resolver's.
mod content_policy;
pub use content_policy::*;
mod retrieval_weights;
pub(crate) use retrieval_weights::{
    RETRIEVAL_WEIGHTS_KEY, decode_retrieval_weights, retrieval_weights_for_run,
};
pub use retrieval_weights::{
    RetrievalWeights, RetrievalWeightsConfigureRequest, RetrievalWeightsReceipt,
    RetrievalWeightsView, configure_retrieval_weights_as_owner, retrieval_weights_as_owner,
};
mod types;
pub use types::*;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

use super::decision::GateOutcome;
use super::input::{GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles};
use super::manifest_authenticity::{manifest_is_quarantined, manifest_is_trusted};
use super::{POLICY_SCHEMA_VERSION, resolve_policy_manifest};

const FIELDS: &[&str] = &[
    "schema_version",
    "pack_id",
    "pack_version",
    "min_engine_version",
    "defaults",
    "rules",
    "actor_ceilings",
    "source_trust",
    "signature",
    "signatures",
    "auto_checker",
];

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

fn id(reference: &str) -> Result<EntityId> {
    EntityId::from_hex(reference).map_err(|_| invalid("manifest_ref is a 32-hex id"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn body_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<Vec<u8>>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
    {
        return Err(invalid("manifest_ref belongs to another entity type"));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if super::project_depth::is_project_depth_id(&id)
        || super::project_depth::is_project_depth_contribution(&body)
    {
        return Err(invalid(
            "a signed project-depth contribution is not an ordinary manifest",
        ));
    }
    Ok(Some(body))
}

fn view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<PolicyManifestView> {
    let mut fields = decode_fields(body)?;
    fields.retain(|(key, _)| key.as_str().is_some_and(|key| FIELDS.contains(&key)));
    let selected = encode_fields(fields)?;
    let manifest = rmp_serde::from_slice(&selected)
        .map_err(|_| invalid("policy manifest write axes do not decode"))?;
    Ok(PolicyManifestView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(body).to_hex().to_string(),
        trusted: manifest_is_trusted(&vault.store, txn, &id, body)?,
        quarantined: manifest_is_quarantined(&vault.store, txn, &id, body)?,
        manifest,
    })
}

fn decode_fields(body: &[u8]) -> Result<Vec<(rmpv::Value, rmpv::Value)>> {
    let mut cursor = std::io::Cursor::new(body);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("malformed policy manifest"))?;
    match value {
        rmpv::Value::Map(fields) if cursor.position() == body.len() as u64 => Ok(fields),
        _ => Err(invalid("malformed policy manifest")),
    }
}

fn encode_fields(fields: Vec<(rmpv::Value, rmpv::Value)>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("policy manifest encoding"))?;
    Ok(data)
}

fn encode_manifest(manifest: &PolicyManifest, existing: Option<&[u8]>) -> Result<Vec<u8>> {
    // Preserve unrelated MessagePack values, including binary values, exactly
    // as values; a JSON round trip would change those policy tables.
    let mut fields = existing.map(decode_fields).transpose()?.unwrap_or_default();
    fields.retain(|(key, _)| !key.as_str().is_some_and(|key| FIELDS.contains(&key)));
    let replacement =
        rmp_serde::to_vec_named(manifest).map_err(|_| invalid("policy manifest encoding"))?;
    fields.extend(decode_fields(&replacement)?);
    let data = encode_fields(fields)?;
    let decoded = super::decode::decode_policy_manifest(&data)
        .ok_or_else(|| invalid("malformed policy manifest"))?;
    if decoded.unsupported_schema
        || decoded.engine_version_floor
        || decoded.source_trust.malformed_manifest_seen
    {
        return Err(invalid(
            "unsupported policy schema, engine version or malformed source trust",
        ));
    }
    Ok(data)
}

fn record(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: crate::WriteActor,
    manifest: EntityId,
    body: &[u8],
    decision: (&str, Vec<String>),
) -> Result<String> {
    let mut receipt = GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: decision.0.to_owned(),
        reason_codes: decision.1,
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: GateContentKind::PolicyManifest.as_str().to_owned(),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: Some(format!("policy_manifest:{}", manifest.to_hex())),
        diff_handle: blake3::hash(body).as_bytes().to_vec(),
        read_frontier_hash: resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?,
        redacted_at: None,
    };
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    Ok(receipt.decision_id.to_hex())
}

/// Read the policy envelope and axes, under the owner's current proof.
pub fn policy_manifests_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &PolicyManifestRead,
) -> Result<PolicyManifestsView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let ids = match &input.manifest_ref {
        Some(reference) => vec![id(reference)?],
        None => crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &vault.store,
            &txn,
            ENTITY_TYPE_POLICY_MANIFEST,
            None,
        )?
        .collect::<Result<Vec<_>>>()?,
    };
    let mut manifests = Vec::new();
    for id in ids {
        if input.manifest_ref.is_none() && super::project_depth::is_project_depth_id(&id) {
            continue;
        }
        let body = body_in_txn(vault, &txn, id)?.ok_or(Error::EntityNotFound)?;
        manifests.push(view_in_txn(vault, &txn, id, &body)?);
    }
    Ok(PolicyManifestsView {
        default_manifest_ref: super::default_policy_manifest_id()?.to_hex(),
        read_frontier_hash: hex(&resolve_policy_manifest(&vault.store, &txn)?.read_frontier_hash()?),
        manifests,
    })
}

/// Replace only the typed write axes through the authenticated install writer.
/// A fresh id contributes another pack; the resolver, not this door, meets it.
pub fn put_policy_manifest_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PolicyManifestPut,
) -> Result<PolicyManifestReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let id = match input.manifest_ref.as_deref() {
            Some(reference) => id(reference)?,
            None => vault.store.clock.entity_id()?,
        };
        let existing = body_in_txn(vault, txn, id)?;
        match (existing.as_deref(), input.expected_body_hash.as_deref()) {
            (Some(body), Some(expected)) if blake3::hash(body).to_hex().as_str() == expected => {
                if !manifest_is_trusted(&vault.store, txn, &id, body)? {
                    return Err(invalid("adopt a proposal as a fresh owner contribution, not by trusting its stored tables"));
                }
            }
            (None, None) => {}
            _ => return Err(invalid("expected_body_hash must match the existing manifest")),
        }
        let data = encode_manifest(&input.manifest, existing.as_deref())?;
        vault.write_owner_policy_manifest_in_txn(owner, txn, id, data, crate::unix_seconds_now())?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let receipt_ref = record(vault, txn, crate::WriteActor::new(actor, EdgeActorClass::Human),
            id, &body, ("allow", vec!["gate.allow.owner_policy_manifest".to_owned()]))?;
        Ok(PolicyManifestReceipt {
            manifest: view_in_txn(vault, txn, id, &body)?,
            approval: PolicyCeiling::Auto,
            receipt_ref,
            read_frontier_hash: hex(&resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?),
        })
    })
}

/// An untrusted contribution always stays an inert proposal, even if tighter.
/// The memory surface supplies the caller's actor and its write admission.
pub fn propose_policy_manifest(
    memory: &Memory<'_>,
    input: PolicyManifestPropose,
) -> MemoryResult<PolicyManifestReceipt> {
    let vault = memory.vault();
    let data = encode_manifest(&input.manifest, None)?;
    memory.with_verified_actor_write_txn(|txn| {
        let actor = crate::WriteActor::new(memory.actor(), memory.actor_class());
        let policy = resolve_policy_manifest(&vault.store, txn)?;
        let decision = policy.evaluate_gate(&GateEvaluatorInput {
            actor: GateActor {
                actor_class: actor.actor_class().gate_actor_class().to_owned(),
                actor_ref: Some(actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            source: Some(
                if memory.writes_generated() || memory.actor_class() != EdgeActorClass::Human {
                    crate::claim::ClaimSource::Generated
                } else {
                    crate::claim::ClaimSource::UserStated
                },
            ),
            content_kind: GateContentKind::PolicyManifest,
            sensitivity_band: None,
            criticality: super::PolicyCriticality::Critical,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(actor.entity_ref()),
                ..GateProvenanceHandles::default()
            },
            external_effect: None,
            agent_definition_ceiling: super::agent_definition_ceiling_for_actor(
                &vault.store,
                txn,
                actor,
            ),
            foreign_agent_ceiling: None,
            consent: None,
        });
        if decision.outcome() == GateOutcome::Deny {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "the caller's Gate refused this policy proposal",
                &[],
            ));
        }
        let id = vault.store.clock.entity_id()?;
        vault.write_policy_manifest_proposal_in_txn(
            txn,
            id,
            data.clone(),
            crate::unix_seconds_now(),
        )?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let receipt_ref = record(
            vault,
            txn,
            actor,
            id,
            &body,
            (
                decision.outcome().as_str(),
                decision
                    .reason_codes()
                    .iter()
                    .map(|reason| reason.as_str().to_owned())
                    .collect(),
            ),
        )?;
        Ok(PolicyManifestReceipt {
            manifest: view_in_txn(vault, txn, id, &body)?,
            approval: PolicyCeiling::Proposed,
            receipt_ref,
            read_frontier_hash: hex(
                &resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?
            ),
        })
    })
}

/// The checker role is the existing model manifest's calibrated verdict binding.
pub fn gate_checker_as_owner(vault: &Vault, owner: &AuthenticatedOwner) -> Result<GateCheckerView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    Ok(GateCheckerView {
        binding: crate::llm::manifest::read_manifest(&vault.store, &txn)?
            .and_then(|row| row.verdict),
    })
}

/// Set the verdict role without changing any model role, route or teacher pin.
/// A vault with no model manifest must configure one first; no host fallback.
pub fn set_gate_checker_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: GateCheckerSet,
) -> Result<GateCheckerReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let mut manifest =
            crate::llm::manifest::read_manifest(&vault.store, txn)?.ok_or_else(|| {
                invalid("configure the vault's model manifest before binding its checker role")
            })?;
        manifest.verdict = Some(input.binding.clone());
        vault.write_model_manifest_in_txn(txn, &manifest, None, None)?;
        let data = rmp_serde::to_vec_named(&input.binding)
            .map_err(|_| invalid("checker binding encoding"))?;
        let receipt_ref = record(
            vault,
            txn,
            crate::WriteActor::new(actor, EdgeActorClass::Human),
            super::default_policy_manifest_id()?,
            &data,
            ("allow", vec!["gate.allow.owner_checker_role".to_owned()]),
        )?;
        Ok(GateCheckerReceipt {
            binding: input.binding.clone(),
            receipt_ref,
        })
    })
}
