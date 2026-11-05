//! Reviewable grant-environment repair data for a failure-ladder case.
//! Native grant terms identify the target; no proposal changes its authority.

use super::coach_heal::CoachHealAuthor;
use super::proposals;
use crate::access_grant::{AccessGrant, decode_live_access_grant_body, encode_access_grant_body};
use crate::attempt_queue::AttemptQueue;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::ArtifactError;
use crate::failure_ladder::{HealerCase, HealerRepairRoute};
use crate::limit_ask::EngineLimit;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::self_heal::HealEvidenceContext;
use crate::{EntityId, Error, Result, Vault, WriteEnvelope};
use serde_json::{Value, json};

/// One real grant belonging to the failed case's agent, including terminal grants.
#[derive(Debug, Clone)]
pub struct EnvironmentGrantTarget {
    pub grant_ref: EntityId,
    pub grant: AccessGrant,
    /// Digest of canonical grant terms, excluding the stored read-witness history.
    pub terms_digest: [u8; 32],
}

/// A host author's proposed change to one of the native targets it received.
/// `change` is an object of reviewable data, never a grant write or an instruction
/// the engine executes. Renewing terminal access still requires a new grant id.
pub struct CoachEnvironmentDraft {
    pub grant_ref: EntityId,
    pub change: Value,
    pub rationale: String,
}

const ENVIRONMENT_REPAIR_PREDICATE: &str = "coach.environment_repair";

pub(super) enum EnvironmentRepair {
    Drafted {
        case: HealerCase,
        target: EnvironmentGrantTarget,
        draft: CoachEnvironmentDraft,
    },
    Skipped(&'static str),
}

/// Reads a native target in the supplied snapshot. Deleted shells and erased
/// history name no current grant principal; revoked and expired terms still do.
fn target_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_ref: EntityId,
) -> Result<Option<EnvironmentGrantTarget>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &grant_ref)?.is_live() {
        return Ok(None);
    }
    let raw = vault
        .store
        .port_entity_raw(txn, &grant_ref)?
        .ok_or(Error::CorruptedIndex("environment grant row"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("environment grant header"))?;
    if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
        return Ok(None);
    }
    let Some(grant) = decode_live_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])? else {
        return Ok(None);
    };
    let terms_digest = *blake3::hash(&encode_access_grant_body(&grant)?).as_bytes();
    Ok(Some(EnvironmentGrantTarget {
        grant_ref,
        grant,
        terms_digest,
    }))
}

/// Collects actual agent grants before calling the custom author, outside the
/// heal writer. A model chooses among these targets; it does not name a new one.
pub(super) fn draft(
    vault: &Vault,
    case: &HealerCase,
    cause: &HealEvidenceContext,
    author: &dyn CoachHealAuthor,
) -> Result<EnvironmentRepair> {
    let agent = EntityId::from_hex(&case.scope.agent_ref)?;
    let targets = {
        let txn = vault.store.env.read_txn()?;
        let mut targets = Vec::new();
        for id in vault
            .store
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_ACCESS_GRANT, None)?
        {
            if let Some(target) = target_in_txn(vault, &txn, id?)?
                && target.grant.principal_ref == agent
            {
                targets.push(target);
            }
        }
        targets
    };
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, targets.len() as u64);
    let draft = match author.draft_environment(case, &targets, cause) {
        Ok(Some(draft))
            if draft
                .change
                .as_object()
                .is_some_and(|change| !change.is_empty())
                && !draft.rationale.trim().is_empty() =>
        {
            draft
        }
        Ok(Some(_)) => return Ok(EnvironmentRepair::Skipped("unusable_draft")),
        Ok(None) => return Ok(EnvironmentRepair::Skipped("declined")),
        Err(_) => return Ok(EnvironmentRepair::Skipped("author_failed")),
    };
    let Some(target) = targets
        .into_iter()
        .find(|target| target.grant_ref == draft.grant_ref)
    else {
        return Ok(EnvironmentRepair::Skipped("unbound_target"));
    };
    Ok(EnvironmentRepair::Drafted {
        case: case.clone(),
        target,
        draft,
    })
}

/// Lands a proposed artifact beside the heal, never a grant mutation. Stale
/// context leaves the ordinary route-only proposal and settlement intact.
pub(super) fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    repair: &EnvironmentRepair,
    evidence: &[EntityId],
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<Value> {
    let skipped = |why| json!({ "skipped": why });
    let (case, target, draft) = match repair {
        EnvironmentRepair::Drafted {
            case,
            target,
            draft,
        } => (case, target, draft),
        EnvironmentRepair::Skipped(why) => return Ok(skipped(*why)),
    };
    if crate::agent_dispatch::validate_healer_case(case).is_err() {
        return Ok(skipped("unbound_case"));
    }
    let Some(failing) =
        AttemptQueue::new(vault).get_in_write_txn(&*txn, case.failing_attempt_id)?
    else {
        return Ok(skipped("case_moved"));
    };
    match crate::failure_ladder::require_healer_case_in_txn(
        vault,
        txn,
        case,
        failing.run_id.as_deref(),
    ) {
        Ok(()) => {}
        Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(_))) => {
            return Ok(skipped("case_moved"));
        }
        Err(error) => return Err(error),
    }
    let agent = EntityId::from_hex(&case.scope.agent_ref)?;
    let Some(current) = target_in_txn(vault, &*txn, target.grant_ref)? else {
        return Ok(skipped("target_moved"));
    };
    if current.grant.principal_ref != agent || current.terms_digest != target.terms_digest {
        return Ok(skipped("target_moved"));
    }
    let change_bytes = serde_json::to_vec(&draft.change).map_err(|_| super::invalid())?;
    let _ = vault.measure_limit(
        EngineLimit::MaintenanceTextBytes,
        change_bytes.len().max(draft.rationale.len()) as u64,
    );
    let value = json!({
        "case": case.case_ref,
        "failing_attempt": crate::entity_id::bytes_to_hex_lower(case.failing_attempt_id.as_bytes()),
        "agent": case.scope.agent_ref,
        "diagnosis": case.evidence_ref,
        "environment_kind": "access_grant",
        "environment": target.grant_ref.to_hex(),
        "terms_digest": crate::entity_id::bytes_to_hex_lower(&target.terms_digest),
        "change": draft.change,
        "rationale": draft.rationale,
    });
    let mut artifact_evidence = evidence.to_vec();
    artifact_evidence.push(target.grant_ref);
    artifact_evidence.sort();
    artifact_evidence.dedup();
    let artifact = proposals::emit_in_txn(
        vault,
        txn,
        envelope.actor().entity_ref(),
        ENVIRONMENT_REPAIR_PREDICATE,
        &value,
        &artifact_evidence,
        envelope,
        now,
    )?;
    let route = HealerRepairRoute::Environment {
        agent_ref: case.scope.agent_ref.clone(),
        environment_ref: target.grant_ref.to_hex(),
        repair_ref: artifact.to_hex(),
        diagnosis_ref: case.evidence_ref.clone(),
    };
    Ok(json!({ "route": route }))
}
