//! Doors for the workaround-skills tests (CLIF-STEALS 2): a leased
//! `coach.skill_distill` attempt (the Coach host job enqueued under its
//! facet's fixed dedupe key, as the nightly enqueue does, and admitted
//! through the Coach host queue's own admission), and reads of what a pass
//! filed: the findings under a predicate, the skills whose id carries a
//! prefix, and a skill's stored files. Nothing here files a skill or a
//! finding, and nothing here names the pass, so the doors build on a tree
//! without it.

use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::maintenance::coach::{COACH_HOST_QUEUE_KIND, COACH_SKILL_DISTILL_FACET};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::vault::Vault;

/// One finding claim as it is stored.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    /// The finding claim.
    pub id: EntityId,
    /// Its JSON value.
    pub value: serde_json::Value,
    /// Its approval: a Coach finding lands Proposed in the owner's run tray.
    pub approval: ClaimApprovalStatus,
    /// Its facet and project stamps.
    pub stamps: (EntityId, EntityId),
}

/// Every claim under `predicate` whose value is JSON text, in claim id order.
///
/// # Errors
///
/// Storage errors, or a finding whose value is not JSON text.
pub fn findings_under(vault: &Vault, predicate: &str) -> Result<Vec<StoredFinding>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut findings = Vec::new();
    for (id, body) in vault.claims_with_predicate_in_txn(&rtxn, predicate)? {
        let text = body
            .value
            .as_str()
            .ok_or(Error::InvalidClaimBody("finding value is not text"))?;
        let value = serde_json::from_str(text)
            .map_err(|_| Error::InvalidClaimBody("finding value is not JSON"))?;
        findings.push(StoredFinding {
            id,
            value,
            approval: body.approval,
            stamps: (body.scope_facet, body.scope_project),
        });
    }
    findings.sort_by_key(|finding| finding.id);
    Ok(findings)
}

/// Every stored SKILL entity whose skill id starts with `prefix`, in id order.
///
/// # Errors
///
/// Storage errors, or a SKILL row that does not decode.
pub fn skills_with_id_prefix(vault: &Vault, prefix: &str) -> Result<Vec<EntityId>> {
    let ids: Vec<EntityId> = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_SKILL, None)?
            .collect::<Result<_>>()?
    };
    let mut skills = Vec::new();
    for id in ids {
        if vault
            .get_skill_record(&id)?
            .is_some_and(|record| record.skill_id.starts_with(prefix))
        {
            skills.push(id);
        }
    }
    Ok(skills)
}

/// The stored files of `skill`'s package, as (path, bytes).
///
/// # Errors
///
/// Storage errors, or a skill with no stored package.
pub fn skill_files(vault: &Vault, skill: &EntityId) -> Result<Vec<(String, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let package = vault
        .export_hub_package_in_txn(&rtxn, skill)?
        .ok_or_else(|| Error::InvalidConfig("skill has no stored package".into()))?;
    Ok(package
        .files
        .into_iter()
        .map(|file| (file.path, file.content))
        .collect())
}

/// The lease owner every admission here takes.
pub const WORKAROUND_LEASE_OWNER: &str = "workaround-skills-test";

/// Queues one `coach.skill_distill` host job at `now` and admits it.
///
/// # Errors
///
/// The vault's, or an admission of nothing or of another job.
pub fn admit_skill_distill_attempt(vault: &Vault, now: u64) -> Result<DreamerAdmittedAttempt> {
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| {
        store
            .enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_SKILL_DISTILL_FACET.into(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
                Some(COACH_SKILL_DISTILL_FACET.into()),
                None,
                now,
            )
            .map(|_| ())
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: WORKAROUND_LEASE_OWNER.to_owned(),
            now,
            budget_id: WORKAROUND_LEASE_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no coach.skill_distill attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != COACH_SKILL_DISTILL_FACET {
        return Err(Error::InvalidConfig(format!(
            "the Coach host queue admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    Ok(*admitted)
}
