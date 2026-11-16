//! Owner-bound library doors over the existing conversion, lifecycle and admission engines.

use crate::claim::ClaimApprovalStatus;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_convert::{ConvertOutcome, ConvertRequest, SkillRefiner};
use crate::skill_hub::HubAdmissionDisposition;
use crate::{EntityId, Error, TimeRange, Vault};

use super::{HubConsentReceipt, HubSkillReceipts, HubSkillRequest};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skills::{
    SkillAdvisoryAskRequest, SkillCapabilityView, SkillCodeAutoInstallRequest, SkillConvertReceipt,
    SkillConvertRequest, SkillForkLineage, SkillGovernanceSetRequest, SkillGovernanceView,
    SkillHashRuleRequest, SkillLibraryCall, SkillLibraryDependency, SkillLibraryFile,
    SkillLibraryForkRequest, SkillLibraryLifecycle, SkillLibraryListRequest, SkillLibraryPage,
    SkillLibraryRestoreReceipt, SkillLibraryRestoreRequest, SkillLibraryScan, SkillLibraryView,
    SkillOptimizeAxisView, SkillOptimizeResultRequest, SkillOptimizeResultView,
    SkillOptimizeStartReceipt, SkillOptimizeStartRequest, SkillOptimizeVerdictView,
    SkillRestoreAdmission, SkillSourceEvidence, SkillStaleView,
};

pub fn skill_convert_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillConvertRequest,
    refiner: &dyn SkillRefiner,
) -> MemoryResult<SkillConvertReceipt> {
    owner.revalidate(vault)?;
    let request = ConvertRequest {
        message_refs: input.message_refs.clone(),
        hint: input.hint.clone(),
    };
    let at = vault.now_recorded_at();
    Ok(
        match crate::skill_convert::convert_messages_to_skill(
            vault,
            &request,
            refiner,
            TimeRange { start: at, end: at },
            at,
        )? {
            ConvertOutcome::Created(entity) => SkillConvertReceipt::Created { entity },
            ConvertOutcome::DupPointer(entity) => SkillConvertReceipt::DupPointer { entity },
            ConvertOutcome::MergeProposed { existing, proposal } => {
                SkillConvertReceipt::MergeProposed { existing, proposal }
            }
        },
    )
}

fn skill(vault: &Vault, entity: &EntityId) -> MemoryResult<SkillRecord> {
    vault
        .get_skill_record(entity)?
        .ok_or_else(|| Error::EntityNotFound.into())
}

pub fn skill_library_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    owner.revalidate(vault)?;
    skill_library_view(vault, input)
}

/// [`skill_library_get_as_owner`]'s view, for a door that admitted its
/// reader itself (`sdk_skill_fork`'s caller-bound fork, FIX 8167).
pub(crate) fn skill_library_view(
    vault: &Vault,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    let record = skill(vault, &input.entity)?;
    let source_refs = crate::skill_convert::source_message_refs(&record)?;
    let (package, source_messages) = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let package = vault.runtime_skill_package_in_txn(&txn, &input.entity, &record)?;
        let source_messages = source_refs
            .into_iter()
            .map(|message_ref| {
                Ok(SkillSourceEvidence {
                    available: crate::vault::live_entity_row_in_txn(
                        &vault.store,
                        &txn,
                        &message_ref,
                    )?
                    .is_live(),
                    message_ref,
                })
            })
            .collect::<crate::Result<Vec<_>>>()?;
        (package, source_messages)
    };
    let mut lineage = Vec::new();
    let mut child = record.clone();
    let mut seen = std::collections::BTreeSet::from([input.entity]);
    while let Some(parent) = child.forked_from {
        if !seen.insert(parent) {
            return Err(MemoryError::bad_request("cyclic skill fork ancestry"));
        }
        let provenance = crate::msgpack_value_to_json(&child.provenance);
        let (parent_document, parent_frontier) =
            crate::write_envelope::skill_record::fork_parent_pin(&child)?
                .map_or((None, None), |(document, frontier)| {
                    (Some(document), Some(frontier))
                });
        let parent_record = vault.get_skill_record(&parent)?;
        lineage.push(SkillForkLineage {
            parent,
            parent_version: provenance
                .get("forkOfVersion")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            parent_document,
            parent_frontier,
            parent_available: parent_record.is_some(),
            hub_sources: vault.skill_hub_sources(&parent)?,
        });
        let Some(parent) = parent_record else { break };
        child = parent;
    }
    let scans = match record.content_hash {
        Some(hash) => vault
            .skill_scan_verdicts_for_content_hash(hash)?
            .into_iter()
            .map(|claim| {
                serde_json::from_value(crate::msgpack_value_to_json(&claim.value))
                    .map_err(|_| MemoryError::bad_request("invalid stored skill scan receipt"))
            })
            .collect::<MemoryResult<Vec<_>>>()?,
        None => Vec::new(),
    };
    let stale =
        crate::skill_convert::skill_stale_note(vault, &input.entity)?.map(|note| SkillStaleView {
            reason: note.reason,
            deleted_refs: note.deleted_refs,
        });
    let provenance = crate::msgpack_value_to_json(&record.provenance);
    Ok(SkillLibraryView {
        provenance,
        source_messages,
        stale,
        lineage,
        scans,
        receipts: super::hub::hub_skill_receipts(vault, input)?,
        ..skill_package_view(input.entity, record, package)
    })
}

/// The view of skill `entity` built from `record` and its runtime `package`
/// alone: the owner's evidence (provenance, source messages, the stale note,
/// fork lineage, scans and hub receipts) is left empty. A caller other than
/// the owner is served this view (`snapshot_read::skill_reader`), built from
/// the read that admitted it; the owner's view fills the evidence in.
pub(crate) fn skill_package_view(
    entity: EntityId,
    record: SkillRecord,
    package: Option<crate::skill_hub::HubPackage>,
) -> SkillLibraryView {
    let (files, capabilities) = match package {
        Some(package) => (
            Some(
                package
                    .files
                    .into_iter()
                    .map(|file| SkillLibraryFile {
                        path: file.path,
                        content: file.content,
                    })
                    .collect(),
            ),
            Some(SkillCapabilityView {
                bins: package.capabilities.bins.into_iter().collect(),
                env: package.capabilities.env.into_iter().collect(),
                mcp: package.capabilities.mcp.into_iter().collect(),
                allowed_tools: package.capabilities.allowed_tools.into_iter().collect(),
            }),
        ),
        None => (None, None),
    };
    SkillLibraryView {
        entity,
        content_hash: record.content_hash.map(|hash| hash.to_hex()),
        lifecycle: record.lifecycle_status.into(),
        approval: record.approval_status,
        loadable: crate::skill::skill_loadable(&record),
        source: record.source.as_str().to_owned(),
        role: record.role.as_str().to_owned(),
        call: record.call.map(|call| SkillLibraryCall {
            reference: call.reference,
            arguments: call.arguments,
            returns: call.returns,
        }),
        governance_tier: record.governance_tier.map(|tier| tier.as_str().to_owned()),
        generated: record.generated,
        human_authored: record.human_authored,
        dependencies: record
            .dependencies
            .into_iter()
            .map(|dependency| SkillLibraryDependency {
                skill_id: dependency.skill_id,
                min_version: dependency.min_version,
            })
            .collect(),
        provenance: serde_json::Value::Null,
        skill_id: record.skill_id,
        desc: record.desc,
        version: record.version,
        source_messages: Vec::new(),
        stale: None,
        lineage: Vec::new(),
        files,
        capabilities,
        scans: Vec::new(),
        receipts: HubSkillReceipts {
            sources: Vec::new(),
            imports: Vec::new(),
            admission: None,
        },
    }
}

pub fn skill_library_list_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryListRequest,
) -> MemoryResult<SkillLibraryPage> {
    owner.revalidate(vault)?;
    if input.limit == 0 {
        return Err(MemoryError::bad_request("limit must be positive"));
    }
    let ids = vault.entities_by_type_page(
        crate::registry::ENTITY_TYPE_SKILL,
        input.after.as_ref(),
        input.limit,
    )?;
    let next_after = ids.last().copied();
    let mut skills = Vec::new();
    for entity in ids {
        if vault.get_skill_record(&entity)?.is_some() {
            skills.push(skill_library_get_as_owner(
                vault,
                owner,
                &HubSkillRequest { entity },
            )?);
        }
    }
    Ok(SkillLibraryPage { skills, next_after })
}

/// Changes only lifecycle/approval, inside the same owner-checked write and ordinary batch gate.
fn lifecycle_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    entity: EntityId,
    lifecycle: SkillLifecycle,
) -> MemoryResult<()> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &entity)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let prior = vault.read_skill_record_in_txn(txn, &entity)?;
        let mut updated = prior.clone();
        updated.lifecycle_status = lifecycle;
        if lifecycle == SkillLifecycle::Quarantined {
            updated.approval_status = ClaimApprovalStatus::Approved;
        }
        crate::skill::validate_skill_update(&prior, &updated)?;
        let at = vault.now_recorded_at();
        vault.apply_skill_record_body(
            txn,
            &entity,
            TimeRange { start: at, end: at },
            at,
            crate::skill::encode_skill_record(&updated)?,
            false,
        )
    })?;
    Ok(())
}

pub fn skill_archive_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<SkillLibraryView> {
    lifecycle_as_owner(vault, owner, input.entity, SkillLifecycle::Quarantined)?;
    vault
        .runtime()
        .skill_invocations()
        .cancel_skill(&input.entity);
    skill_library_get_as_owner(vault, owner, input)
}

pub use super::skill_fork::{skill_library_fork_as_owner, skill_library_fork_by_caller};

pub fn skill_restore_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryRestoreRequest,
    scorer: Option<&dyn crate::skill_optimize::HeldOutReplayNotes>,
) -> MemoryResult<SkillLibraryRestoreReceipt> {
    owner.revalidate(vault)?;
    let record = skill(vault, &input.entity)?;
    if record.lifecycle_status != SkillLifecycle::Quarantined {
        return Err(MemoryError::bad_request(
            "restore requires an archived skill",
        ));
    }
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        for source in crate::skill_convert::source_message_refs(&record)? {
            if !crate::vault::live_entity_row_in_txn(&vault.store, &txn, &source)?.is_live() {
                return Err(MemoryError::bad_request(
                    "restore source evidence is unavailable",
                ));
            }
        }
    }
    let admission = if let Some(admission) = &input.admission {
        let publisher =
            vault.admit_skill_publisher(owner, &admission.publisher, admission.source.hub_id)?;
        let ask = vault.prepare_marketplace_activation(
            input.entity,
            &admission.source,
            &publisher,
            admission.evidence_skill,
        )?;
        let digest = ask.effect_digest().to_hex();
        let Some(shown) = &admission.effect_digest else {
            return Ok(SkillLibraryRestoreReceipt::PendingAdmission {
                entity: input.entity,
                content_hash: ask.content_hash().to_hex(),
                effect_digest: digest,
            });
        };
        if shown != &digest {
            return Err(MemoryError::bad_request(
                "restore admission moved; prepare it again",
            ));
        }
        let scorer = scorer.ok_or_else(|| {
            MemoryError::new(
                crate::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                "no held-out skill judge is registered",
                &[],
            )
        })?;
        vault.approve_marketplace_activation(&ask, owner)?;
        let at = vault.now_recorded_at();
        match vault.admit_marketplace_skill(&ask, scorer, TimeRange { start: at, end: at }, at)? {
            HubAdmissionDisposition::Ruled(receipt) if receipt.accepted => Some(*receipt),
            HubAdmissionDisposition::Ruled(receipt) => {
                return Ok(SkillLibraryRestoreReceipt::Refused {
                    entity: input.entity,
                    admission: *receipt,
                });
            }
            HubAdmissionDisposition::PendingConsent => {
                return Err(MemoryError::bad_request(
                    "restore needs current owner consent",
                ));
            }
        }
    } else {
        // The normal hub/fork activation gate refuses without its admission proof.
        lifecycle_as_owner(vault, owner, input.entity, SkillLifecycle::Active)?;
        None
    };
    Ok(SkillLibraryRestoreReceipt::Restored {
        skill: Box::new(skill_library_get_as_owner(
            vault,
            owner,
            &HubSkillRequest {
                entity: input.entity,
            },
        )?),
        admission,
    })
}

pub fn skill_hash_rule_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillHashRuleRequest,
) -> MemoryResult<HubConsentReceipt> {
    let hash = crate::skill::SkillContentHash::parse_hex(&input.content_hash)?;
    Ok(vault
        .set_marketplace_blocked_hash(owner, hash, input.blocked)?
        .into())
}

pub fn skill_code_auto_install_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillCodeAutoInstallRequest,
) -> MemoryResult<HubConsentReceipt> {
    Ok(vault
        .set_marketplace_code_auto_install(owner, input.enabled)?
        .into())
}

pub fn skill_advisory_ask_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillAdvisoryAskRequest,
) -> MemoryResult<HubConsentReceipt> {
    Ok(vault
        .set_marketplace_advisory_ask(owner, input.enabled)?
        .into())
}

fn governance_view(vault: &Vault, entity: &EntityId) -> MemoryResult<SkillGovernanceView> {
    let record = skill(vault, entity)?;
    let verdict = crate::skill_optimize::skill_governance_tier(vault, entity)?;
    let tier = verdict.tier();
    Ok(SkillGovernanceView {
        entity: *entity,
        skill_id: record.skill_id,
        version: record.version,
        lifecycle: record.lifecycle_status.into(),
        verdict: match verdict {
            crate::skill_optimize::SkillTierVerdict::Marked(_) => "marked",
            crate::skill_optimize::SkillTierVerdict::LegacyStandard => "legacy_standard",
            crate::skill_optimize::SkillTierVerdict::Ambiguous => "ambiguous",
        }
        .to_owned(),
        tier: tier.map(|tier| tier.as_str().to_owned()),
        protected: tier.is_some_and(|tier| tier.is_protected()),
        optimizable: verdict.optimizable(),
    })
}

pub fn skill_governance_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &HubSkillRequest,
) -> MemoryResult<SkillGovernanceView> {
    owner.revalidate(vault)?;
    governance_view(vault, &input.entity)
}

/// Marks (or clears) only the governance tier: a state flip in the same
/// owner-checked write transaction that re-reads the record, never content.
pub fn skill_governance_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillGovernanceSetRequest,
) -> MemoryResult<SkillGovernanceView> {
    let tier =
        match input.tier.as_deref() {
            None => None,
            Some(value) => Some(crate::skill::SkillGovernanceTier::parse(value).ok_or_else(
                || MemoryError::bad_request("tier must be identity, alignment or standard"),
            )?),
        };
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &input.entity)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let prior = vault.read_skill_record_in_txn(txn, &input.entity)?;
        let mut updated = prior.clone();
        updated.governance_tier = tier;
        crate::skill::validate_skill_update(&prior, &updated)?;
        let at = vault.now_recorded_at();
        vault.apply_skill_record_body(
            txn,
            &input.entity,
            TimeRange { start: at, end: at },
            at,
            crate::skill::encode_skill_record(&updated)?,
            false,
        )
    })?;
    governance_view(vault, &input.entity)
}

/// Starts one skill_optimize attempt through the existing Dreamer queue.
/// A named identity/alignment (or ambiguous) skill is excluded inside the
/// same write transaction and never enqueued. An admitted named target is
/// carried through the queued work; drafting and held-out admission stay the
/// wake job's and the gate's acts.
pub fn skill_optimize_start_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeStartRequest,
) -> MemoryResult<SkillOptimizeStartReceipt> {
    let now = input.now.unwrap_or_else(|| vault.now_recorded_at());
    let mut selectors = Vec::new();
    if let Some(resident) = input.resident {
        selectors.push((
            rmpv::Value::from("resident"),
            rmpv::Value::from(resident.to_hex()),
        ));
    }
    if let Some(skill) = input.skill {
        selectors.push((
            rmpv::Value::from("skill"),
            rmpv::Value::from(skill.to_hex()),
        ));
    }
    let payload = if selectors.is_empty() {
        rmpv::Value::Nil
    } else {
        rmpv::Value::Map(selectors)
    };
    let store = crate::dreamer_runner::DreamerRunnerStore::new(vault);
    let outcome = vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if let Some(skill_entity) = input.skill {
            if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &skill_entity)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let record = vault.read_skill_record_in_txn(txn, &skill_entity)?;
            let verdict =
                crate::skill_optimize::tier_verdict_in_txn(vault, &*txn, &skill_entity, &record)?;
            if !verdict.optimizable() {
                return Ok(None);
            }
        }
        store
            .enqueue_skill_optimize_in_txn(
                txn,
                crate::dreamer_runner::EnqueueDreamerSkillOptimizeAttempt {
                    input: payload,
                    parent_attempt: None,
                    dedupe_key: input.dedupe_key.clone(),
                    run_id: input.run_id.clone(),
                    now,
                },
            )
            .map(Some)
    })?;
    match outcome {
        None => Ok(SkillOptimizeStartReceipt {
            outcome: "excluded".to_owned(),
            job_ref: None,
            state: None,
            skill: input.skill,
            governance: input
                .skill
                .map(|skill| governance_view(vault, &skill))
                .transpose()?,
        }),
        Some(outcome) => {
            let (status, existing) = match outcome {
                crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status) => {
                    (status, false)
                }
                crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => {
                    (status, true)
                }
            };
            let (_, skill) = crate::skill_optimize::optimize_target_input(&status.payload.input)
                .ok_or_else(|| {
                    Error::InvalidConfig("invalid Coach skill optimization input".into())
                })?;
            Ok(SkillOptimizeStartReceipt {
                outcome: if existing { "existing" } else { "enqueued" }.to_owned(),
                job_ref: Some(crate::entity_id::bytes_to_hex_lower(
                    status.attempt.id.as_bytes(),
                )),
                state: Some(attempt_state_name(status.attempt.state)),
                skill,
                governance: skill
                    .map(|skill| governance_view(vault, &skill))
                    .transpose()?,
            })
        }
    }
}

fn attempt_state_name(state: crate::attempt_queue::AttemptState) -> String {
    use crate::attempt_queue::AttemptState;
    match state {
        AttemptState::Queued => "queued",
        AttemptState::Leased => "leased",
        AttemptState::Paused => "paused",
        AttemptState::Completed => "completed",
        AttemptState::Failed => "failed",
        AttemptState::Cancelled => "cancelled",
        AttemptState::Scheduled => "scheduled",
        AttemptState::Landing => "landing",
        AttemptState::Abandoned => "abandoned",
    }
    .to_owned()
}

fn parse_attempt_ref(job_ref: &str) -> MemoryResult<crate::attempt_queue::AttemptId> {
    let reference = job_ref
        .trim()
        .strip_prefix("job:")
        .unwrap_or(job_ref.trim());
    if reference.len() != 32 || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(MemoryError::bad_request(format!(
            "attempt ref {job_ref:?} is not a 32-hex attempt id"
        )));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&reference[index * 2..index * 2 + 2], 16)
            .map_err(|_| MemoryError::bad_request(format!("attempt ref {job_ref:?} is not hex")))?;
    }
    crate::attempt_queue::AttemptId::from_bytes(&bytes)
        .map_err(|_| MemoryError::bad_request(format!("attempt ref {job_ref:?} is not hex")))
}

pub(crate) fn verdict_view(
    verdict: crate::skill_optimize::HeldOutVerdict,
) -> SkillOptimizeVerdictView {
    SkillOptimizeVerdictView {
        id: verdict.id,
        proposal: verdict.proposal,
        skill: verdict.skill,
        disposition: verdict.disposition.as_str().to_owned(),
        accepted: verdict.accepted,
        before: verdict.before,
        after: verdict.after,
        goal_axes: verdict
            .goal_axes
            .into_iter()
            .map(|(axis, score)| SkillOptimizeAxisView {
                axis,
                before: score.before,
                after: score.after,
            })
            .collect(),
        goal_revision: verdict.goal_revision,
        judge_revision: verdict.judge_revision,
        cycle: verdict.cycle,
        held_out_receipts: verdict.held_out_receipts,
        held_out_count: verdict.held_out_count,
        held_out_digest: verdict.held_out_digest,
        held_out_truncated: verdict.held_out_truncated,
        proposal_digest: verdict.proposal_digest,
        target_digest: verdict.target_digest,
        proposal_tier: verdict.proposal_tier.map(|tier| tier.as_str().to_owned()),
        at: verdict.at,
    }
}

/// Finds the optimizer-born proposal a started attempt drafted, by its
/// birth-stamped attempt provenance (the wake resume rule).
fn proposal_for_attempt(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
) -> MemoryResult<Option<EntityId>> {
    let attempt_hex = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
    let mut after = None;
    loop {
        let page =
            vault.entities_by_type_page(crate::registry::ENTITY_TYPE_SKILL, after.as_ref(), 128)?;
        for id in &page {
            let Some(record) = vault.get_skill_record(id)? else {
                continue;
            };
            let rmpv::Value::Map(fields) = &record.provenance else {
                continue;
            };
            let field = |name: &str| {
                fields.iter().find_map(|(key, value)| {
                    (key.as_str() == Some(name))
                        .then(|| value.as_str())
                        .flatten()
                })
            };
            if field(crate::skill_convert::PROVENANCE_BIRTH_KEY)
                == Some(crate::skill_optimize::SKILL_OPTIMIZE_BIRTH_PATH)
                && field(crate::skill_optimize::PROVENANCE_OPTIMIZE_ATTEMPT_KEY)
                    == Some(attempt_hex.as_str())
            {
                return Ok(Some(*id));
            }
        }
        if page.len() < 128 {
            return Ok(None);
        }
        after = page.last().copied();
    }
}

/// Reads a started optimize job and, once drafted and ruled, its proposal,
/// incumbent, governance and every held-out verdict on that proposal.
pub fn skill_optimize_result_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeResultRequest,
) -> MemoryResult<SkillOptimizeResultView> {
    owner.revalidate(vault)?;
    if input.job_ref.is_none() && input.proposal.is_none() {
        return Err(MemoryError::bad_request(
            "optimize result needs a job_ref or a proposal",
        ));
    }
    let (state, kind, last_error, found_proposal) = match &input.job_ref {
        Some(job_ref) => {
            let attempt = parse_attempt_ref(job_ref)?;
            let store = crate::dreamer_runner::DreamerRunnerStore::new(vault);
            match store.status(attempt)? {
                Some(status) => (
                    Some(attempt_state_name(status.attempt.state)),
                    Some(status.attempt.kind),
                    status.attempt.last_error,
                    proposal_for_attempt(vault, attempt)?,
                ),
                None => (None, None, None, None),
            }
        }
        None => (None, None, None, None),
    };
    let proposal = input.proposal.or(found_proposal);
    let (skill, proposal_lifecycle, incumbent_lifecycle, governance, verdicts) = match proposal {
        Some(proposal_entity) => {
            let verdicts =
                crate::skill_optimize::skill_edit_verdicts_for_proposal(vault, &proposal_entity)?;
            let skill_entity = verdicts.last().map(|verdict| verdict.skill).or_else(|| {
                vault
                    .get_skill_record(&proposal_entity)
                    .ok()
                    .flatten()
                    .and_then(|record| {
                        let rmpv::Value::Map(fields) = &record.provenance else {
                            return None;
                        };
                        fields.iter().find_map(|(key, value)| {
                            (key.as_str()
                                == Some(crate::skill_optimize::PROVENANCE_OPTIMIZE_OF_ENTITY_KEY))
                            .then(|| value.as_str())
                            .flatten()
                            .and_then(|hex| EntityId::from_hex(hex).ok())
                        })
                    })
            });
            let proposal_lifecycle = vault
                .get_skill_record(&proposal_entity)?
                .map(|record| record.lifecycle_status.into());
            let incumbent_lifecycle = match skill_entity {
                Some(skill_entity) => vault
                    .get_skill_record(&skill_entity)?
                    .map(|record| record.lifecycle_status.into()),
                None => None,
            };
            let governance = match skill_entity {
                Some(skill_entity) => Some(governance_view(vault, &skill_entity)?),
                None => None,
            };
            (
                skill_entity,
                proposal_lifecycle,
                incumbent_lifecycle,
                governance,
                verdicts.into_iter().map(verdict_view).collect::<Vec<_>>(),
            )
        }
        None => (None, None, None, None, Vec::new()),
    };
    Ok(SkillOptimizeResultView {
        verdict: verdicts.last().cloned(),
        job_ref: input.job_ref.clone(),
        state,
        kind,
        last_error,
        skill,
        proposal,
        proposal_lifecycle,
        incumbent_lifecycle,
        governance,
        verdicts,
    })
}
