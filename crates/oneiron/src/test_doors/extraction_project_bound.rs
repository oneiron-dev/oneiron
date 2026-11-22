//! One project-bound Meso extraction attempt over witnessed TURNs, for
//! integration tests.
//!
//! The production planner cuts the one partition, and the attempt is queued
//! with `ConsolidationPartitionPlan::scoped_input`: its branch scope names
//! `project` and every exact resource the branch reads, each document pinned
//! at the revision the Dreamer's own scoped read serves now. No production
//! path queues a project-bound partition yet; the bound extraction step reads
//! this one as it reads any queued scope. Nothing here mints a binding or
//! pages.

use std::collections::BTreeSet;

use oneiron_model::llm::{Scope, ScopeResource};

use super::extraction_inputs::{
    EXTRACTION_RUN, admit_extraction_attempt, disable_extraction_prefilter,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::vault::Vault;

/// `id` as an exact document read: the revision the Dreamer's scoped read
/// serves it at now, the version a queued scope names a document by. `None`
/// when the Dreamer does not read it.
fn dreamer_document_version(
    vault: &Vault,
    dreamer: EntityId,
    id: EntityId,
) -> Result<Option<ScopeResource>> {
    Ok(
        super::derive::source_version(vault, dreamer, EdgeActorClass::System, id)?.map(|version| {
            ScopeResource::DocumentVersion {
                document: id,
                version: version.revision,
            }
        }),
    )
}

/// [`dreamer_document_version`] of a row the branch must read.
fn required_document_version(
    vault: &Vault,
    dreamer: EntityId,
    id: EntityId,
) -> Result<ScopeResource> {
    dreamer_document_version(vault, dreamer, id)?
        .ok_or_else(|| Error::InvalidConfig(format!("the Dreamer does not read {}", id.to_hex())))
}

/// Enqueues one Meso partition attempt over `turns`, bound to `project`, and
/// admits it, returning its id with its admission.
///
/// The bound scope holds what an unbound branch's own scope holds: the
/// partition bucket, the signals projection, the output, the gap projection
/// for this scope, and the conversation, each TURN and each of its MESSAGE
/// rows at the Dreamer's revision, with each TURN's byline the Dreamer reads,
/// which the request lists first. Each of `listed` is readable, as an entity
/// the request may list; each of `heads` is readable and writable, as a
/// prior head the branch may hold. The turns must share one conversation, so
/// they plan as one partition.
///
/// # Errors
///
/// The vault's, a row the Dreamer does not read, a plan that cuts no single
/// partition attempt, or an admission of another attempt than the one
/// enqueued.
pub fn enqueue_admitted_project_bound_extraction_attempt(
    vault: &Vault,
    turns: &[EntityId],
    project: EntityId,
    listed: &[EntityId],
    heads: &[EntityId],
    now: u64,
) -> Result<(AttemptId, DreamerAdmittedAttempt)> {
    disable_extraction_prefilter(vault)?;
    let scope_kind = DreamerConsolidationScope::Meso;
    let (planned, watermark, mut messages) = {
        let txn = vault.store.env.read_txn()?;
        let watermark =
            crate::dreamer_consolidation::read_watermark_in_txn(vault, &txn, scope_kind)?;
        let planned = crate::dreamer_consolidation::read_partition_turns_in_txn(
            vault, &txn, scope_kind, turns,
        )?;
        let mut messages = Vec::new();
        for turn in turns {
            messages.extend(vault.filtered_edge_peers(
                &txn,
                EdgeDirection::In,
                turn,
                EdgeKind::PartOf,
                Some(ENTITY_TYPE_MESSAGE),
            )?);
        }
        (planned, watermark, messages)
    };
    messages.sort_unstable();
    messages.dedup();
    let plans =
        crate::dreamer_consolidation::plan_partitions(vault, scope_kind, &planned, &watermark)?;
    let [plan] = plans.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "the Meso plan cut {} partitions, not one",
            plans.len()
        )));
    };
    let dreamer = super::steward::dreamer(vault)?;
    let mut readable = BTreeSet::from([
        ScopeResource::Bucket {
            key: bytes_to_hex_lower(&plan.key.partition_hash()),
        },
        plan.signals_resource(),
    ]);
    let documents = std::iter::once(plan.key.conversation_ref)
        .chain(turns.iter().copied())
        .chain(messages)
        .chain(listed.iter().copied());
    for id in documents {
        readable.insert(required_document_version(vault, dreamer, id)?);
    }
    // The byline as the listing reads it: a TURN body's actor, where it has
    // one (`neighbourhood::named_entities`).
    for turn in turns {
        let body = vault
            .get(turn)?
            .ok_or_else(|| Error::InvalidConfig("a queued TURN has no body".into()))?;
        if let Ok(Some(author)) = crate::conversation::record_author(&body)
            && let Some(pin) = dreamer_document_version(vault, dreamer, author)?
        {
            readable.insert(pin);
        }
    }
    let mut writable = BTreeSet::from([plan.output_resource()]);
    for head in heads {
        let pin = required_document_version(vault, dreamer, *head)?;
        readable.insert(pin.clone());
        writable.insert(pin);
    }
    let mut scope = Scope {
        world: plan.key.world_ref,
        facet: plan.key.facet_ref,
        relationship: None,
        project: Some(project),
        readable,
        writable,
    };
    let gap = plan.gap_resource(&scope);
    scope.writable.insert(gap);
    let outcome = DreamerRunnerStore::new(vault).enqueue_consolidation(
        EnqueueDreamerConsolidationAttempt {
            scope: scope_kind,
            input: plan.scoped_input(&scope)?,
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(EXTRACTION_RUN.to_owned()),
            now,
        },
    )?;
    let id = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    let admitted = admit_extraction_attempt(vault, id, now)?;
    if admitted.status.attempt.id != id {
        return Err(Error::InvalidConfig(
            "the consolidation lane admitted another attempt".into(),
        ));
    }
    Ok((id, admitted))
}
