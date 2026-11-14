//! One Meso extraction attempt over witnessed TURNs, for integration tests.
//!
//! A conversation is witnessed turn by turn, the prefilter screen is disabled
//! so the production planner keeps every turn, one Meso partition attempt is
//! enqueued through the production planner, and the consolidation lane admits
//! it with its lease. A turn is moved by appending one more MESSAGE through
//! the production witness, and rows are settled into a project through the
//! production leader stamp. Nothing here mints a binding or pages.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The lease owner every extraction admission here takes.
pub const EXTRACTION_LEASE_OWNER: &str = "extraction-inputs-worker";
/// The run the extraction attempt is enqueued in.
pub const EXTRACTION_RUN: &str = "run-extraction-inputs";

/// One conversation witnessed for an extraction inputs test.
#[derive(Debug, Clone)]
pub struct ExtractionConversation {
    /// The conversation the turns were witnessed into.
    pub conversation: EntityId,
    /// The turns in witness order.
    pub turns: Vec<EntityId>,
    /// The visible message of each turn, in witness order.
    pub messages: Vec<EntityId>,
}

/// Witnesses each of `words` as one visible user MESSAGE into its own TURN of
/// one fresh conversation, in order, each spoken by a fresh person.
///
/// # Errors
///
/// The vault's.
pub fn witness_extraction_turns(vault: &Vault, words: &[&str]) -> Result<ExtractionConversation> {
    let conversation = EntityId::now();
    let mut turns = Vec::with_capacity(words.len());
    let mut messages = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let occurred = 10u64.saturating_add(index as u64);
        let (turn, message) =
            super::consolidation::witness_user_turn(vault, conversation, word, None, occurred)?;
        turns.push(turn);
        messages.push(message);
    }
    Ok(ExtractionConversation {
        conversation,
        turns,
        messages,
    })
}

/// Disables the Dreamer prefilter screen, so the production partition planner
/// keeps every planned turn.
///
/// # Errors
///
/// The vault's.
pub fn disable_extraction_prefilter(vault: &Vault) -> Result<()> {
    let mut config = vault.prefilter_config()?;
    config.enabled = false;
    vault.set_prefilter_config(config)
}

/// Enqueues one Meso partition attempt over `turns` through the production
/// partition planner, after disabling the prefilter screen, and returns its
/// attempt id.
///
/// The turns must share one conversation, so they plan as one partition.
///
/// # Errors
///
/// The vault's, or a plan that cuts no single partition attempt.
pub fn enqueue_extraction_attempt(
    vault: &Vault,
    turns: &[EntityId],
    now: u64,
) -> Result<AttemptId> {
    disable_extraction_prefilter(vault)?;
    let scope = DreamerConsolidationScope::Meso;
    let outcomes = vault.with_write_txn(|txn| {
        let watermark = crate::dreamer_consolidation::read_watermark_in_txn(vault, txn, scope)?;
        crate::dreamer_consolidation::enqueue_partition_plans_in_txn(
            vault,
            txn,
            scope,
            turns,
            &watermark,
            Some(EXTRACTION_RUN),
            now,
        )
    })?;
    let [(_, outcome)] = outcomes.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "the Meso plan cut {} partitions, not one",
            outcomes.len()
        )));
    };
    match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status.attempt.id),
    }
}

/// Admits the next Meso consolidation attempt under
/// [`EXTRACTION_LEASE_OWNER`] at `now`, through the consolidation lane's own
/// admission.
///
/// # Errors
///
/// The vault's, or an admission of nothing or of another scope.
pub fn admit_extraction_attempt(vault: &Vault, now: u64) -> Result<DreamerAdmittedAttempt> {
    let scope = DreamerConsolidationScope::Meso;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = DreamerRunnerStore::new(vault).admit_next_consolidation(
        AdmitDreamerConsolidationAttempt {
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: EXTRACTION_LEASE_OWNER.to_owned(),
                now,
                budget_id: "extraction-inputs".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 1,
                started_milestone: None,
            },
        },
    )?
    else {
        return Err(Error::InvalidConfig(
            "no extraction attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != scope.as_str() {
        return Err(Error::InvalidConfig(format!(
            "the consolidation lane admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    Ok(*admitted)
}

/// Enqueues one Meso attempt over `turns` and admits it, returning its id
/// with its admission.
///
/// # Errors
///
/// As [`enqueue_extraction_attempt`] and [`admit_extraction_attempt`], or an
/// admission of another attempt than the one enqueued.
pub fn enqueue_admitted_extraction_attempt(
    vault: &Vault,
    turns: &[EntityId],
    now: u64,
) -> Result<(AttemptId, DreamerAdmittedAttempt)> {
    let id = enqueue_extraction_attempt(vault, turns, now)?;
    let admitted = admit_extraction_attempt(vault, now)?;
    if admitted.status.attempt.id != id {
        return Err(Error::InvalidConfig(
            "the consolidation lane admitted another attempt".into(),
        ));
    }
    Ok((id, admitted))
}

/// Settles each of `rows` into `project`, as the leader-chat door settles a
/// project's turn and message.
///
/// The conversation stays in the default project, so a grant narrowed to it
/// still reaches the conversation while these rows fall outside.
///
/// # Errors
///
/// The vault's.
pub fn settle_extraction_rows_in_project(
    vault: &Vault,
    rows: &[EntityId],
    project: EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        for row in rows {
            crate::federation::record_scope::stamp_leader_project(
                &vault.store,
                txn,
                *row,
                project,
            )?;
        }
        Ok(())
    })
}

/// Appends one visible user MESSAGE saying `words` to `turn` of
/// `conversation` through the production witness, moving the turn's source
/// version.
///
/// The new message takes order one, after the birth message's order zero, so
/// it never collides with the turn's stored child.
///
/// # Errors
///
/// The vault's.
pub fn append_extraction_turn_words(
    vault: &Vault,
    conversation: EntityId,
    turn: EntityId,
    words: &str,
) -> Result<()> {
    let speaker = EntityId::now();
    vault.put_entity(
        &speaker,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"witness",
    )?;
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 1,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })
        .map_err(|error| Error::InvalidConfig(format!("witness: {error:?}")))?;
    Ok(())
}
