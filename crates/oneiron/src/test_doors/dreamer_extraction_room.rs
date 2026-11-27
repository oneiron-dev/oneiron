//! Door for `tests/dreamer_extraction_room.rs` (FIX
//! DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW): one real Meso wake pass
//! over one conversation whose TURNs say the given words, with the
//! extraction model's input window lent or not, keeping every extraction
//! call's transcript; the native slices of one witnessed conversation in a
//! given room, with host material, its words bound to a relationship or
//! not; and the calls the packing keeps when a built call carries bytes its
//! estimate leaves out.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rmpv::Value;

use super::meso_extraction_width::{
    allow_fixture_extraction, authorize_fixture_inference, encode, occurred, text_response,
};
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::attempt_queue::AttemptState;
use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, RoleBackends, enqueue_partition_attempts,
    read_watermark, scan_dirty_turns,
};
use crate::dreamer_promotion::AttemptPromotionSink;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
};
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::memory::MemoryResult;
use crate::registry::{
    ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, EdgeKind, EntityId, FatalLlmError,
    LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
    ModelLocality, UnsupportedCapability, Vault,
};

const WAKE_PASS_POLL_LIMIT: usize = 100_000;

/// Runs one Meso pass over one conversation whose TURNs say `turns` in
/// order, at most `turns_per_child` TURNs a call, lending the extraction
/// model's input window `window_tokens` when given (as the host's factory
/// does from its model windows), and returns each extraction call's
/// transcript, its last user message, in call order.
///
/// # Errors
///
/// Vault setup, the wake pass, or an attempt that did not complete.
pub fn meso_extraction_transcripts(
    turns: &[String],
    turns_per_child: usize,
    window_tokens: Option<u64>,
) -> Result<Vec<String>> {
    let directory = tempfile::tempdir()?;
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = crate::VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let vault = Arc::new(Vault::open(directory.path(), config)?);
    crate::test_fixtures::provision_engine_machines(&vault);
    authorize_fixture_inference(&vault)?;
    crate::test_fixtures::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        partition_extraction_parallelism: 1,
        extraction_parallelism: 1,
        extraction_turns_per_child: turns_per_child,
        ..Default::default()
    })?;
    seed_conversation(&vault, turns)?;
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, turns.len() + 1)?;
    let queued = enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "room", 20)?;
    let [queued] = queued.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "expected one Meso partition, got {}",
            queued.len()
        )));
    };
    let attempt = match queued {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    let backend = TranscriptBackend::default();
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let guard =
        BudgetGuard::with_reserve_units("room", 10_000, 500, BudgetExhaustionPolicy::Suspend);
    let mut sink = AttemptPromotionSink::new(Arc::clone(&vault));
    let model = ModelId::new("test/model@r1").expect("fixture model id");
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: model.clone(),
        inference: HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model,
                locality: ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&allow_fixture_extraction),
        },
        roles: RoleBackends::default().with_follower_window(window_tokens),
        sink: &mut sink,
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    let mut driver = DreamerWakeDriver::new(&vault, "room", deadline);
    store_clock.set(21);
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            lease_owner: "room-worker".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now: 21,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    let status = DreamerRunnerStore::new(&vault)
        .status(attempt)?
        .ok_or(Error::EntityNotFound)?;
    if status.attempt.state != AttemptState::Completed {
        return Err(Error::InvalidConfig(format!(
            "the Meso attempt ended {:?}",
            status.attempt.state
        )));
    }
    let transcripts = backend
        .transcripts
        .lock()
        .expect("transcript backend state")
        .clone();
    Ok(transcripts)
}

/// One native extraction call as the slicing cut it.
#[derive(Debug, Clone)]
pub struct RoomSliceCall {
    /// The call's transcript.
    pub transcript: String,
    /// Whether its listing page, as rendered, fills its room, so the
    /// extraction model is never called over it.
    pub page_past_room: bool,
}

/// The native extraction calls over one witnessed conversation whose TURNs
/// say `words`, each word a MESSAGE scoped to one fresh relationship the
/// Dreamer reads when `bound`, with `material` as the wake's admitted host
/// material and at most `room` transcript bytes a call when given, in call
/// order.
///
/// # Errors
///
/// Vault setup, or the slicing.
pub fn room_slice_calls(
    words: &[&str],
    bound: bool,
    material: &[String],
    room: Option<usize>,
) -> MemoryResult<Vec<RoomSliceCall>> {
    let directory = tempfile::tempdir().map_err(Error::from)?;
    drop(super::consolidation::open_dreamer_vault(
        directory.path(),
        "owen",
    )?);
    let vault = Vault::open_owned(directory.path(), crate::VaultConfig::device())?;
    crate::test_fixtures::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let dreamer = super::steward::dreamer(&vault)?;
    super::steward::stand_steward_grant(&vault, dreamer, &super::steward::STEWARD_VERBS)?;
    let turns = if bound {
        relationship_bound_turns(&vault, words)?
    } else {
        super::extraction_inputs::witness_extraction_turns(&vault, words)?.turns
    };
    let (attempt, _) =
        super::extraction_inputs::enqueue_admitted_extraction_attempt(&vault, &turns, 1_000)?;
    let calls = crate::dreamer_consolidation::resources::native_slice_calls_in_room_for_test(
        &vault, attempt, &turns, material, room,
    )?;
    Ok(calls
        .into_iter()
        .map(|(transcript, page_past_room)| RoomSliceCall {
            transcript,
            page_past_room,
        })
        .collect())
}

/// Each of `words` witnessed in order into its own TURN of one fresh
/// conversation, as one visible user MESSAGE scoped to one fresh
/// relationship, after the Dreamer gets a live `MessagesRead` grant on it,
/// so the slice's scope is bound to it (FIX 10357).
fn relationship_bound_turns(vault: &Vault, words: &[&str]) -> Result<Vec<EntityId>> {
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        occurred(1),
        1,
        b"relationship",
    )?;
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            principal_ref: vault.dreamer_authority()?.entity_ref(),
            scope: AccessGrantScope::Messages {
                space_ref: relationship,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: None,
            authority_scope: crate::federation::scope_codec::read_preset(),
            companion_bounds: None,
        },
    )?;
    let conversation = EntityId::now();
    let metadata = serde_json::json!({"rel": relationship.to_hex()});
    let mut turns = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let (turn, _) = super::consolidation::witness_user_turn(
            vault,
            conversation,
            word,
            Some(metadata.clone()),
            10u64.saturating_add(index as u64),
        )?;
        turns.push(turn);
    }
    Ok(turns)
}

/// The chunk sizes the extraction packing keeps for TURN lines of `lines`
/// bytes, at most `turns_per_child` a call in `room` bytes, when each built
/// call also carries `unseen` bytes its estimate leaves out (a chunk's bound
/// relationship lines and the labels they widen).
#[must_use]
pub fn fitted_chunk_sizes(
    lines: &[usize],
    turns_per_child: usize,
    room: usize,
    unseen: usize,
) -> Vec<usize> {
    fitted_calls(lines, turns_per_child, room, unseen, &[])
        .into_iter()
        .map(|(turns, _)| turns)
        .collect()
}

/// The calls the extraction packing keeps for TURN lines of `lines` bytes,
/// at most `turns_per_child` a call in `room` bytes, with host material
/// texts of `material` framed bytes, when each built call also carries
/// `unseen` bytes its estimate leaves out: each call's TURN count and the
/// material texts it carries.
#[must_use]
pub fn fitted_calls(
    lines: &[usize],
    turns_per_child: usize,
    room: usize,
    unseen: usize,
    material: &[usize],
) -> Vec<(usize, usize)> {
    crate::dreamer_consolidation::resources::fitted_calls_for_test(
        lines,
        turns_per_child,
        room,
        unseen,
        material,
    )
}

/// Answers every call with no candidates, keeping each extraction call's
/// transcript.
#[derive(Default)]
struct TranscriptBackend {
    transcripts: Mutex<Vec<String>>,
}

impl LlmBackend for TranscriptBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if request.envelope.purpose == CallPurpose::Extraction {
            let transcript: String = request
                .messages
                .last()
                .map(|message| {
                    message
                        .content
                        .iter()
                        .filter_map(|part| match part {
                            ContentPart::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.transcripts
                .lock()
                .expect("transcript backend state")
                .push(transcript);
        }
        let response = text_response(serde_json::json!({"candidates": []}));
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// One conversation of `turns`, each a user TURN said by one person.
fn seed_conversation(vault: &Vault, turns: &[String]) -> Result<()> {
    let conversation = EntityId::now();
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        occurred(1),
        1,
        b"session",
    )?;
    let person = EntityId::now();
    let named = encode(&Value::Map(vec![("name".into(), "owen".into())]))?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    for words in turns {
        let turn = EntityId::now();
        let encoded = encode(&Value::Map(vec![
            ("txt".into(), words.as_str().into()),
            ("spkr".into(), "user".into()),
            ("actor".into(), person.to_hex().into()),
        ]))?;
        vault
            .batch()
            .put(&turn, ENTITY_TYPE_TURN, occurred(10), 10, &encoded)
            .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
            .commit()?;
    }
    Ok(())
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..WAKE_PASS_POLL_LIMIT {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
    panic!("the extraction room wake pass did not end within its poll limit");
}

/// Who wrote one MESSAGE of [`writer_label_slice_calls`].
pub enum TurnWriter {
    /// The vault's embedded owner.
    Owner,
    /// The second PERSON ("mira").
    Member,
}

/// The native extraction calls (each call's transcript, in call order) over one witnessed conversation of a fresh
/// personal vault (`shared` false) or a fresh shared vault (`shared` true, the owner its Owner and the second PERSON
/// a Member), whose user MESSAGEs `said` gives in order as (writer, turn slot, words): entries with the same slot are
/// MESSAGEs of one TURN, in order. The second PERSON is a live named PERSON ("mira").
///
/// Each TURN's PERSON byline (the writer of its first MESSAGE) is listed in its call, so TURNs that different PERSONs
/// opened fall into different calls, each with its own labels. In a shared vault the owner's conferring Owner grant
/// and the member's Member grant stand as `own_device_grant::stand_shared_owner_census` stands the owner's, without
/// renaming the owner.
///
/// # Errors
///
/// Vault setup, witnessing, or the slicing.
pub fn writer_label_slice_calls(
    shared: bool,
    said: &[(TurnWriter, usize, &str)],
) -> MemoryResult<Vec<String>> {
    Ok(writer_label_slices(shared, said, false)?
        .into_iter()
        .map(|(transcript, _)| transcript)
        .collect())
}

/// [`writer_label_slice_calls`] with the member PERSON deleted after the conversation is queued for extraction (a
/// shell-keeping user delete, which keeps its MESSAGEs and their writer edges): each call's transcript and whether
/// every row the call was read from still stands, as the model run's source fence asks before it sends.
///
/// # Errors
///
/// As [`writer_label_slice_calls`], or the delete.
pub fn writer_label_slice_calls_after_member_delete(
    shared: bool,
    said: &[(TurnWriter, usize, &str)],
) -> MemoryResult<Vec<(String, bool)>> {
    writer_label_slices(shared, said, true)
}

/// The calls of [`writer_label_slice_calls`], each with whether its source rows stand; `delete_member` deletes the
/// member PERSON between the queueing and the slicing.
fn writer_label_slices(
    shared: bool,
    said: &[(TurnWriter, usize, &str)],
    delete_member: bool,
) -> MemoryResult<Vec<(String, bool)>> {
    let directory = tempfile::tempdir().map_err(Error::from)?;
    drop(super::consolidation::open_dreamer_vault(
        directory.path(),
        "owen",
    )?);
    let vault = Vault::open_owned(directory.path(), crate::VaultConfig::device())?;
    crate::test_fixtures::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor()?;
    let member = EntityId::now();
    super::untangle_regressions::seed_named_person(&vault, &member, "mira", 1)?;
    if shared {
        stand_writer_label_shared_census(&vault, owner, member)?;
    }
    let dreamer = super::steward::dreamer(&vault)?;
    super::steward::stand_steward_grant(&vault, dreamer, &super::steward::STEWARD_VERBS)?;
    let conversation = EntityId::now();
    let owner_actor = crate::WriteActor::new(owner, crate::edge::EdgeActorClass::Human);
    vault.create_conversation(
        conversation,
        &crate::conversation::ConversationBody::default(),
        owner_actor,
        1,
    )?;
    vault.join_member(
        conversation,
        member,
        owner_actor,
        2,
        crate::conversation::HistoryChoice::Share,
    )?;
    let mut slots = std::collections::BTreeMap::<usize, (EntityId, u32)>::new();
    let mut turns = Vec::new();
    for (index, (writer, slot, words)) in said.iter().enumerate() {
        let (turn, order) = slots.entry(*slot).or_insert_with(|| {
            let turn = EntityId::now();
            turns.push(turn);
            (turn, 0)
        });
        let writer_id = match writer {
            TurnWriter::Owner => owner,
            TurnWriter::Member => member,
        };
        let occurred = 10u64.saturating_add(index as u64);
        vault
            .memory(writer_id, crate::edge::EdgeActorClass::Human)
            .witness(&crate::memory::WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: (*words).to_owned(),
                    parts: None,
                    metadata: None,
                    is_visible: true,
                    order: *order,
                    quote: None,
                }],
                occurred_at: occurred,
                assertions: crate::memory::WitnessAssertions::default(),
            })?;
        *order = order.saturating_add(1);
    }
    let (attempt, _) =
        super::extraction_inputs::enqueue_admitted_extraction_attempt(&vault, &turns, 1_000)?;
    if delete_member && !vault.delete_entity(&member)? {
        return Err(Error::InvalidConfig("the member PERSON to delete exists".to_owned()).into());
    }
    crate::dreamer_consolidation::resources::native_slice_sources_standing_for_test(
        &vault, attempt, &turns,
    )
}

/// Stands shared vault membership for [`writer_label_slice_calls`]: the owner's conferring Owner grant and the
/// member's Member grant over one vault, with the vault's creation record naming both, as
/// `own_device_grant::stand_shared_owner_census` stands the owner's half.
///
/// # Errors
///
/// The vault's, or a live-owner census that does not name the owner.
fn stand_writer_label_shared_census(
    vault: &Vault,
    owner: EntityId,
    member: EntityId,
) -> Result<()> {
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
        SharedTrainingSetup, SharedVaultCreation, encode_federation_grant_body,
    };
    const VAULT_ID: u64 = 42;
    let mut batch = vault.batch();
    let mut grant_refs = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for (person, role, preset) in [
            (
                owner,
                FederationGrantRole::Owner,
                FederationGrantPreset::Owner,
            ),
            (
                member,
                FederationGrantRole::Member,
                FederationGrantPreset::Member,
            ),
        ] {
            let mut grant =
                FederationGrant::new(FederationGrantScope::vault(VAULT_ID), person, role, preset);
            grant.authority_scope =
                vault.grant_default_scope_in_txn(&txn, role, VAULT_ID, person)?;
            let id = EntityId::now();
            batch = batch.put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred(1),
                1,
                None,
                &encode_federation_grant_body(&grant)?,
            );
            grant_refs.push(id.to_hex());
        }
    }
    batch.commit()?;
    const CREATION: crate::side_table::SideTable<
        (),
        SharedVaultCreation,
        crate::side_table::LegacyJson,
    > = crate::side_table::SideTable::new(&crate::side_table::SHARED_VAULT_CREATION);
    let creation = SharedVaultCreation {
        vault_id: VAULT_ID,
        preset: None,
        owner_ref: owner.to_hex(),
        grant_refs,
        policy_ref: None,
        training_setup: SharedTrainingSetup::Pending {
            question_ref: [0; 32],
            created_at: 0,
        },
    };
    vault.with_write_txn(|wtxn| CREATION.put(&vault.store, wtxn, &(), &creation))?;
    let txn = vault.store.env.read_txn()?;
    if !crate::policy_model::holds_live_ownership_in_txn(vault, &txn, &owner)? {
        return Err(Error::InvalidConfig(
            "the vault's live-owner census does not name the owner".to_owned(),
        ));
    }
    Ok(())
}
