//! A selector's born-with Prompt carries no words of a scope SUMMARY its member
//! does not read (SELECTOR-SCOPE-SUMMARY-WORDS, Astra F1 on L5-02 PR 4).
//!
//! A Member holds a live federation grant with unrestricted read Scope and a
//! Prompt travel choice, but no grant on relationship R. The owner witnesses
//! an R MESSAGE; a scripted, network-free Dreamer run reads it under its own
//! R grant and mints a v2 scope SUMMARY S holding a unique phrase W. An open
//! MESSAGE holds unrelated open words. An open stated CLAIM R0 has a birth
//! naming S and the open MESSAGE as Prompt inputs, and the owner lets Prompt
//! travel.
//!
//! The ordinary window filter withholds S itself (its word source is the R
//! MESSAGE the member does not read). Before the fix the export still leaks
//! W through R0's `row_born_with` Prompt; after it, only the open words
//! travel. The peer-aware export is essential: plain `filtered_window_doc`
//! does not carry born-with.
//!
//! A second test uses an Owner-role grant and requires W to travel, guarding
//! the co-Owner exemption against over-refusal.
//!
//! FIXTURE assertions establish the setup. The final LEAK assertion checks
//! the disclosure, and the final OVER-REFUSAL assertion checks the exemption.
//!
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron --all-features
//! --test selector_born_with_summary_words
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use loro::{LoroValue, ValueOrContainer};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{ActSurface, MachineRole, PeerMachine};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::dreamer_consolidation::ScopeSummaryExecutor;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, ReplyAssertions};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::provenance::birth::RowBirth;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget, decode_scope_summary_body};
use oneiron::share_travel::{BornWith, BornWithField, TravelChoice};
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity_with_birth};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector,
    filtered_window_doc_for_peer, put_selector_test_federation_grant,
};
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::test_support::test_host_issuer;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ClaimApprovalStatus, ClaimBody,
    ClaimLifecycleStatus, ClaimSource, ClaimSubject, ContentPart, DreamerAttemptExecution,
    DreamerAttemptExecutor, EdgeActorClass, EntityId, FinishReason, LlmBackend, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId,
    ModelLocality, TimeRange, Vault, VaultConfig, WakeAttemptContext, WakePassDeadline, WriteActor,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;
use serde_json::json;

const SHARED_VAULT_ID: u64 = 7;
const SUMMARY_TEXT: &str = "orchid observatory shutters close before sunrise";
const OPEN_PROMPT_TEXT: &str = "cobalt archive windows remain open after midday";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    }
}

/// A txt-less witnessed TURN: its words come from its MESSAGE, not from an
/// inline TURN body that would leave the summary's message pins empty.
fn witness_source(
    vault: &Vault,
    owner: EntityId,
    relationship: Option<EntityId>,
    text: &str,
    now: u64,
) -> (EntityId, EntityId, EntityId) {
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: relationship.map(|id| json!({ "rel": id.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's source MESSAGE");
    assert_eq!(
        vault
            .resolve_dag_scope(&canonical(conversation))
            .expect("scope")
            .records,
        vec![turn],
        "FIXTURE: the witness conversation resolves to its TURN, not its MESSAGE"
    );
    (conversation, turn, message)
}

struct NoInner;

impl DreamerAttemptExecutor for NoInner {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("FIXTURE: only the requested scope-summary attempt runs")
    }
}

struct SummaryBackend {
    source_text: String,
    response: Mutex<Option<LlmResponse>>,
}

impl LlmBackend for SummaryBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        assert!(
            request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .any(|part| {
                    matches!(part, ContentPart::Text { text, .. }
                    if text.contains(self.source_text.as_str()))
                }),
            "FIXTURE: the Dreamer's actual input contains the source MESSAGE's words"
        );
        let response = self
            .response
            .lock()
            .expect("script")
            .take()
            .expect("one call");
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

fn summary_response(text: &str) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: json!({ "text": text, "keep": "" }).to_string(),
                signature: None,
            }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
        reply_assertions: ReplyAssertions::default(),
        token_scores: None,
    }
}

/// The scripted backend is immediately ready, as in verb_self_memory_self_model.
fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("FIXTURE: the scripted executor unexpectedly waited"),
    }
}

fn allow_egress(_: &LlmRequest) -> bool {
    true
}

/// The public Dreamer path is needed: mint_scope_summary's v1 test door
/// leaves messages empty. No new mint door or generic SUMMARY put is used.
fn compose_summary(
    vault: &Vault,
    owner: EntityId,
    conversation: EntityId,
    text: &str,
    now: u64,
) -> EntityId {
    let queued = vault
        .request_scope_summary(&ScopeSummaryRequest {
            target: ScopeSummaryTarget::Scope {
                scope: canonical(conversation),
                land_on: None,
                as_record: false,
            },
            requester: WriteActor::new(owner, EdgeActorClass::Human),
        })
        .expect("declare summary");
    assert!(!queued.coalesced, "FIXTURE: a fresh summary declaration");
    let store = DreamerRunnerStore::new(vault);
    let admitted = match store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "fixture".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit summary")
    {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => *admitted,
        other => panic!("FIXTURE: summary was not admitted: {other:?}"),
    };
    assert_eq!(
        admitted.status.attempt.id, queued.attempt,
        "FIXTURE: the admitted attempt is this summary's declaration"
    );
    let backend = SummaryBackend {
        source_text: text.to_owned(),
        response: Mutex::new(Some(summary_response(text))),
    };
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let model = ModelId::new("test/model@r1").expect("model");
    let inference = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&allow_egress),
    };
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0u64));
    let mut executor = ScopeSummaryExecutor::new(
        NoInner,
        &backend,
        &guard,
        vault.dreamer_authority().expect("Dreamer authority"),
        model,
        inference,
        Some("Summarize the supplied records."),
    );
    let mut context = WakeAttemptContext {
        vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: now.saturating_mul(1000),
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let outcome =
        block_on_ready(executor.execute(&admitted, &mut context)).expect("compose summary");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "FIXTURE: the summary completed, not parked: {outcome:?}"
    );
    store
        .complete(CompleteDreamerAttempt {
            id: admitted.status.attempt.id,
            lease_owner: "fixture".to_owned(),
            attempt_count: admitted.status.attempt.attempt_count,
            now,
        })
        .expect("complete summary attempt");
    let result = vault
        .scope_summary_status(queued.attempt)
        .expect("summary status")
        .result
        .expect("the summary landed");
    EntityId::from_hex(&result.summary).expect("summary id")
}

/// Witnesses one MESSAGE through the owner's real write lane. Each source
/// gets its own turn, and only the R source names a relationship. A new
/// MESSAGE keeps its words inline in its row (FIX 4840), and a born-with
/// Prompt reads only a source's document text, so the owner then moves the
/// words into the MESSAGE's document, as a later edit does.
fn prompt_message(
    vault: &Vault,
    owner: EntityId,
    authorization: &DocAuthorization<'_>,
    relationship: Option<EntityId>,
    content: &str,
    now: u64,
) -> EntityId {
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: relationship
                    .map(|relationship| serde_json::json!({ "rel": relationship.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: WitnessAssertions::default(),
        })
        .expect("FIXTURE: the owner witnesses a prompt MESSAGE");
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".to_owned()),
            WriteActor::new(owner, EdgeActorClass::Human),
            authorization,
        )
        .expect("FIXTURE: the owner moves the MESSAGE's words into its document");
    vault
        .entity_document_head(&message)
        .expect("FIXTURE: the prompt MESSAGE owns a document head");
    assert_eq!(
        vault.entity_text(&message).expect("FIXTURE: MESSAGE text"),
        content,
        "FIXTURE: the prompt source has authoritative nonempty text"
    );
    message
}

/// Replays an open CLAIM with its immutable Rule A birth, using the public
/// replay-with-birth door. The CLAIM has its own open body and read scope;
/// its Prompt sources are recorded only in its birth, never in its value.
fn open_record_with_prompts(
    vault: &Vault,
    owner: EntityId,
    subject: EntityId,
    prompts: [EntityId; 2],
    now: u64,
) -> EntityId {
    let row = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    assert!(
        body.rel.is_none() && body.world.is_none(),
        "FIXTURE: the output CLAIM itself names no relationship or world"
    );
    let body_bytes = encode_claim_body(&body).expect("FIXTURE: encode the open CLAIM");
    let prompt_rows: Vec<Vec<u8>> = prompts
        .iter()
        .map(|prompt| {
            vault
                .get(prompt)
                .expect("FIXTURE: read the prompt row")
                .expect("FIXTURE: the prompt row exists")
        })
        .collect();
    let prompt_bytes: Vec<&[u8]> = prompt_rows.iter().map(Vec::as_slice).collect();
    let birth = RowBirth {
        made_by: MadeBy {
            inputs: prompts
                .into_iter()
                .map(|row| MadeByInput {
                    row,
                    role: MadeByInputRole::Prompt,
                })
                .collect(),
            process: MadeByProcess {
                actor: owner,
                class: MadeByClass::Stated,
                identity: "selector.prompt_fixture".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: now,
            trigger: None,
        },
        content_hash: RowBirth::content_hash_of(&prompt_bytes),
        withheld: Vec::new(),
        room_evidence: None,
    };
    replay_entity_with_birth(
        vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: at(now),
            learned_at: now,
            row_version: 0,
            body: &body_bytes,
        },
        Some(&birth),
        ImportTier::OwnDevice,
    )
    .expect("FIXTURE: replay the open CLAIM with its birth");
    // Replay keeps a row even when it refuses a malformed birth. The call
    // succeeding is not enough: both Prompt inputs must actually land.
    assert_eq!(
        vault.row_birth(&row).expect("FIXTURE: read the row birth"),
        Some(birth),
        "FIXTURE: the open CLAIM retains the exact birth with both Prompt inputs"
    );
    row
}

struct Export {
    prompt: String,
}

/// Exports the same fixture for a Member or a co-Owner. Only the role/preset
/// and Member-only read/row-denial checks differ between the two tests.
fn export_through(
    role: FederationGrantRole,
    preset: FederationGrantPreset,
    check_read_lane: bool,
) -> Export {
    let dir = tempfile::tempdir().expect("FIXTURE: tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("FIXTURE: member vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let (owner, proof) = embedded_owner(&vault).expect("FIXTURE: authenticated owner");
    // Engine MACHINE provisioning alone does not profile this install as a
    // carrier of signed owner acts. The real grant-travel door needs both.
    vault
        .ensure_serving_install_profile(&test_host_issuer(), MachineRole::Unanswered)
        .expect("FIXTURE: a live serving-install profile for the owner's travel act");

    let now = vault.now_recorded_at();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("FIXTURE: a relationship");
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "Yuki" }))
                .expect("FIXTURE: member body"),
        )
        .expect("FIXTURE: a member outside the relationship");
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                principal_ref: vault
                    .dreamer_authority()
                    .expect("Dreamer authority")
                    .entity_ref(),
                scope: AccessGrantScope::Messages {
                    space_ref: relationship,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: now,
                revoked_at: None,
                expires_at: None,
                authority_scope: read_preset(),
                companion_bounds: None,
            },
        )
        .expect("the Dreamer's R MESSAGE grant, not the member's");
    let mut defaults = vault.purpose_default_table().expect("inference defaults");
    defaults.extraction_max_locality = ModelLocality::OwnServer;
    defaults
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("extraction defaults")
        .locality = ModelLocality::OwnServer;
    vault
        .set_purpose_default_table(&defaults)
        .expect("scripted inference policy");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("FIXTURE: the live federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector).expect("FIXTURE: the selector is authorized");

    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Prompt]),
    };
    let effective = vault
        .set_federation_grant_travel_as(
            &proof,
            ActSurface::ThisInstall,
            &grant_id,
            Some(choice.clone()),
            None,
            now,
        )
        .expect("FIXTURE: the owner signs the grant's Prompt travel choice");
    assert_eq!(
        effective.map(|bound| bound.travel),
        Some(choice.clone()),
        "FIXTURE: the owner's Prompt travel choice is effective"
    );
    assert_eq!(
        vault
            .federation_grant_travel(&grant_id)
            .expect("FIXTURE: read the stored travel choice")
            .map(|bound| bound.travel),
        Some(choice),
        "FIXTURE: the export will read the stored Prompt travel choice"
    );

    let authorization = DocAuthorization::Owner(&proof);
    let (relationship_conversation, relationship_turn, relationship_message) =
        witness_source(&vault, owner, Some(relationship), SUMMARY_TEXT, now);
    let open_prompt = prompt_message(&vault, owner, &authorization, None, OPEN_PROMPT_TEXT, now);
    let summary = compose_summary(&vault, owner, relationship_conversation, SUMMARY_TEXT, now);
    let body = decode_scope_summary_body(
        &vault
            .get(&summary)
            .expect("summary read")
            .expect("summary exists"),
    )
    .expect("a scope-summary body, not an epoch");
    assert_eq!(body.v, 2, "FIXTURE: a composed v2 summary");
    assert_eq!(
        body.scope,
        Some(canonical(relationship_conversation)),
        "FIXTURE: the source scope"
    );
    assert_eq!(
        body.covers,
        vec![relationship_turn],
        "FIXTURE: the exact TURN cover"
    );
    assert_eq!(
        body.messages
            .iter()
            .map(|source| source.id)
            .collect::<Vec<_>>(),
        vec![relationship_message],
        "FIXTURE: the MESSAGE is a word source, not merely a child of a covered TURN"
    );
    assert_eq!(
        body.text, SUMMARY_TEXT,
        "FIXTURE: the composed source words"
    );
    assert!(
        vault
            .entity_text(&summary)
            .expect("FIXTURE: SUMMARY text")
            .contains(SUMMARY_TEXT),
        "FIXTURE: the SUMMARY owns authoritative text for born-with"
    );
    let open_claim = open_record_with_prompts(&vault, owner, member, [summary, open_prompt], now);
    let birth = vault
        .row_birth(&open_claim)
        .expect("FIXTURE: read the row birth")
        .expect("FIXTURE: the carried row has a birth");
    assert!(
        birth
            .made_by
            .inputs
            .iter()
            .any(|input| input.row == summary && input.role == MadeByInputRole::Prompt),
        "FIXTURE: the carried row names the SUMMARY as its born-with Prompt source"
    );
    let owner_text = vault
        .born_with_text(&open_claim, None)
        .expect("FIXTURE: the owner's born-with read");
    let owner_prompt = owner_text
        .get(&BornWithField::Prompt)
        .expect("FIXTURE: the birth provides a Prompt field");
    assert!(
        owner_prompt.contains(SUMMARY_TEXT) && owner_prompt.contains(OPEN_PROMPT_TEXT),
        "FIXTURE: the owner's born-with Prompt reads both SUMMARY and MESSAGE contents"
    );

    if check_read_lane {
        let reads = |id: EntityId| {
            vault
                .memory(member, EdgeActorClass::Human)
                .get_entity(&id.to_hex())
                .expect("FIXTURE: the member's own read lane")
                .value
                .is_some()
        };
        assert!(
            reads(open_claim),
            "FIXTURE: the member reads the open CLAIM"
        );
        // The member's own read lane reads no MESSAGE without a MessagesRead
        // grant, so it is no witness for the open prompt. The selector gate
        // is the relationship gate, which leaves a row that names no
        // relationship open: the window check below proves the open prompt
        // rides.
        assert!(
            !reads(relationship_message),
            "FIXTURE: the member's own read lane does not read the R MESSAGE"
        );
    }

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("FIXTURE: the window pack");
    for id in [
        open_claim,
        summary,
        relationship_turn,
        relationship_message,
        open_prompt,
    ] {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    let selected = filtered_window_doc_for_peer(
        &vault,
        &source,
        &key,
        scope,
        &selector,
        PeerMachine::Unknown,
    )
    .expect("FIXTURE: the selector export to another vault");
    assert!(
        selected
            .get_map("entities")
            .get(&open_claim.to_hex())
            .is_some(),
        "FIXTURE: the open CLAIM rides the selector window"
    );
    assert!(
        selected
            .get_map("entities")
            .get(&open_prompt.to_hex())
            .is_some(),
        "FIXTURE: the open prompt MESSAGE rides the selector window"
    );
    if check_read_lane {
        assert!(
            selected
                .get_map("entities")
                .get(&relationship_message.to_hex())
                .is_none(),
            "FIXTURE: round 2 withholds the R MESSAGE itself"
        );
        assert!(
            selected
                .get_map("entities")
                .get(&summary.to_hex())
                .is_none(),
            "FIXTURE: the window filter withholds the SUMMARY itself"
        );
    }

    let entry = selected
        .get_map("row_born_with")
        .get(&open_claim.to_hex())
        .expect("FIXTURE: the open CLAIM has a row_born_with entry");
    let ValueOrContainer::Value(LoroValue::Binary(bytes)) = entry else {
        panic!("FIXTURE: row_born_with stores binary MessagePack");
    };
    let born_with: BornWith =
        rmp_serde::from_slice(bytes.as_ref()).expect("FIXTURE: decode BornWith");
    let prompt = born_with
        .get(&BornWithField::Prompt)
        .cloned()
        .expect("FIXTURE: the carried open CLAIM still has a Prompt field");
    assert!(
        prompt.contains(OPEN_PROMPT_TEXT),
        "FIXTURE: readable prompt words still travel in the same row_born_with entry"
    );
    Export { prompt }
}

#[test]
fn a_born_with_prompt_carries_no_words_of_a_withheld_summary() {
    let export = export_through(
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
        true,
    );
    let travelled: Vec<&str> = [SUMMARY_TEXT, OPEN_PROMPT_TEXT]
        .into_iter()
        .filter(|text| export.prompt.contains(*text))
        .collect();
    assert!(
        !export.prompt.contains(SUMMARY_TEXT),
        "LEAK: the open CLAIM's row_born_with Prompt carries SUMMARY words to a member who does not read its R source; travelled={travelled:?}; prompt={:?}",
        export.prompt
    );
}

#[test]
fn a_co_owners_born_with_prompt_keeps_withheld_summary_words() {
    let export = export_through(
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
        false,
    );
    let travelled: Vec<&str> = [SUMMARY_TEXT, OPEN_PROMPT_TEXT]
        .into_iter()
        .filter(|text| export.prompt.contains(*text))
        .collect();
    assert!(
        export.prompt.contains(SUMMARY_TEXT),
        "OVER-REFUSAL: the open CLAIM's row_born_with Prompt withholds SUMMARY words from a co-Owner; travelled={travelled:?}; prompt={:?}",
        export.prompt
    );
}
