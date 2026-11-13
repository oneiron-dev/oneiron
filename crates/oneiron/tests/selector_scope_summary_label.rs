//! A selector discloses a scope SUMMARY and its copied reply only when its
//! member reads every word source (SELECTOR-SCOPE-SUMMARY-WORDS).
//!
//! A Member federation grant and a core:read policy row admit every record,
//! but the member has no grant on relationship R. The owner witnesses an R
//! MESSAGE. A scripted, network-free Dreamer run reads it under its own R
//! grant and mints a v2 scope SUMMARY with the MESSAGE in `messages`. The
//! owner lands a reply TURN copying that summary. An open MESSAGE, summary
//! and reply provide the positive control through the same member selector.
//!
//! FIXTURE assertions check source pins, read lanes, packing, the existing
//! R MESSAGE fence and the open control. The VISIBILITY / LEAK assertion is
//! last and reports which of SUMMARY and TURN the selector exported.
//!
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test selector_scope_summary_label
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::dreamer_consolidation::ScopeSummaryExecutor;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
    DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission,
    DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, ReplyAssertions};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{
    ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_RELATIONSHIP,
};
use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget, decode_scope_summary_body};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerAttemptExecution, DreamerAttemptExecutor, EdgeActorClass, EntityId, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, TimeRange, Vault, VaultConfig,
    WakeAttemptContext, WakePassDeadline, WriteActor,
};
use oneiron_authority::federation::scope_codec::read_preset;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const SHARED_VAULT_ID: u64 = 7;
const FIXTURE_TIMESTAMP: u64 = 1_780_000_000;

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

/// Keep the shipped Dreamer and landing-writer policy rows, adding only the
/// member's core:read row, as the model test's vault helper does.
fn permit_member_reads(vault: &Vault, member: EntityId) {
    let (id, mut manifest) = vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
        .into_iter()
        .find_map(|id| {
            let bytes = vault.get(&id).expect("policy read")?;
            let body: serde_json::Value = rmp_serde::from_slice(&bytes).expect("policy body");
            (body["pack_id"] == "oneiron-default-policy").then_some((id, body))
        })
        .expect("the shipped policy manifest");
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("scoped grants")
        .push(json!({
            "actor_ref": member.to_hex(),
            "effector": "core:read",
            "scope": read_preset(),
            "receipt_required": false,
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("policy encoding"),
    )
    .expect("the member's read policy");
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

fn land_reply(
    vault: &Vault,
    owner: EntityId,
    summary: EntityId,
    turn: EntityId,
    text: &str,
) -> EntityId {
    let reply = vault
        .land_header(
            &summary,
            &turn,
            WriteActor::new(owner, EdgeActorClass::Human),
            true,
        )
        .expect("land the summary reply")
        .record
        .expect("as_record lands a TURN");
    let body: serde_json::Value = rmp_serde::from_slice(
        &vault
            .get(&reply)
            .expect("reply read")
            .expect("reply exists"),
    )
    .expect("reply body");
    assert_eq!(
        body["txt"], text,
        "FIXTURE: the reply copies the summary's words"
    );
    assert_eq!(
        body["summary"],
        summary.to_hex(),
        "FIXTURE: the reply names this summary"
    );
    reply
}

#[test]
fn a_selector_window_carries_no_summary_words_its_member_does_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(FIXTURE_TIMESTAMP);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(dir.path(), config).expect("fixture vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner binding");
    let now = vault.now_recorded_at();
    let member = EntityId::now();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&json!({ "name": "member" })).expect("member body"),
        )
        .expect("member outside R");
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("relationship");
    permit_member_reads(&vault, member);
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

    let grant_scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        grant_scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now).expect("federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, grant_scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    let relationship_text = "We moved the date.";
    let open_text = "We kept the order.";
    let (relationship_conversation, relationship_turn, relationship_message) =
        witness_source(&vault, owner, Some(relationship), relationship_text, now);
    let (open_conversation, open_turn, open_message) =
        witness_source(&vault, owner, None, open_text, now);
    let relationship_summary = compose_summary(
        &vault,
        owner,
        relationship_conversation,
        relationship_text,
        now,
    );
    let open_summary = compose_summary(&vault, owner, open_conversation, open_text, now);
    for (summary, conversation, turn, message, text) in [
        (
            relationship_summary,
            relationship_conversation,
            relationship_turn,
            relationship_message,
            relationship_text,
        ),
        (
            open_summary,
            open_conversation,
            open_turn,
            open_message,
            open_text,
        ),
    ] {
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
            Some(canonical(conversation)),
            "FIXTURE: the source scope"
        );
        assert_eq!(body.covers, vec![turn], "FIXTURE: the exact TURN cover");
        assert_eq!(
            body.messages
                .iter()
                .map(|source| source.id)
                .collect::<Vec<_>>(),
            vec![message],
            "FIXTURE: the MESSAGE is a word source, not merely a child of a covered TURN"
        );
        assert_eq!(body.text, text, "FIXTURE: the composed source words");
    }
    let relationship_reply = land_reply(
        &vault,
        owner,
        relationship_summary,
        relationship_turn,
        relationship_text,
    );
    let open_reply = land_reply(&vault, owner, open_summary, open_turn, open_text);
    let reads = |id: EntityId| {
        vault
            .memory(member, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("member read")
            .value
            .is_some()
    };
    assert!(
        !reads(relationship_message),
        "FIXTURE: the member does not read the R MESSAGE"
    );
    assert!(
        reads(member),
        "FIXTURE: the member's read policy admits an open PERSON"
    );

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("window pack");
    for id in [
        relationship_turn,
        relationship_message,
        relationship_summary,
        relationship_reply,
        open_turn,
        open_message,
        open_summary,
        open_reply,
    ] {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    let selected = filtered_window_doc(&vault, &source, &key, grant_scope, &selector)
        .expect("the member's selector window");
    let mut carried = BTreeSet::new();
    selected.get_map("entities").for_each(|key, _| {
        carried.insert(EntityId::from_hex(key).expect("entity key"));
    });
    assert!(
        !carried.contains(&relationship_message),
        "FIXTURE: the round-2 label gate withholds the R MESSAGE from this selector"
    );
    assert!(
        [open_message, open_summary, open_reply]
            .iter()
            .all(|id| carried.contains(id)),
        "FIXTURE: the selector carries the open MESSAGE, SUMMARY and TURN"
    );
    let leaked: Vec<&str> = [
        (relationship_summary, "SUMMARY"),
        (relationship_reply, "TURN"),
    ]
    .into_iter()
    .filter(|(id, _)| carried.contains(id))
    .map(|(_, kind)| kind)
    .collect();
    // VISIBILITY: the regression assertion is last.
    assert!(
        leaked.is_empty(),
        "LEAK: the selector window carries the R-derived {leaked:?} to a member who does not read R"
    );
}
