//! Rows [RESTORED-UNJOINED-ROUND1-TESTS] and [RESTORED-UNJOINED-ROUND2-TESTS] (parent row
//! RESTORED-UNJOINED-STARTS-NO-WORK): the review-round fixes of #10257 hold an unjoined copy's
//! work on every path the rounds touched.
//! - A held tagging marker plans no work: the tagging reconciler's ready read answers none, and
//!   the row stays as it was. After the join the marker reads ready.
//! - The Dreamer micro kind reads held, and the owner's join wakes the proactivity watchers.
//! - A held Dreamer micro row's admission answers empty before the budget trap, so no budget
//!   check pauses it. After the join the same admission traps as on a vault no restore made.
//! - The connector-send drain plans no held send and reports no next-ready instant, and its pass
//!   commits no write. After the join the send is due and the drain runs it.
//! - A calendar write refuses before any outbox row stages or the provider is called. After the
//!   join the same write goes through.
//!
//! On the red head (main with the fix call sites reverted) each test fails at its named assert:
//! the tagging none assert, the proactivity wake assert, the admission empty assert, the readiness
//! none and no-wake asserts, and the calendar refusal assert.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_unjoined_hold_paths`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::calendar::caldav::CALDAV_PROVIDER_KEY;
use oneiron::calendar::connectors::door::{
    self, CalendarConnectorOperation, CalendarConnectorRequest,
};
use oneiron::calendar::connectors::{
    CalendarConnectorError, CalendarConnectorSeatConfig, CalendarConnectorSeatState,
    CalendarRemoteTransport, RemoteSyncBatch, RemoteWriteReceipt, RemoteWriteRequest,
    calendar_write_outbox_rows, write_calendar_event,
};
use oneiron::calendar::parse_ics_feed;
use oneiron::connector_key::{
    CalendarPeriod, ConnectorKeyRecord, EffectorBudget, EffectorBudgetOnExhaust,
    EffectorBudgetWindow,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier, DreamerClaimEvidenceState,
    DreamerConsolidationAdmissionOutcome, DreamerRunnerStore, DreamerTournamentAdmission,
    DreamerTournamentBudgetAxes, DreamerTournamentClaim, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt,
};
use oneiron::embed::EmbedderLocality;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::outbound::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyGrantMapEntry, PolicyGrantValue, PolicyManifestPut,
    PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::tagging::{TAGGING_MARKER_KIND, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::{
    DreamerConsolidationScope, EdgeActorClass, EntityId, ModelId, OutboundDraftInput, TimeRange,
    Vault, VaultConfig,
};
use rmpv::Value;

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// and the vault's root held as its owner key. It never restored, so it is joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        vault_id,
    }
}

/// A copy restored beside a host from its checkpoint image, with its own keystore and owner
/// proof: born of a restore, and no machine of the vault yet. The vault rides in an `Arc` for
/// the tagging reconciler, which takes one; every other use derefs.
struct Copy {
    vault: Arc<Vault>,
    proof: AuthenticatedOwner,
}

/// The copy of `host` restored from an image taken now into an empty place under `backups`.
fn restored_copy(host: &Host, backups: &Path) -> Copy {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption)
        .expect("FIXTURE: the copy's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("FIXTURE: the copy's fold")
            .machine(request.machine)
            .is_none(),
        "FIXTURE: the copy is no machine of the vault yet"
    );
    Copy {
        vault: Arc::new(vault),
        proof,
    }
}

/// The owner's word that no other machine is left joins `copy` (`Vault::join_restored_install`),
/// with the vault's root held on it as the owner's key.
fn owner_joins(host: &Host, copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

/// A transport that counts the sends that reach it.
#[derive(Default)]
struct CountingSink {
    calls: usize,
}

impl OutboundExecutionSink for CountingSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        OutboundExecutionOutcome::delivered_to_channel("provider:message:one")
    }
}

fn row(vault: &Vault, id: AttemptId) -> String {
    let record = AttemptQueue::new(vault)
        .get(id)
        .expect("the row reads")
        .expect("the row is kept");
    format!("{record:?}")
}

/// The tagging checkpoint the copy's witness marks under: 16 lowercase hex digits, as the marker
/// config checks.
const TAG_CHECKPOINT: &str = "0123456789abcdef";

/// A tagger that reads nothing: the ready read this test drives never calls it.
struct StubTagger(ModelId);

impl ExtractionEncoder for StubTagger {
    fn model_id(&self) -> &ModelId {
        &self.0
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, _input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(EncoderOutput {
                spans: Vec::new(),
                links: Vec::new(),
                vad: None,
                context_links: Vec::new(),
                speaker_links: Vec::new(),
                mood_parts: Vec::new(),
                relations: None,
                stack_sha16: None,
            }),
        }
    }
}

/// The tagging plan plans nothing for a held kind: the reconciler's ready read answers none on
/// the unjoined copy, which the round-1 plan hold proves.
#[test]
fn an_unjoined_copy_plans_no_tagging_work_for_its_held_marker() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    // Tagging arms at open, which the restore does not carry: arm the copy itself, under the
    // same checkpoint its witness then marks with.
    let armed = copy
        .vault
        .arm_tagging_once(
            TaggingMarkerConfig::new(TAG_CHECKPOINT)
                .expect("FIXTURE: the checkpoint")
                .with_mode(TaggingMode::Shadow),
        )
        .expect("FIXTURE: the copy arms tagging");
    assert!(
        armed,
        "FIXTURE: the copy opens unarmed, so this call arms it"
    );
    let owner = copy
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the copy");
    let turn = EntityId::now();
    copy.vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "the tagging marker row".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .expect("the witness lands");
    let marker = copy
        .vault
        .tagging_marker(&turn)
        .expect("the marker reads")
        .expect("a marker is pending");
    assert_eq!(
        marker.kind, TAGGING_MARKER_KIND,
        "the witness owes a tagging marker"
    );
    let before = row(copy.vault.as_ref(), marker.id);
    let reconciler = TaggingReconciler::new(
        Arc::clone(&copy.vault),
        Arc::new(StubTagger(
            "fixture/stub-tagger@v1".parse().expect("FIXTURE: model id"),
        )),
    )
    .expect("the reconciler opens");
    assert_eq!(
        reconciler.ready_class().expect("ready reads"),
        None,
        "a held tagging marker plans nothing on the unjoined copy"
    );
    assert_eq!(
        row(copy.vault.as_ref(), marker.id),
        before,
        "the peek leaves the row as it was"
    );

    owner_joins(&host, &copy);
    assert!(
        reconciler.ready_class().expect("ready reads").is_some(),
        "after the join the marker reads ready"
    );
}

/// The Dreamer micro kind reads held on the copy, and the owner's join wakes the proactivity
/// watchers that armed nothing for it: the round-2 kind read and join wake.
#[test]
fn an_unjoined_copy_holds_the_dreamer_kind_and_its_join_wakes_proactivity() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let kind = DreamerConsolidationScope::Micro.attempt_kind();
    assert_eq!(
        AttemptQueue::new(copy.vault.as_ref())
            .kind_held_while_unjoined(kind)
            .expect("the hold reads"),
        true,
        "the Dreamer micro kind is held on the unjoined copy"
    );
    assert_eq!(
        AttemptQueue::new(&host.vault)
            .kind_held_while_unjoined(kind)
            .expect("the hold reads"),
        false,
        "a vault no restore made holds no kind"
    );
    let mut changes = copy.vault.subscribe_proactivity_changes();
    assert!(
        !changes.has_changed().expect("vault still open"),
        "no wake before the join"
    );

    owner_joins(&host, &copy);
    assert!(
        changes.has_changed().expect("vault still open"),
        "the join wakes proactivity watchers"
    );
    assert_eq!(
        AttemptQueue::new(copy.vault.as_ref())
            .kind_held_while_unjoined(kind)
            .expect("the hold reads"),
        false,
        "after the join the kind is no longer held"
    );
}

/// One ready Dreamer micro consolidation row on `vault`, and its row id.
fn enqueue_micro(vault: &Vault) -> AttemptId {
    let outcome = DreamerRunnerStore::new(vault)
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: Value::from(format!(
                "input:{}",
                DreamerConsolidationScope::Micro.as_str()
            )),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: vault.now_recorded_at(),
        })
        .expect("FIXTURE: the micro row enqueues");
    match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        _ => panic!("FIXTURE: the micro row enqueues"),
    }
}

/// A tournament micro admission whose grant reserve (12) tops its fresh budget (10), so without
/// the hold check the budget trap pauses the row.
fn tournament_micro_input(vault: &Vault) -> AdmitDreamerConsolidationAttempt {
    AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: 77,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::Tournament(DreamerTournamentAdmission {
            claim: DreamerTournamentClaim {
                predicate: "pattern.sleep".to_owned(),
                sample_count: 3,
                incumbent_confidence: 0.4,
                evidence_state: DreamerClaimEvidenceState::Uncontested,
            },
            uncertainty_tau: 0.7,
            budget_axes: DreamerTournamentBudgetAxes {
                fanout_m: 2,
                depth_k: 3,
                reserve_units_per_step: 2,
            },
        }),
        admission: AdmitDreamerAttempt {
            lease_owner: "tournament-worker".to_owned(),
            now: vault.now_recorded_at(),
            budget_id: "wake:micro".to_owned(),
            budget_total_units: 10,
            // The tournament grant overwrites this before validation, so zero here is sound:
            // a gate-input typo would fail at admission, not at an outcome assert.
            reserve_units: 0,
            started_milestone: None,
        },
    }
}

/// Dreamer admission of a held kind answers empty before the budget trap: the round-1 admission
/// hold, which keeps the row ready and unpaused for the join.
#[test]
fn an_unjoined_copy_admits_no_held_dreamer_row_and_pauses_none() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let id = enqueue_micro(copy.vault.as_ref());
    let before = row(copy.vault.as_ref(), id);
    let outcome = DreamerRunnerStore::new(copy.vault.as_ref())
        .admit_next_consolidation(tournament_micro_input(copy.vault.as_ref()))
        .expect("admission answers");
    assert!(
        matches!(
            outcome,
            DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Empty)
        ),
        "held micro admission answers empty on the unjoined copy, got {outcome:?}"
    );
    assert_eq!(
        row(copy.vault.as_ref(), id),
        before,
        "the held row stays ready and unpaused: no lease, no pause"
    );

    owner_joins(&host, &copy);
    let joined = DreamerRunnerStore::new(copy.vault.as_ref())
        .admit_next_consolidation(tournament_micro_input(copy.vault.as_ref()))
        .expect("admission answers");
    assert!(
        matches!(
            joined,
            DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(_)
        ),
        "after the join the tournament admission traps as on a vault no restore made, \
         got {joined:?}"
    );
    let trap_attempt = match &joined {
        DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(trap) => trap.attempt_id,
        _ => panic!("after the join the admission traps"),
    };
    assert_eq!(trap_attempt, id, "the trap names the held row");
    assert_eq!(
        AttemptQueue::new(copy.vault.as_ref())
            .get(id)
            .expect("the row reads")
            .expect("the row is kept")
            .state,
        AttemptState::Paused,
        "after the join the trap pauses the row"
    );

    enqueue_micro(&host.vault);
    let host_outcome = DreamerRunnerStore::new(&host.vault)
        .admit_next_consolidation(tournament_micro_input(&host.vault))
        .expect("admission answers");
    assert!(
        matches!(
            host_outcome,
            DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(_)
        ),
        "a vault no restore made traps the same input, got {host_outcome:?}"
    );
}

/// A provider channel no built-in pack names: a seeded vault holds its built-in email packs only
/// as candidates, and a channel one of them serves sends only through an installed, checked pack.
const SEND_CHANNEL: &str = "email_resend";

/// The owner grants the agent `actor` sends on [`SEND_CHANNEL`]: a ceiling and a scoped grant
/// added to the default manifest, and the channel's sends key registered, so the seeded gate
/// holds the agent's send.
fn grant_agent_sends(host: &Host, proof: &AuthenticatedOwner, actor: EntityId) {
    let view = policy_manifests_as_owner(
        &host.vault,
        proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("FIXTURE: the host policy manifests read");
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .expect("FIXTURE: the default policy manifest");
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".to_owned(),
        actor_ref: Some(actor.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["effect".to_owned()]));
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(actor.to_hex()),
        effector: "external:send".to_owned(),
        scope,
        selectors: Some(PolicyGrantValue::Map(vec![PolicyGrantMapEntry {
            key: PolicyGrantValue::String("channel".to_owned()),
            value: PolicyGrantValue::String(SEND_CHANNEL.to_owned()),
        }])),
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &host.vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )
    .expect("FIXTURE: the owner grants the agent sends on the channel");
    host.vault
        .register_connector_key(
            &EntityId::from_bytes([0x4E; 16]).expect("FIXTURE: the sends key id"),
            ConnectorKeyRecord::active(
                SEND_CHANNEL,
                None,
                vec![EffectorBudget::sends(
                    5,
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                )],
                1_000,
            ),
        )
        .expect("FIXTURE: the host registers the channel's sends key");
}

/// One connector send scheduled on `host` before the image, and its row id.
fn schedule_send_on_host(host: &Host) -> AttemptId {
    let owner = host
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the host owner");
    let proof = host
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the host owner proof");
    let actor = EntityId::from_bytes([0x71; 16]).expect("FIXTURE: the send actor's id");
    host.vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"connector-send actor",
        )
        .expect("FIXTURE: the send actor");
    grant_agent_sends(host, &proof, actor);
    let receipt = host
        .vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(
            &OutboundDraftInput {
                verb: "send".to_owned(),
                channel: SEND_CHANNEL.to_owned(),
                target: "transport:shared-inbox".to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some("r21:email-resend:party-yuki".to_owned()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "hold-paths:r2-1".to_owned(),
                job_ref: None,
                occurred_at: Some(100),
                mention: None,
            },
            "counterparty:hold-paths-r2-1",
        )
        .expect("FIXTURE: the send schedules");
    assert_eq!(
        receipt.outcome, "held",
        "FIXTURE: the schedule queues the send: {receipt:?}"
    );
    assert!(
        !receipt.deduped,
        "FIXTURE: the schedule is not a dedupe: {receipt:?}"
    );
    let tasks = host
        .vault
        .connector_send_tasks()
        .expect("FIXTURE: the send tasks read");
    assert_eq!(
        tasks.len(),
        1,
        "FIXTURE: the host holds one unsettled send task"
    );
    AttemptQueue::new(&host.vault)
        .list()
        .expect("FIXTURE: the rows list")
        .iter()
        .find(|record| record.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .expect("FIXTURE: the send's row")
        .id
}

/// The connector-send drain plans no held send and reports no next-ready instant: the round-2
/// drain hold, whose pass commits no write and wakes no one.
#[test]
fn an_unjoined_copy_runs_no_connector_send_until_its_join() {
    let host = rooted_host();
    let send = schedule_send_on_host(&host);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let rows = AttemptQueue::new(copy.vault.as_ref())
        .list()
        .expect("the rows list");
    assert!(
        rows.iter()
            .any(|record| record.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND
                && record.state == AttemptState::Queued),
        "the scheduled send restores with the image"
    );
    let before = row(copy.vault.as_ref(), send);
    assert_eq!(
        copy.vault
            .next_connector_send_ready_at()
            .expect("readiness reads"),
        None,
        "no next-ready instant while the queue holds every send"
    );
    let mut woken = AttemptQueue::new(copy.vault.as_ref()).subscribe();
    let mut sink = CountingSink::default();
    let executed = copy
        .vault
        .run_connector_task_executor(&mut sink, copy.vault.now_recorded_at())
        .expect("the executor pass answers");
    assert_eq!(executed, 0, "the drain executes no held send");
    assert_eq!(sink.calls, 0, "no send reaches the transport");
    assert_eq!(
        row(copy.vault.as_ref(), send),
        before,
        "the held row stays ready as it was"
    );
    assert!(
        woken.try_recv().is_err(),
        "the pass commits no write: no attempt-observer wake"
    );

    owner_joins(&host, &copy);
    assert!(
        copy.vault
            .next_connector_send_ready_at()
            .expect("readiness reads")
            .is_some(),
        "after the join the send is due again"
    );
    let mut sink = CountingSink::default();
    let executed = copy
        .vault
        .run_connector_task_executor(&mut sink, copy.vault.now_recorded_at())
        .expect("the executor answers");
    assert_eq!(executed, 1, "after the join the drain executes the send");
    assert_eq!(sink.calls, 1, "the send reaches the transport");
}

/// The refusal's words that name the copy's state (`machine_answers::RESTORED_NOT_JOINED`).
const NOT_JOINED: &str = "has not joined the vault";
/// Fixed run instants.
const T0: u64 = 1_800_000_000;
const T1: u64 = 1_800_000_100;
/// A fixed, in-range occurrence window for written EVENT fixtures.
const WRITE_START: u64 = 1_786_024_800;
const WRITE_END: u64 = 1_786_028_400;
/// The CalDAV discovery URL every seat here is installed with.
const SEAT_ENDPOINT: &str = "https://calendar.example.test/";

/// The CalDAV seat config this file reuses.
fn caldav_config() -> CalendarConnectorSeatConfig {
    CalendarConnectorSeatConfig {
        seat_ref: "seat:caldav:work".to_owned(),
        secret_ref: "caldav:work".to_owned(),
        system: "caldav-work".to_owned(),
        calendar_ref: "work".to_owned(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    }
}

/// The CalDAV seat, cursor-free and live.
fn caldav_seat() -> CalendarConnectorSeatState {
    CalendarConnectorSeatState::new(caldav_config())
}

/// Mints one local EVENT row directly, the state a locally originated write starts from: entity
/// plus no calendar claims yet.
fn mint_local_event(vault: &Vault, seed: u8, name: &str) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("FIXTURE: the event's id");
    let mut data = Vec::new();
    rmpv::encode::write_value(
        &mut data,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: WRITE_START,
                end: WRITE_END,
            },
            T0,
            &data,
        )
        .expect("put local event");
    id
}

/// The vault's owner, authenticated: the seats here are the owner's.
fn seat_owner(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    let id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    (id, owner)
}

/// The owner installs `seat` as the `calendar.connector_seat` setting, one item per seat ref. The
/// same setup again applies and writes nothing.
fn install_seat(vault: &Vault, owner: &AuthenticatedOwner, seat: &CalendarConnectorSeatState) {
    let setup = serde_json::json!({ "config": seat.config, "endpoint": SEAT_ENDPOINT });
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(owner),
            SetSetting {
                item: Some(seat.config.seat_ref.clone()),
                ..SetSetting::vault_value("calendar.connector_seat", setup)
            },
        )
        .expect("the owner installs the seat");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's install applies: {outcome:?}"
    );
}

/// The calendar operation on `seat` on the copy: its owner binds to the exact installed row the
/// image carried. No setting is written: the seat key is shared, so the copy installs nothing.
fn operation_on_copy(copy: &Copy, seat: &CalendarConnectorSeatState) -> CalendarConnectorOperation {
    let id = copy
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let row = door::get(
        &copy.vault.memory(id, EdgeActorClass::Human),
        &copy.proof,
        &CalendarConnectorRequest {
            seat_ref: seat.config.seat_ref.clone(),
        },
    )
    .expect("FIXTURE: the installed seat reads")
    .expect("FIXTURE: the seat is installed");
    CalendarConnectorOperation::new(copy.vault.as_ref(), copy.proof.clone(), row)
        .expect("FIXTURE: the operation on the installed seat")
}

/// The receipt one honest wire returns for a conditional put: every field read back through the
/// ICS parse, so the echo the pull side later sees hashes identically by construction.
fn parsed_receipt(
    calendar_href: &str,
    etag: Option<&str>,
    request: &RemoteWriteRequest,
) -> RemoteWriteReceipt {
    let feed = parse_ics_feed(&request.ics).expect("written ics parses");
    let event = feed
        .events
        .iter()
        .find(|event| event.uid == request.uid)
        .or_else(|| feed.events.first())
        .expect("written ics carries a VEVENT");
    RemoteWriteReceipt {
        href: request
            .href
            .clone()
            .unwrap_or_else(|| format!("{calendar_href}{uid}.ics", uid = event.uid)),
        etag: etag.map(str::to_owned),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
    }
}

/// A provider that counts the upserts that reach it, and answers each honestly.
struct CountingTransport {
    upserts: Mutex<Vec<RemoteWriteRequest>>,
}

impl CalendarRemoteTransport for CountingTransport {
    fn provider_key(&self) -> &'static str {
        CALDAV_PROVIDER_KEY
    }

    fn pull(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        Ok(RemoteSyncBatch {
            next_cursor: None,
            changes: Vec::new(),
        })
    }

    fn upsert(
        &self,
        _secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.upserts.lock().expect("upserts").push(request.clone());
        Ok(parsed_receipt(
            &format!("/{calendar_ref}/"),
            Some("test-etag-1"),
            request,
        ))
    }

    fn delete(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        href: &str,
        _expected_etag: Option<&str>,
        uid: &str,
        sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        Ok(RemoteWriteReceipt {
            href: href.to_owned(),
            etag: None,
            uid: uid.to_owned(),
            sequence,
            content_hash: [0; 32],
        })
    }
}

/// `write_calendar_event` refuses on an unjoined copy before staging or calling: the round-1
/// calendar refusal, which keeps the outbox empty and the provider silent.
#[test]
fn an_unjoined_copy_refuses_a_calendar_write_before_any_provider_call() {
    let host = rooted_host();
    // The seat installs on the host before the image: its setting is shared, so the copy cannot
    // install it, and reads the installed row the image carried instead.
    let (_, host_proof) = seat_owner(&host.vault);
    let seat = caldav_seat();
    install_seat(&host.vault, &host_proof, &seat);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let event = mint_local_event(copy.vault.as_ref(), 0x51, "the copied write");
    let transport = CountingTransport {
        upserts: Mutex::new(Vec::new()),
    };
    let err = write_calendar_event(
        copy.vault.as_ref(),
        &operation_on_copy(&copy, &seat),
        &transport,
        event,
        T1,
    )
    .expect_err("the unjoined copy refuses the calendar write");
    assert!(
        err.to_string().contains(NOT_JOINED),
        "the refusal names the copy's state, got {err}"
    );
    assert!(
        calendar_write_outbox_rows(copy.vault.as_ref())
            .expect("outbox reads")
            .is_empty(),
        "no outbox row is staged"
    );
    assert!(
        transport.upserts.lock().expect("upserts").is_empty(),
        "the provider upsert is never called"
    );

    owner_joins(&host, &copy);
    let receipt = write_calendar_event(
        copy.vault.as_ref(),
        &operation_on_copy(&copy, &seat),
        &transport,
        event,
        T1,
    )
    .expect("the joined copy writes");
    assert!(
        receipt.uid.ends_with("@calendar.invalid"),
        "the joined copy's write mints the engine's uid shape"
    );
    assert_eq!(
        transport.upserts.lock().expect("upserts").len(),
        1,
        "the joined copy PUTs once"
    );
    assert_eq!(
        calendar_write_outbox_rows(copy.vault.as_ref())
            .expect("outbox reads")
            .len(),
        1,
        "one outbox row stages"
    );
}
