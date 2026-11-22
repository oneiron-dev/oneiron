//! Row RESTORED-UNJOINED-STARTS-NO-WORK, part 3 (Setting DESIGN pass 15e "Joined"; ruling
//! RESTORED-UNJOINED-OWNER-DIRECT-WORK = A): outbound work in a rooted vault's restored copy
//! waits for the owner to join it. The held rows are not advanced before the join.
//!
//! - Recovery takes no lease and sends nothing; its first sweep after the join retries the intent.
//! - The connector resume and expiry sweep leave overdue held calls alone before the join.
//! - The e-sign worker idles, its principal sees the join answer, and each can dispatch after join.
//! - Remote polls are not listed, and the trusted notice sender's claim stamps no clock. The
//!   existing reply-kind claim hold still offers no job to its worker.
//! - Owed MCP session ends are not listed, and a notice lease the image kept is refused before
//!   its lease check and consent preflight (review of #10339, round 1).
//!
//! On base 47b5f60c15c7, recovery errors, the connector flows expire the call, and the e-sign
//! doors return a nonempty view and no join refusal, respectively. The poll list includes the
//! due task, and the session list the owed end. The trusted notice sender's claim writes the clock
//! floor, and the kept lease's dispatch fails the notice. The reply-kind claim check is already green on that base.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_unjoined_sends`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::blob_artifact::esign::{
    DocumentKind, ESIGN_NOTICE_ATTEMPT_KIND, EsignCreateRequest, EsignDispatchRequest,
    EsignDocument, EsignField, EsignItem, EsignNoticeGroup, EsignNoticesDispatchRequest,
    EsignNoticesDispatchView, EsignRecipient, EsignUnattendedNotices, FieldGeometry, FieldMeta,
    RecipientRole,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::connector_key::events::ConnectorEvent;
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCallRoute, ConnectorCatalogEntry, ConnectorConsentTarget,
    ConnectorKeySpec, ConnectorToolConsent, ConnectorToolConsentRow, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::tool_scope::DataClass;
use oneiron::counterparty_contact::{
    TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND, TrustedContactNotice, TrustedContactNoticeAuthorization,
};
use oneiron::outbound::{
    ConnectorReplyJob, ConnectorReplyJobResult, ConnectorReplyStage,
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use oneiron::outbound_consent::tool_call::{
    ConnectorToolCallPreparation, MutationIntent, ToolCallDescriptor,
};
use oneiron::outbound_consent::{
    ConnectorCallHost, ConnectorCallOutcome, OutboundBindingAuthority, OutboundResultSender,
    OutboundTransportResult, RawOutboundResult, ScopedMcpCallContext, UntrustedToolResult,
    recover_authorized_outbound_intents,
};
use oneiron::outbound_intent_ledger::{
    FrozenOutboundCall, IntentRecoveryReport, IntentState, OutboundSendOutcome,
    OutboundToolDescriptor, intent_ledger_records,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::coach::last_committed_txn_id;
use oneiron::test_doors::outbound_wait_setting_keys::{
    held_connector_call_settled, put_held_connector_call,
};
use oneiron::test_doors::schedule::{
    REMOTE_TASK_POLL, defer_pollable_remote_task, due_at, owe_remote_task_session_end,
    remote_task_polls_due_now,
};
use oneiron::test_support::test_host_issuer;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The refusal's words that name the copy's state (`machine_answers::RESTORED_NOT_JOINED`).
const NOT_JOINED: &str = "has not joined the vault";
const SENDER_SEED: u8 = 0x61;

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// the vault's root held as its owner key, and the sending agent. It never restored, so it is
/// joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
    clock: Arc<ManualClock>,
}

fn sender() -> EntityId {
    EntityId::from_bytes([SENDER_SEED; 16]).expect("FIXTURE: the sender's id")
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(1_700_000_000);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    vault
        .put_entity(
            &sender(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"restored send sender",
        )
        .expect("FIXTURE: the sending agent");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        vault_id,
        clock,
    }
}

/// A copy restored beside a host from its checkpoint image, with its own keystore and owner
/// proof: born of a restore, and no machine of the vault yet.
struct Copy {
    vault: Vault,
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
    let mut config = VaultConfig::device();
    config.store_clock = host.clock.bundle();
    let (vault, _) =
        Vault::restore_checkpoint_beside(&image, &key, &backups.join("copy"), config, &origin, 200)
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
    Copy { vault, proof }
}

/// The owner's word that no other machine is left joins `copy` (`Vault::join_restored_install`),
/// with the vault's root held on it as the owner's key.
fn owner_joins(host: &Host, copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

fn row(vault: &Vault, id: AttemptId) -> String {
    let record = AttemptQueue::new(vault)
        .get(id)
        .expect("the row reads")
        .expect("the row is kept");
    format!("{record:?}")
}

struct RecoverySender {
    outcome: OutboundSendOutcome,
    calls: usize,
}

impl OutboundResultSender for RecoverySender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.calls += 1;
        OutboundTransportResult {
            outcome: self.outcome,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

fn stage_scoped_pending(vault: &Vault, authority: &OutboundBindingAuthority, now: u64) {
    const SERVER: &str = "restored_recovery";
    const TOOL: &str = "record";
    const REVISION: &str = "2026-09-01";
    const ENDPOINT: &str = "https://connector.invalid/mcp";

    let schema = serde_json::json!({"type": "object"});
    let manifest = [SlateToolManifest {
        name: TOOL.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(schema),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: true,
        price: None,
    }];
    let draft = serde_json::to_string(&draft_connector_slate(&manifest)).unwrap();
    let slate_id = vault.store_connector_slate(&manifest, &draft).unwrap();
    let mut spec = ConnectorKeySpec::new(SERVER);
    spec.slate_ref = Some(slate_id);
    spec.protocol_revision = Some(REVISION.to_owned());
    let (catalog, _) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: SERVER.to_owned(),
                connector: SERVER.to_owned(),
                summary: "Restored recovery fixture".to_owned(),
                verbs: vec![TOOL.to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: now,
            },
            spec,
            now,
        )
        .unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let slate = vault.connector_slate(slate_id).unwrap().unwrap();
    vault
        .stamp_connector_slate(&proof, slate_id, slate.revision(), &BTreeMap::new(), None)
        .unwrap();
    vault
        .attest_connector_key(&proof, &catalog, REVISION, now)
        .unwrap();
    let grants = vault
        .consent_connector_tools(
            &proof,
            &ConnectorToolConsent {
                connector: SERVER.to_owned(),
                target: ConnectorConsentTarget::Owner,
                endpoint: ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: TOOL.to_owned(),
                    data_class_ceiling: DataClass::Personal,
                    headers: false,
                }],
            },
        )
        .unwrap();
    let grant_id = EntityId::from_hex(&grants[0].grant_id).unwrap();
    let grant = vault
        .get_standing_outbound_grant(&grant_id)
        .unwrap()
        .unwrap();
    let key_id = EntityId::from_hex(&grants[0].key_id).unwrap();
    let key = vault.get_connector_key(&key_id).unwrap().unwrap();
    let approved = &key.retained_manifest.as_ref().unwrap().tools()[0].input_schema;
    let preparation = vault
        .prepare_connector_tool_call(
            &key_id,
            ScopedMcpCallContext {
                server: SERVER.to_owned(),
                tool: TOOL.to_owned(),
                payload_data_class: DataClass::Personal,
                resolved_endpoint: ENDPOINT.to_owned(),
            },
            ToolCallDescriptor {
                schema: approved,
                destructive_hint: false,
                replay: OutboundToolDescriptor {
                    read_only_hint: Some(false),
                    idempotency_supported_hint: Some(true),
                },
            },
            &serde_json::json!({}),
            MutationIntent::default(),
        )
        .unwrap();
    let ConnectorToolCallPreparation::Ready(prepared) = preparation else {
        panic!("FIXTURE: the consented and stamped tool is ready");
    };
    let mut sender = RecoverySender {
        outcome: OutboundSendOutcome::Ambiguous,
        calls: 0,
    };
    let admitted = prepared
        .execute(
            vault,
            authority,
            grant_id,
            &grant,
            &grant.principal_ref,
            AttemptId::from_bytes(&[0x63; 16]).unwrap(),
            1,
            now * 1_000,
            &mut sender,
        )
        .expect("FIXTURE: admit an ambiguously sent scoped intent");
    assert_eq!(sender.calls, 1, "FIXTURE: the first send was ambiguous");
    assert_eq!(admitted.dispatch.unwrap().state, Some(IntentState::Pending));
}

/// The scoped recovery sweep takes no lease and drives no admitted intent until the join (Q2).
#[test]
fn an_unjoined_copy_sweeps_no_scoped_intent() {
    let host = rooted_host();
    let now = host.vault.now_recorded_at();
    // Reuse the same session-scoped authority on the copy to isolate the join hold from
    // device-key rotation: the binding under test remains valid across the restore.
    let authority = OutboundBindingAuthority::from_secret([0x65; 32]);
    stage_scoped_pending(&host.vault, &authority, now);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let before = intent_ledger_records(&copy.vault).unwrap().records;
    assert_eq!(before.len(), 1, "FIXTURE: the admitted intent was restored");
    assert_eq!(before[0].state, IntentState::Pending);
    let mut sender = RecoverySender {
        outcome: OutboundSendOutcome::Acked,
        calls: 0,
    };
    let committed = last_committed_txn_id(&copy.vault);

    let held = recover_authorized_outbound_intents(
        &copy.vault,
        &authority,
        &mut sender,
        (now + 1) * 1_000,
        60_000,
    )
    .expect("the unjoined sweep returns an empty report, not a send refusal");
    assert_eq!(held.ledger, IntentRecoveryReport::default());
    assert!(held.stale_manifest_refusals.is_empty());
    assert!(held.slate_asks.is_empty());
    assert_eq!(held.effectful_sends, 0);
    assert_eq!(held.authorization_rejections, 0);
    assert_eq!(held.scrubbable_result_fields, 0);
    assert_eq!(held.scrubbed_result_fields, 0);
    assert_eq!(sender.calls, 0, "the sender was not called");
    assert_eq!(
        last_committed_txn_id(&copy.vault),
        committed,
        "no lease write"
    );
    assert_eq!(intent_ledger_records(&copy.vault).unwrap().records, before);

    owner_joins(&host, &copy);
    let sent = recover_authorized_outbound_intents(
        &copy.vault,
        &authority,
        &mut sender,
        (now + 1) * 1_000,
        60_000,
    )
    .unwrap();
    assert_eq!(sent.ledger.resent, 1);
    assert_eq!(sent.ledger.completed, 1);
    assert_eq!(sender.calls, 1);
}

impl ConnectorCallHost for RecoverySender {
    fn tool_endpoint(&self, _route: &ConnectorCallRoute) -> Option<String> {
        None
    }

    fn take_result(&mut self) -> Option<UntrustedToolResult> {
        None
    }
}

/// Resuming a held connector call does not expire it or send on a copy before join (Q3b).
#[test]
fn an_unjoined_copy_keeps_a_connector_resume_held() {
    let host = rooted_host();
    let call_ref = put_held_connector_call(&host.vault, 1).unwrap();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let settled = || held_connector_call_settled(&copy.vault, &call_ref).unwrap();
    assert_eq!(
        settled(),
        Some(false),
        "FIXTURE: the held call was restored"
    );
    let committed = last_committed_txn_id(&copy.vault);
    let mut transport = RecoverySender {
        outcome: OutboundSendOutcome::Acked,
        calls: 0,
    };

    let (outcome, rows) = copy
        .vault
        .resume_connector_call_listing(&call_ref, &mut transport)
        .unwrap();
    assert_eq!(
        outcome,
        ConnectorCallOutcome::Held {
            call_ref,
            decision_ref: None,
            reasons: vec!["restored_not_joined".to_owned()],
            approval_digest: None,
        },
        "the restored call remains held"
    );
    assert_eq!(
        rows,
        Some(Vec::new()),
        "the held answer reports the call's own rows"
    );
    assert_eq!(transport.calls, 0);
    assert_eq!(settled(), Some(false));
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let (outcome, _) = copy
        .vault
        .resume_connector_call_listing(&call_ref, &mut transport)
        .unwrap();
    assert!(matches!(outcome, ConnectorCallOutcome::Refused { .. }));
    assert_eq!(
        settled(),
        Some(true),
        "the resumed call runs its overdue expiry"
    );
    assert_eq!(
        transport.calls, 0,
        "an expired call must not send after join either"
    );
}

/// The bulk connector expiry sweep leaves an overdue hold alone until the copy joins (Q3b).
#[test]
fn an_unjoined_copy_expires_no_connector_call() {
    let host = rooted_host();
    let call_ref = put_held_connector_call(&host.vault, 1).unwrap();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let settled = || held_connector_call_settled(&copy.vault, &call_ref).unwrap();
    assert_eq!(settled(), Some(false));
    let now_ms = host.vault.now_recorded_at() * 1_000;
    let committed = last_committed_txn_id(&copy.vault);

    assert_eq!(copy.vault.expire_connector_calls(now_ms).unwrap(), 0);
    assert_eq!(settled(), Some(false));
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    assert_eq!(copy.vault.expire_connector_calls(now_ms).unwrap(), 1);
    assert_eq!(settled(), Some(true));
}

fn stage_esign_notice(host: &Host) -> (EsignNoticeGroup, AttemptId) {
    let vault = &host.vault;
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let now = vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let expires = now + 86_400;
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "restored-notice-test", "pack_version": "v1",
        "min_engine_version": "0.0.0",
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{
            "actor_class": "human", "actor_ref": owner.to_hex(), "ceiling": "auto"
        }],
        "scoped_grants": [
            {"actor_ref": owner.to_hex(), "effector": "external:send_for_signature",
              "scope": oneiron::test_support::effect_preset(), "selectors": {"channel": "esign"}},
            {"actor_ref": owner.to_hex(), "effector": "external:send",
              "scope": oneiron::test_support::effect_preset(), "selectors": {"channel": "email"}},
        ],
    });
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy).unwrap(),
    )
    .unwrap();
    let identity = ChannelIdentity::requested(
        "email",
        "sender@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(owner),
        now,
    )
    .step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        now,
    )
    .unwrap()
    .step(ChannelIdentityStep::Fulfill, now)
    .unwrap();
    vault
        .create_channel_identity(&EntityId::now(), &identity)
        .unwrap();
    let document = EntityId::now();
    vault
        .put_blob_artifact(
            &document,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            at,
            now,
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &document,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
            )),
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            at,
            now,
        )
        .unwrap();
    let recipient = EntityId::now().to_hex();
    let request = EsignCreateRequest {
        document_ref: document.to_hex(),
        draft: EsignDocument {
            schema_version: 1,
            kind: DocumentKind::Document,
            title: "Agreement".to_owned(),
            sequential: false,
            expires_at: expires,
            token_expires_at: None,
            items: vec![EsignItem {
                artifact_ref: document.to_hex(),
                original_version: 1,
            }],
            recipients: vec![EsignRecipient {
                id: recipient.clone(),
                email: "recipient@example.com".to_owned(),
                name: "Recipient".to_owned(),
                role: RecipientRole::Signer,
                order: 0,
                expires_at: expires,
                principal_ref: None,
                automated: false,
                natural_person: None,
            }],
            fields: vec![EsignField {
                id: EntityId::now().to_hex(),
                item: 0,
                recipient,
                required: true,
                geometry: FieldGeometry {
                    page: 1,
                    x_percent: 10.0,
                    y_percent: 10.0,
                    width_percent: 30.0,
                    height_percent: 8.0,
                },
                meta: FieldMeta::Signature,
            }],
            full_trail_appendix: true,
            lifecycle: None,
            project: None,
            commitments: Vec::new(),
        },
        qr_pdf_download: false,
    };
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory.esign_create(&request).unwrap();
    host.clock.set(now + 60);
    let sent = memory
        .esign_send_for_signature(&EsignDispatchRequest {
            document_ref: document.to_hex(),
            recipient_count: 1,
            on_behalf_of: None,
            idempotency_key: Some("restored-notice-document".to_owned()),
            check_in_ref: None,
        })
        .unwrap();
    assert_eq!(
        sent.outcome, "delivered_to_channel",
        "FIXTURE: the draft was sent"
    );
    host.clock.set(expires);
    assert_eq!(vault.sweep_esign_expiry(&[document], expires).unwrap(), 1);
    let group = EsignNoticeGroup {
        document,
        principal: owner,
    };
    assert_eq!(vault.esign_notice_groups_due().unwrap(), vec![group]);
    let notices: Vec<_> = AttemptQueue::new(vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|attempt| attempt.kind == ESIGN_NOTICE_ATTEMPT_KIND)
        .collect();
    assert_eq!(notices.len(), 1);
    (group, notices[0].id)
}

fn esign_deliveries(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .unwrap()
        .iter()
        .filter(|attempt| attempt.kind == "esign.delivery")
        .count()
}

fn unattended(vault: &Vault, group: &EsignNoticeGroup) -> EsignNoticesDispatchView {
    match vault.dispatch_esign_notices_unattended(group).unwrap() {
        EsignUnattendedNotices::Dispatched { view, .. } => view,
        answer => panic!("the owner's unattended carrier should stand: {answer:?}"),
    }
}

/// The unattended e-sign pass has no work and does not queue a delivery before join (Q4b).
#[test]
fn an_unjoined_copy_has_no_unattended_esign_notice_work() {
    let host = rooted_host();
    let (group, id) = stage_esign_notice(&host);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let before = row(&copy.vault, id);
    let deliveries = esign_deliveries(&copy.vault);
    let committed = last_committed_txn_id(&copy.vault);

    let view = unattended(&copy.vault, &group);
    assert!(view.notices.is_empty(), "the unattended pass returns idle");
    assert_eq!(view.recovered, 0);
    assert_eq!(
        esign_deliveries(&copy.vault),
        deliveries,
        "the sink queued nothing"
    );
    assert_eq!(row(&copy.vault, id), before);
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let sent = unattended(&copy.vault, &group);
    assert_eq!(sent.notices.len(), 1);
    assert_eq!(sent.notices[0].outcome, "delivered_to_channel");
    assert_eq!(esign_deliveries(&copy.vault), deliveries + 1);
}

/// An owner's own e-sign dispatch shows the join answer and leaves the notice staged (Q4b).
#[test]
fn an_unjoined_copy_tells_the_esign_sender_to_join() {
    let host = rooted_host();
    let (group, id) = stage_esign_notice(&host);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let before = row(&copy.vault, id);
    let deliveries = esign_deliveries(&copy.vault);
    let committed = last_committed_txn_id(&copy.vault);
    let memory = copy.vault.memory(group.principal, EdgeActorClass::Human);
    let request = EsignNoticesDispatchRequest {
        document_ref: group.document.to_hex(),
    };

    let refusal = memory
        .esign_notices_dispatch(&request)
        .expect_err("the principal sees a join refusal, not an idle view");
    assert!(refusal.to_string().contains(NOT_JOINED), "{refusal}");
    assert_eq!(
        esign_deliveries(&copy.vault),
        deliveries,
        "the sink queued nothing"
    );
    assert_eq!(row(&copy.vault, id), before);
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let sent = memory.esign_notices_dispatch(&request).unwrap();
    assert_eq!(sent.notices.len(), 1);
    assert_eq!(sent.notices[0].outcome, "delivered_to_channel");
    assert_eq!(esign_deliveries(&copy.vault), deliveries + 1);
}

/// The engine's due list offers no task to the poll transport until the copy joins (Q6b).
#[test]
fn an_unjoined_copy_lists_no_due_remote_task() {
    let host = rooted_host();
    let intent = defer_pollable_remote_task(&host.vault, 0x53, None);
    remote_task_polls_due_now(&host.vault, &[intent]);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let subject = EntityId::from_bytes(intent[..16].try_into().unwrap()).unwrap();
    let scheduled = || due_at(&copy.vault, REMOTE_TASK_POLL, Some(subject)).unwrap();
    let ledger = || {
        intent_ledger_records(&copy.vault)
            .unwrap()
            .records
            .into_iter()
            .find(|record| record.id == intent)
            .expect("the restored task keeps its intent")
    };
    let before = ledger();
    let due = scheduled().expect("the restored poll is armed");
    let committed = last_committed_txn_id(&copy.vault);
    assert_eq!(before.state, IntentState::Deferred);
    assert!(
        due <= copy.vault.now_recorded_at(),
        "the poll is already due"
    );

    assert!(
        copy.vault.remote_tasks_due(32).unwrap().is_empty(),
        "the host gets no task to poll before the join"
    );
    assert_eq!(scheduled(), Some(due), "the poll stays armed as before");
    assert_eq!(ledger(), before, "the frozen deferred intent does not move");
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let tasks = copy.vault.remote_tasks_due(32).unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].intent, intent);
    assert_eq!(tasks[0].polls, 0);
}

/// A transport that counts every call made by the notice dispatch.
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

fn stage_notice_without_live_consent(
    vault: &Vault,
    sender: EntityId,
) -> (TrustedContactNotice, AttemptId) {
    // A decodable notice with no matching fire. Its liveness preflight fails the row once
    // the join allows work, without sending anything to the contact.
    let notice = TrustedContactNotice {
        fire: EntityId::now().to_hex(),
        person: sender.to_hex(),
        contact: EntityId::now().to_hex(),
        version: 1,
        sender: sender.to_hex(),
        channel: "email".to_owned(),
        verb: "send".to_owned(),
        target: "contact@example.com".to_owned(),
        authorization: TrustedContactNoticeAuthorization::Ask {
            ask_ref: EntityId::now().to_hex(),
        },
    };
    let EnqueueOutcome::Enqueued(queued) = AttemptQueue::new(vault)
        .enqueue(EnqueueAttempt {
            kind: TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND.to_owned(),
            payload: serde_json::to_vec(&notice).unwrap(),
            dedupe_key: None,
            run_id: None,
            now: vault.now_recorded_at(),
        })
        .unwrap()
    else {
        panic!("FIXTURE: a fresh notice is queued");
    };
    (notice, queued.id)
}

/// A sender's own trusted notice claim opens no writing path before the copy joins (Q7.2).
#[test]
fn an_unjoined_copy_does_not_stamp_the_clock_to_claim_a_trusted_notice() {
    let host = rooted_host();
    let owner = host.vault.ensure_embedded_owner_actor().unwrap();
    let (_, id) = stage_notice_without_live_consent(&host.vault, owner);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let memory = copy.vault.memory(owner, EdgeActorClass::Human);
    let mut sink = CountingSink::default();
    let before = row(&copy.vault, id);
    let committed = last_committed_txn_id(&copy.vault);
    // The base's point claim stamps this newer recording time before its own kind hold.
    host.clock.set(copy.vault.now_recorded_at() + 60);

    assert!(
        copy.vault
            .deliver_trusted_contact_notice(&memory, &mut sink)
            .unwrap()
            .is_none()
    );
    assert_eq!(sink.calls, 0);
    assert_eq!(row(&copy.vault, id), before);
    assert_eq!(
        last_committed_txn_id(&copy.vault),
        committed,
        "no claim wrote the clock floor"
    );

    owner_joins(&host, &copy);
    assert!(
        copy.vault
            .deliver_trusted_contact_notice(&memory, &mut sink)
            .unwrap()
            .is_none()
    );
    let after = AttemptQueue::new(&copy.vault).get(id).unwrap().unwrap();
    assert_eq!(after.state, AttemptState::Failed);
    assert_eq!(sink.calls, 0);
}

/// The connector-reply kind still hands no job to the reply worker before the join (Q7.5).
#[test]
fn an_unjoined_copy_claims_no_connector_reply_job() {
    let host = rooted_host();
    let now = host.vault.now_recorded_at();
    let job = ConnectorReplyJob {
        agent: sender(),
        event: ConnectorEvent {
            event_id: "restored-reply-event".to_owned(),
            connector: "email".to_owned(),
            event_kind: "received".to_owned(),
            predicate: "email.received".to_owned(),
            payload: serde_json::json!({}),
        },
        parent_attempt: AttemptId::from_bytes(&[0x62; 16]).unwrap(),
        budget_steering: Vec::new(),
    };
    let id = host.vault.enqueue_connector_reply_job(&job, now).unwrap();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let before = row(&copy.vault, id);
    let committed = last_committed_txn_id(&copy.vault);

    assert!(copy.vault.claim_connector_reply_job(now).unwrap().is_none());
    assert_eq!(row(&copy.vault, id), before, "no reply lease was taken");
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let (claimed, restored) = copy.vault.claim_connector_reply_job(now).unwrap().unwrap();
    assert_eq!(claimed.id, id);
    assert_eq!(restored, job);
    copy.vault
        .settle_connector_reply_job(
            &claimed,
            &restored,
            &ConnectorReplyJobResult::at(ConnectorReplyStage::NoReply),
            now,
        )
        .unwrap();
}

/// The owed MCP session ends wait for the join: ending a session is a send (review of #10339,
/// round 1).
#[test]
fn an_unjoined_copy_lists_no_session_to_end() {
    let host = rooted_host();
    let intent = [0x5e; 32];
    owe_remote_task_session_end(&host.vault, intent);
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let committed = last_committed_txn_id(&copy.vault);

    assert!(
        copy.vault
            .remote_task_sessions_to_end(32)
            .unwrap()
            .is_empty(),
        "the host gets no session to end before the join"
    );
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    let ends = copy.vault.remote_task_sessions_to_end(32).unwrap();
    assert_eq!(ends.len(), 1, "the owed end waited in the copy");
    assert_eq!(ends[0].0, intent);
}

/// The host's request for `notice`, bound as its dispatch requires.
fn notice_request(notice: &TrustedContactNotice, sender: EntityId) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        format!("receipt:{}", notice.fire),
        format!("trusted-contact-notice:{}", notice.fire),
        OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                notice.sender.as_str(),
                notice.verb.as_str(),
                notice.channel.as_str(),
                notice.target.as_str(),
            ),
            OutboundIntentTrigger::record_transition(notice.fire.as_str()),
        ),
        OutboundDispatchActor::agent(sender),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
}

/// A notice lease the image kept is refused before its lease check and consent preflight, so
/// the copy fails no notice before the join (review of #10339, round 1).
#[test]
fn an_unjoined_copy_dispatches_no_notice_its_image_kept_leased() {
    let host = rooted_host();
    let owner = host.vault.ensure_embedded_owner_actor().unwrap();
    let (notice, id) = stage_notice_without_live_consent(&host.vault, owner);
    let ClaimOutcome::Claimed(_) = AttemptQueue::new(&host.vault)
        .claim_kind(
            TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "notice-sender".into(),
                now: host.vault.now_recorded_at(),
            },
        )
        .unwrap()
    else {
        panic!("FIXTURE: the host leases the notice before the image");
    };
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let attempt = AttemptQueue::new(&copy.vault).get(id).unwrap().unwrap();
    assert_eq!(
        attempt.state,
        AttemptState::Leased,
        "FIXTURE: the image kept the lease"
    );
    let mut sink = CountingSink::default();
    let before = row(&copy.vault, id);
    let committed = last_committed_txn_id(&copy.vault);

    let refused = copy
        .vault
        .dispatch_trusted_contact_notice(&attempt, notice_request(&notice, owner), &mut sink)
        .err()
        .expect("the copy dispatches no notice before the join")
        .to_string();
    assert!(
        refused.contains(NOT_JOINED),
        "the refusal names the copy's state: {refused}"
    );
    assert_eq!(sink.calls, 0);
    assert_eq!(
        row(&copy.vault, id),
        before,
        "the kept lease stays as the image left it"
    );
    assert_eq!(last_committed_txn_id(&copy.vault), committed);

    owner_joins(&host, &copy);
    assert!(
        copy.vault
            .dispatch_trusted_contact_notice(&attempt, notice_request(&notice, owner), &mut sink)
            .is_err(),
        "the notice's consent is not live"
    );
    let after = AttemptQueue::new(&copy.vault).get(id).unwrap().unwrap();
    assert_eq!(
        after.state,
        AttemptState::Failed,
        "after the join the preflight fails the dead notice"
    );
    assert_eq!(sink.calls, 0);
}
