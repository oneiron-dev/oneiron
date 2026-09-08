mod connector_schedule;
mod dispatch_budget;
#[path = "sender_selection/facet_selection.rs"]
mod facet_selection;
mod gate_window;
mod linkedin_send;
mod pipeline_contract;
mod quiet_window;
mod retry_audit;
mod sender_selection;

use super::*;
use crate::delivery_window::DeliveryWindowDecision;
use rmpv::Value;

use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::config::VaultConfig;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
use crate::delivery_window::{
    DELIVERY_WINDOW_SCHEMA_VERSION, DeliveryWindowApnsInterruptionLevel, DeliveryWindowAppliesTo,
    DeliveryWindowContextCondition, PREDICATE_DELIVERY_WINDOW_CHANNEL,
    PREDICATE_DELIVERY_WINDOW_CONTEXT, PREDICATE_DELIVERY_WINDOW_QUIET,
};
use crate::edge::EdgeKind;
use crate::linkedin_connector::{
    LINKEDIN_CHANNEL, LinkedInMcpConnectorAdapter, LinkedInMcpSendMessageRequest,
    LinkedInMcpSendTransport, LinkedInMcpVerifiedSendSink, LinkedInSandboxHostConfig,
    LinkedInSandboxHostHarness, LinkedInSeatDispatchState, LinkedInSeatSandboxPolicy,
    LinkedInVerifiedSendPlan, run_linkedin_kill_switch,
};
use crate::llm::{BudgetSignalDeliveryChannel, BudgetThreshold};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

use crate::test_util::{entity, entity_record, put_policy_manifest_bytes};

fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
    let scoped_grants = verbs
        .iter()
        .map(|verb| {
            Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (
                    Value::from("effector"),
                    Value::from(format!("external:{verb}")),
                ),
                (
                    Value::from("scope"),
                    Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("outbound-o2-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(scoped_grants)),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn put_claim_body(vault: &Vault, seed: u8, body: &ClaimBody) -> crate::Result<()> {
    let id = entity(seed);
    let data = encode_claim_body(body)?;
    let payload = entity_record(
        ENTITY_TYPE_CLAIM,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        &data,
    );

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })?;

    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)?;
    }
    Ok(())
}

struct RecordingExecutor {
    calls: Vec<(String, String, String)>,
    idempotency_keys: Vec<Option<String>>,
    apns_levels: Vec<Option<DeliveryWindowApnsInterruptionLevel>>,
    outcome: OutboundExecutionOutcome,
}

impl Default for RecordingExecutor {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            idempotency_keys: Vec::new(),
            apns_levels: Vec::new(),
            outcome: OutboundExecutionOutcome::delivered_to_channel("provider:message:one"),
        }
    }
}

impl OutboundExecutionSink for RecordingExecutor {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.idempotency_keys
            .push(request.idempotency_key.map(str::to_owned));
        self.apns_levels.push(request.apns_interruption_level);
        self.calls.push((
            request.intent_ref.to_owned(),
            request.intent.channel.clone(),
            request.verb_contract.kind.clone(),
        ));
        self.outcome.clone()
    }
}

fn exercise_connector_schedule_and_executor() -> crate::Result<()> {
    use crate::attempt_queue::AttemptQueue;
    use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, OutboundDraftInput};
    use crate::receipt::{FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptKind, ReceiptQuery};

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x31);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 10, end: 10 },
        10,
        b"connector task actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x32),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;

    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&OutboundDraftInput {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "counterparty:test".to_owned(),
            on_behalf_of: None,
            content_ref: Some("content:test".to_owned()),
            idempotency_key: Some("connector-task:test".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:test".to_owned(),
            job_ref: None,
            occurred_at: Some(10),
        })
        .expect("schedule outbound");

    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;
    let task_ref_hex = task_ref.to_hex();
    assert_eq!(tasks[0].task_ref, task_ref);
    assert_eq!(tasks[0].assignee_ref, connector_actor_id("email")?);
    assert_eq!(vault.standalone_outbound_intent_count()?, 0);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        0
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .into_iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(FIELD_TRANSPORT_DISPATCHED)
                    .is_some_and(|value| value == "true")
            })
            .count(),
        0
    );
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?
            .len(),
        1
    );
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
            .count(),
        1
    );

    let mut executor = RecordingExecutor::default();
    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 11)
            .unwrap(),
        1
    );
    assert_eq!(executor.calls.len(), 1);
    let intent_row = crate::outbound_intent_ledger::intent_ledger_records(&vault)
        .map_err(|_| Error::InvariantViolation("connector execution intent ledger read failed"))?
        .into_iter()
        .next()
        .expect("connector execution journals one intent");
    // email/send is NonIdempotentInterrupt: the sink is not handed the ledger id
    // as a provider idempotency (dedup) token, even though the ledger row still
    // keys the intent internally.
    assert_eq!(executor.idempotency_keys, vec![None]);
    assert!(!intent_row.idempotency_key.is_empty());
    assert_eq!(
        intent_row.state,
        crate::outbound_intent_ledger::IntentState::Done
    );
    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get(FIELD_TASK_REF).map(String::as_str),
        Some(task_ref_hex.as_str())
    );
    assert_eq!(
        receipts[0]
            .fields
            .get(FIELD_TRANSPORT_DISPATCHED)
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| {
                receipt
                    .fields
                    .get(FIELD_TRANSPORT_DISPATCHED)
                    .is_some_and(|value| value == "true")
            })
            .count(),
        1
    );
    let lineaged_task = receipts[0]
        .fields
        .get(FIELD_TASK_REF)
        .and_then(|task_ref| EntityId::from_hex(task_ref).ok())
        .and_then(|task_ref| vault.connector_send_task(&task_ref).ok().flatten());
    assert_eq!(usize::from(lineaged_task.is_some()), 1);

    assert_eq!(
        vault
            .run_connector_task_executor(&mut executor, 12)
            .unwrap(),
        0
    );
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );
    Ok(())
}

fn connector_task_draft(
    idempotency_key: &str,
    trigger_ref: &str,
    occurred_at: u64,
) -> crate::memory::OutboundDraftInput {
    crate::memory::OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: format!("counterparty:{idempotency_key}"),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some(idempotency_key.to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: trigger_ref.to_owned(),
        job_ref: None,
        occurred_at: Some(occurred_at),
    }
}

fn put_connector_task_actor(vault: &Vault, actor: EntityId, at: u64) -> crate::Result<()> {
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: at, end: at },
        at,
        b"connector task actor",
    )
}

struct ScriptedLinkedInTransport {
    send_calls: Vec<LinkedInMcpSendMessageRequest>,
    get_calls: Vec<String>,
    send_result: std::result::Result<serde_json::Value, String>,
    conversations: std::collections::VecDeque<std::result::Result<serde_json::Value, String>>,
}

impl ScriptedLinkedInTransport {
    fn new(conversations: Vec<serde_json::Value>) -> Self {
        Self {
            send_calls: Vec::new(),
            get_calls: Vec::new(),
            send_result: Ok(serde_json::json!({"status": "ignored"})),
            conversations: conversations.into_iter().map(Ok).collect(),
        }
    }

    fn failing_send(mut self, error_code: &str) -> Self {
        self.send_result = Err(error_code.to_owned());
        self
    }

    fn with_get_error_after_precheck(mut self, error_code: &str) -> Self {
        self.conversations.insert(1, Err(error_code.to_owned()));
        self
    }
}

impl LinkedInMcpSendTransport for ScriptedLinkedInTransport {
    fn send_message(
        &mut self,
        request: &LinkedInMcpSendMessageRequest,
    ) -> std::result::Result<serde_json::Value, String> {
        self.send_calls.push(request.clone());
        self.send_result.clone()
    }

    fn get_conversation(
        &mut self,
        thread_id: &str,
    ) -> std::result::Result<serde_json::Value, String> {
        self.get_calls.push(thread_id.to_owned());
        self.conversations
            .pop_front()
            .unwrap_or_else(|| Err("no_more_recorded_conversations".to_owned()))
    }
}

#[derive(Default)]
struct RecordingLinkedInSandboxHarness {
    destroyed: Vec<String>,
    revoked: Vec<String>,
}

impl LinkedInSandboxHostHarness for RecordingLinkedInSandboxHarness {
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> crate::Result<()> {
        self.destroyed.push(host.sandbox_ref.clone());
        Ok(())
    }

    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> crate::Result<()> {
        self.revoked.push(seat_ref.to_owned());
        Ok(())
    }
}

fn linkedin_adapter() -> crate::Result<LinkedInMcpConnectorAdapter> {
    LinkedInMcpConnectorAdapter::new("linkedin:member:yura")?
        .with_session_ref("linkedin:session:yura:tokyo-sandbox")
}

fn linkedin_sandbox_host() -> crate::Result<LinkedInSandboxHostConfig> {
    LinkedInSandboxHostConfig::new(
        "linkedin:seat:yura",
        "sandbox:tokyo:yura",
        "browser-profile:linkedin:yura",
        "vault-secret:linkedin:yura:session-cookie",
    )
}

fn active_linkedin_policy() -> crate::Result<LinkedInSeatSandboxPolicy> {
    Ok(LinkedInSeatSandboxPolicy::active(linkedin_sandbox_host()?)
        .with_state(LinkedInSeatDispatchState::active()))
}

fn linkedin_conversation(thread_id: &str, conversation: &str) -> serde_json::Value {
    serde_json::json!({
        "url": format!("https://www.linkedin.com/messaging/thread/{thread_id}/"),
        "sections": {
            "conversation": conversation
        },
        "references": {
            "conversation": [
                {
                    "kind": "conversation",
                    "url": format!("/messaging/thread/{thread_id}/"),
                    "context": "conversation",
                    "text": "Jane Doe"
                }
            ]
        }
    })
}

fn linkedin_conversation_without_thread_metadata(conversation: &str) -> serde_json::Value {
    serde_json::json!({
        "sections": {
            "conversation": conversation
        }
    })
}

fn dispatch_intent(trigger: OutboundIntentTrigger) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "email", "kenji@example.com")
            .on_behalf_of("owner")
            .content_ref("content:invite-kenji")
            .idempotency_key("idem:invite-kenji")
            .dedupe_key("dedupe:invite-kenji"),
        trigger,
    )
}

fn linkedin_send_intent(trigger: OutboundIntentTrigger) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            "agent-alpha",
            "send_dm",
            LINKEDIN_CHANNEL,
            "linkedin:member:jane-doe",
        )
        .on_behalf_of("owner")
        .content_ref("content:linkedin-jane")
        .idempotency_key("lnkd:send:jane:overview")
        .dedupe_key("lnkd:thread:2-jane-doe-abc:overview"),
        trigger,
    )
}

fn allow_linkedin_send(
    vault: &Vault,
    actor: &OutboundDispatchActor,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    put_policy_manifest_bytes(
        vault,
        entity(0xE0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            LINKEDIN_CHANNEL,
            &["send_dm"],
        ),
    )?;
    Ok(())
}

fn linkedin_send_request(
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        receipt_id,
        intent_ref,
        linkedin_send_intent(OutboundIntentTrigger::agent_immediate(
            "session:linkedin-send",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_060,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("linkedin:member:jane-doe")
}

fn quiet_delivery_window_claim_body(subject_seed: u8) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("tz"), Value::from("user-local")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

fn quiet_delivery_window_policy() -> DeliveryWindowPolicyClaim {
    let claim = quiet_delivery_window_claim_body(0x5E);
    DeliveryWindowPolicyClaim::from_claim_body(&claim).expect("valid quiet claim")
}

fn calendar_busy_delivery_window_claim_body(subject_seed: u8) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CONTEXT,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from("when"),
                Value::from(DeliveryWindowContextCondition::CalendarBusy.as_str()),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

fn channel_delivery_window_claim_body(subject_seed: u8, channel: &str, reason: &str) -> ClaimBody {
    let mut claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CHANNEL,
        ClaimSubject::Entity(entity(subject_seed)),
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from("applies_to"),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from("channel"), Value::from(channel)),
            (
                Value::from("window"),
                Value::Map(vec![
                    (Value::from("start_minute"), Value::from(22 * 60)),
                    (Value::from("end_minute"), Value::from(8 * 60)),
                ]),
            ),
            (Value::from("reason"), Value::from(reason)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    claim
}

// --- GOV-01 connector-key effector budgets (ONE-1416) ------------------------

/// An agent actor whose STORED definition carries an Auto ceiling.
///
/// The gate derives an agent actor's authority from its AGENT_DEF ROW, so a
/// fixture that needs an auto-eligible agent seeds the row. (These fixtures
/// previously borrowed a pinned system-agent actor id, which carried a
/// compiled ceiling; SEAM-GATE-PRESET-NEUTRALIZATION removed that table.)
fn auto_agent_actor(vault: &Vault) -> crate::Result<OutboundDispatchActor> {
    let id = entity(0x5C);
    vault.put_agent_definition(
        &id,
        &AgentDefinition::new(
            "oneiron.agent.outbound.auto",
            "Outbound dispatch fixture",
            "1",
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            AgentScope::All,
            AgentCeiling::Auto,
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
            None,
            true,
            None,
        ),
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(OutboundDispatchActor::agent(id))
}

fn email_send_dispatch_request(actor: OutboundDispatchActor, seq: u32) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        format!("outbound:intent:budget-{seq}"),
        format!("intent:budget-{seq}"),
        dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:budget-{seq}"
        ))),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000 + u64::from(seq),
        OutboundDeliveryWindowDecision::DeliverNow,
    )
}

// --- GOV-02 budget legibility + graceful wrap (ONE-1418) ---------------------

fn sends_per_day_key(limit: u64) -> crate::connector_key::ConnectorKeyRecord {
    crate::connector_key::ConnectorKeyRecord::active(
        "email",
        None,
        vec![crate::connector_key::EffectorBudget::sends(
            limit,
            crate::connector_key::EffectorBudgetWindow::Calendar {
                period: crate::connector_key::CalendarPeriod::Day,
                tz: None,
            },
            crate::connector_key::EffectorBudgetOnExhaust::Suspend,
        )],
        1_000,
    )
}

fn budget_vault_with_key(
    limit: u64,
) -> std::result::Result<
    (tempfile::TempDir, Vault, OutboundDispatchActor),
    Box<dyn std::error::Error>,
> {
    let (tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    vault.register_connector_key(&entity(0xB7), sends_per_day_key(limit))?;
    Ok((tmp, vault, actor))
}

// --- GOV-10 charter drift at the dispatch surface (ONE-1417) ------------------

// ---------------------------------------------------------------------------
// ONE-1768 done-means oracles.
//
// Every test below drives the REAL schedule → TASK → executor → live-claim door
// path. None of them delegate to a shared happy-path exercise: a wrapper that
// re-runs the hostless email fixture proves nothing about ambient promotion,
// live claims, host refresh, bounded hostless backoff, or the human rung.
// ---------------------------------------------------------------------------

/// 22:00 UTC. With a frozen `+60` offset the executor derives local 23:00 —
/// inside the 22:00–08:00 quiet window carried by the fixture claim.
const ONE_1768_EXECUTE_AT: u64 = 79_200;
const ONE_1768_QUIET_OFFSET: i16 = 60;
const ONE_1768_SCHEDULED_AT: u64 = 10;

struct QuietWindowFixture {
    _tmp: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
}

/// A vault whose acting subject carries ONE live 22:00–08:00 quiet-window
/// claim and a manifest granting `channel × verbs`.
fn quiet_window_fixture(
    seed: u8,
    channel: &str,
    verbs: &[&str],
) -> crate::Result<QuietWindowFixture> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(seed);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(seed.wrapping_add(1)),
        &policy_manifest(&actor.to_hex(), channel, verbs),
    )?;
    put_claim_body(
        &vault,
        seed.wrapping_add(2),
        &quiet_delivery_window_claim_body(seed),
    )?;
    Ok(QuietWindowFixture { _tmp, vault, actor })
}

fn one_1768_draft(channel: &str, verb: &str, key: &str) -> crate::memory::OutboundDraftInput {
    crate::memory::OutboundDraftInput {
        verb: verb.to_owned(),
        channel: channel.to_owned(),
        target: format!("counterparty:{key}"),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some(format!("one-1768:{key}")),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: format!("session:{key}"),
        job_ref: None,
        occurred_at: Some(ONE_1768_SCHEDULED_AT),
    }
}

fn one_1768_receipts(vault: &Vault) -> crate::Result<Vec<crate::receipt::ReceiptRecord>> {
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    vault.receipts(ReceiptQuery::new(1).with_kind(ReceiptKind::Outbound))
}

fn one_1768_bridge_attempts(
    vault: &Vault,
) -> crate::Result<Vec<crate::attempt_queue::AttemptRecord>> {
    use crate::attempt_queue::AttemptQueue;
    use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect())
}

fn receipt_field<'a>(receipt: &'a crate::receipt::ReceiptRecord, key: &str) -> Option<&'a str> {
    receipt.fields.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------
// ONE-1879 — a hold the GATE parked re-arms on its own curve.
//
// A window hold waits on the clock, so minutes are the right grain. A
// Gate-Pending hold waits on a PERSON: the window already admits the send, and
// it goes the moment authority lands, so the executor polls it on seconds and
// saturates at five minutes. Both curves read the `retry_of` lineage and never
// `attempt_count`, which every fresh retry row resets to zero.
// ---------------------------------------------------------------------------

/// A vault whose actor may schedule but whose standing policy grants nothing
/// on the channel it sends over, so every execute-time gate check parks the
/// send Pending on human authority.
///
/// The manifest is REAL and grants a different channel — a missing manifest
/// would fail closed for its own unrelated reason. No delivery-window claim is
/// seeded, so the window admits and the Gate is the only thing holding the
/// send.
fn gate_pending_fixture(seed: u8) -> crate::Result<(tempfile::TempDir, Vault, EntityId)> {
    let (tmp, vault) = temp_vault();
    let actor = entity(seed);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(seed.wrapping_add(1)),
        &policy_manifest(&actor.to_hex(), "slack", &["send"]),
    )?;
    Ok((tmp, vault, actor))
}

/// One executor round that must park the send rather than deliver it.
fn run_parked_round(vault: &Vault, sink: &mut RecordingExecutor, now: u64, round: usize) {
    assert_eq!(
        vault.run_connector_task_executor(sink, now).unwrap(),
        0,
        "round {round}: a parked send delivers nothing"
    );
}

/// Schedules one hostless email send that the Gate will park at execute time.
fn schedule_gate_pending_send(
    vault: &Vault,
    actor: EntityId,
    key: &str,
) -> crate::Result<EntityId> {
    let receipt = vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("email", "send", key))
        .expect("an ungranted send still schedules — it parks, it is not lost");
    assert_eq!(receipt.gate_outcome.as_deref(), Some("pending"));
    assert_eq!(receipt.outcome, "held");
    Ok(vault.connector_send_tasks()?.remove(0).task_ref)
}

fn exercise_provider_retry_after_collision(
    raw_retry_after: Option<&str>,
    expected_secs: Option<u64>,
) -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x20);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x21),
        &policy_manifest(&actor.to_hex(), "slack", &["react"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("slack", "react", "retry-after-collision"))
        .expect("schedule");

    let mut outcome = OutboundExecutionOutcome::failed("provider_rate_limited")
        .with_receipt_field("provider_retry_after", "7")
        .with_receipt_field("provider_error_code", " rate_limited ");
    if let Some(raw) = raw_retry_after {
        outcome = outcome.with_receipt_field("retry_after", raw);
    }
    let mut executor = RecordingExecutor {
        outcome,
        ..RecordingExecutor::default()
    };
    run_parked_round(&vault, &mut executor, ONE_1768_EXECUTE_AT, 0);
    assert_eq!(executor.calls.len(), 1, "the provider was actually called");

    let receipt = one_1768_receipts(&vault)?
        .pop()
        .expect("the failed send has a durable audit receipt");
    assert_eq!(receipt.outcome, "failed");
    assert_eq!(receipt_field(&receipt, "dispatch_outcome"), Some("failed"));
    assert_eq!(receipt_field(&receipt, "gate_outcome"), Some("allow"));
    let expected_normalized = expected_secs.map(|secs| secs.to_string());
    assert_eq!(
        receipt_field(&receipt, "provider_retry_after"),
        expected_normalized.as_deref(),
        "only parsed raw retry_after may author the normalized field: {raw_retry_after:?}"
    );
    assert_eq!(
        receipt_field(&receipt, "retry_after"),
        raw_retry_after.filter(|raw| !raw.trim().is_empty()),
        "nonblank provider text survives verbatim; blank fields stay omitted"
    );
    assert_eq!(
        receipt_field(&receipt, "provider_error_code"),
        Some(" rate_limited "),
        "stripping the reserved key must preserve ordinary provider evidence"
    );
    let surfaced: u64 = receipt_field(&receipt, "retry_at")
        .expect("every executor re-arm stamps retry_at")
        .parse()
        .expect("retry_at is an instant");
    assert_eq!(
        surfaced,
        ONE_1768_EXECUTE_AT + expected_secs.unwrap_or(60),
        "use the parsed provider delay or the exact transport fallback, never the injected 7s"
    );
    let attempts = one_1768_bridge_attempts(&vault)?;
    let armed = attempts
        .iter()
        .find(|attempt| attempt.state == AttemptState::Scheduled)
        .expect("a failed send re-arms rather than failing terminally");
    assert_eq!(armed.scheduled_at, Some(surfaced));
    Ok(())
}
