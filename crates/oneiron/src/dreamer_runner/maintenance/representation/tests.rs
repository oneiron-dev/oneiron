//! Public-path fixture: queued wake -> review -> OF-327 task -> recorded sink.
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerConsolidationScope};
use crate::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerWakeDriver, RunWakePass,
    WakeAttemptContext, WakeCancellation, WakePassDeadline, WakeTrigger,
};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, TimeRange,
    Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}
fn id(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
}
impl Fixture {
    fn new(allow_send: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        // Keep the production default policy. No legacy fixture helper that
        // deletes it, no fail-open policy, no modified production gate.
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        vault
            .put_entity(
                &id(0x51),
                crate::registry::ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"owner",
            )
            .unwrap();
        vault
            .put_entity(
                &id(0x52),
                crate::registry::ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"other owner",
            )
            .unwrap();
        let owner = vault
            .authenticate_owner(
                id(0x51),
                "principal:representation-owner",
                true,
                crate::store::GateDecisionId::now(),
            )
            .unwrap();
        let actor = vault.dreamer_authority().unwrap().entity_ref();
        install_policy(&vault, actor, allow_send);
        seed_source(
            &vault,
            id(0x61),
            id(0x51),
            "The report is ready for review.",
            None,
        );
        seed_source(
            &vault,
            id(0x62),
            id(0x51),
            "Keep it brief. Thanks, Alex.",
            None,
        );
        Self {
            _dir: dir,
            vault,
            owner,
        }
    }
    fn request(&self, kind: RepresentationKind) -> RepresentationRequest {
        RepresentationRequest {
            owner: self.owner.actor(),
            kind,
            verb: "send".into(),
            channel: "email".into(),
            target: "counterparty:representation-fixture".into(),
            evidence: vec![RepresentationSourceRef { claim: id(0x61) }],
            voice: vec![RepresentationSourceRef { claim: id(0x62) }],
        }
    }
    fn propose(&self, kind: RepresentationKind, now: u64) -> EntityId {
        let request = self.request(kind);
        self.vault
            .representation_context(&request)
            .expect("scoped source context");
        self.vault
            .schedule_representation(&request, &mut Author, now)
            .unwrap();
        drive(&self.vault, now);
        let ids = self.vault.claims_for_subject(&self.owner.actor()).unwrap();
        ids.into_iter()
            .find(|id| {
                let body = self.vault.get_claim(id).unwrap().unwrap();
                body.predicate == PREDICATE
                    && serde_json::from_str::<serde_json::Value>(body.value.as_str().unwrap())
                        .unwrap()["request"]["kind"]
                        == serde_json::to_value(kind).unwrap()
            })
            .unwrap()
    }
}
fn seed_source(
    vault: &Vault,
    claim: EntityId,
    owner: EntityId,
    text: &str,
    world: Option<EntityId>,
) {
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("representation fixture source")).unwrap(),
        ClaimApprovalStatus::Auto,
    );
    let mut candidate = ClaimCandidate::new(
        "profile.representation_sample",
        ClaimSubject::Entity(owner),
        Value::from(text),
        1.0,
    );
    if let Some(world) = world {
        candidate = candidate.with_world(world);
    }
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, at(1), 1)
        .commit()
        .unwrap();
}
fn install_policy(vault: &Vault, actor: EntityId, allow_send: bool) {
    let mut manifest =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice()).unwrap();
    let Value::Map(ref mut entries) = manifest else {
        panic!("default manifest map");
    };
    let ceilings = entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("actor_ceilings"))
        .unwrap();
    let Value::Array(ref mut rows) = ceilings.1 else {
        panic!("actor ceilings");
    };
    rows.push(Value::Map(vec![
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("ceiling"), Value::from("auto")),
    ]));
    let mut grants = vec![Value::Map(vec![
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("effector"), Value::from("core:read")),
        (Value::from("receipt_required"), Value::from(false)),
        (
            Value::from("scope"),
            Value::Map(vec![(Value::from("world"), Value::from("base"))]),
        ),
    ])];
    if allow_send {
        grants.push(Value::Map(vec![
            (Value::from("actor_ref"), Value::from(actor.to_hex())),
            (Value::from("effector"), Value::from("external:send")),
            (
                Value::from("scope"),
                Value::Map(vec![(Value::from("channel"), Value::from("email"))]),
            ),
        ]));
    }
    entries.retain(|(k, _)| k.as_str() != Some("scoped_grants"));
    entries.push((Value::from("scoped_grants"), Value::Array(grants)));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).unwrap();
    // Seed previously owner-admitted maintenance state with the dedicated
    // policy fixture door. Keep the production default and explicit grants.
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
}
struct Author;
impl RepresentationPlanner for Author {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft> {
        let evidence = context.evidence[0].cite("report is ready");
        let voice = context.voice[0].cite("Thanks, Alex.");
        Ok(RepresentationDraft {
            text: format!(
                "The report is ready for review. {}\nThanks, Alex.",
                evidence.marker()
            ),
            evidence: vec![evidence],
            voice: vec![voice],
        })
    }
}
struct WrongQuote;
impl RepresentationPlanner for WrongQuote {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft> {
        let mut draft = Author.plan(context)?;
        draft.evidence[0].quote = "fabricated quotation".into();
        Ok(draft)
    }
}
struct ExtraCitation;
impl RepresentationPlanner for ExtraCitation {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft> {
        let mut draft = Author.plan(context)?;
        draft
            .text
            .push_str(&format!(" [{}@{}]", id(0xEE).to_hex(), "00".repeat(32)));
        Ok(draft)
    }
}
struct NeverDelegate;
impl DreamerAttemptExecutor for NeverDelegate {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        _: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        panic!("maintenance facets must be driven by the production wake arm")
    }
}
fn drive(vault: &Vault, now: u64) {
    let mut driver = DreamerWakeDriver::new(
        vault,
        format!("representation-{now}"),
        WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let cancel = WakeCancellation::new();
    let mut executor = NeverDelegate;
    let future = driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: crate::identity::load_or_mint_client_id(vault).unwrap(),
            lease_owner: "representation-fixture".into(),
            budget_total_units: 1000,
            reserve_units: 10,
            now,
        },
        &mut executor,
        &cancel,
    );
    let report = crate::dreamer_wake::block_on_ready(future).unwrap();
    assert_eq!(report.completed, 1);
}
struct RecordingSink<'a> {
    vault: &'a Vault,
    sent: Vec<Vec<u8>>,
}
impl OutboundExecutionSink for RecordingSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.sent.push(
            self.vault
                .read_representation_content(request.intent.content_ref.as_deref().unwrap())
                .unwrap(),
        );
        OutboundExecutionOutcome::delivered_to_channel("provider:representation-fixture")
    }
}

#[test]
fn wake_cites_scoped_sources_owner_accept_delivers_via_of327_decline_sends_nothing() {
    let f = Fixture::new(true);
    let accepted = f.propose(RepresentationKind::Reply, 100);
    let declined = f.propose(RepresentationKind::FollowUp, 101);
    assert!(f.vault.connector_send_tasks().unwrap().is_empty());
    assert!(f.vault.approved_representation(&accepted).is_err());
    let review = f.vault.review_representation(&f.owner, &accepted).unwrap();
    let bytes = crate::compaction::output::restore_output(&f.vault, review.content()).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains(&review.evidence()[0].marker())
    );
    assert_eq!(review.voice()[0].claim, id(0x62));
    let other = f
        .vault
        .authenticate_owner(
            id(0x52),
            "principal:other",
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    assert!(
        f.vault
            .approve_representation(&other, &review, 102)
            .is_err()
    );
    let rejected_review = f.vault.review_representation(&f.owner, &declined).unwrap();
    f.vault
        .decline_representation(&f.owner, &rejected_review, 102)
        .unwrap();
    assert_eq!(
        f.vault.get_claim(&declined).unwrap().unwrap().approval,
        ClaimApprovalStatus::Rejected
    );
    assert!(f.vault.approved_representation(&declined).is_err());
    assert!(f.vault.connector_send_tasks().unwrap().is_empty());
    let approved = f
        .vault
        .approve_representation(&f.owner, &review, 103)
        .unwrap();
    let actor = f.vault.dreamer_authority().unwrap().entity_ref();
    let facade = f.vault.memory(actor, EdgeActorClass::Agent);
    let context = crate::memory::OutboundScheduleContext {
        utc_offset_minutes: Some(0),
        ..Default::default()
    };
    let receipt =
        schedule_approved_representation(&facade, approved.clone(), &context, 104).unwrap();
    assert_eq!(receipt.gate_outcome.as_deref(), Some("allow"));
    assert_eq!(f.vault.connector_send_tasks().unwrap().len(), 1);
    let mut sink = RecordingSink {
        vault: &f.vault,
        sent: Vec::new(),
    };
    // Email is ambient in the existing delivery-window ladder. Approval
    // permits the bound draft to deliver; it does not invent an interrupt.
    assert_eq!(
        f.vault.run_connector_task_executor(&mut sink, 105).unwrap(),
        1
    );
    assert_eq!(sink.sent, vec![bytes]);
    let replay =
        schedule_approved_representation(&facade, approved, &context, 106).unwrap();
    assert!(replay.deduped);
    assert_eq!(
        f.vault
            .run_connector_task_executor(&mut sink, 107)
            .unwrap(),
        0
    );
    let receipts = f
        .vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10).with_kind(crate::receipt::ReceiptKind::Outbound),
        )
        .unwrap();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt
                .fields
                .get("transport_dispatched")
                .map(String::as_str)
                == Some("true"))
            .count(),
        1
    );
}
#[test]
fn fabricated_quotes_unlisted_citations_unreadable_world_and_foreign_voice_refuse() {
    let f = Fixture::new(true);
    let request = f.request(RepresentationKind::Introduction);
    assert!(
        f.vault
            .schedule_representation(&request, &mut WrongQuote, 100)
            .is_err()
    );
    assert!(
        f.vault
            .schedule_representation(&request, &mut ExtraCitation, 100)
            .is_err()
    );
    seed_source(&f.vault, id(0x63), id(0x52), "Thanks, Alex.", None);
    let mut foreign = request.clone();
    foreign.voice[0].claim = id(0x63);
    assert!(f.vault.representation_context(&foreign).is_err());
    seed_source(
        &f.vault,
        id(0x64),
        id(0x51),
        "The report is ready.",
        Some(id(0x70)),
    );
    let mut hidden = request;
    hidden.evidence[0].claim = id(0x64);
    assert!(f.vault.representation_context(&hidden).is_err());
    assert!(f.vault.connector_send_tasks().unwrap().is_empty());
}
#[test]
fn source_revision_drift_refuses_review_token_schedule_and_queued_dispatch() {
    let f = Fixture::new(true);
    let proposal = f.propose(RepresentationKind::Post, 100);
    let review = f.vault.review_representation(&f.owner, &proposal).unwrap();
    let approved = f
        .vault
        .approve_representation(&f.owner, &review, 101)
        .unwrap();
    let facade = f.vault.memory(
        f.vault.dreamer_authority().unwrap().entity_ref(),
        EdgeActorClass::Agent,
    );
    let context = crate::memory::OutboundScheduleContext {
        utc_offset_minutes: Some(0),
        ..Default::default()
    };
    schedule_approved_representation(&facade, approved.clone(), &context, 102).unwrap();
    // The old quote still exists. Its revision does not: hash validation must
    // reject this case, not merely search for a matching substring again.
    seed_source(
        &f.vault,
        id(0x61),
        id(0x51),
        "The report is ready for review. New scope.",
        None,
    );
    assert!(
        f.vault
            .approve_representation(&f.owner, &review, 103)
            .is_err()
    );
    assert!(schedule_approved_representation(&facade, approved, &context, 103).is_err());
    let mut sink = RecordingSink {
        vault: &f.vault,
        sent: Vec::new(),
    };
    assert_eq!(
        f.vault.run_connector_task_executor(&mut sink, 104).unwrap(),
        0
    );
    assert!(sink.sent.is_empty());
}
#[test]
fn owner_approval_is_not_an_external_effect_grant() {
    let f = Fixture::new(false);
    let proposal = f.propose(RepresentationKind::Reply, 100);
    let review = f.vault.review_representation(&f.owner, &proposal).unwrap();
    let approved = f
        .vault
        .approve_representation(&f.owner, &review, 101)
        .unwrap();
    let facade = f.vault.memory(
        f.vault.dreamer_authority().unwrap().entity_ref(),
        EdgeActorClass::Agent,
    );
    let receipt =
        schedule_approved_representation(&facade, approved, &Default::default(), 102).unwrap();
    assert_ne!(receipt.gate_outcome.as_deref(), Some("allow"));
    let mut sink = RecordingSink {
        vault: &f.vault,
        sent: Vec::new(),
    };
    assert_eq!(
        f.vault.run_connector_task_executor(&mut sink, 103).unwrap(),
        0
    );
    assert!(sink.sent.is_empty());
}

#[test]
fn generic_inbox_approval_cannot_arm_representation_delivery() {
    let f = Fixture::new(true);
    let proposal = f.propose(RepresentationKind::Reply, 100);
    f.vault
        .set_inbox_review_dial(crate::inbox::InboxReviewDial::ReviewEverything)
        .unwrap();
    let group = f
        .vault
        .inbox_groups(crate::inbox::InboxQuery::at(101, 10))
        .unwrap();
    let group = group
        .into_iter()
        .find(|group| {
            group
                .members
                .iter()
                .any(|member| member.claim_id == proposal.to_hex())
        })
        .unwrap();
    f.vault
        .resolve_inbox_group_at(
            &group.group_key,
            crate::inbox::InboxBulkVerb::AcceptAll,
            None,
            101,
        )
        .unwrap();
    assert_eq!(
        f.vault.get_claim(&proposal).unwrap().unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert!(matches!(
        f.vault.approved_representation(&proposal),
        Err(crate::Error::InvalidClaimBody(_))
    ));
    assert!(f.vault.connector_send_tasks().unwrap().is_empty());
}
