use super::*;
use crate::attempt_queue::AttemptState;
use crate::campaign::claims::{
    CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER, decode_campaign_member_value,
    encode_campaign_member_value,
};
use crate::campaign::stage::{ReentryPlan, WakeCondition, snooze_with_wake};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentState, OutboundSendOutcome, intent_ledger_records,
};
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

const CHANNEL: &str = "email";
const HOME_NODE: u64 = 11;
const OTHER_NODE: u64 = 12;
const VERB: &str = "send";

/// The fixture's sticky sender: the actor the send policy grants and the
/// actor the program step carries. Named because two fixtures share it.
const SENDER_SEED: u8 = 0x57;

// Re-entry seeds, all outside `PINNED_ID_BYTES` and outside the seeds the
// enrollment fixtures above already claim.
const REENTRY_PARTY_SEED: u8 = 0x91;
const REENTRY_MEMBER_SEED: u8 = 0x92;
const REENTRY_REASON_SEED: u8 = 0x93;
const REENTRY_AT: u64 = 1_754_400_000;

fn vault_fixture() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// The host's ordinary policy posture for this sender/channel/verb. The
/// outward-leg tests must prove the ledger fires INSIDE the existing gate,
/// so they install a real manifest rather than bypassing governance.
fn install_send_policy(vault: &Vault, sender_ref: EntityId) {
    vault
        .put_entity(
            &sender_ref,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"campaign enrollment sender",
        )
        .expect("seed sender actor");
    let scoped_grant = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("actor_ref"),
            rmpv::Value::from(sender_ref.to_hex()),
        ),
        (
            rmpv::Value::from("effector"),
            rmpv::Value::from(format!("external:{VERB}")),
        ),
        (
            rmpv::Value::from("scope"),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("channel"),
                rmpv::Value::from(CHANNEL),
            )]),
        ),
    ]);
    let manifest = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.1"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("campaign-enrollment-test"),
        ),
        (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
        (
            rmpv::Value::from("min_engine_version"),
            rmpv::Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            rmpv::Value::from("defaults"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("normal"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ),
        (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
        (
            rmpv::Value::from("actor_ceilings"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                (
                    rmpv::Value::from("actor_ref"),
                    rmpv::Value::from(sender_ref.to_hex()),
                ),
                (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
            ])]),
        ),
        (
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(vec![scoped_grant]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encode");
    put_policy_manifest_bytes(vault, entity(0xD0), &bytes).expect("policy manifest");
}

/// Transport that reads the ledger AT SEND TIME. That is the only way to
/// prove the record exists BEFORE the bytes leave, rather than after.
struct LedgerWitnessTransport<'a> {
    vault: &'a Vault,
    outcome: OutboundSendOutcome,
    sent_intents: Vec<[u8; 32]>,
    sent_payload_hashes: Vec<[u8; 32]>,
    ledger_rows_at_send: Vec<usize>,
}

impl<'a> LedgerWitnessTransport<'a> {
    fn new(vault: &'a Vault, outcome: OutboundSendOutcome) -> Self {
        Self {
            vault,
            outcome,
            sent_intents: Vec::new(),
            sent_payload_hashes: Vec::new(),
            ledger_rows_at_send: Vec::new(),
        }
    }
}

impl OutboundTransport for LedgerWitnessTransport<'_> {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.ledger_rows_at_send.push(
            intent_ledger_records(self.vault)
                .expect("ledger is readable at send time")
                .len(),
        );
        self.sent_intents.push(
            *call
                .intent_id()
                .expect("an effectful frozen call carries its ledger identity"),
        );
        self.sent_payload_hashes.push(*call.payload_hash());
        self.outcome
    }
}

struct Fixture {
    event: CampaignEnrollmentEvent,
    payload: CampaignEnrollmentAttemptPayload,
}

fn install_fixture(vault: &Vault, outbound: Option<CampaignProgramOutbound>) -> Fixture {
    install_send_policy(vault, entity(SENDER_SEED));
    install_enrollment_rows(vault, outbound)
}

/// The persisted rows an attempt payload points at, WITHOUT the send
/// policy. Split out because the re-entry path sends nothing: installing a
/// governance manifest there would only gate the cohort row the test seeds.
fn install_enrollment_rows(vault: &Vault, outbound: Option<CampaignProgramOutbound>) -> Fixture {
    let campaign_ref = entity(0x41);
    let program_ref = entity(0x51);
    let step_ref = entity(0x52);
    let sender_ref = entity(SENDER_SEED);
    let event = CampaignEnrollmentEvent {
        event_ref: entity(0x53),
        query_ref: entity(0x54),
        campaign_ref,
        entity_ref: entity(0x55),
        owner_actor: entity(0x56),
        epoch: 1,
        valid_at: 1_000,
        detected_at: 1_000,
        transition: MembershipTransition::Entered,
        cause: MembershipCause::DataChange,
        evidence_hash: [0x11; EVIDENCE_HASH_LEN],
        definition_version: 1,
        scope_digest: [0x22; 32],
    };
    put_event(vault, &event).expect("event row");
    put_campaign_program(
        vault,
        &CampaignProgram {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref,
            campaign_ref,
        },
    )
    .expect("program row");
    put_campaign_program_step(
        vault,
        &CampaignProgramStep {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref,
            step_ref,
            channel: CHANNEL.to_owned(),
            sender_ref,
            basis_evidence: entity(0x58),
            outbound,
        },
    )
    .expect("step row");
    elect_campaign_home_node_designation(
        vault,
        &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
        1,
    )
    .expect("home-node designation");
    Fixture {
        event,
        payload: CampaignEnrollmentAttemptPayload {
            membership_event_ref: entity(0x53),
            campaign_program_ref: program_ref,
            program_step_ref: step_ref,
        },
    }
}

fn outbound_step() -> CampaignProgramOutbound {
    CampaignProgramOutbound {
        call_seq: 7,
        verb: VERB.to_owned(),
        payload: b"enrollment-body".to_vec(),
        idempotency_supported: true,
    }
}

/// Runs the outward leg as the designated node and unwraps its dispatch.
fn dispatch_leg<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    attempt: &AttemptRecord,
    transport: &mut T,
    now_ms: u64,
) -> IntentDispatchResult {
    match run_enrollment_outbound_leg(vault, authority, HOME_NODE, attempt, transport, now_ms)
        .expect("outbound leg")
    {
        EnrollmentOutboundLeg::Dispatched(dispatch) => dispatch,
        other => panic!("expected a dispatch, got {other:?}"),
    }
}

fn queued_attempt(vault: &Vault, fixture: &Fixture) -> AttemptRecord {
    let runner = CampaignEnrollmentRunner::new(vault);
    match runner
        .enqueue(&fixture.payload, None, 10)
        .expect("enqueue succeeds")
    {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
    }
}

// -----------------------------------------------------------------------
// Home-node election
// -----------------------------------------------------------------------

#[test]
fn campaign_home_node_election_matches_preference_order() {
    let designation = select_campaign_home_node(
        &[
            CampaignHomeNodeCandidate::primary_device(2),
            CampaignHomeNodeCandidate::always_on_local(9),
            CampaignHomeNodeCandidate::cloud(7, true),
        ],
        5,
    )
    .expect("election")
    .expect("an eligible candidate exists");
    assert_eq!(designation.class, CampaignHomeNodeClass::CloudAttached);
    assert_eq!(designation.node_id, 7);
    assert_eq!(designation.elected_at, 5);

    // A DETACHED cloud node is ineligible, not demoted: it does not become
    // a local candidate just because the cloud link dropped.
    let without_cloud = select_campaign_home_node(
        &[
            CampaignHomeNodeCandidate::cloud(7, false),
            CampaignHomeNodeCandidate::primary_device(2),
            CampaignHomeNodeCandidate::always_on_local(9),
        ],
        5,
    )
    .expect("election")
    .expect("an eligible candidate exists");
    assert_eq!(without_cloud.class, CampaignHomeNodeClass::AlwaysOnLocal);
    assert_eq!(without_cloud.node_id, 9);

    // Lowest stable node id wins inside a tier, whatever the input order.
    let tie = select_campaign_home_node(
        &[
            CampaignHomeNodeCandidate::always_on_local(9),
            CampaignHomeNodeCandidate::always_on_local(3),
            CampaignHomeNodeCandidate::always_on_local(6),
        ],
        5,
    )
    .expect("election")
    .expect("an eligible candidate exists");
    assert_eq!(tie.node_id, 3);

    assert_eq!(
        select_campaign_home_node(&[CampaignHomeNodeCandidate::cloud(7, false)], 5)
            .expect("election"),
        None,
        "an all-ineligible set clears the designation"
    );
}

#[test]
fn campaign_home_node_election_rejects_unusable_candidate_sets() {
    assert!(matches!(
        select_campaign_home_node(&[CampaignHomeNodeCandidate::always_on_local(0)], 1),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        select_campaign_home_node(
            &[
                CampaignHomeNodeCandidate::always_on_local(4),
                CampaignHomeNodeCandidate::primary_device(4),
            ],
            1
        ),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn campaign_designation_persists_under_the_campaign_key_only() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let elected = elect_campaign_home_node_designation(
        &vault,
        &[CampaignHomeNodeCandidate::always_on_local(11)],
        42,
    )?
    .expect("a candidate is eligible");

    assert_eq!(campaign_home_node_designation(&vault)?, Some(elected));
    assert!(
        read_meta(&vault, b"dreamer:home_node_macro:v1")?.is_none(),
        "the Dreamer's private designation key must be untouched"
    );

    // An empty candidate set clears the row rather than freezing a leader
    // that no longer exists.
    assert_eq!(elect_campaign_home_node_designation(&vault, &[], 43)?, None);
    assert_eq!(campaign_home_node_designation(&vault)?, None);
    Ok(())
}

#[test]
fn campaign_designation_row_fails_closed_on_malformed_input() {
    assert!(matches!(
        decode_designation(br#"{"schema_version":1,"node_id":3,"class":"always_on_local","elected_at":1,"extra":true}"#),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        decode_designation(
            br#"{"schema_version":2,"node_id":3,"class":"always_on_local","elected_at":1}"#
        ),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        decode_designation(
            br#"{"schema_version":1,"node_id":3,"class":"tertiary_toaster","elected_at":1}"#
        ),
        Err(Error::CorruptedIndex(_))
    ));
    assert!(matches!(
        decode_designation(
            br#"{"schema_version":1,"node_id":0,"class":"cloud_attached","elected_at":1}"#
        ),
        Err(Error::CorruptedIndex(_))
    ));
}

// -----------------------------------------------------------------------
// Payload
// -----------------------------------------------------------------------

#[test]
fn enrollment_attempt_payload_is_three_refs_and_nothing_else() -> Result<()> {
    let payload = CampaignEnrollmentAttemptPayload {
        membership_event_ref: entity(0x81),
        campaign_program_ref: entity(0x82),
        program_step_ref: entity(0x83),
    };
    let encoded = encode_enrollment_attempt_payload(&payload)?;
    assert_eq!(decode_enrollment_attempt_payload(&encoded)?, payload);

    let wire: serde_json::Value = serde_json::from_slice(&encoded).expect("payload is json");
    let keys: Vec<&str> = wire
        .as_object()
        .expect("payload is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "schema_version",
            "membership_event_ref",
            "campaign_program_ref",
            "program_step_ref"
        ],
        "no cause, epoch, evidence hash, timestamp, enrolled flag, or \
         outbound request may ride the queue"
    );

    // A payload that smuggles a cause is rejected outright, not ignored.
    assert!(matches!(
        decode_enrollment_attempt_payload(
            br#"{"schema_version":1,"membership_event_ref":"00","campaign_program_ref":"00","program_step_ref":"00","cause":"data_change"}"#
        ),
        Err(Error::CorruptedIndex(_))
    ));
    Ok(())
}

// -----------------------------------------------------------------------
// Outward leg
// -----------------------------------------------------------------------

#[test]
fn outward_enrollment_records_intent_before_transport() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let attempt = queued_attempt(&vault, &fixture);
    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

    let dispatch = dispatch_leg(&vault, &authority, &attempt, &mut transport, 50);

    assert_eq!(transport.ledger_rows_at_send, vec![1]);
    assert_eq!(dispatch.state, Some(IntentState::Done));
    assert!(!dispatch.replayed);
    let records = intent_ledger_records(&vault).expect("ledger");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].attempt_id,
        enrollment_consequence_id(
            &fixture.event,
            &resolve_program_step(&vault, &fixture.payload, &fixture.event)?
        )?
    );
    assert_eq!(records[0].call_seq, 7);
    assert_eq!(transport.sent_intents, vec![records[0].id]);
    Ok(())
}

#[test]
fn outward_intent_uses_durable_consequence_and_call_sequence() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let attempt = queued_attempt(&vault, &fixture);

    let step = resolve_program_step(&vault, &fixture.payload, &fixture.event)?;
    let consequence = enrollment_consequence_id(&fixture.event, &step)?;
    let derived = enrollment_intent_id(&fixture.event, &step)?.expect("an outward leg exists");

    // Clock-free and process-free: recomputing from the same durable inputs
    // reproduces the identity a restarted process would use.
    assert_eq!(
        derived,
        derive_intent_id(
            consequence,
            7,
            CHANNEL,
            VERB,
            &crate::outbound_intent_ledger::hash_frozen_payload(b"enrollment-body"),
        )
        .expect("intent id")
    );

    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
    let dispatch = dispatch_leg(&vault, &authority, &attempt, &mut transport, 50);
    assert_eq!(dispatch.intent_id, Some(derived));

    let request = derive_enrollment_outbound_request(&vault, &fixture.payload, &fixture.event, 50)?
        .expect("an outward leg exists");
    assert_eq!(request.attempt_id, consequence);
    assert_ne!(
        request.attempt_id, attempt.id,
        "the ledger identity belongs to the consequence, not the queue row"
    );
    assert_eq!(request.call_seq, 7);
    Ok(())
}

#[test]
fn crash_after_send_before_queue_complete_reuses_the_frozen_intent() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let attempt = queued_attempt(&vault, &fixture);
    let authority = OutboundBindingAuthority::for_vault(&vault)?;

    let mut first = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Ambiguous);
    let ambiguous = dispatch_leg(&vault, &authority, &attempt, &mut first, 50);
    assert_eq!(ambiguous.state, Some(IntentState::Pending));

    // The recovery path re-enters with the SAME attempt row. It must reuse
    // the frozen bytes and identity, never mint a fresh send.
    let mut second = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
    let replay = dispatch_leg(&vault, &authority, &attempt, &mut second, 60);
    assert!(replay.replayed);
    assert_eq!(replay.intent_id, ambiguous.intent_id);
    assert_eq!(second.sent_intents, first.sent_intents);
    assert_eq!(second.sent_payload_hashes, first.sent_payload_hashes);
    assert_eq!(
        intent_ledger_records(&vault).expect("ledger").len(),
        1,
        "recovery must not open a second intent"
    );
    Ok(())
}

#[test]
fn outward_leg_is_absent_when_the_program_step_declares_none() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, None);
    let attempt = queued_attempt(&vault, &fixture);
    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

    assert_eq!(
        run_enrollment_outbound_leg(&vault, &authority, HOME_NODE, &attempt, &mut transport, 50)
            .expect("outbound leg"),
        EnrollmentOutboundLeg::NoOutboundStep
    );
    assert!(transport.sent_intents.is_empty());
    assert!(intent_ledger_records(&vault).expect("ledger").is_empty());
    Ok(())
}

#[test]
fn gate_rejection_prevents_a_direct_send() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    // The installed policy grants `external:send` on this channel and
    // nothing else. A step declaring an UNGRANTED verb must be stopped by
    // the ordinary gate — not by a campaign-local check, and not at all.
    let fixture = install_fixture(
        &vault,
        Some(CampaignProgramOutbound {
            call_seq: 7,
            verb: "call".to_owned(),
            payload: b"enrollment-body".to_vec(),
            idempotency_supported: true,
        }),
    );
    let attempt = queued_attempt(&vault, &fixture);
    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

    let dispatch = dispatch_leg(&vault, &authority, &attempt, &mut transport, 50);

    assert_eq!(dispatch.state, None);
    assert_eq!(dispatch.send_outcome, None);
    assert!(
        transport.sent_intents.is_empty(),
        "no connector was reached"
    );
    assert!(
        intent_ledger_records(&vault).expect("ledger").is_empty(),
        "a refused effect leaves no frozen intent behind"
    );
    Ok(())
}

/// The advisory dedupe key is allowed to fail — that is the whole design.
/// When it does, one transition reaches the queue as two attempts, and both
/// owe an outward leg (an `AlreadyApplied` membership still has a send to
/// recover). If the ledger identity were a function of the QUEUE ROW, those
/// two attempts would freeze two intents and send the enrollment twice.
#[test]
fn duplicate_attempts_for_one_transition_send_once() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let authority = OutboundBindingAuthority::for_vault(&vault)?;

    let queue = AttemptQueue::new(&vault);
    let mut attempts = Vec::new();
    for now in [10, 11] {
        match queue.enqueue(EnqueueAttempt {
            kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
            payload: encode_enrollment_attempt_payload(&fixture.payload)?,
            dedupe_key: None,
            run_id: None,
            now,
        })? {
            EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => {
                attempts.push(record);
            }
        }
    }
    assert_ne!(attempts[0].id, attempts[1].id, "two real queue rows");

    let mut first = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
    let one = dispatch_leg(&vault, &authority, &attempts[0], &mut first, 50);
    let mut second = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);
    let two = dispatch_leg(&vault, &authority, &attempts[1], &mut second, 60);

    assert_eq!(one.intent_id, two.intent_id);
    assert!(two.replayed);
    assert_eq!(first.sent_intents.len(), 1);
    assert!(
        second.sent_intents.is_empty(),
        "the duplicate attempt reaches no connector"
    );
    assert_eq!(
        intent_ledger_records(&vault).expect("ledger").len(),
        1,
        "one transition, one frozen intent"
    );
    Ok(())
}

/// The outward leg is the crash-recovery entry point, so it cannot borrow
/// the membership leg's authority: a node can apply the cohort row while
/// designated and come back for the send after losing designation.
#[test]
fn outward_leg_refuses_a_demoted_node() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let attempt = queued_attempt(&vault, &fixture);
    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    elect_campaign_home_node_designation(
        &vault,
        &[CampaignHomeNodeCandidate::always_on_local(OTHER_NODE)],
        40,
    )?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

    assert!(matches!(
        run_enrollment_outbound_leg(&vault, &authority, HOME_NODE, &attempt, &mut transport, 50)
            .expect("outbound leg"),
        EnrollmentOutboundLeg::NotHomeNode(designation)
            if designation.node_id == OTHER_NODE
    ));
    assert!(
        transport.sent_intents.is_empty(),
        "a demoted node must not reach transport"
    );
    assert!(
        intent_ledger_records(&vault).expect("ledger").is_empty(),
        "and must not freeze an intent on the way there"
    );
    Ok(())
}

#[test]
fn outward_leg_refuses_a_foreign_attempt_kind() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let mut attempt = queued_attempt(&vault, &fixture);
    attempt.kind = "dreamer.consolidation.macro".to_owned();
    let authority = OutboundBindingAuthority::for_vault(&vault)?;
    let mut transport = LedgerWitnessTransport::new(&vault, OutboundSendOutcome::Acked);

    assert!(
        run_enrollment_outbound_leg(&vault, &authority, HOME_NODE, &attempt, &mut transport, 50)
            .is_err()
    );
    assert!(transport.sent_intents.is_empty());
    Ok(())
}

#[test]
fn mismatched_program_refs_fail_closed() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));

    // A program belonging to a DIFFERENT campaign must not be usable just
    // because the caller pointed the payload at it.
    let foreign_program = entity(0x61);
    put_campaign_program(
        &vault,
        &CampaignProgram {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref: foreign_program,
            campaign_ref: entity(0x62),
        },
    )?;
    let crossed = CampaignEnrollmentAttemptPayload {
        campaign_program_ref: foreign_program,
        ..fixture.payload
    };
    assert!(matches!(
        resolve_program_step(&vault, &crossed, &fixture.event),
        Err(Error::InvalidConfig(_))
    ));

    // A step ref that does not resolve under the program is not silently
    // skipped either.
    let dangling = CampaignEnrollmentAttemptPayload {
        program_step_ref: entity(0x63),
        ..fixture.payload
    };
    assert!(matches!(
        resolve_program_step(&vault, &dangling, &fixture.event),
        Err(Error::EntityNotFound)
    ));
    Ok(())
}

#[test]
fn enqueue_refuses_an_unresolvable_membership_ref() {
    let (_dir, vault) = vault_fixture();
    let runner = CampaignEnrollmentRunner::new(&vault);
    assert!(matches!(
        runner.enqueue(
            &CampaignEnrollmentAttemptPayload {
                membership_event_ref: entity(0x71),
                campaign_program_ref: entity(0x72),
                program_step_ref: entity(0x73),
            },
            None,
            1,
        ),
        Err(Error::EntityNotFound)
    ));
}

#[test]
fn enqueued_attempt_uses_exactly_the_one_kind() -> Result<()> {
    let (_dir, vault) = vault_fixture();
    let fixture = install_fixture(&vault, Some(outbound_step()));
    let attempt = queued_attempt(&vault, &fixture);
    assert_eq!(attempt.kind, "campaign.enrollment.macro");
    assert_eq!(attempt.kind, CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND);
    assert_eq!(attempt.state, AttemptState::Queued);
    assert_eq!(
        decode_enrollment_attempt_payload(&attempt.payload)?,
        fixture.payload
    );
    Ok(())
}

// -----------------------------------------------------------------------
// CA-04 re-entry (ONE-1775) — the enqueue SUCCESS arm
// -----------------------------------------------------------------------

/// ONE-1775's `snooze_with_wake` reaches this module's enqueue door only
/// through `ReentryPlan::reentry_attempt`, and that door needs a PERSISTED
/// [`CampaignEnrollmentEvent`] — whose writer, [`put_event`], is
/// module-private by design (an event is engine-detected, never
/// caller-asserted). A cross-module oracle can therefore only reach the
/// REFUSAL arm, which is exactly where ONE-1779 stopped: an unresolvable
/// membership ref is [`Error::EntityNotFound`] with the membership left
/// untouched. The success arm is reachable from inside the owning module
/// and nowhere else, so it is asserted here.
///
/// One call, two durable consequences: the membership pauses AND the
/// re-entry attempt lands, keyed by this module's own dedupe key.
#[test]
fn reentry_snooze_pauses_the_member_and_enqueues_the_attempt() -> Result<()> {
    // The `campaign.` predicates carry no rule in the default policy
    // manifest, so seeding a cohort row under it lands `pending` on the
    // criticality floor. The CA-01/CA-03/CA-04 oracles all take the same
    // carve-out: the subject here is the re-entry seam, not the manifest.
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let fixture = install_enrollment_rows(&vault, Some(outbound_step()));
    let step = resolve_program_step(&vault, &fixture.payload, &fixture.event)?;
    let party = entity(REENTRY_PARTY_SEED);

    // The cohort row as CA-03's OWN membership leg writes it: the channel
    // comes from the persisted program step, so the row this re-entry
    // pauses is one this module could actually have produced.
    let member = CampaignMemberValue {
        campaign: fixture.event.campaign_ref,
        state: CampaignMemberState::Enrolled,
        channels: vec![step.member_channel()],
        derivation: None,
    };
    put_enrolled_member(&vault, party, &member);

    let plan = ReentryPlan {
        party_ref: party,
        campaign_ref: fixture.event.campaign_ref,
        wake: WakeCondition::AtOrNewTrigger {
            at: REENTRY_AT + 60,
        },
        restart_touch_index: 0,
        reason_evidence_ref: entity(REENTRY_REASON_SEED),
        reentry_attempt: Some(fixture.payload),
    };
    let paused_ref = snooze_with_wake(&vault, &entity(REENTRY_MEMBER_SEED), &plan, REENTRY_AT)?;

    // Consequence one: the pause carries BOTH wake fields, and the channel
    // rows that authorize contact ride across the transition. A pause
    // changes state; it does not erase what authorized the outreach.
    let body = vault
        .get_claim(&paused_ref)?
        .expect("the replacement head exists");
    assert_eq!(
        decode_campaign_member_value(&body.value)?,
        CampaignMemberValue {
            state: CampaignMemberState::Paused {
                until: Some(REENTRY_AT + 60),
                new_trigger: Some(true),
            },
            ..member
        },
    );

    // Consequence two — the arm only this module can reach: the attempt
    // ACTUALLY LANDED. One row, this module's one kind, still queued, and
    // carrying the refs-only payload under CA-03's own advisory key.
    let queued = AttemptQueue::new(&vault).list()?;
    assert_eq!(queued.len(), 1, "one re-entry, one queue row");
    assert_eq!(queued[0].kind, CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND);
    assert_eq!(queued[0].state, AttemptState::Queued);
    assert_eq!(
        queued[0].dedupe_key,
        Some(enrollment_dedupe_key(&vault, &fixture.payload)?),
    );
    let landed = decode_enrollment_attempt_payload(&queued[0].payload)?;
    assert_eq!(landed, fixture.payload);

    // And the row is EXECUTABLE, not a dangling pointer: the refs it
    // carries still cross-bind to the step that will do the work.
    assert_eq!(resolve_program_step(&vault, &landed, &fixture.event)?, step);
    Ok(())
}

/// Seeds the PERSON and the live `campaign.member` head a re-entry pauses.
fn put_enrolled_member(vault: &Vault, party: EntityId, member: &CampaignMemberValue) {
    vault
        .put_entity(
            &party,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"campaign re-entry party",
        )
        .expect("seed re-entry party");
    vault
        .put_claim(
            &entity(REENTRY_MEMBER_SEED),
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(party),
                encode_campaign_member_value(member),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("seed campaign.member head");
}
