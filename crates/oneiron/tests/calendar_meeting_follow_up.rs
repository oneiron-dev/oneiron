//! CAL-08 (Engine RULING CAL-08-FOLLOWUP-APPROVAL = A, Sun 15 Nov 12:04;
//! canon ARCH-0060:190 "drafts, never sends"): every follow-up a meeting
//! transcript yields is a draft in the owner's inbox, internal meetings
//! included, and approving it is the one way it reaches the outbound gate.
//!
//! A draft is written `Proposed` and `Imported` about the PERSON it goes to,
//! citing the transcript's TURNs, and sends nothing. It waits in its
//! meeting's own run, `mfu:<session hex>`. The owner's approval of that run
//! schedules exactly one send, to the recipient's native route, as the agent
//! that wrote the draft; a second approval pass keeps that one send. A
//! declined run, and a recipient the vault cannot reach natively, send
//! nothing. A retracted draft stops the send it scheduled, and its words are
//! no longer read out for it.
//!
//! The agent holds the full-access ceiling and a standing `send` grant, so
//! the outbound gate admits its sends to the queue as it admits a granted
//! send in production; the route is on `email_resend`, a channel with a
//! `send` verb that no built-in pack names (a seeded vault refuses a channel
//! a built-in pack names until that pack is installed).
//!
//! Red on main: the follow-up door does not exist, so this file does not
//! build there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_meeting_follow_up`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::attempt_queue::AttemptId;
use oneiron::calendar::follow_up::{
    MeetingFollowUpDraft, PREDICATE_MEETING_FOLLOW_UP, approved_meeting_follow_up,
    meeting_follow_up_run_id, meeting_follow_up_send_ref, schedule_approved_meeting_follow_ups,
    write_meeting_follow_up_draft,
};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound::ConnectorSendTask;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    ClaimSubject, EdgeActorClass, EntityId, GateConsentBundleAction, TimeRange, Vault, VaultConfig,
};

const NOW: u64 = 1_800_000_000;
/// A channel with a `send` verb that no built-in pack names.
const CHANNEL: &str = "email_resend";
const RECIPIENT_ADDRESS: &str = "yuki@example.com";
const OWN_ADDRESS: &str = "assistant@example.com";
const TRANSCRIPT: &str = "Owen: I will send you the slides tomorrow\nYuki: Thanks, that helps";
const WORDS: &str = "Hi Yuki, here are the slides from today's meeting.";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The agent that writes the drafts.
    agent: EntityId,
    session_ref: EntityId,
    turn_refs: Vec<EntityId>,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns, as an embedded host opens it, with the
/// engine's MACHINE writers provisioned.
fn open_owned(path: &Path) -> (Vault, EntityId) {
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(path, config).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = open_owned(dir.path());
    let agent = common::entity(0xC4);
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"follow-up agent",
        )
        .expect("put the agent");
    let (session_ref, turn_refs) = ingest_meeting(&vault, TRANSCRIPT, 0);
    let fx = Fixture {
        vault,
        owner,
        agent,
        session_ref,
        turn_refs,
        _dir: dir,
    };
    fx.vault
        .grant_agent_principal(&fx.owner_proof(), &agent.to_hex(), AgentCeiling::Auto)
        .expect("the owner gives the agent the full-access ceiling");
    fx.vault
        .mint_standing_outbound_grant(
            &fx.owner_proof(),
            common::entity(0xD4),
            &GrantMintIntent {
                principal_ref: agent.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
        )
        .expect("the owner grants the agent's sends");
    fx
}

/// One file-drop meeting transcript: its SESSION and TURNs.
fn ingest_meeting(vault: &Vault, text: &str, offset_ms: u64) -> (EntityId, Vec<EntityId>) {
    let TranscriptIngestOutcome::Session {
        session_ref,
        turn_refs,
        ..
    } = ingest_file_drop_transcript(
        vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: text,
            arrived_at_ms: NOW * 1_000 + offset_ms,
        },
    )
    .expect("the transcript lands")
    else {
        panic!("a speaker transcript mints a session");
    };
    (session_ref, turn_refs)
}

impl Fixture {
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// A PERSON the vault already knows on `CHANNEL`: a comm party, one of
    /// our own active identities there, and a live contact on it.
    fn reachable_recipient(&self) -> EntityId {
        let person = oneiron::comm::resolve_or_create_comm_party(&self.vault, RECIPIENT_ADDRESS)
            .expect("the recipient's comm party");
        let identity_ref = common::entity(0x7C);
        let identity = common::self_held_identity_in_state(
            CHANNEL,
            OWN_ADDRESS,
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::vault(1),
            ChannelIdentityState::Active,
            NOW,
        );
        self.vault
            .create_channel_identity(&identity_ref, &identity)
            .expect("our active identity");
        self.vault
            .create_counterparty_contact(
                &common::entity(0x7D),
                &CounterpartyContactRecord::user_introduction(identity_ref, RECIPIENT_ADDRESS, NOW)
                    .expect("contact record"),
            )
            .expect("a live contact with the recipient");
        let route = oneiron::human_task::resolve_native_human_route(&self.vault, person)
            .expect("precondition: the recipient has a native route");
        assert_eq!(route.channel, CHANNEL);
        person
    }

    fn draft_for(&self, recipient: EntityId) -> MeetingFollowUpDraft {
        MeetingFollowUpDraft {
            session_ref: self.session_ref,
            recipient,
            text: WORDS.to_owned(),
            turn_refs: self.turn_refs.clone(),
        }
    }

    fn write(&self, draft: &MeetingFollowUpDraft) -> oneiron::Result<EntityId> {
        write_meeting_follow_up_draft(
            &self.vault,
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            AttemptId::now(),
            draft,
        )
    }

    /// The owner's decision on the meeting's run, through the run approval
    /// door the owner's server route takes; the claims it decided.
    fn decide(&self, action: GateConsentBundleAction) -> Vec<EntityId> {
        let run = meeting_follow_up_run_id(&self.session_ref);
        let bundle = self
            .vault
            .review_gate_consent_bundle(&WriteActor::new(self.owner, EdgeActorClass::Human), &run)
            .expect("the owner reviews the meeting's follow-ups");
        self.vault
            .resolve_gate_consent_bundle(
                &self.owner_proof(),
                bundle.bundle_id,
                &run,
                action,
                NOW + 5,
            )
            .expect("the owner decides the run")
            .member_claim_ids
    }

    /// Scheduled sends that name `claim`'s draft.
    fn sends_of(&self, claim: &EntityId) -> Vec<ConnectorSendTask> {
        let send_ref = meeting_follow_up_send_ref(claim);
        self.vault
            .connector_send_tasks()
            .expect("connector send tasks")
            .into_iter()
            .filter(|task| task.intent.trigger_ref == send_ref)
            .collect()
    }
}

#[test]
fn a_written_draft_waits_in_its_meetings_run_and_sends_nothing() {
    let fx = fixture();
    let recipient = fx.reachable_recipient();
    let draft = fx.draft_for(recipient);
    let before = fx.vault.standalone_outbound_intent_count().unwrap();

    let claim = fx.write(&draft).expect("the draft is written");

    let body = fx
        .vault
        .get_claim(&claim)
        .unwrap()
        .expect("the draft lands");
    assert_eq!(body.predicate, PREDICATE_MEETING_FOLLOW_UP);
    assert_eq!(body.subject, ClaimSubject::Entity(recipient));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Imported));
    let bundle = fx
        .vault
        .review_gate_consent_bundle(
            &WriteActor::new(fx.owner, EdgeActorClass::Human),
            &meeting_follow_up_run_id(&fx.session_ref),
        )
        .expect("the draft waits in its meeting's run");
    let members: Vec<_> = bundle
        .members
        .iter()
        .map(|member| member.claim_id)
        .collect();
    assert_eq!(members, vec![claim]);
    assert!(fx.vault.connector_send_tasks().unwrap().is_empty());
    assert_eq!(fx.vault.standalone_outbound_intent_count().unwrap(), before);

    // The same draft again is the claim already written.
    assert_eq!(fx.write(&draft).expect("a replayed draft"), claim);
    assert!(
        approved_meeting_follow_up(&fx.vault, &claim).is_err(),
        "an undecided draft mints no approved token"
    );
}

#[test]
fn approving_the_run_schedules_one_send_to_the_native_route() {
    let fx = fixture();
    let recipient = fx.reachable_recipient();
    let claim = fx.write(&fx.draft_for(recipient)).expect("the draft");

    let decided = fx.decide(GateConsentBundleAction::Approve);
    assert_eq!(decided, vec![claim]);
    let scheduled = schedule_approved_meeting_follow_ups(&fx.vault, &decided);
    assert_eq!(scheduled.len(), 1, "{scheduled:?}");
    assert_eq!(scheduled[0].0, claim);
    let receipt = scheduled[0]
        .1
        .as_ref()
        .expect("the approved draft schedules");
    assert!(receipt.intent_ref.starts_with("intent:"), "{receipt:?}");

    let sends = fx.sends_of(&claim);
    assert_eq!(sends.len(), 1, "one send for the approved draft");
    let send = &sends[0];
    let send_ref = meeting_follow_up_send_ref(&claim);
    assert_eq!(send.actor_ref, fx.agent, "the send is the drafting agent's");
    assert_eq!(send.intent.intent_source, "meeting_follow_up");
    assert_eq!(send.intent.verb, "send");
    assert_eq!(send.intent.channel, CHANNEL);
    assert_eq!(send.intent.target, RECIPIENT_ADDRESS);
    assert_eq!(send.intent.content_ref.as_deref(), Some(send_ref.as_str()));
    assert_eq!(
        send.intent.idempotency_key.as_deref(),
        Some(send_ref.as_str())
    );
    assert_eq!(
        fx.vault
            .outbound_content_text(&send_ref)
            .unwrap()
            .as_deref(),
        Some(WORDS),
        "the send carries the approved words"
    );
    assert!(
        oneiron::test_doors::meeting_follow_up::scheduled_send_authorised(
            &fx.vault,
            &send.task_ref
        )
        .unwrap(),
        "the standing approval authorises its send"
    );

    // A second approval pass keeps the one send.
    let again = schedule_approved_meeting_follow_ups(&fx.vault, &decided);
    assert!(again[0].1.is_ok(), "{again:?}");
    assert_eq!(fx.sends_of(&claim).len(), 1, "a replay coalesces");
}

#[test]
fn declining_the_run_schedules_nothing() {
    let fx = fixture();
    let recipient = fx.reachable_recipient();
    let claim = fx.write(&fx.draft_for(recipient)).expect("the draft");

    let decided = fx.decide(GateConsentBundleAction::Decline);
    assert_eq!(decided, vec![claim]);
    assert!(schedule_approved_meeting_follow_ups(&fx.vault, &decided).is_empty());
    assert!(fx.vault.connector_send_tasks().unwrap().is_empty());
    assert_ne!(
        fx.vault.get_claim(&claim).unwrap().unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert!(approved_meeting_follow_up(&fx.vault, &claim).is_err());
}

#[test]
fn a_recipient_with_no_native_route_reports_and_sends_nothing() {
    let fx = fixture();
    let stranger = common::entity(0x6E);
    fx.vault
        .put_entity(
            &stranger,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"a person with no route",
        )
        .unwrap();
    let claim = fx.write(&fx.draft_for(stranger)).expect("the draft");

    let decided = fx.decide(GateConsentBundleAction::Approve);
    let scheduled = schedule_approved_meeting_follow_ups(&fx.vault, &decided);
    assert!(
        matches!(scheduled.as_slice(), [(id, Err(_))] if *id == claim),
        "the approval reports the draft it could not send: {scheduled:?}"
    );
    assert!(fx.vault.connector_send_tasks().unwrap().is_empty());
}

#[test]
fn a_retracted_draft_stops_its_scheduled_send() {
    let fx = fixture();
    let recipient = fx.reachable_recipient();
    let claim = fx.write(&fx.draft_for(recipient)).expect("the draft");
    let decided = fx.decide(GateConsentBundleAction::Approve);
    schedule_approved_meeting_follow_ups(&fx.vault, &decided)[0]
        .1
        .as_ref()
        .expect("the approved draft schedules");
    let task_ref = fx.sends_of(&claim)[0].task_ref;
    assert!(
        oneiron::test_doors::meeting_follow_up::scheduled_send_authorised(&fx.vault, &task_ref)
            .unwrap()
    );

    fx.vault.retract_claim(&claim, NOW + 10).expect("retract");

    assert!(
        !oneiron::test_doors::meeting_follow_up::scheduled_send_authorised(&fx.vault, &task_ref)
            .unwrap(),
        "a retracted draft authorises no send"
    );
    assert!(
        fx.vault
            .outbound_content_text(&meeting_follow_up_send_ref(&claim))
            .is_err(),
        "a retracted draft's words are not read out"
    );
}

#[test]
fn a_draft_cites_only_its_own_meetings_turns_and_has_words() {
    let fx = fixture();
    let recipient = fx.reachable_recipient();
    let (_other_session, other_turns) =
        ingest_meeting(&fx.vault, "Ada: one more thing\nBob: noted", 60_000);
    let mut foreign = fx.draft_for(recipient);
    foreign.turn_refs = other_turns;
    assert!(
        fx.write(&foreign).is_err(),
        "a turn of another meeting is not this meeting's evidence"
    );
    let mut empty = fx.draft_for(recipient);
    empty.text = "   ".to_owned();
    assert!(fx.write(&empty).is_err(), "a draft has words");
    let mut uncited = fx.draft_for(recipient);
    uncited.turn_refs.clear();
    assert!(fx.write(&uncited).is_err(), "a draft cites its turns");
    assert!(fx.vault.connector_send_tasks().unwrap().is_empty());
}
