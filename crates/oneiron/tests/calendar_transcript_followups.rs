//! CAL-08's producer (Engine RULINGs CAL-08-FOLLOWUP-APPROVAL = A, Sun 15
//! Nov 12:04; CAL-08-FOLLOWUP-OWNER-SPEAKER = A and
//! CAL-08-FOLLOWUP-UNKNOWN-RECIPIENT = A, 14:49): a meeting transcript's
//! landing queues one drafting attempt, and a host worker's model drafts the
//! follow-ups the owner promised in it. Each one is a draft in the owner's
//! inbox; nothing is sent.
//!
//! The drafting model here is scripted ([`ScriptedDrafter`]), and the
//! attempt is claimed and run as a host worker runs it. Only the owner's own
//! promises become drafts: the engine marks the TURNs whose speaker label is
//! one of the owner's names, and a transcript with none asks no model. A
//! draft goes only to a PERSON the request listed, those the vault knows by a
//! name the transcript says.
//!
//! Red on main: the producer does not exist, so this file does not build
//! there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_transcript_followups`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::calendar::follow_up::{
    MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND, MeetingFollowUpDraftPayload, MeetingFollowUpDrafter,
    MeetingFollowUpRead, MeetingFollowUpRequest, MeetingFollowUpRunOutcome, MeetingFollowUpSilence,
    MeetingFollowUpSource, PREDICATE_MEETING_FOLLOW_UP, meeting_follow_up_run_id,
    run_meeting_follow_up_drafting,
};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::provenance::made_by::MadeByInputRole;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::settings::ReadDestination;
use oneiron::store::ports::ManualClock;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const NOW: u64 = 1_800_000_000;
/// Whom the tests claim drafting attempts as.
const LEASE_OWNER: &str = "follow-up-drafting-test";
const TRANSCRIPT: &str = "Owen: I will send you the slides tomorrow\nYuki: Thanks, that helps";
const WORDS: &str = "Hi Yuki, here are the slides from today's meeting.";

/// A drafting model that answers one scripted reply and keeps each request.
struct ScriptedDrafter {
    reply: String,
    asked: RefCell<Vec<MeetingFollowUpRequest>>,
}

impl ScriptedDrafter {
    fn replying(reply: &str) -> Self {
        Self {
            reply: reply.to_owned(),
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl MeetingFollowUpDrafter for ScriptedDrafter {
    fn draft(&self, request: &MeetingFollowUpRequest) -> oneiron::Result<String> {
        self.asked.borrow_mut().push(request.clone());
        Ok(self.reply.clone())
    }
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns, as an embedded host opens it, with the
/// engine's MACHINE writers provisioned and this install's signing keys
/// loaded (the Dreamer signs the drafts it writes).
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = open_owned(dir.path());
    Fixture {
        vault,
        owner,
        _dir: dir,
    }
}

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

impl Fixture {
    /// The owner's name, as a names-class claim about the owner's PERSON.
    fn name_the_owner(&self, name: &str) {
        self.vault
            .put_claim(
                &EntityId::now(),
                &ClaimBody::new(
                    "person.name",
                    ClaimSubject::Entity(self.owner),
                    Value::from(name),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                )
                .expect("the name claim"),
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("the owner's name");
    }

    /// A PERSON the vault knows by `name`.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(Value::from("name"), Value::from(name))]),
        )
        .expect("encode the person body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                &body,
            )
            .expect("put the person");
        id
    }

    /// One file-drop meeting transcript: its SESSION and TURNs.
    fn ingest(&self, text: &str, offset_ms: u64) -> (EntityId, Vec<EntityId>) {
        let TranscriptIngestOutcome::Session {
            session_ref,
            turn_refs,
            ..
        } = ingest_file_drop_transcript(
            &self.vault,
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

    /// Every queued drafting attempt's SESSION, sorted.
    fn queued_sessions(&self) -> Vec<String> {
        let mut sessions: Vec<String> = AttemptQueue::new(&self.vault)
            .list()
            .expect("the attempt queue")
            .into_iter()
            .filter(|attempt| attempt.kind == MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND)
            .map(|attempt| payload(&attempt).session_ref)
            .collect();
        sessions.sort();
        sessions
    }

    /// The next due drafting attempt, claimed as the host's worker claims it.
    fn claim(&self) -> AttemptRecord {
        let claimed = AttemptQueue::new(&self.vault)
            .claim_kind(
                MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: LEASE_OWNER.to_owned(),
                    now: self.vault.now_recorded_at(),
                },
            )
            .expect("claim a drafting attempt");
        let ClaimOutcome::Claimed(attempt) = claimed else {
            panic!("a drafting attempt is queued");
        };
        attempt
    }

    fn run(
        &self,
        drafter: &ScriptedDrafter,
        attempt: &AttemptRecord,
    ) -> oneiron::Result<MeetingFollowUpRunOutcome> {
        run_meeting_follow_up_drafting(
            &self.vault,
            drafter,
            &ReadDestination::on_device(),
            attempt,
            LEASE_OWNER,
        )
    }

    /// The claims waiting in `session`'s run.
    fn waiting(&self, session: &EntityId) -> Vec<EntityId> {
        let Ok(bundle) = self.vault.review_gate_consent_bundle(
            &WriteActor::new(self.owner, EdgeActorClass::Human),
            &meeting_follow_up_run_id(session),
        ) else {
            return Vec::new();
        };
        bundle
            .members
            .iter()
            .map(|member| member.claim_id)
            .collect()
    }

    fn follow_up_claims(&self, about: EntityId) -> Vec<(EntityId, ClaimBody)> {
        self.vault
            .claims_for_subject(&about)
            .expect("claims about the person")
            .into_iter()
            .filter_map(|id| {
                let body = self.vault.get_claim(&id).expect("get claim")?;
                (body.predicate == PREDICATE_MEETING_FOLLOW_UP).then_some((id, body))
            })
            .collect()
    }
}

fn payload(attempt: &AttemptRecord) -> MeetingFollowUpDraftPayload {
    serde_json::from_slice(&attempt.payload).expect("a drafting payload")
}

fn reply(items: &[serde_json::Value]) -> String {
    serde_json::json!({ "follow_ups": items }).to_string()
}

fn item(recipient: &str, text: &str, turns: &[&str]) -> serde_json::Value {
    serde_json::json!({ "recipient": recipient, "text": text, "evidence_turn_refs": turns })
}

#[test]
fn parsable_transcript_yields_session_then_followups() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    let yuki = fx.person("Yuki");
    let before = fx.vault.standalone_outbound_intent_count().unwrap();

    let (session, turns) = fx.ingest(TRANSCRIPT, 0);
    assert_eq!(turns.len(), 2, "one TURN per transcript line");
    assert_eq!(
        fx.queued_sessions(),
        vec![session.to_hex()],
        "the landing queues one drafting attempt for its SESSION"
    );

    let attempt = fx.claim();
    let drafter = ScriptedDrafter::replying(&reply(&[item("P1", WORDS, &["T1", "T2"])]));
    let outcome = fx.run(&drafter, &attempt).expect("the attempt runs");
    let MeetingFollowUpRunOutcome::Filed(written) = outcome else {
        panic!("the transcript is read and the reply filed, not {outcome:?}");
    };

    let asked = drafter.asked.borrow();
    assert_eq!(asked.len(), 1, "one model call");
    let request = &asked[0];
    assert_eq!(request.turns.len(), 2);
    assert_eq!(request.turns[0].label, "T1");
    assert_eq!(request.turns[0].speaker, "Owen");
    assert!(
        request.turns[0].owner,
        "the owner's name marks the owner's line"
    );
    assert!(
        !request.turns[1].owner,
        "another speaker's line is not the owner's"
    );
    assert_eq!(
        request.recipients.len(),
        1,
        "only the PERSON the transcript names"
    );
    assert_eq!(request.recipients[0].label, "P1");
    assert_eq!(request.recipients[0].name, "Yuki");
    let message = request.transcript_message();
    assert!(message.contains("[T1] Owen: I will send you the slides tomorrow"));
    assert!(message.contains("P1 \"Yuki\""));

    let drafts = fx.follow_up_claims(yuki);
    assert_eq!(drafts.len(), 1, "one draft, about its recipient");
    let (claim, body) = &drafts[0];
    assert_eq!(written, vec![*claim]);
    assert_eq!(body.subject, ClaimSubject::Entity(yuki));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Imported));
    let birth = fx
        .vault
        .row_birth(claim)
        .unwrap()
        .expect("the draft carries a birth");
    let prompt: Vec<EntityId> = birth
        .made_by
        .inputs
        .iter()
        .filter(|input| input.role == MadeByInputRole::Prompt)
        .map(|input| input.row)
        .collect();
    assert_eq!(
        prompt,
        vec![turns[0], turns[1], yuki],
        "the birth names every row the prompt carried: the meeting's TURNs, then Yuki's name row"
    );
    assert_eq!(
        fx.waiting(&session),
        vec![*claim],
        "the draft waits for the owner in its meeting's run"
    );
    assert!(fx.vault.connector_send_tasks().unwrap().is_empty());
    assert_eq!(fx.vault.standalone_outbound_intent_count().unwrap(), before);

    // A second meeting queues its own attempt.
    let (second, _) = fx.ingest(TRANSCRIPT, 60_000);
    let mut both = vec![session.to_hex(), second.to_hex()];
    both.sort();
    assert_eq!(fx.queued_sessions(), both);
}

#[test]
fn no_owner_speaker_asks_no_model_and_drafts_nothing() {
    let fx = fixture();
    let yuki = fx.person("Yuki");
    let (session, _) = fx.ingest(TRANSCRIPT, 0);

    // The owner's PERSON carries only its placeholder name.
    let read = fx
        .vault
        .meeting_follow_up_source_for(
            &MeetingFollowUpDraftPayload {
                session_ref: session.to_hex(),
            },
            &ReadDestination::on_device(),
        )
        .expect("read the transcript");
    assert!(
        matches!(
            read,
            MeetingFollowUpRead::Silent(MeetingFollowUpSilence::NoOwnerSpeaker)
        ),
        "no speaker is the owner: {read:?}"
    );

    let attempt = fx.claim();
    let drafter = ScriptedDrafter::replying(&reply(&[item("P1", WORDS, &["T1"])]));
    let outcome = fx.run(&drafter, &attempt).expect("the attempt runs");
    assert_eq!(outcome, MeetingFollowUpRunOutcome::Nothing);
    assert!(drafter.asked.borrow().is_empty(), "no model call");
    assert!(fx.follow_up_claims(yuki).is_empty());
    assert!(fx.waiting(&session).is_empty());
}

#[test]
fn only_the_owners_promises_to_listed_people_become_drafts() {
    let fx = fixture();
    fx.name_the_owner("Owen Park");
    let yuki = fx.person("Yuki Tanaka");
    let (session, _) = fx.ingest(
        "Owen: I will send you the slides tomorrow\n\
         Yuki: And I will send you the budget\n\
         Owen: I will also send Mallory the notes",
        0,
    );
    let attempt = fx.claim();
    let too_long = "x".repeat(4_097);
    let drafter = ScriptedDrafter::replying(&reply(&[
        // Yuki's own promise: no owner TURN is cited.
        item("P1", "Here is the budget.", &["T2"]),
        // Mallory is no PERSON the request listed.
        item("P2", "Here are the notes.", &["T3"]),
        // Words past the cap are skipped, never cut.
        item("P1", &too_long, &["T1"]),
        // A label the request never showed binds nothing.
        item("P1", "Here are the slides.", &["T9"]),
        item("P1", WORDS, &["T1", "T9"]),
    ]));

    let outcome = fx.run(&drafter, &attempt).expect("the attempt runs");

    let asked = drafter.asked.borrow();
    let request = &asked[0];
    assert!(
        request.turns[0].owner && !request.turns[1].owner && request.turns[2].owner,
        "a speaker label that is the owner's first name is the owner's"
    );
    assert_eq!(
        request.recipients.len(),
        1,
        "Yuki Tanaka, by the first name the transcript says"
    );
    let drafts = fx.follow_up_claims(yuki);
    assert_eq!(
        drafts.len(),
        1,
        "only the owner's promise to a listed person"
    );
    assert_eq!(outcome, MeetingFollowUpRunOutcome::Filed(vec![drafts[0].0]));
    assert_eq!(fx.waiting(&session), vec![drafts[0].0]);
}

#[test]
fn a_reply_outside_the_contract_or_a_lost_lease_files_nothing() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    let yuki = fx.person("Yuki");
    let (session, _) = fx.ingest(TRANSCRIPT, 0);
    let attempt = fx.claim();

    let prose = ScriptedDrafter::replying("Owen promised to send Yuki the slides.");
    let refused = fx
        .run(&prose, &attempt)
        .expect_err("prose is not the contract");
    assert!(matches!(refused, oneiron::Error::InvalidClaimBody(_)));

    let source = match fx
        .vault
        .meeting_follow_up_source_for(&payload(&attempt), &ReadDestination::on_device())
        .expect("read the transcript")
    {
        MeetingFollowUpRead::Ready(source) => source,
        other => panic!("the transcript reads: {other:?}"),
    };
    let lost = fx.vault.file_meeting_follow_up_drafts_attempt(
        attempt.id,
        "another-worker",
        attempt.attempt_count,
        &source,
        &reply(&[item("P1", WORDS, &["T1"])]),
    );
    assert!(lost.is_err(), "another worker's lease files nothing");

    // A fenced reply in the contract is read.
    let fenced = format!("```json\n{}\n```", reply(&[item("P1", WORDS, &["T1"])]));
    let filed = fx
        .vault
        .file_meeting_follow_up_drafts_attempt(
            attempt.id,
            LEASE_OWNER,
            attempt.attempt_count,
            &source,
            &fenced,
        )
        .expect("the lease holder files");
    assert_eq!(filed.len(), 1);
    assert_eq!(fx.follow_up_claims(yuki).len(), 1);
    assert_eq!(fx.waiting(&session), filed);
}

/// E2a review D3: a name in a script written without spaces runs straight
/// into the words around it ("田中さん"), and is still heard; a two-character
/// first word in that script names the owner alone ("大野" for "大野 太郎").
#[test]
fn a_name_in_an_unspaced_script_is_heard_inside_its_sentence() {
    let fx = fixture();
    fx.name_the_owner("大野 太郎");
    let tanaka = fx.person("田中");
    fx.ingest(
        "大野: 田中さんに資料を明日送ります\n鈴木: よろしくお願いします",
        0,
    );

    let attempt = fx.claim();
    let drafter = ScriptedDrafter::replying(&reply(&[item(
        "P1",
        "田中さん、本日の資料をお送りします。",
        &["T1"],
    )]));
    let outcome = fx.run(&drafter, &attempt).expect("the attempt runs");
    let MeetingFollowUpRunOutcome::Filed(written) = outcome else {
        panic!("the transcript is read and the reply filed, not {outcome:?}");
    };
    let asked = drafter.asked.borrow();
    assert!(asked[0].turns[0].owner, "大野 is the owner's first word");
    assert!(!asked[0].turns[1].owner);
    assert_eq!(asked[0].recipients.len(), 1);
    assert_eq!(asked[0].recipients[0].name, "田中");
    assert_eq!(written.len(), 1);
    assert_eq!(fx.follow_up_claims(tanaka).len(), 1);
}

/// E2a review D4: the owner's first word follows the recipients' rule, so a
/// first word too short to name anyone alone ("Al" of "Al Smith") does not
/// make its speaker the owner, and no model is asked.
#[test]
fn a_short_first_word_does_not_make_its_speaker_the_owner() {
    let fx = fixture();
    fx.name_the_owner("Al Smith");
    let _yuki = fx.person("Yuki");
    fx.ingest(
        "Al: I will send you the slides tomorrow\nYuki: Thanks, that helps",
        0,
    );

    let attempt = fx.claim();
    let read = fx
        .vault
        .meeting_follow_up_source_for(&payload(&attempt), &ReadDestination::on_device())
        .expect("the SESSION is read");
    assert!(
        matches!(
            read,
            MeetingFollowUpRead::Silent(MeetingFollowUpSilence::NoOwnerSpeaker)
        ),
        "no speaker is the owner, not {read:?}"
    );
}

/// E2a review D1 and D2: a read files only under the attempt queued for its
/// own SESSION, and only while it stands: an owner renamed since the read
/// may move which speaker is the owner, so the read files nothing. A fresh
/// read then files.
#[test]
fn a_read_files_only_under_its_own_attempt_and_while_it_stands() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    let yuki = fx.person("Yuki");
    let (first, _) = fx.ingest(TRANSCRIPT, 0);
    let (second, _) = fx.ingest(TRANSCRIPT, 60_000);
    let attempt = fx.claim();
    let claimed = payload(&attempt);
    let other = if claimed.session_ref == first.to_hex() {
        second
    } else {
        first
    };
    let ready = |payload: &MeetingFollowUpDraftPayload| {
        let read = fx
            .vault
            .meeting_follow_up_source_for(payload, &ReadDestination::on_device())
            .expect("the SESSION is read");
        let MeetingFollowUpRead::Ready(source) = read else {
            panic!("the SESSION is ready to draft from, not {read:?}");
        };
        source
    };
    let answer = reply(&[item("P1", WORDS, &["T1"])]);
    let file = |source: &MeetingFollowUpSource| {
        fx.vault.file_meeting_follow_up_drafts_attempt(
            attempt.id,
            LEASE_OWNER,
            attempt.attempt_count,
            source,
            &answer,
        )
    };

    let foreign = ready(&MeetingFollowUpDraftPayload {
        session_ref: other.to_hex(),
    });
    assert!(
        file(&foreign).is_err(),
        "another SESSION's read never files under this attempt"
    );

    let stale = ready(&claimed);
    fx.name_the_owner("Owen Park");
    assert!(
        file(&stale).is_err(),
        "a read the owner's rename moved files nothing"
    );
    assert!(fx.follow_up_claims(yuki).is_empty());

    let fresh = ready(&claimed);
    assert_eq!(file(&fresh).expect("a fresh read files").len(), 1);
    assert_eq!(fx.follow_up_claims(yuki).len(), 1);
}
