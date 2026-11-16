//! CAL-08's drafting read never holds on a TURN no read may serve (Engine
//! RULING CAL-08-FOLLOWUP-APPROVAL = A, Sun 15 Nov 12:04).
//!
//! A transcript TURN whose recorded source no longer stands is withdrawn:
//! every scoped read withholds it, the owner's too, and nothing brings it
//! back. The drafting read holds on any TURN its destination's scoped read
//! withholds, so before this fix such a TURN held every try of its SESSION's
//! drafting, forever. The read now leaves such a TURN out, as it leaves out a
//! deleted one, and drafts from the TURNs that remain.
//!
//! Red on PR-E2a's head: once a TURN's source is withdrawn, the read answers
//! `Held` (the first test's second read and the second test's read fail).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_followup_withdrawn_source`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::calendar::follow_up::{MeetingFollowUpDraftPayload, MeetingFollowUpRead};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::settings::ReadDestination;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::disclosure_word_sources::register_editor_source;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

const NOW: u64 = 1_800_000_000;
const TRANSCRIPT: &str =
    "Owen: Yuki, I will send you the slides tomorrow\nYuki: Thanks, that helps";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns, as an embedded host opens it, with the
/// engine's MACHINE writers provisioned and this install's signing keys
/// loaded (PR-E2a's `calendar_transcript_followups` fixture).
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

    /// A PERSON stored with `body`, a msgpack map of `fields`.
    fn person_with(&self, fields: Vec<(Value, Value)>) -> EntityId {
        let id = EntityId::now();
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &Value::Map(fields)).expect("encode the person body");
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

    /// A row whose own words are withdrawn: its body carries `stale: true`,
    /// so nothing derived from it stands either.
    fn withdrawn_source(&self) -> EntityId {
        self.person_with(vec![(Value::from("stale"), Value::from(true))])
    }

    /// One file-drop meeting transcript: its SESSION and TURNs.
    fn ingest(&self, text: &str) -> (EntityId, Vec<EntityId>) {
        let TranscriptIngestOutcome::Session {
            session_ref,
            turn_refs,
            ..
        } = ingest_file_drop_transcript(
            &self.vault,
            TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: text,
                arrived_at_ms: NOW * 1_000,
            },
        )
        .expect("the transcript lands")
        else {
            panic!("a speaker transcript mints a session");
        };
        (session_ref, turn_refs)
    }

    /// The drafting read of `session` for this device.
    fn read(&self, session: &EntityId) -> MeetingFollowUpRead {
        self.vault
            .meeting_follow_up_source_for(
                &MeetingFollowUpDraftPayload {
                    session_ref: session.to_hex(),
                },
                &ReadDestination::on_device(),
            )
            .expect("the drafting read")
    }
}

#[test]
fn a_turn_whose_source_no_longer_stands_leaves_the_read_and_never_holds_it() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    fx.person_with(vec![(Value::from("name"), Value::from("Yuki"))]);
    let (session, turns) = fx.ingest(TRANSCRIPT);
    assert_eq!(turns.len(), 2, "one TURN per transcript line");
    let MeetingFollowUpRead::Ready(source) = fx.read(&session) else {
        panic!("both TURNs stand, so the read is ready");
    };
    assert_eq!(source.request.turns.len(), 2);

    // Yuki's line was derived from a row whose words are withdrawn.
    register_editor_source(&fx.vault, &turns[1], &fx.withdrawn_source())
        .expect("record the TURN's source");
    let read = fx.read(&session);
    let MeetingFollowUpRead::Ready(source) = read else {
        panic!("a withdrawn TURN never holds the read; it read {read:?}");
    };
    let turns_read: Vec<(&str, &str)> = source
        .request
        .turns
        .iter()
        .map(|turn| (turn.label.as_str(), turn.speaker.as_str()))
        .collect();
    assert_eq!(
        turns_read,
        vec![("T1", "Owen")],
        "the owner's line remains, and only it"
    );
    assert_eq!(
        source.request.recipients.len(),
        1,
        "the owner's line names Yuki"
    );
    assert_eq!(source.request.recipients[0].name, "Yuki");
}

#[test]
fn a_session_whose_every_turn_is_withdrawn_reads_missing() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    fx.person_with(vec![(Value::from("name"), Value::from("Yuki"))]);
    let (session, turns) = fx.ingest(TRANSCRIPT);
    let source = fx.withdrawn_source();
    for turn in &turns {
        register_editor_source(&fx.vault, turn, &source).expect("record the TURN's source");
    }
    let read = fx.read(&session);
    assert!(
        matches!(read, MeetingFollowUpRead::Missing),
        "no TURN is left to draft from, so the attempt completes; it read {read:?}"
    );
}
