//! [MEETING-FOLLOW-UP-NAME-NORMALISATION]: the meeting follow-up producer
//! matches the owner's names against a transcript's speaker labels, and
//! PERSON names against what the transcript says, in one folded form: NFKC,
//! then full Unicode case folding, then whitespace collapsed. A name the
//! vault holds composed and a transcript says decomposed (or the reverse),
//! and "ß" against "SS", are the same name.
//!
//! Red on main: the producer folds by `str::to_lowercase` alone, so a
//! decomposed speaker label is not the owner (the read is silent) and
//! "Strauss" is not "Strauß" (no recipient).
//!
//! `cargo test --locked -p oneiron --all-features --test
//! calendar_follow_up_name_folding`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::calendar::follow_up::{
    MeetingFollowUpDraftPayload, MeetingFollowUpRead, MeetingFollowUpRequest,
};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::settings::ReadDestination;
use oneiron::store::ports::ManualClock;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

const NOW: u64 = 1_800_000_000;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns, as an embedded host opens it, with the
/// engine's MACHINE writers provisioned and this install's signing keys
/// loaded.
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

    /// One file-drop meeting transcript, read for the on-device model as
    /// the drafting worker reads it.
    fn read(&self, text: &str) -> MeetingFollowUpRead {
        let TranscriptIngestOutcome::Session { session_ref, .. } = ingest_file_drop_transcript(
            &self.vault,
            TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: text,
                arrived_at_ms: NOW * 1_000,
            },
        )
        .expect("the transcript lands") else {
            panic!("a speaker transcript mints a session");
        };
        self.vault
            .meeting_follow_up_source_for(
                &MeetingFollowUpDraftPayload {
                    session_ref: session_ref.to_hex(),
                },
                &ReadDestination::on_device(),
            )
            .expect("read the transcript")
    }
}

fn ready(read: MeetingFollowUpRead) -> MeetingFollowUpRequest {
    let MeetingFollowUpRead::Ready(source) = read else {
        panic!("the transcript is read for the model, not {read:?}");
    };
    source.request
}

#[test]
fn owner_name_stored_decomposed_marks_a_composed_speaker_label() {
    let fx = fixture();
    // "Zoë" with U+0308 COMBINING DIAERESIS; the transcript writes U+00EB.
    fx.name_the_owner("Zoe\u{308}");
    fx.person("Yuki");

    let request =
        ready(fx.read("Zo\u{eb}: I will send you the slides tomorrow\nYuki: Thanks, that helps"));

    assert!(
        request.turns[0].owner,
        "the owner's name read composed is the owner's speaker label"
    );
    assert!(!request.turns[1].owner);
    assert_eq!(request.recipients.len(), 1);
    assert_eq!(request.recipients[0].heard, "yuki");
}

#[test]
fn sharp_s_name_matches_its_ss_spelling_and_a_decomposed_mention() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    fx.person("Strauß");
    // "José" stored composed; the transcript writes it decomposed.
    fx.person("Jos\u{e9}");

    let request = ready(fx.read(
        "Owen: I will send STRAUSS the slides tomorrow\n\
         Owen: And I will send Jose\u{301} the notes",
    ));

    let heard: Vec<&str> = request
        .recipients
        .iter()
        .map(|recipient| recipient.heard.as_str())
        .collect();
    assert_eq!(
        heard,
        vec!["strauss", "jos\u{e9}"],
        "both PERSONs are listed, in the order first named, by their folded forms"
    );
    assert_eq!(request.recipients[0].label, "P1");
    assert_eq!(request.recipients[1].label, "P2");
}

#[test]
fn a_decomposed_accent_ends_no_word() {
    let fx = fixture();
    fx.name_the_owner("Owen");
    fx.person("Jose");
    fx.person("Yuki");

    // "José", decomposed: the PERSON named "Jose" is not who is named here.
    let request =
        ready(fx.read("Owen: I will send Jose\u{301} the slides\nOwen: and Yuki the notes"));

    let heard: Vec<&str> = request
        .recipients
        .iter()
        .map(|recipient| recipient.heard.as_str())
        .collect();
    assert_eq!(
        heard,
        vec!["yuki"],
        "a combining accent after \"jose\" makes another word"
    );
}
