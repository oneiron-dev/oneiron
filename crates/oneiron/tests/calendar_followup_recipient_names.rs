//! CAL-08's producer, the names it reads and the names it prints (blind
//! review round 1 of #8806 and #8807, Mon 16 Nov 15:37-15:38).
//!
//! A PERSON is heard by every name its body carries, its `name` as well as
//! its `display_name`; the owner's speaker label and a recipient's mention
//! are matched by the same reader. A recipient's name reaches the drafting
//! model only where the Dreamer's model channel prints it: above that
//! channel's Names ceiling the PERSON is listed by its bare handle, never a
//! stand-in and never a drop (canon ARCH-0069 S9), beside the words the
//! transcript said. An agent connection's default ceiling is public, and an
//! unstamped name is sensitive, so the owner raises the ceiling to let it
//! print.
//!
//! Red at the producer's head 4 (a2a98da6bb63): a PERSON is heard only by
//! its `display_name`, so the first test reads no recipient; and the full
//! name is listed whatever the ceiling, so the second test finds it in the
//! model's message. The third test passes there too.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_followup_recipient_names`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::calendar::follow_up::{
    MeetingFollowUpDraftPayload, MeetingFollowUpRead, MeetingFollowUpSource,
};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
};
use oneiron::disclosure::{DisclosureBand, DisclosureDataClass};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::settings::ReadDestination;
use oneiron::store::GateDecisionId;
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
    /// A names-class claim about `about`, unstamped (so sensitive).
    fn name_claim(&self, about: EntityId, name: &str) {
        self.vault
            .put_claim(
                &EntityId::now(),
                &ClaimBody::new(
                    "person.name",
                    ClaimSubject::Entity(about),
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
            .expect("the name");
    }

    /// A PERSON whose body carries `fields` (`name`, `display_name`).
    fn person(&self, fields: &[(&str, &str)]) -> EntityId {
        let id = EntityId::now();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(
                fields
                    .iter()
                    .map(|(key, value)| (Value::from(*key), Value::from(*value)))
                    .collect(),
            ),
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

    /// One file-drop meeting transcript, read for the device's own model.
    fn read(&self, text: &str) -> MeetingFollowUpSource {
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
        let read = self
            .vault
            .meeting_follow_up_source_for(
                &MeetingFollowUpDraftPayload {
                    session_ref: session_ref.to_hex(),
                },
                &ReadDestination::on_device(),
            )
            .expect("the SESSION is read");
        let MeetingFollowUpRead::Ready(source) = read else {
            panic!("the SESSION is ready to draft from, not {read:?}");
        };
        source
    }

    /// The owner sets the Dreamer's model channel's Names ceiling.
    fn raise_dreamers_names_ceiling(&self, ceiling: DisclosureBand) {
        let proof = self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof");
        let dreamer = self
            .vault
            .dreamer_authority()
            .expect("the Dreamer")
            .entity_ref();
        let dial = format!(
            "agent:{}/{}",
            dreamer.to_hex(),
            DisclosureDataClass::Names.as_str()
        );
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&proof),
                SetSetting {
                    item: Some(dial),
                    ..SetSetting::vault_value(
                        "disclosure.model_ceiling",
                        serde_json::json!(ceiling.as_str()),
                    )
                },
            )
            .expect("set the ceiling");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's ceiling applies: {outcome:?}"
        );
    }
}

/// Review of #8806, P1: a PERSON with a `display_name` is still heard by its
/// `name`.
#[test]
fn a_person_is_heard_by_its_name_as_well_as_its_display_name() {
    let fx = fixture();
    fx.name_claim(fx.owner, "Owen");
    let _alice = fx.person(&[("name", "Alice Jones"), ("display_name", "AJ")]);

    let source = fx.read("Owen: Alice, I will send you the notes\nBob: Thanks");

    assert_eq!(
        source.request.recipients.len(),
        1,
        "Alice Jones, by the first word of her name"
    );
}

/// Review of #8807, P1: a name above the Dreamer's Names ceiling never
/// reaches the model; the PERSON is listed by its handle.
#[test]
fn a_name_above_the_model_channel_ceiling_is_listed_by_its_handle() {
    let fx = fixture();
    fx.name_claim(fx.owner, "Owen");
    let jane = fx.person(&[("name", "Jane Doe")]);
    fx.name_claim(jane, "Jane Doe");

    let source = fx.read("Owen: Jane, I will send you the report\nJane: Thanks");

    assert_eq!(
        source.request.recipients.len(),
        1,
        "the PERSON stays listed: a handle, never a drop"
    );
    let listed = &source.request.recipients[0].name;
    assert!(
        !listed.contains("Jane"),
        "the vault's name is not listed: {listed}"
    );
    let message = source.request.transcript_message();
    assert!(
        !message.contains("Doe"),
        "no word of the name the transcript did not say reaches the model: {message}"
    );
}

/// The owner's own dial lets the name print, as the board's people list.
#[test]
fn a_raised_names_ceiling_lets_the_name_reach_the_model() {
    let fx = fixture();
    fx.name_claim(fx.owner, "Owen");
    let jane = fx.person(&[("name", "Jane Doe")]);
    fx.name_claim(jane, "Jane Doe");
    fx.raise_dreamers_names_ceiling(DisclosureBand::Sensitive);

    let source = fx.read("Owen: Jane, I will send you the report\nJane: Thanks");

    assert_eq!(source.request.recipients.len(), 1);
    assert_eq!(source.request.recipients[0].name, "Jane Doe");
    assert!(
        source
            .request
            .transcript_message()
            .contains("P1 \"Jane Doe\"")
    );
}
