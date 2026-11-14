//! The sweep that re-tags turns saved under an older tagger (ARCH-0036, a
//! named follow-up of serving the tagger; census L9-29).
//!
//! A saved tag set names the tagger that made it: `<made by>@<checkpoint>`
//! and the stack its answer named. Once the vault is opened with another
//! checkpoint, or pins another stack, the tagging upkeep marks each turn
//! whose set an earlier tagger made, so the worker tags it again with the
//! tagger armed now and the save replaces the set. On main nothing marks such
//! a turn: its set keeps the older tagger's tags. A set the armed tagger made
//! is left alone, and an unpinned tagger takes every saved stack as its own.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! tag_set_older_tagger_sweep`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{HeldTagsOutcome, TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, ModelId, Vault, VaultConfig};

const OLD_CHECKPOINT: &str = "0123456789abcdef";
const NEW_CHECKPOINT: &str = "fedcba9876543210";
const STACK: &str = "aaaaaaaaaaaaaaaa";
const ROOM: &str = "52525252525252525252525252525252";
const TURN: &str = "76767676767676767676767676767676";
const TEXT: &str = "Yuki met Owen at the harbour.";
const NAME: &str = "Owen";

/// A tagger the upkeep never calls: the sweep only marks.
struct UncalledTagger(ModelId);

impl ExtractionEncoder for UncalledTagger {
    fn model_id(&self) -> &ModelId {
        &self.0
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, _input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        panic!("the tagging upkeep calls no tagger")
    }
}

/// A device config whose tagger, at `checkpoint` and pinned to `stack` when
/// one is named, saves its tags and maps the `PERSON` label.
fn tagging_config(checkpoint: &str, stack: Option<&str>) -> VaultConfig {
    let mut tagging = TaggingMarkerConfig::new(checkpoint)
        .expect("checkpoint")
        .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
        .with_mode(TaggingMode::Save);
    if let Some(stack) = stack {
        tagging = tagging.with_stack(stack);
    }
    let mut config = VaultConfig::device();
    config.tagging = Some(tagging);
    config
}

fn open(path: &Path, checkpoint: &str, stack: Option<&str>) -> Arc<Vault> {
    Arc::new(Vault::open(path, tagging_config(checkpoint, stack)).expect("open vault"))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// The tags an importer holds for [`TEXT`]: one `PERSON` span on [`NAME`],
/// naming `stack` as the stack that read it.
fn held_tags(stack: Option<&str>) -> EncoderOutput {
    let start = TEXT.find(NAME).expect("the name is in the text");
    EncoderOutput {
        spans: vec![NerSpan {
            message: 0,
            start,
            end: start + NAME.len(),
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        stack_sha16: stack.map(str::to_owned),
        mood_parts: Vec::new(),
    }
}

/// Witnesses [`TEXT`] as one turn with the importer's held tags, saved in
/// the witness write under the tagger `vault` arms; returns the turn.
fn witness_tagged(vault: &Vault, stack: Option<&str>) -> EntityId {
    let speaker = person(vault, "Yuki");
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(TURN.to_owned()),
        thread_audience: None,
        occurred_at: now_seconds(),
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: TEXT.into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        assertions: WitnessAssertions::default(),
    };
    let (_, outcome) = vault
        .memory(speaker, EdgeActorClass::Human)
        .witness_with_held_tags(&turn, &held_tags(stack))
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "the held tags are saved in the witness write: {outcome:?}"
    );
    EntityId::from_hex(TURN).expect("turn id")
}

/// The saved set's envelope: what made it, and the stack it names.
fn saved_by(vault: &Vault, turn: &EntityId) -> (String, Option<String>) {
    let tags = vault
        .turn_tags(turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    (tags.envelope.model_id, tags.envelope.stack)
}

/// Runs the tagging upkeep alone, as a worker's pass starts: no tagger call.
fn upkeep(vault: &Arc<Vault>) {
    let tagger = UncalledTagger("fixture/uncalled@v1".parse().expect("model id"));
    let reconciler =
        TaggingReconciler::new(Arc::clone(vault), Arc::new(tagger)).expect("a reconciler");
    let cut_short = reconciler
        .upkeep_until_paused(&|| false)
        .expect("the upkeep runs");
    assert!(!cut_short, "nothing pauses the upkeep");
}

/// The dedupe key of the marker `turn` owes the armed tagger, if it owes one.
fn owed_marker(vault: &Vault, turn: &EntityId) -> Option<String> {
    vault
        .tagging_marker(turn)
        .expect("marker read")
        .map(|marker| marker.dedupe_key.unwrap_or_default())
}

/// Red on main: the reopened vault arms a new checkpoint, the upkeep marks
/// nothing, and the turn keeps the older tagger's set with no pass owed.
#[test]
fn a_set_an_older_checkpoint_saved_is_marked_for_the_armed_tagger() {
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let vault = open(dir.path(), OLD_CHECKPOINT, None);
        let turn = witness_tagged(&vault, None);
        assert_eq!(saved_by(&vault, &turn).0, format!("held@{OLD_CHECKPOINT}"));
        assert_eq!(owed_marker(&vault, &turn), None, "the witness settled it");
        turn
    };
    let vault = open(dir.path(), NEW_CHECKPOINT, None);
    assert_eq!(owed_marker(&vault, &turn), None, "nothing is owed at open");

    upkeep(&vault);

    let key = owed_marker(&vault, &turn)
        .expect("the turn an older checkpoint tagged owes the armed tagger a pass");
    assert!(
        key.starts_with(&turn.to_hex()) && key.ends_with(NEW_CHECKPOINT),
        "the marker is owed to the armed checkpoint: {key}"
    );
    let freshness = vault
        .tagging_freshness(&turn)
        .expect("freshness read")
        .expect("the turn has saved tags");
    assert!(freshness.pending_retag);
    assert_eq!(
        saved_by(&vault, &turn).0,
        format!("held@{OLD_CHECKPOINT}"),
        "the older set stays until the pass settles"
    );

    // The pass settles, here with held tags: the set is replaced under the
    // armed checkpoint and nothing more is owed.
    let outcome = vault
        .complete_tagging_with_held_tags(&turn, &held_tags(None))
        .expect("complete");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "{outcome:?}"
    );
    assert_eq!(saved_by(&vault, &turn).0, format!("held@{NEW_CHECKPOINT}"));
    assert_eq!(owed_marker(&vault, &turn), None);
}

/// Red on main: a vault that now pins a stack at the same checkpoint holds
/// a set whose answer named no stack, and nothing marks it.
#[test]
fn a_set_saved_under_another_stack_than_the_pinned_one_is_marked() {
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let vault = open(dir.path(), OLD_CHECKPOINT, None);
        witness_tagged(&vault, None)
    };
    let vault = open(dir.path(), OLD_CHECKPOINT, Some(STACK));

    upkeep(&vault);

    let key = owed_marker(&vault, &turn)
        .expect("the turn another stack tagged owes the pinned stack a pass");
    assert!(
        key.ends_with(&format!("@{OLD_CHECKPOINT}+{STACK}")),
        "{key}"
    );
    let outcome = vault
        .complete_tagging_with_held_tags(&turn, &held_tags(Some(STACK)))
        .expect("complete");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "{outcome:?}"
    );
    assert_eq!(
        saved_by(&vault, &turn),
        (format!("held@{OLD_CHECKPOINT}"), Some(STACK.to_owned()))
    );
    assert_eq!(owed_marker(&vault, &turn), None);
}

/// Passes on main and on the head: a set the armed tagger made is not marked
/// again, and an unpinned tagger takes the stack any saved answer named as
/// its own.
#[test]
fn a_set_the_armed_tagger_saved_is_not_marked() {
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let vault = open(dir.path(), OLD_CHECKPOINT, None);
        witness_tagged(&vault, Some(STACK))
    };
    let vault = open(dir.path(), OLD_CHECKPOINT, None);

    upkeep(&vault);
    upkeep(&vault);

    assert_eq!(owed_marker(&vault, &turn), None);
    assert_eq!(
        saved_by(&vault, &turn),
        (format!("held@{OLD_CHECKPOINT}"), Some(STACK.to_owned()))
    );
}
