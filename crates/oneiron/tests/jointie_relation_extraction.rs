//! JointIE inside the Dreamer's child (L2-03; ARCH-0026 `#wake-model`:
//! "Inside the child JointIE extracts claims ... A big model only
//! generates"; SWITCH = A, by coverage).
//!
//! The tagger's relation head saves its relations with the turn's tag set
//! (PR 1). A consolidation slice whose every TURN holds such a set, fresh and
//! made by the armed tagger, under a host relation table that maps a label,
//! is extracted from those relations by the engine, with no model call: the
//! claim's subject is the head span's linked entity, its predicate the
//! table's, its value the tail span's words, and its evidence the TURN. A
//! slice with an untagged TURN keeps the extraction model's step, so nothing
//! drops, and a covered slice whose relations the table does not map files
//! nothing and never falls back to the model.
//!
//! The scripted model's reply is a decoy: a call to it lands `decoy.value`.
//! On main the file does not compile: there is no `EncoderOutput.relations`,
//! no `TaggingMarkerConfig::with_relations` and no tagged consolidation door.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test jointie_relation_extraction`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::memory::extraction::{
    EncoderOutput, NerSpan, RelationLink, SpeakerLink, SpeakerTarget,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::test_doors::consolidation::{
    UnboundPass, consolidate_tagged_turn, consolidate_unbound_turn, open_tagged_dreamer_vault,
};
use oneiron::write_envelope::claim_body::{ClaimBody, ClaimSubject, EvidenceKind};

const READER: &str = "reader";
const CHECKPOINT: &str = "0123456789abcdef";
const WORDS: &str = "I work at Acme";
const PREDICATE: &str = "work.employer";

/// A vault whose tagger saves its tags, maps `PERSON`, and maps the
/// `works_at` relation to [`PREDICATE`].
fn tagged_vault(dir: &tempfile::TempDir) -> oneiron::Vault {
    let tagging = TaggingMarkerConfig::new(CHECKPOINT)
        .expect("checkpoint")
        .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
        .with_relations(BTreeMap::from([(
            "works_at".to_owned(),
            PREDICATE.to_owned(),
        )]))
        .with_mode(TaggingMode::Save);
    open_tagged_dreamer_vault(dir.path(), READER, tagging).expect("fixture vault")
}

/// A relation-capable tagger's answer for [`WORDS`]: `I`, the turn's
/// speaker; `Acme`; and one relation from `I` to `Acme` labelled `label`.
fn tags(label: &str) -> EncoderOutput {
    let span = |start: usize, end: usize, label: &str| NerSpan {
        message: 0,
        start,
        end,
        label: label.to_owned(),
        confidence: 0.9,
    };
    EncoderOutput {
        spans: vec![span(0, 1, "PRONOUN"), span(10, 14, "ORG")],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: vec![SpeakerLink {
            span: 0,
            target: SpeakerTarget::Speaker,
            confidence: 0.9,
        }],
        mood_parts: Vec::new(),
        relations: Some(vec![RelationLink {
            head: 0,
            tail: 1,
            label: label.to_owned(),
            confidence: 0.9,
        }]),
        stack_sha16: None,
    }
}

/// The scripted model's reply: a claim no relation would file.
fn decoy() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Acme", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "decoy.value",
            "value": "model",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Acme"}],
        }],
    })
    .to_string()
}

/// The one claim `pass` landed: its subject, predicate and value.
fn landed(vault: &oneiron::Vault, pass: &UnboundPass) -> ClaimBody {
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    vault
        .get_claim(claim)
        .expect("claim read")
        .expect("the landed claim")
}

#[test]
fn a_slice_whose_turns_hold_relations_extracts_its_claim_with_no_model_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = tagged_vault(&dir);

    let pass = consolidate_tagged_turn(&vault, WORDS, &tags("works_at"), &decoy())
        .expect("one consolidation pass");

    // The saved tags link `I` to the turn's speaker.
    let saved = vault
        .turn_tags(&pass.turn)
        .expect("tags read")
        .expect("FIXTURE: the held tags are saved");
    let MentionLink::Candidates { entities, .. } = &saved.mentions[0].link else {
        panic!(
            "FIXTURE: the speaker span links its speaker: {:?}",
            saved.mentions[0].link
        );
    };
    let [speaker] = entities.as_slice() else {
        panic!("FIXTURE: the speaker span names one person: {entities:?}");
    };

    assert!(
        pass.call_relationships.is_empty(),
        "a covered slice calls no model: {:?}",
        pass.call_relationships
    );
    let body = landed(&vault, &pass);
    assert_eq!(body.subject, ClaimSubject::Entity(*speaker));
    assert_eq!(body.predicate, PREDICATE);
    assert_eq!(
        body.value,
        rmpv::Value::from("Acme"),
        "the value is the tail span's words"
    );
    let cited: Vec<_> = body
        .evidence_refs()
        .expect("evidence refs")
        .into_iter()
        .map(|cited| (cited.kind, cited.entity))
        .collect();
    assert_eq!(cited, vec![(EvidenceKind::Turn, pass.turn.to_hex())]);
}

#[test]
fn a_slice_with_an_untagged_turn_keeps_the_model_step() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = tagged_vault(&dir);

    let pass = consolidate_unbound_turn(&vault, WORDS, None, None, &decoy())
        .expect("one consolidation pass");

    assert!(
        vault.turn_tags(&pass.turn).expect("tags read").is_none(),
        "FIXTURE: the turn holds no tag set"
    );
    assert_eq!(pass.call_relationships.len(), 1, "the model is called once");
    assert_eq!(landed(&vault, &pass).predicate, "decoy.value");
}

#[test]
fn an_unmapped_relation_files_nothing_and_calls_no_model() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = tagged_vault(&dir);

    let pass = consolidate_tagged_turn(&vault, WORDS, &tags("likes"), &decoy())
        .expect("one consolidation pass");

    assert!(
        pass.call_relationships.is_empty(),
        "a covered slice never falls back to the model: {:?}",
        pass.call_relationships
    );
    assert!(
        pass.landed.is_empty(),
        "a relation the table does not map files nothing: {:?}",
        pass.landed
    );
}
