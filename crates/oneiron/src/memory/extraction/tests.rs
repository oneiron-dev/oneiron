use super::*;
use crate::{
    EntityId, TimeRange, Vault, VaultConfig,
    affect::Vad,
    edge::{EdgeActorClass, EdgeKind},
    memory::{WitnessAuthor, WitnessMessage, WitnessTurn},
    registry::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_EVENT, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_ORG,
        ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE,
    },
};
use std::collections::BTreeMap;
struct Scripted {
    pin: crate::ModelId,
    output: Option<EncoderOutput>,
}
impl ExtractionEncoder for Scripted {
    fn model_id(&self) -> &crate::ModelId {
        &self.pin
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, _input: &EncoderInput) -> crate::Result<EncoderOutput> {
        self.output
            .clone()
            .ok_or_else(|| crate::Error::InvalidConfig("fixture refusal".into()))
    }
}
fn scripted(output: Option<EncoderOutput>) -> Scripted {
    Scripted {
        pin: "fixture/multitask@v1".parse().unwrap(),
        output,
    }
}
fn short_output() -> EncoderOutput {
    EncoderOutput {
        spans: vec![
            NerSpan {
                message: 0,
                start: 0,
                end: 5,
                label: "PERSON".into(),
                confidence: 0.9,
            },
            NerSpan {
                message: 0,
                start: 7,
                end: 10,
                label: "PERSON".into(),
                confidence: 0.8,
            },
        ],
        links: vec![CorefLink {
            span: 1,
            antecedent: 0,
        }],
        vad: Some(Vad {
            valence: 0.5,
            arousal: 0.6,
            dominance: 0.4,
        }),
    }
}
fn named(vault: &Vault, kind: u8, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            kind,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).unwrap(),
        )
        .unwrap();
    id
}
fn turn() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: "31313131313131313131313131313131".into(),
        turn_ref: Some("32323232323232323232323232323232".into()),
        occurred_at: 100,
        messages: vec![WitnessMessage {
            id: Some("33333333333333333333333333333333".into()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "Alice. She agreed.".into(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    }
}
#[test]
fn shadow_has_no_store_delta_matches_golden_and_failure_never_fails_witness() {
    for fail in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let actor = named(&vault, ENTITY_TYPE_PERSON, "fixture actor");
        let memory = vault.memory(actor, EdgeActorClass::Human);
        memory.witness(&turn()).unwrap();
        let counts = || {
            (
                entity_count(&vault),
                vault
                    .edges_out(&EntityId::from_hex("33333333333333333333333333333333").unwrap())
                    .unwrap()
                    .len(),
            )
        };
        let before = counts();
        let result = memory
            .witness_with_shadow(&turn(), &scripted((!fail).then(short_output)))
            .unwrap();
        assert_eq!(counts(), before);
        if fail {
            assert!(result.trace.failure().is_some());
        } else {
            let golden: serde_json::Value =
                serde_json::from_str(include_str!("../../data/encoder_shadow.v1.json")).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(
                    &serde_json::to_string(&result.trace).unwrap()
                )
                .unwrap(),
                golden
            );
        }
    }
}

fn entity_count(vault: &Vault) -> u64 {
    (0..=u8::MAX)
        .map(|kind| vault.count_entities_by_type(kind).unwrap())
        .sum()
}

// ---------------------------------------------------------------------------
// Saving. The fixture turn is two messages written for these tests.
// ---------------------------------------------------------------------------

const TURN: &str = "41414141414141414141414141414141";
const FIRST: &str = "42424242424242424242424242424242";
const SECOND: &str = "43434343434343434343434343434343";
const FIRST_TEXT: &str = "Alice met Sam and Bob at the harvest fair.";
const SECOND_TEXT: &str = "She said Alice Rivera would host it next year.";

fn message(id: &str, content: &str, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: Some(id.into()),
        author: WitnessAuthor::User,
        message_type: "text".into(),
        content: content.into(),
        metadata: None,
        is_visible: true,
        order,
    }
}
fn fixture_turn() -> WitnessTurn {
    WitnessTurn {
        conversation_ref: "40404040404040404040404040404040".into(),
        turn_ref: Some(TURN.into()),
        occurred_at: 100,
        messages: vec![
            message(FIRST, FIRST_TEXT, 0),
            message(SECOND, SECOND_TEXT, 1),
        ],
    }
}
fn span_at(start: usize, end: usize, label: &str, confidence: f32) -> NerSpan {
    NerSpan {
        message: 0,
        start,
        end,
        label: label.into(),
        confidence,
    }
}
fn span(message: usize, needle: &str, label: &str, confidence: f32) -> NerSpan {
    let text = [FIRST_TEXT, SECOND_TEXT][message];
    let start = text.find(needle).unwrap();
    NerSpan {
        message,
        start,
        end: start + needle.len(),
        label: label.into(),
        confidence,
    }
}
const MOOD: Vad = Vad {
    valence: 0.4,
    arousal: 0.3,
    dominance: 0.5,
};
/// Spans 0..=5: Alice, Sam, Bob, the harvest fair, She, Alice Rivera. "She"
/// and "Alice Rivera" corefer with "Alice".
fn fixture_output() -> EncoderOutput {
    EncoderOutput {
        spans: vec![
            span(0, "Alice", "PERSON", 0.95),
            span(0, "Sam", "PERSON", 0.9),
            span(0, "Bob", "PERSON", 0.85),
            span(0, "the harvest fair", "EVENT", 0.8),
            span(1, "She", "PRONOUN", 0.7),
            span(1, "Alice Rivera", "PERSON", 0.9),
        ],
        links: vec![
            CorefLink {
                span: 4,
                antecedent: 0,
            },
            CorefLink {
                span: 5,
                antecedent: 0,
            },
        ],
        vad: Some(MOOD),
    }
}
fn spans_only(mut output: EncoderOutput) -> EncoderOutput {
    output.links.clear();
    output.vad = None;
    output
}
fn config() -> ExtractionSaveConfig {
    let labels = ExtractionLabels::new(BTreeMap::from([
        ("PERSON".to_owned(), ENTITY_TYPE_PERSON),
        ("ORG".to_owned(), ENTITY_TYPE_ORG),
        ("PLACE".to_owned(), ENTITY_TYPE_PLACE),
    ]))
    .unwrap();
    ExtractionSaveConfig::new(
        labels,
        "decode-v1",
        BTreeMap::from([
            ("register".to_owned(), "live".to_owned()),
            ("k".to_owned(), "512".to_owned()),
        ]),
    )
    .unwrap()
}
fn golden_of(trace: &ShadowTrace, tolerance: Option<f32>) -> EncoderGolden {
    EncoderGolden {
        model: trace.model().into(),
        input_hash: trace.input_hash().into(),
        output: trace.output().unwrap().clone(),
        tolerance,
    }
}
fn parity_of(trace: &ShadowTrace) -> EncoderParity {
    EncoderParity::verify(std::slice::from_ref(trace), &[golden_of(trace, None)]).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rows {
    entities: u64,
    claims: u64,
    events: u64,
    topology_events: u64,
    overlay: usize,
    message_edges: usize,
}
fn rows(vault: &Vault) -> Rows {
    Rows {
        entities: entity_count(vault),
        claims: vault.count_entities_by_type(ENTITY_TYPE_CLAIM).unwrap(),
        events: vault.count_entities_by_type(ENTITY_TYPE_EVENT).unwrap(),
        topology_events: vault
            .count_entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
            .unwrap(),
        overlay: super::persist::overlay_rows(vault).unwrap(),
        message_edges: [FIRST, SECOND]
            .iter()
            .map(|id| {
                vault
                    .edges_out(&EntityId::from_hex(id).unwrap())
                    .unwrap()
                    .len()
            })
            .sum(),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    alice: EntityId,
    sams: [EntityId; 2],
    rivera: EntityId,
    trace: ShadowTrace,
}
impl Fixture {
    fn new(output: EncoderOutput) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let actor = named(&vault, ENTITY_TYPE_PERSON, "fixture actor");
        let alice = named(&vault, ENTITY_TYPE_PERSON, "Alice");
        let mut sams = [
            named(&vault, ENTITY_TYPE_PERSON, "Sam"),
            named(&vault, ENTITY_TYPE_PERSON, "Sam"),
        ];
        sams.sort();
        let rivera = named(&vault, ENTITY_TYPE_PERSON, "Alice Rivera");
        let trace = vault
            .memory(actor, EdgeActorClass::Human)
            .witness_with_shadow(&fixture_turn(), &scripted(Some(output)))
            .unwrap()
            .trace;
        assert!(trace.failure().is_none(), "{:?}", trace.failure());
        Self {
            _dir: dir,
            vault,
            actor,
            alice,
            sams,
            rivera,
            trace,
        }
    }
    fn save(&self) -> Result<ExtractionReceipt, ExtractionSaveError> {
        self.save_trace(&self.trace)
    }
    fn save_trace(&self, trace: &ShadowTrace) -> Result<ExtractionReceipt, ExtractionSaveError> {
        self.vault
            .memory(self.actor, EdgeActorClass::Human)
            .persist_extraction(trace, &parity_of(&self.trace), &config(), 200)
    }
    /// Saves the fixture and returns the receipt with the rows before and after.
    fn saved(&self) -> (ExtractionReceipt, Rows, Rows) {
        let before = rows(&self.vault);
        let receipt = self.save().unwrap();
        (receipt, before, rows(&self.vault))
    }
}
fn turn_id() -> EntityId {
    EntityId::from_hex(TURN).unwrap()
}

#[test]
fn a_fixture_turn_lands_mentions_links_mood_and_evidence_under_one_envelope() {
    let fixture = Fixture::new(fixture_output());
    let (receipt, before, after) = fixture.saved();
    let tags = &receipt.tags;
    let [bob] = receipt.minted.as_slice() else {
        panic!("one provisional entity expected: {:?}", receipt.minted)
    };
    let links: Vec<_> = tags.mentions.iter().map(|m| m.link.clone()).collect();
    let person = ENTITY_TYPE_PERSON;
    assert_eq!(
        links,
        vec![
            MentionLink::Sure {
                kind: person,
                entity: fixture.alice
            },
            MentionLink::Soft {
                kind: person,
                candidates: fixture.sams.to_vec(),
                provisional: Vec::new(),
            },
            MentionLink::Provisional {
                kind: person,
                entity: *bob
            },
            MentionLink::Tag,
            MentionLink::Sure {
                kind: person,
                entity: fixture.alice
            },
            MentionLink::Sure {
                kind: person,
                entity: fixture.rivera
            },
        ]
    );
    let antecedents: Vec<_> = tags.mentions.iter().map(|m| m.antecedent).collect();
    assert_eq!(antecedents, [None, None, None, None, Some(0), Some(0)]);
    assert_eq!(
        tags.merge_evidence,
        vec![MergeEvidence {
            span: 5,
            antecedent: 0,
            entity: fixture.rivera,
            antecedent_entity: fixture.alice,
            confidence: 0.9,
        }]
    );
    assert_eq!(tags.mood, Some(MOOD));
    assert_eq!(
        tags.envelope,
        DerivationEnvelope {
            content_hash: fixture.trace.input_hash().into(),
            model_id: "fixture/multitask@v1".into(),
            version: "decode-v1".into(),
            params_hash: config().params_hash(),
        }
    );
    assert_eq!(
        fixture
            .vault
            .extraction_tag_set(&turn_id())
            .unwrap()
            .as_ref(),
        Some(tags)
    );
    assert_eq!(
        fixture.vault.provisional_entity_origin(bob).unwrap(),
        Some(turn_id())
    );
    // Rows: one tag set and one provisional marker in the overlay; the
    // provisional PERSON plus the substrate FACET every PERSON birth mints.
    assert_eq!(
        after,
        Rows {
            entities: before.entities + 2,
            overlay: before.overlay + 2,
            ..before
        }
    );
    assert_eq!(after.overlay, 2);
    // The same envelope again writes nothing.
    let again = fixture.save().unwrap();
    assert!(again.unchanged);
    assert_eq!(again.tags, receipt.tags);
    assert_eq!(rows(&fixture.vault), after);
}

#[test]
fn a_spans_only_output_lands_its_mentions_and_no_mood() {
    let fixture = Fixture::new(spans_only(fixture_output()));
    let (receipt, before, after) = fixture.saved();
    assert_eq!(receipt.tags.mentions.len(), 6);
    assert_eq!(receipt.tags.mood, None);
    assert!(receipt.tags.merge_evidence.is_empty());
    // Without its link, "She" is a tag of its own and mints nothing.
    assert_eq!(receipt.tags.mentions[4].link, MentionLink::Tag);
    assert_eq!(receipt.minted.len(), 1);
    assert_eq!(
        fixture
            .vault
            .extraction_tag_set(&turn_id())
            .unwrap()
            .unwrap()
            .mood,
        None
    );
    assert!(
        fixture
            .vault
            .get_turn_vad_annotation(&turn_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(after.claims, before.claims);
}

#[test]
fn a_provisional_entity_seeds_no_pagerank() {
    let fixture = Fixture::new(fixture_output());
    let (receipt, _, _) = fixture.saved();
    let bob = receipt.minted[0];
    let seeds = receipt.tags.ppr_seeds();
    assert!(seeds.iter().all(|(entity, _)| *entity != bob));
    let weight = |id: EntityId| seeds.iter().find(|(e, _)| *e == id).map(|(_, w)| *w);
    assert_eq!(weight(fixture.alice), Some(0.95));
    assert_eq!(weight(fixture.sams[0]), Some(0.45));
    assert_eq!(weight(fixture.sams[1]), Some(0.45));
    assert_eq!(weight(fixture.rivera), Some(0.9));
    assert_eq!(seeds.len(), 4);
    // A later mention finds the provisional entity through the identity key,
    // mints no twin, and it still seeds nothing.
    let memory = fixture.vault.memory(fixture.actor, EdgeActorClass::Human);
    let tag_bob = |turn_ref: &str, message_id: &str, text: &str, at: u64| {
        let later = WitnessTurn {
            conversation_ref: "40404040404040404040404040404040".into(),
            turn_ref: Some(turn_ref.into()),
            occurred_at: at,
            messages: vec![message(message_id, text, 0)],
        };
        let output = EncoderOutput {
            spans: vec![span_at(0, 3, "PERSON", 0.9)],
            links: Vec::new(),
            vad: None,
        };
        let trace = memory
            .witness_with_shadow(&later, &scripted(Some(output)))
            .unwrap()
            .trace;
        let entities = entity_count(&fixture.vault);
        let receipt = memory
            .persist_extraction(&trace, &parity_of(&trace), &config(), at)
            .unwrap();
        (receipt, entity_count(&fixture.vault) - entities)
    };
    let (again, added) = tag_bob(
        "44444444444444444444444444444444",
        "45454545454545454545454545454545",
        "Bob called.",
        300,
    );
    assert!(again.minted.is_empty());
    assert_eq!(added, 0);
    assert_eq!(
        again.tags.mentions[0].link,
        MentionLink::Provisional {
            kind: ENTITY_TYPE_PERSON,
            entity: bob
        }
    );
    assert!(again.tags.ppr_seeds().is_empty());
    // Once a second Bob exists the key returns both: a soft link that seeds
    // only the one that is not provisional.
    let other_bob = named(&fixture.vault, ENTITY_TYPE_PERSON, "Bob");
    let (soft, added) = tag_bob(
        "46464646464646464646464646464646",
        "47474747474747474747474747474747",
        "Bob waved.",
        400,
    );
    assert_eq!(added, 0);
    let mut both = vec![bob, other_bob];
    both.sort();
    assert_eq!(
        soft.tags.mentions[0].link,
        MentionLink::Soft {
            kind: ENTITY_TYPE_PERSON,
            candidates: both,
            provisional: vec![bob],
        }
    );
    assert_eq!(soft.tags.ppr_seeds(), vec![(other_bob, 0.45)]);
}

fn assert_refused(fixture: &Fixture, trace: &ShadowTrace, refusal: ExtractionRefusal) {
    let before = rows(&fixture.vault);
    assert_eq!(
        fixture.save_trace(trace).unwrap_err(),
        ExtractionSaveError::Refused(refusal)
    );
    assert_eq!(rows(&fixture.vault), before);
    assert!(
        fixture
            .vault
            .extraction_tag_set(&turn_id())
            .unwrap()
            .is_none()
    );
}
#[test]
fn changed_message_text_is_refused_with_no_new_rows() {
    let fixture = Fixture::new(fixture_output());
    let mut trace = fixture.trace.clone();
    trace.input.messages[0].text = FIRST_TEXT.replace("harvest", "harbour");
    assert_refused(&fixture, &trace, ExtractionRefusal::SourceChanged);
}
#[test]
fn bad_offsets_are_refused_with_no_new_rows() {
    let fixture = Fixture::new(fixture_output());
    let mut trace = fixture.trace.clone();
    trace.output.as_mut().unwrap().spans[2].end = FIRST_TEXT.len() + 1;
    assert_refused(&fixture, &trace, ExtractionRefusal::BadOffsets);
}
#[test]
fn a_span_count_that_does_not_match_the_links_is_refused_with_no_new_rows() {
    let fixture = Fixture::new(fixture_output());
    let mut trace = fixture.trace.clone();
    let output = trace.output.as_mut().unwrap();
    output.spans.truncate(5);
    assert_refused(&fixture, &trace, ExtractionRefusal::SpanCount);
}

#[test]
fn the_tagger_creates_no_claim() {
    let fixture = Fixture::new(fixture_output());
    let (_, before, after) = fixture.saved();
    assert_eq!(after.claims, before.claims);
    assert!(
        fixture
            .vault
            .get_turn_vad_annotation(&turn_id())
            .unwrap()
            .is_none()
    );
}
#[test]
fn the_tagger_writes_no_confirmed_mention() {
    let fixture = Fixture::new(fixture_output());
    let (_, before, after) = fixture.saved();
    assert_eq!(after.message_edges, before.message_edges);
    for id in [FIRST, SECOND] {
        let edges = fixture
            .vault
            .edges_out(&EntityId::from_hex(id).unwrap())
            .unwrap();
        assert!(edges.iter().all(|edge| edge.kind != EdgeKind::Mentions));
    }
}
#[test]
fn the_tagger_creates_no_event_entity() {
    assert_eq!(
        ExtractionLabels::new(BTreeMap::from([("EVENT".to_owned(), ENTITY_TYPE_EVENT)])),
        Err(ExtractionRefusal::LabelWithoutIdentityKey)
    );
    let fixture = Fixture::new(fixture_output());
    let (receipt, before, after) = fixture.saved();
    assert_eq!(after.events, before.events);
    assert_eq!(receipt.tags.mentions[3].label, "EVENT");
    assert_eq!(receipt.tags.mentions[3].link, MentionLink::Tag);
}
#[test]
fn the_tagger_applies_and_proposes_no_merge() {
    let fixture = Fixture::new(fixture_output());
    let (receipt, before, after) = fixture.saved();
    assert_eq!(receipt.tags.merge_evidence.len(), 1);
    assert_eq!(after.topology_events, before.topology_events);
    assert_eq!(
        fixture.vault.resolve_entity(&fixture.rivera).unwrap(),
        vec![fixture.rivera]
    );
    assert!(
        !fixture
            .vault
            .edge_exists(&fixture.rivera, EdgeKind::MergedInto, &fixture.alice)
            .unwrap()
    );
}

#[test]
fn parity_tolerance_passes_float_drift_and_fails_span_or_label_changes() {
    let fixture = Fixture::new(fixture_output());
    let trace = &fixture.trace;
    let drifted = |tolerance: Option<f32>, change: &dyn Fn(&mut EncoderOutput)| {
        let mut golden = golden_of(trace, tolerance);
        change(&mut golden.output);
        EncoderParity::verify(std::slice::from_ref(trace), &[golden])
    };
    let floats = |output: &mut EncoderOutput| {
        output.spans[0].confidence += 0.0004;
        output.vad.as_mut().unwrap().arousal -= 0.0004;
    };
    // The golden file declares its tolerance.
    let declared: EncoderGolden = serde_json::from_value(serde_json::json!({
        "model": trace.model(),
        "input_hash": trace.input_hash(),
        "output": trace.output().unwrap(),
        "tolerance": 0.001,
    }))
    .unwrap();
    assert_eq!(declared.tolerance, Some(0.001));
    assert!(drifted(Some(0.001), &floats).is_ok());
    assert!(drifted(None, &floats).is_err());
    assert!(drifted(Some(0.0001), &floats).is_err());
    assert!(
        drifted(Some(0.001), &|output: &mut EncoderOutput| output.spans
            [1]
        .end -= 1)
        .is_err()
    );
    assert!(
        drifted(Some(0.001), &|output: &mut EncoderOutput| {
            output.spans[1].label = "ORG".into();
        })
        .is_err()
    );
    assert!(drifted(Some(f32::NAN), &|_: &mut EncoderOutput| {}).is_err());
}
