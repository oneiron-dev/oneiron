use super::*;
use crate::{
    EntityId, TimeRange, Vault, VaultConfig,
    affect::Vad,
    edge::{EdgeActorClass, EdgeKind},
    memory::{WitnessAuthor, WitnessMessage, WitnessTurn},
    registry::ENTITY_TYPE_PERSON,
};
struct Scripted {
    pin: crate::ModelId,
    fail: bool,
}
impl ExtractionEncoder for Scripted {
    fn model_id(&self) -> &crate::ModelId {
        &self.pin
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, _input: &EncoderInput) -> crate::Result<EncoderOutput> {
        if self.fail {
            return Err(crate::Error::InvalidConfig("fixture refusal".into()));
        }
        Ok(EncoderOutput {
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
        })
    }
}
fn person(vault: &Vault, byte: u8) -> EntityId {
    named_person(vault, byte, "fixture actor")
}
fn named_person(vault: &Vault, byte: u8, name: &str) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).unwrap();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).unwrap(),
        )
        .unwrap();
    id
}
/// A vault whose tagger saves its tags, mapping the fixture's label.
fn armed() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.tagging = Some(
        crate::tagging::TaggingMarkerConfig::new("0123456789abcdef")
            .unwrap()
            .with_labels([("PERSON".to_owned(), ENTITY_TYPE_PERSON)].into()),
    );
    config
}
/// A shadow trace of the fixture turn, and its parity receipt.
fn shadowed(memory: &crate::memory::Memory<'_>) -> (ShadowTrace, EncoderParity) {
    let result = memory
        .witness_with_shadow(
            &turn(),
            &Scripted {
                pin: "fixture/multitask@v1".parse().unwrap(),
                fail: false,
            },
        )
        .unwrap();
    let mut gold: serde_json::Value =
        serde_json::from_str(include_str!("../../data/encoder_shadow.v1.json")).unwrap();
    gold.as_object_mut().unwrap().remove("failure");
    let golden: EncoderGolden = serde_json::from_value(gold).unwrap();
    let parity = EncoderParity::verify(
        std::slice::from_ref(&result.trace),
        std::slice::from_ref(&golden),
    )
    .unwrap();
    let mut wrong = golden;
    wrong.output.spans[0].end = 4;
    assert!(EncoderParity::verify(std::slice::from_ref(&result.trace), &[wrong]).is_err());
    (result.trace, parity)
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
        let actor = person(&vault, 0x21);
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
            .witness_with_shadow(
                &turn(),
                &Scripted {
                    pin: "fixture/multitask@v1".parse().unwrap(),
                    fail,
                },
            )
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
/// ARCH-0036: the tagger writes no claim, and a mention is saved unconfirmed.
/// A parity-checked shadow lands as the turn's tag set: the name links to
/// the entity its identity key names as a candidate, the pronoun takes its
/// antecedent's link, and the mood lands on the turn. No edge, claim or
/// merge is written, and saving it again changes nothing.
#[test]
fn a_parity_checked_shadow_saves_its_turns_tags_and_writes_no_edge_claim_or_merge() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), armed()).unwrap();
    let actor = person(&vault, 0x21);
    let alice = named_person(&vault, 0x22, "Alice");
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let (trace, parity) = shadowed(&memory);
    let turn_id = EntityId::from_hex("32323232323232323232323232323232").unwrap();
    let message = EntityId::from_hex("33333333333333333333333333333333").unwrap();
    let before = entity_count(&vault);

    let tags = memory.persist_extraction(&trace, &parity, 200).unwrap();

    let soft = crate::tagging::MentionLink::Candidates {
        kind: ENTITY_TYPE_PERSON,
        entities: vec![alice],
    };
    assert_eq!(tags.mentions.len(), 2);
    assert_eq!(tags.mentions[0].link, soft);
    assert_eq!(tags.mentions[1].link, soft);
    assert_eq!(tags.mentions[1].antecedent, Some(0));
    assert!(tags.merge_evidence.is_empty());
    assert_eq!(vault.turn_tags(&turn_id).unwrap(), Some(tags.clone()));
    assert_eq!(entity_count(&vault), before);
    assert!(
        !vault
            .edge_exists(&message, EdgeKind::Mentions, &alice)
            .unwrap()
    );
    let mood = vault.get_turn_vad_annotation(&turn_id).unwrap().unwrap();
    assert_eq!(Some(mood.vad), tags.mood);
    assert_eq!(
        mood.source,
        crate::affect::VadAnnotationSource::ModelInference
    );
    assert_eq!(
        memory.persist_extraction(&trace, &parity, 300).unwrap(),
        tags
    );
}

fn entity_count(vault: &Vault) -> u64 {
    (0..=u8::MAX)
        .map(|kind| vault.count_entities_by_type(kind).unwrap())
        .sum()
}

/// A save stands only for the text the model read: a source that no longer
/// reads as the shadow's input is refused and writes nothing.
#[test]
fn a_shadow_whose_source_changed_saves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), armed()).unwrap();
    let actor = person(&vault, 0x21);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let (mut trace, parity) = shadowed(&memory);
    trace.input.messages[0].text = "Bobby. He agreed.".into();
    let turn_id = EntityId::from_hex("32323232323232323232323232323232").unwrap();
    let before = entity_count(&vault);

    let error = memory.persist_extraction(&trace, &parity, 200).unwrap_err();

    assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert_eq!(entity_count(&vault), before);
    assert_eq!(vault.turn_tags(&turn_id).unwrap(), None);
    assert!(vault.get_turn_vad_annotation(&turn_id).unwrap().is_none());
}

/// A turn whose messages were sent out of message order is the source the
/// model read: the shadow reads them in the order they arrived, the save in
/// message order, and the same messages with the same text are saved.
#[test]
fn a_shadow_of_messages_sent_out_of_order_is_saved() {
    struct FindsAda(crate::ModelId);
    impl ExtractionEncoder for FindsAda {
        fn model_id(&self) -> &crate::ModelId {
            &self.0
        }
        fn locality(&self) -> crate::embed::EmbedderLocality {
            crate::embed::EmbedderLocality::OnDevice
        }
        fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput> {
            let message = input
                .messages
                .iter()
                .position(|message| message.text.starts_with("Ada"))
                .ok_or_else(|| crate::Error::InvalidConfig("no Ada".into()))?;
            Ok(EncoderOutput {
                spans: vec![NerSpan {
                    message,
                    start: 0,
                    end: 3,
                    label: "PERSON".into(),
                    confidence: 0.9,
                }],
                links: Vec::new(),
                vad: None,
            })
        }
    }
    let message = |id: &str, order: u32, content: &str| WitnessMessage {
        id: Some(id.into()),
        author: WitnessAuthor::User,
        message_type: "text".into(),
        content: content.into(),
        metadata: None,
        is_visible: true,
        order,
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), armed()).unwrap();
    let actor = person(&vault, 0x21);
    let ada = named_person(&vault, 0x22, "Ada");
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let result = memory
        .witness_with_shadow(
            &WitnessTurn {
                conversation_ref: "34343434343434343434343434343434".into(),
                turn_ref: Some("35353535353535353535353535353535".into()),
                occurred_at: 100,
                messages: vec![
                    message("36363636363636363636363636363636", 1, "Bob replied"),
                    message("37373737373737373737373737373737", 0, "Ada called"),
                ],
            },
            &FindsAda("fixture/finds-ada@v1".parse().unwrap()),
        )
        .unwrap();
    let golden = EncoderGolden {
        model: result.trace.model.clone(),
        input_hash: result.trace.input_hash.clone(),
        output: result.trace.output.clone().unwrap(),
    };
    let parity = EncoderParity::verify(std::slice::from_ref(&result.trace), &[golden]).unwrap();

    let tags = memory
        .persist_extraction(&result.trace, &parity, 200)
        .unwrap();

    assert_eq!(
        tags.mentions[0].link,
        crate::tagging::MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![ada],
        }
    );
    assert_eq!(
        tags.mentions[0].message,
        EntityId::from_hex("37373737373737373737373737373737").unwrap()
    );
}
