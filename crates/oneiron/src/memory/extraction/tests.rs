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
            vad: Vad {
                valence: 0.5,
                arousal: 0.6,
                dominance: 0.4,
            },
        })
    }
}
fn person(vault: &Vault, byte: u8) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).unwrap();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name":"fixture actor"})).unwrap(),
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
#[test]
fn encoder_persistence_commits_mentions_coref_and_vad_or_rolls_back_everything() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let actor = person(&vault, 0x21);
    let alice = person(&vault, 0x22);
    let other = person(&vault, 0x23);
    let memory = vault.memory(actor, EdgeActorClass::Human);
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

    let turn_id = EntityId::from_hex("32323232323232323232323232323232").unwrap();
    let message = EntityId::from_hex("33333333333333333333333333333333").unwrap();
    let claim = EntityId::now();
    let mut body = crate::ClaimBody::new(
        "dream.symbol",
        crate::ClaimSubject::Entity(alice),
        rmpv::Value::from("agreement"),
        0.9,
        crate::ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.source = Some(crate::ClaimSource::Inferred);
    body.evidence = Some(rmpv::Value::Array(vec![rmpv::Value::Binary(
        turn_id.as_bytes().to_vec(),
    )]));
    vault
        .put_claim(
            &claim,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .unwrap();
    let before = entity_count(&vault);
    // The final consolidation lookup refuses after mention/annotation staging.
    assert!(
        memory
            .persist_extraction(
                &result.trace,
                &parity,
                &[alice, other],
                &[EntityId::now()],
                200
            )
            .is_err()
    );
    assert_eq!(entity_count(&vault), before);
    assert!(
        !vault
            .edge_exists(&message, EdgeKind::Mentions, &alice)
            .unwrap()
    );
    assert!(vault.get_turn_vad_annotation(&turn_id).unwrap().is_none());
    let receipt = memory
        .persist_extraction(&result.trace, &parity, &[alice, other], &[claim], 200)
        .unwrap();
    assert_eq!(receipt.consolidated.len(), 1);
    assert_eq!(receipt.consolidated[0].vad, Some(receipt.annotation.vad));
    assert!(
        receipt.consolidated[0]
            .reappraisal
            .active_claim_id
            .is_some()
    );
    assert_eq!(receipt.mention_targets, vec![alice, other]);
    assert!(
        vault
            .edge_exists(&message, EdgeKind::Mentions, &alice)
            .unwrap()
    );
    assert_eq!(
        vault.get_turn_vad_annotation(&turn_id).unwrap(),
        Some(receipt.annotation)
    );
    assert!(matches!(
        receipt.coref_proposals.as_slice(),
        [crate::identity_topology::IdentityOpOutcome::Parked { .. }]
    ));
    assert!(
        !vault
            .edge_exists(&other, EdgeKind::MergedInto, &alice)
            .unwrap()
    );
}

fn entity_count(vault: &Vault) -> u64 {
    (0..=u8::MAX)
        .map(|kind| vault.count_entities_by_type(kind).unwrap())
        .sum()
}

#[test]
fn coreference_gate_refusal_rolls_back_mentions_and_annotation() {
    use crate::identity_topology::{AssertDistinctOp, IdentityOpWrite, IdentityTopologyOp};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let actor = person(&vault, 0x21);
    let alice = person(&vault, 0x22);
    let other = person(&vault, 0x23);
    let memory = vault.memory(actor, EdgeActorClass::Human);
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
    let parity = EncoderParity::verify(std::slice::from_ref(&result.trace), &[golden]).unwrap();
    vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                a: alice,
                b: other,
                reason: "owner confirmed distinct people".into(),
            }),
            &IdentityOpWrite::auto(crate::ClaimSource::UserStated)
                .with_actor(crate::WriteActor::new(actor, EdgeActorClass::Human)),
            150,
        )
        .unwrap();
    let before = entity_count(&vault);
    let error = memory
        .persist_extraction(&result.trace, &parity, &[alice, other], &[], 200)
        .unwrap_err();
    assert_eq!(error.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert_eq!(entity_count(&vault), before);
    assert!(
        vault
            .get_turn_vad_annotation(
                &EntityId::from_hex("32323232323232323232323232323232").unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(
        !vault
            .edge_exists(
                &EntityId::from_hex("33333333333333333333333333333333").unwrap(),
                EdgeKind::Mentions,
                &alice
            )
            .unwrap()
    );
}
