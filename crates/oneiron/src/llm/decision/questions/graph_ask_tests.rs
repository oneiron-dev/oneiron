use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, DecisionRung, ProviderPin,
};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use crate::test_util::open_test_vault_with;
use crate::{EntityId, TimeRange, Vault, WriteActor};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn put_entity(vault: &Vault, id: EntityId, entity_type: u8, body: &[u8]) -> crate::Result<()> {
    vault.put_entity(&id, entity_type, at(1), 1, body)
}

fn identities(vault: &Vault) -> crate::Result<(EntityId, WriteActor)> {
    let principal = EntityId::now();
    let actor = EntityId::now();
    put_entity(vault, principal, ENTITY_TYPE_PERSON, b"principal")?;
    put_entity(vault, actor, ENTITY_TYPE_PERSON, b"actor")?;
    grant_graph_reads(vault, principal)?;
    Ok((principal, WriteActor::new(actor, EdgeActorClass::Agent)))
}

fn grant_graph_reads(vault: &Vault, principal: EntityId) -> crate::Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest: serde_json::Value = rmp_serde::from_slice(&bytes).expect("default policy");
    manifest["scoped_grants"] = serde_json::json!([{
        "actor_ref": principal.to_hex(),
        "effector": "core:read",
        "scope": serde_json::to_value(crate::federation::scope_codec::read_preset())
            .expect("read preset"),
        "receipt_required": false,
    }]);
    manifest["rules"]
        .as_array_mut()
        .expect("policy rules")
        .push(serde_json::json!({"prefix":"judgment.answer","exact":true,
            "axes":{"criticality":"normal","sensitivity":"normal"}}));
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).expect("fixture policy"),
    )
}

fn grant_class_bound_graph_reads(vault: &Vault, principal: EntityId) -> crate::Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest: serde_json::Value = rmp_serde::from_slice(&bytes).expect("default policy");
    manifest["scoped_grants"] = serde_json::json!([{
        "actor_ref": principal.to_hex(),
        "actor_class": "human",
        "effector": "core:read",
        "scope": serde_json::to_value(crate::federation::scope_codec::read_preset())
            .expect("read preset"),
        "receipt_required": false,
    }]);
    manifest["rules"]
        .as_array_mut()
        .expect("policy rules")
        .push(serde_json::json!({"prefix":"judgment.answer","exact":true,
            "axes":{"criticality":"normal","sensitivity":"normal"}}));
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).expect("fixture policy"),
    )
}

fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Is the evidence relevant?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Choice {
            options: vec!["yes".into(), "no".into()],
        },
        accept_type: false,
    }
}

fn prediction() -> GraphPrediction {
    GraphPrediction {
        answer: DecisionAnswer::Choice("yes".into()),
        probability: 0.8,
        provider: ProviderPin {
            rung: DecisionRung::Local,
            model: "local/fixture".into(),
            version: "r1".into(),
        },
        cost_per_thousand: 0.25,
    }
}

struct FixedAnswerer {
    prediction: Option<GraphPrediction>,
    contexts: Vec<GraphUnitContext>,
}

impl FixedAnswerer {
    fn returning(prediction: Option<GraphPrediction>) -> Self {
        Self {
            prediction,
            contexts: Vec::new(),
        }
    }
}

impl GraphAnswerer for FixedAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> crate::Result<Option<GraphPrediction>> {
        self.contexts.push(context.clone());
        Ok(self.prediction.clone())
    }
}

fn scoped_claim(principal: EntityId, subject: EntityId) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from("scoped evidence"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.scope = Some(Value::Map(vec![(
        Value::from("typed_question_principal"),
        Value::from(principal.to_hex()),
    )]));
    body
}

fn put_scoped_claim(
    vault: &Vault,
    id: EntityId,
    principal: EntityId,
    subject: EntityId,
) -> crate::Result<()> {
    vault.put_claim(&id, &scoped_claim(principal, subject), at(1), 1)
}

#[test]
fn scoped_graph_context_omits_unreadable_neighbors_and_units() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let stranger = EntityId::now();
    put_entity(&vault, stranger, ENTITY_TYPE_PERSON, b"stranger")?;

    let unit = EntityId::now();
    let public_neighbor = EntityId::now();
    let private_neighbor = EntityId::now();
    put_entity(&vault, unit, ENTITY_TYPE_PERSON, b"unit")?;
    put_entity(
        &vault,
        public_neighbor,
        ENTITY_TYPE_PERSON,
        b"public neighbor",
    )?;
    put_scoped_claim(&vault, private_neighbor, stranger, unit)?;
    vault.put_edge(&unit, EdgeKind::Mentions, &public_neighbor, 0.8)?;
    vault.put_edge(&unit, EdgeKind::Mentions, &private_neighbor, 0.8)?;

    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit, private_neighbor],
        &mut answerer,
        10,
    )
    .map_err(|failure| *failure.error)?;

    assert_eq!(result.answers.len(), 1);
    assert_eq!(result.answers[0].unit, unit);
    assert!(result.abstained.is_empty());
    assert_eq!(answerer.contexts.len(), 1);
    let context = &answerer.contexts[0];
    assert_eq!(context.unit, unit);
    assert_eq!(context.sources[0].id, unit);
    assert!(
        context
            .sources
            .iter()
            .any(|source| source.id == public_neighbor)
    );
    assert!(
        context
            .sources
            .iter()
            .all(|source| source.id != private_neighbor)
    );
    Ok(())
}

#[test]
fn missing_or_oversized_input_and_answerer_refusal_abstain_without_claims() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let empty = EntityId::now();
    let oversized = EntityId::now();
    let refusal = EntityId::now();
    put_entity(&vault, empty, ENTITY_TYPE_PERSON, b"")?;
    put_entity(
        &vault,
        oversized,
        ENTITY_TYPE_PERSON,
        &vec![b'x'; 1_048_577],
    )?;
    put_entity(&vault, refusal, ENTITY_TYPE_PERSON, b"answerer will refuse")?;
    let claims_before = vault.entities_by_type(ENTITY_TYPE_CLAIM)?;

    let mut answerer = FixedAnswerer::returning(None);
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[empty, oversized, refusal],
        &mut answerer,
        11,
    )
    .map_err(|failure| *failure.error)?;

    assert!(result.answers.is_empty());
    assert_eq!(result.abstained, vec![empty, oversized, refusal]);
    assert_eq!(answerer.contexts.len(), 1);
    assert_eq!(answerer.contexts[0].unit, refusal);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_CLAIM)?, claims_before);
    Ok(())
}

#[test]
fn each_prediction_lands_as_its_own_proposed_claim_with_source_receipt() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let first = EntityId::now();
    let second = EntityId::now();
    let first_body = b"first decision source";
    let second_body = b"second decision source";
    put_entity(&vault, first, ENTITY_TYPE_PERSON, first_body)?;
    put_entity(&vault, second, ENTITY_TYPE_PERSON, second_body)?;
    let question = question();
    let question_id = question.id;
    let gate_before = vault.gate_decisions(100)?.len();
    let mut answerer = FixedAnswerer::returning(Some(prediction()));

    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question,
        &[first, second],
        &mut answerer,
        12,
    )
    .map_err(|failure| *failure.error)?;

    assert!(result.abstained.is_empty());
    assert_eq!(result.answers.len(), 2);
    let gate_receipts = vault.gate_decisions(100)?;
    assert_eq!(gate_receipts.len(), gate_before + result.answers.len());
    for answer in &result.answers {
        assert_eq!(
            gate_receipts
                .iter()
                .filter(|row| row.claim_id == Some(*answer.claim.as_bytes()))
                .count(),
            1
        );
    }
    for (record, unit, body) in [
        (&result.answers[0], first, first_body.as_slice()),
        (&result.answers[1], second, second_body.as_slice()),
    ] {
        assert_eq!(record.unit, unit);
        assert_eq!(record.decision.answer, DecisionAnswer::Choice("yes".into()));
        assert_eq!(record.decision.probability, Some(0.8));
        assert_eq!(record.decision.evidence[0], unit);
        assert_eq!(
            record.decision.evidence.len(),
            record.decision.receipt.evidence_versions.len()
        );
        assert_eq!(record.frontier, *blake3::hash(body).as_bytes());
        let receipt = &record.decision.receipt;
        assert_eq!(receipt.question, question_id);
        assert_eq!(receipt.question_version, 1);
        assert_eq!(receipt.principal, principal);
        assert_eq!(receipt.providers, vec![prediction().provider]);
        assert_eq!(receipt.cost_per_thousand, Some(0.25));
        assert!(!receipt.evidence_versions.is_empty());
        assert_eq!(receipt.evidence_versions[0].id, unit);
        assert_eq!(
            receipt.evidence_versions[0].body_hash,
            *blake3::hash(body).as_bytes()
        );

        let stored = vault
            .get_claim(&record.claim)?
            .expect("proposed answer claim stored");
        assert_eq!(stored.predicate, "judgment.answer");
        assert_eq!(stored.subject, ClaimSubject::Entity(unit));
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    }
    Ok(())
}

#[test]
fn invalid_provider_output_fails_before_any_claim_is_written() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let unit = EntityId::now();
    put_entity(&vault, unit, ENTITY_TYPE_PERSON, b"valid source")?;
    let claims_before = vault.entities_by_type(ENTITY_TYPE_CLAIM)?;
    let mut invalid = prediction();
    invalid.provider.model = "not-a-provider-model".into();
    let mut answerer = FixedAnswerer::returning(Some(invalid));

    let error = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        13,
    )
    .expect_err("invalid provider output must be refused");

    assert!(matches!(*error.error, crate::Error::InvalidConfig(_)));
    assert_eq!(error.failed_unit, Some(unit));
    assert!(error.completed.answers.is_empty());
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_CLAIM)?, claims_before);
    Ok(())
}

enum Mutation {
    Entity { entity_type: u8, body: Vec<u8> },
    Claim(Box<ClaimBody>),
}

struct MutatingAnswerer<'a> {
    vault: &'a Vault,
    unit: EntityId,
    mutation: Mutation,
    contexts: Vec<GraphUnitContext>,
}

impl GraphAnswerer for MutatingAnswerer<'_> {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> crate::Result<Option<GraphPrediction>> {
        self.contexts.push(context.clone());
        match &self.mutation {
            Mutation::Entity { entity_type, body } => {
                self.vault
                    .put_entity(&self.unit, *entity_type, at(2), 2, body)?;
            }
            Mutation::Claim(body) => self.vault.put_claim(&self.unit, body, at(2), 2)?,
        }
        Ok(Some(prediction()))
    }
}

#[test]
fn revoked_scope_during_answering_discards_the_prediction() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let stranger = EntityId::now();
    put_entity(&vault, stranger, ENTITY_TYPE_PERSON, b"stranger")?;
    let unit = EntityId::now();
    put_scoped_claim(&vault, unit, principal, principal)?;
    let claims_before = vault.entities_by_type(ENTITY_TYPE_CLAIM)?;
    let mut answerer = MutatingAnswerer {
        vault: &vault,
        unit,
        mutation: Mutation::Claim(Box::new(scoped_claim(stranger, principal))),
        contexts: Vec::new(),
    };

    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        14,
    )
    .map_err(|failure| *failure.error)?;

    assert!(result.answers.is_empty());
    assert_eq!(result.abstained, vec![unit]);
    assert_eq!(answerer.contexts.len(), 1);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_CLAIM)?, claims_before);
    Ok(())
}

#[test]
fn stale_source_after_answering_is_abstained_without_a_claim() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let unit = EntityId::now();
    put_entity(&vault, unit, ENTITY_TYPE_PERSON, b"before answer")?;
    let claims_before = vault.entities_by_type(ENTITY_TYPE_CLAIM)?;
    let mut answerer = MutatingAnswerer {
        vault: &vault,
        unit,
        mutation: Mutation::Entity {
            entity_type: ENTITY_TYPE_PERSON,
            body: b"changed while the answerer ran".to_vec(),
        },
        contexts: Vec::new(),
    };

    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        15,
    )
    .map_err(|failure| *failure.error)?;

    assert!(result.answers.is_empty());
    assert_eq!(result.abstained, vec![unit]);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_CLAIM)?, claims_before);
    Ok(())
}

#[test]
fn type_selector_limits_candidates_to_visible_rows_of_that_type() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, _actor) = identities(&vault)?;
    let first_org = EntityId::now();
    let second_org = EntityId::now();
    let person = EntityId::now();
    put_entity(&vault, first_org, ENTITY_TYPE_ORG, b"first org")?;
    put_entity(&vault, second_org, ENTITY_TYPE_ORG, b"second org")?;
    put_entity(&vault, person, ENTITY_TYPE_PERSON, b"not an org")?;

    let organizations = select_graph_units_by_type(&vault, principal, ENTITY_TYPE_ORG, 10)?;
    assert_eq!(organizations.len(), 2);
    assert!(organizations.contains(&first_org));
    assert!(organizations.contains(&second_org));
    assert!(!organizations.contains(&person));

    let visible_claim = EntityId::now();
    let hidden_claim = EntityId::now();
    put_scoped_claim(&vault, visible_claim, principal, principal)?;
    put_scoped_claim(&vault, hidden_claim, EntityId::now(), principal)?;
    let claims = select_graph_units_by_type(&vault, principal, ENTITY_TYPE_CLAIM, 10)?;
    assert!(claims.contains(&visible_claim));
    assert!(!claims.contains(&hidden_claim));
    assert!(select_graph_units_by_type(&vault, principal, ENTITY_TYPE_ORG, 0)?.is_empty());
    assert!(select_graph_units_by_type(&vault, principal, ENTITY_TYPE_ORG, 4097).is_err());
    Ok(())
}

#[test]
fn mail_and_private_note_each_get_one_receipted_prediction() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let receipt = vault
        .memory(principal, EdgeActorClass::Human)
        .witness(&crate::WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            messages: vec![crate::WitnessMessage {
                id: None,
                author: crate::WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "Fixture inbound mail".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 10,
        })
        .expect("witness message");
    assert_eq!(receipt.message_short_ids.len(), 1);
    let mail = vault.entities_by_type(ENTITY_TYPE_MESSAGE)?[0];
    let note = vault
        .create_note(
            "diary",
            "A paragraph of fixture notes.",
            WriteActor::new(principal, EdgeActorClass::Human),
        )
        .expect("author a private NOTE");

    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[mail, note],
        &mut answerer,
        16,
    )
    .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 2);
    assert!(result.abstained.is_empty());
    assert_eq!(answerer.contexts.len(), 2);
    for (answer, source) in result.answers.iter().zip([mail, note]) {
        assert_eq!(answer.unit, source);
        assert_eq!(answer.decision.probability, Some(0.8));
        assert_eq!(answer.decision.receipt.evidence_versions[0].id, source);
        assert_eq!(
            vault.get_claim(&answer.claim)?.unwrap().approval,
            ClaimApprovalStatus::Proposed
        );
    }
    let mut other = FixedAnswerer::returning(Some(prediction()));
    let stranger = EntityId::now();
    put_entity(&vault, stranger, ENTITY_TYPE_PERSON, b"stranger")?;
    let hidden = run_graph_ask(&vault, stranger, actor, question(), &[note], &mut other, 17)
        .map_err(|failure| *failure.error)?;
    assert!(hidden.answers.is_empty());
    assert!(other.contexts.is_empty());
    Ok(())
}

#[test]
fn derived_answer_keeps_the_least_trusted_neighborhood_source() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, _) = identities(&vault)?;
    let unit = EntityId::now();
    let neighbor = EntityId::now();
    put_entity(&vault, neighbor, ENTITY_TYPE_ORG, b"imported context")?;
    let mut body = scoped_claim(principal, principal);
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(&unit, &body, at(1), 1)?;
    vault.put_edge(&unit, EdgeKind::Mentions, &neighbor, 0.8)?;
    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        WriteActor::new(principal, EdgeActorClass::Human),
        question(),
        &[unit],
        &mut answerer,
        18,
    )
    .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 1);
    assert!(
        answerer.contexts[0]
            .sources
            .iter()
            .any(|s| s.id == neighbor)
    );
    let landed = vault
        .get_claim(&result.answers[0].claim)?
        .expect("answer claim");
    assert_eq!(landed.source, Some(ClaimSource::Imported));
    Ok(())
}

#[test]
fn distinct_writer_can_answer_asker_private_claim() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let unit = EntityId::now();
    put_scoped_claim(&vault, unit, principal, principal)?;
    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        19,
    )
    .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 1);
    assert_eq!(result.answers[0].unit, unit);
    assert_eq!(
        vault.get_claim(&result.answers[0].claim)?.unwrap().approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[test]
fn class_bound_asker_grant_does_not_require_a_writer_read_grant() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    grant_class_bound_graph_reads(&vault, principal)?;
    let unit = EntityId::now();
    put_scoped_claim(&vault, unit, principal, principal)?;
    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        20,
    )
    .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 1);
    assert_eq!(result.answers[0].decision.receipt.principal, principal);
    Ok(())
}

struct FailsOnSecond(usize);
impl GraphAnswerer for FailsOnSecond {
    fn answer(
        &mut self,
        _: &DecisionQuestion,
        _: &GraphUnitContext,
    ) -> crate::Result<Option<GraphPrediction>> {
        self.0 += 1;
        if self.0 == 2 {
            Err(crate::Error::InvalidConfig(
                "fixture provider failed".into(),
            ))
        } else {
            Ok(Some(prediction()))
        }
    }
}

#[test]
fn later_provider_failure_returns_earlier_committed_receipts() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    for id in ids {
        put_entity(&vault, id, ENTITY_TYPE_ORG, b"graph unit")?;
    }
    let error = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &ids,
        &mut FailsOnSecond(0),
        21,
    )
    .expect_err("provider must fail at second unit");
    assert_eq!(error.failed_unit, Some(ids[1]));
    assert!(matches!(*error.error, crate::Error::InvalidConfig(_)));
    assert_eq!(error.completed.answers.len(), 1);
    assert_eq!(error.completed.answers[0].unit, ids[0]);
    assert!(
        vault
            .get_claim(&error.completed.answers[0].claim)?
            .is_some()
    );
    assert!(vault.claims_for_subject(&ids[1])?.iter().all(|id| {
        vault
            .get_claim(id)
            .unwrap()
            .is_none_or(|body| body.predicate != "judgment.answer")
    }));
    Ok(())
}

#[test]
fn write_snapshot_invalidation_abstains_and_continues_after_committed_answer() -> crate::Result<()>
{
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    let (_temp, vault) = open_vault();
    let vault = Arc::new(vault);
    let (principal, actor) = identities(&vault)?;
    let ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    for id in ids {
        put_entity(&vault, id, ENTITY_TYPE_ORG, b"original")?;
    }
    let (arrived_tx, arrived_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    vault
        .test_hooks()
        .install_graph_ask_preflight(ids[1], move || {
            arrived_tx.send(()).expect("notify writer");
            resume_rx.recv().expect("resume graph ask");
        });
    let worker_vault = Arc::clone(&vault);
    let worker = std::thread::spawn(move || {
        let mut answerer = FixedAnswerer::returning(Some(prediction()));
        run_graph_ask(
            &worker_vault,
            principal,
            actor,
            question(),
            &ids,
            &mut answerer,
            22,
        )
    });
    arrived_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("preflight reached");
    put_entity(&vault, ids[1], ENTITY_TYPE_ORG, b"changed after preflight")?;
    resume_tx.send(()).expect("release write check");
    let result = worker
        .join()
        .expect("ask thread")
        .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 2);
    assert_eq!(result.answers[0].unit, ids[0]);
    assert_eq!(result.answers[1].unit, ids[2]);
    assert_eq!(result.abstained, vec![ids[1]]);
    Ok(())
}

#[test]
fn high_degree_unit_stops_after_bounded_readable_neighborhood() -> crate::Result<()> {
    let (_temp, vault) = open_vault();
    let (principal, actor) = identities(&vault)?;
    let unit = EntityId::now();
    put_entity(&vault, unit, ENTITY_TYPE_ORG, b"hub")?;
    let ids: Vec<_> = (0..100_001_u32)
        .map(|i| {
            let mut bytes = [0x42; 16];
            bytes[12..].copy_from_slice(&i.to_be_bytes());
            EntityId::from_bytes(bytes).expect("neighbor id")
        })
        .collect();
    for id in ids.iter().take(16) {
        put_entity(&vault, *id, ENTITY_TYPE_ORG, b"nearby")?;
    }
    let value = crate::edge::encode_edge_value(
        EdgeKind::Mentions,
        0.8,
        1,
        crate::affect::Vad::NEUTRAL,
        None,
    )?;
    vault.with_write_txn(|txn| {
        for id in &ids {
            let forward = crate::store::Store::encode_edge_key(&unit, EdgeKind::Mentions, id);
            let reverse = crate::store::Store::encode_edge_key(id, EdgeKind::Mentions, &unit);
            vault.store.edges_out.put(txn, &forward, &value)?;
            vault.store.edges_in.put(txn, &reverse, &value)?;
        }
        Ok(())
    })?;
    let mut answerer = FixedAnswerer::returning(Some(prediction()));
    let result = run_graph_ask(
        &vault,
        principal,
        actor,
        question(),
        &[unit],
        &mut answerer,
        23,
    )
    .map_err(|failure| *failure.error)?;
    assert_eq!(result.answers.len(), 1);
    assert_eq!(answerer.contexts.len(), 1);
    assert_eq!(answerer.contexts[0].sources.len(), 17);
    Ok(())
}
