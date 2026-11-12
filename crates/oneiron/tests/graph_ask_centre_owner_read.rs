//! STANDING-GRAPH-OWNER-CENTRE-READ: a manual refresh admits its centre and
//! peers under the same request as its point reads, without opting other lanes in.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphPrediction, GraphUnitContext, QuestionActivation, QuestionDefinitionInput,
    RefreshPolicy, answer_records, create_question, read_question, refresh_standing_question_with,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::graph_ask_centre as doors;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, Result, TimeRange, Vault, VaultConfig, WriteActor,
};

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    unit: EntityId,
    neighbor: EntityId,
}

fn put_person_and_read_back(vault: &Vault, owner: EntityId, body: &[u8]) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        body,
    )?;
    let read = vault
        .scoped_read(
            vault
                .memory(owner, EdgeActorClass::Human)
                .read_key()
                .expect("the owner's read key"),
        )
        .get_entity_parts_with_receipt(&id, None)?;
    let (kind, _, stored) = read.value.expect("written PERSON reads back as the owner");
    assert_eq!(kind, ENTITY_TYPE_PERSON);
    assert_eq!(stored, body);
    Ok(id)
}

fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, _proof) = embedded_owner(&vault)?;
    let owner_read = vault
        .scoped_read(
            vault
                .memory(owner, EdgeActorClass::Human)
                .read_key()
                .expect("the owner's read key"),
        )
        .get_entity_parts_with_receipt(&owner, None)?;
    assert_eq!(
        owner_read.value.expect("owner reads back").0,
        ENTITY_TYPE_PERSON
    );

    // Leave the freshly seeded policy manifest unchanged: the bare human
    // identity has no read row, unlike the explicit vault-owner key.
    let unit = put_person_and_read_back(&vault, owner, b"graph centre")?;
    let neighbor = put_person_and_read_back(&vault, owner, b"graph neighbour")?;
    vault.put_edge(&unit, EdgeKind::Mentions, &neighbor, 1.0)?;
    let edge_read = vault
        .scoped_read(
            vault
                .memory(owner, EdgeActorClass::Human)
                .read_key()
                .expect("the owner's read key"),
        )
        .edges_out(&unit)?;
    let edges = edge_read
        .value
        .expect("written adjacency reads back as the owner");
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Mentions && edge.target == neighbor)
    );
    Ok(Fixture {
        vault,
        _dir: dir,
        owner,
        unit,
        neighbor,
    })
}

struct ScriptedAnswerer;

impl GraphAnswerer for ScriptedAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        Ok(Some(GraphPrediction {
            answer: DecisionAnswer::Choice("yes".into()),
            probability: 0.8,
            provider: ProviderPin {
                rung: DecisionRung::Local,
                model: "local/fixture".into(),
                version: "r1".into(),
            },
            cost_per_thousand: 0.0,
            paired: None,
            rule: None,
        }))
    }
}

fn definition(units: Vec<EntityId>) -> QuestionDefinitionInput {
    QuestionDefinitionInput {
        question: DecisionQuestionInput {
            text: "Is the graph evidence relevant?".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Choice {
                options: vec!["yes".into(), "no".into()],
            },
            accept_type: false,
        },
        adapter: "graph".into(),
        units,
        recipe: "unit".into(),
        profile: "fixture".into(),
        dial: DecisionDial {
            first: DecisionRung::Local,
            ceiling: DecisionRung::Local,
            band: DecisionBand::default(),
        },
        activation: QuestionActivation::Standing,
        refresh: RefreshPolicy {
            on_arrival: false,
            every_seconds: None,
        },
        delivery: "now".into(),
        learning: false,
        binding: None,
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    }
}

#[test]
fn the_question_owner_reads_its_graph_unit_and_neighbour() -> Result<()> {
    let fixture = fixture()?;
    let actor = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let record = create_question(
        &fixture.vault,
        actor,
        definition(vec![fixture.unit, fixture.neighbor]),
        2,
    )?;
    let question = record.definition.question.id;
    let stored = read_question(&fixture.vault, fixture.owner, question, None)?
        .expect("created standing question reads back");
    assert_eq!(stored, record);

    let answers = refresh_standing_question_with(
        &fixture.vault,
        actor,
        fixture.owner,
        question,
        3,
        |_, _| Ok(ScriptedAnswerer),
    )?;
    // Read back every answer write before asserting on the refresh result.
    let stored_answers = answer_records(&fixture.vault, fixture.owner, question)?;
    let stored_claims = answers
        .iter()
        .map(|answer| fixture.vault.get_claim(&answer.claim))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        answers.len(),
        2,
        "the owner's standing graph refresh must answer each owned PERSON unit"
    );
    assert_eq!(stored_answers.len(), answers.len());
    assert!(stored_claims.iter().all(Option::is_some));
    for unit in [fixture.unit, fixture.neighbor] {
        let answer = answers
            .iter()
            .find(|answer| answer.unit == unit)
            .expect("one answer per owned unit");
        assert!(stored_answers.contains(answer));
        assert_eq!(answer.decision.answer, DecisionAnswer::Choice("yes".into()));
    }
    let neighbors = doors::neighbors(&fixture.vault, fixture.owner, &fixture.unit, true)?
        .expect("the question owner reads its graph neighbourhood");
    assert!(neighbors.contains(&fixture.neighbor));
    Ok(())
}

#[test]
fn a_lane_without_the_owner_alternative_still_reads_nothing() -> Result<()> {
    let fixture = fixture()?;
    let neighbors = doors::neighbors(&fixture.vault, fixture.owner, &fixture.unit, false)?;
    assert!(
        neighbors.is_none(),
        "a plain bare-owner lane must not gain owner authority"
    );
    Ok(())
}

#[test]
fn an_opted_in_lane_of_a_non_owner_reads_nothing() -> Result<()> {
    let fixture = fixture()?;
    let non_owner = put_person_and_read_back(&fixture.vault, fixture.owner, b"non-owner human")?;
    let neighbors = doors::neighbors(&fixture.vault, non_owner, &fixture.unit, true)?;
    assert!(
        neighbors.is_none(),
        "opting in must not make a non-owner an owner"
    );
    Ok(())
}
