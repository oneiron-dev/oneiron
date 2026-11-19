//! A saved graph question's answer sits in a facet every source it rests on
//! is read in (FIX STANDING-ANSWER-TWO-FACETLESS-SOURCES-CONFLICT, Engine
//! ruling 19 Nov 12:50; review P1 on #9582). A non-PERSON row born under the
//! default record stamp sits at its own derived substrate id, which no FACET
//! row holds. One said in a project's home room is read in the room's facet,
//! and the answer sits there; one read in no facet stands at the vault
//! default facet. Two such rows fold; two rows whose stored facets differ
//! still refuse. Rows read in several facets meet at the lowest facet id
//! (Engine ANSWER STANDING-ANSWER-FACET-PLACEMENT = A, 19 Nov 12:57). When a
//! room's facet set changes under an unchanged row, the next answer lands
//! where the row is read now (review round 2 on #9582). When the set narrows,
//! an answer already written in a facet the room left is marked stale
//! (FIX STANDING-ANSWER-STAYS-IN-LEFT-FACET, Engine ruling A, 19 Nov 13:29).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test graph_answer_source_facets`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    AnswerProposal, GraphAnswerer, GraphAskResult, GraphPrediction, GraphQuestionInput,
    GraphQuestionRef, GraphUnitContext, QuestionActivation, QuestionDefinitionInput, RefreshBatch,
    RefreshPolicy, create_question, refresh_due_questions, run_graph_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::{create_owner_project, set_room_facets};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The refusal of an answer whose sources share no position.
const NO_SHARED_POSITION: &str = "incompatible evidence scope";

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer; the root project carries the owner's
/// signature. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.sign_owner_project(
        &owner_proof,
        &vault.owner_project_signer(&issuer)?,
        vault.root_project()?,
    )?;
    Ok(Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    })
}

impl Fixture {
    fn actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    /// A row of type `kind` with a small map body.
    fn put_row(&self, kind: u8, name: &str) -> TestResult<EntityId> {
        let id = EntityId::now();
        self.vault.put_entity(
            &id,
            kind,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({ "name": name }))?,
        )?;
        Ok(id)
    }

    /// The owner's one-MESSAGE turn in `room`.
    fn turn(&self, room: EntityId, text: &str) -> WitnessTurn {
        WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            project: None,
            occurred_at: self.vault.now_recorded_at(),
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        }
    }

    /// The owner's MESSAGE in a fresh ordinary conversation: it sits in no
    /// facet.
    fn message_in_no_facet(&self, text: &str) -> TestResult<EntityId> {
        let turn = self.turn(EntityId::now(), text);
        let message = message_of(&turn)?;
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness(&turn)?;
        Ok(message)
    }

    /// The owner's MESSAGE said in the project home room `room`.
    fn message_in_room(&self, room: EntityId, text: &str) -> TestResult<EntityId> {
        let turn = self.turn(room, text);
        let message = message_of(&turn)?;
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&turn)?;
        Ok(message)
    }

    /// An owner-born project under the root, led by the owner and sliced to
    /// `facet`; returns the project and its home room.
    fn project_room(&self, facet: EntityId) -> TestResult<(EntityId, EntityId)> {
        let root = self.vault.root_project()?;
        let id = EntityId::now();
        let mut record = ProjectRecord::new(id, Some(root), root, self.owner)?;
        record.slice.facet = Some(facet);
        record.depth_remaining = 1;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
            self.owner,
            id,
            &record,
        )?;
        Ok((id, EntityId::from_hex(&record.home_room)?))
    }

    /// The owner's saved graph question over `units`.
    fn question(&self, units: Vec<EntityId>) -> TestResult<GraphQuestionRef> {
        self.question_of(definition(units))
    }

    /// The owner's saved graph question `definition`.
    fn question_of(&self, definition: QuestionDefinitionInput) -> TestResult<GraphQuestionRef> {
        let record = create_question(&self.vault, self.actor(), definition, 2)?;
        Ok(GraphQuestionRef {
            id: record.definition.question.id,
            version: record.definition.question.version,
        })
    }

    /// One pass of the question pump over the work due now.
    fn refresh_due(&self) -> TestResult<RefreshBatch> {
        Ok(refresh_due_questions(
            &self.vault,
            self.actor(),
            self.vault.now_recorded_at(),
            |_, _, _| {
                Ok(AnswerProposal {
                    answer: DecisionAnswer::Choice("yes".into()),
                    probability: Some(0.8),
                    providers: vec![ProviderPin {
                        rung: DecisionRung::Local,
                        model: "local/fixture".into(),
                        version: "r1".into(),
                    }],
                    paired: Vec::new(),
                    rule: None,
                    cost_per_thousand: None,
                })
            },
        )?)
    }

    /// The owner's answer on `unit` resting on `evidence` too.
    fn ask(
        &self,
        question: GraphQuestionRef,
        unit: EntityId,
        evidence: Vec<EntityId>,
    ) -> Result<GraphAskResult, String> {
        run_graph_question(
            &self.vault,
            self.owner,
            self.actor(),
            question,
            &[GraphQuestionInput { unit, evidence }],
            &mut ScriptedAnswerer,
            3,
        )
        .map_err(|failure| failure.error.to_string())
    }

    /// The facet the stored answer CLAIM of `result`'s one answer sits in.
    fn answer_facet(&self, result: &GraphAskResult) -> TestResult<EntityId> {
        assert_eq!(result.answers.len(), 1, "one answer is written");
        let claim = self
            .vault
            .get_claim(&result.answers[0].claim)?
            .ok_or("the written answer reads back")?;
        Ok(claim.scope_facet)
    }

    /// Whether the answer CLAIM `claim` is marked stale.
    fn answer_stale(&self, claim: EntityId) -> TestResult<bool> {
        Ok(self
            .vault
            .get_claim(&claim)?
            .ok_or("the written answer reads back")?
            .stale)
    }

    /// The one answer CLAIM of `result`.
    fn answer_claim(result: &GraphAskResult) -> EntityId {
        assert_eq!(result.answers.len(), 1, "one answer is written");
        result.answers[0].claim
    }

    /// A project home room whose signed set reads `facets`, the project's own
    /// slice facet the highest of them; returns the project and its room.
    fn project_room_reading(
        &self,
        facets: &BTreeSet<EntityId>,
    ) -> TestResult<(EntityId, EntityId)> {
        let slice = *facets.last().ok_or("a set holds a facet")?;
        let (project, room) = self.project_room(slice)?;
        self.set_room(project, Some(facets.clone()))?;
        Ok((project, room))
    }

    /// Signs `facets` as `project`'s room facet set, or drops the set.
    fn set_room(&self, project: EntityId, facets: Option<BTreeSet<EntityId>>) -> TestResult {
        set_room_facets(
            &self.vault,
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
            project,
            facets,
        )?;
        Ok(())
    }
}

fn message_of(turn: &WitnessTurn) -> TestResult<EntityId> {
    let id = turn.messages[0]
        .id
        .as_deref()
        .ok_or("the turn names its MESSAGE")?;
    Ok(EntityId::from_hex(id)?)
}

struct ScriptedAnswerer;

impl GraphAnswerer for ScriptedAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> oneiron::Result<Option<GraphPrediction>> {
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
            text: "Does the evidence settle the unit?".into(),
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
fn an_answer_on_two_rows_in_no_facet_stands_at_the_vault_default_facet() -> TestResult {
    let fixture = open()?;
    let first = fixture.message_in_no_facet("The garden rota is posted.")?;
    let second = fixture.message_in_no_facet("The rota names every bed.")?;
    let club = fixture.put_row(ENTITY_TYPE_ORG, "Garden club")?;
    let question = fixture.question(vec![first])?;
    let default = fixture.vault.default_facet()?;

    let messages = fixture
        .ask(question, first, vec![second])
        .map_err(|error| {
            format!("an answer on two MESSAGEs in no facet folds; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&messages)?,
        default,
        "an answer on two MESSAGEs in no facet stands at the vault default facet"
    );
    let mixed = fixture.ask(question, first, vec![club]).map_err(|error| {
        format!("an answer on a MESSAGE and an ORG in no facet folds; it refused: {error}")
    })?;
    assert_eq!(
        fixture.answer_facet(&mixed)?,
        default,
        "an answer on a MESSAGE and an ORG in no facet stands at the vault default facet"
    );
    Ok(())
}

#[test]
fn an_answer_on_rows_said_in_a_project_room_sits_in_the_rooms_facet() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let (_, room) = fixture.project_room(work)?;
    let first = fixture.message_in_room(room, "The launch slips a week.")?;
    let second = fixture.message_in_room(room, "The launch notes are in.")?;
    let question = fixture.question(vec![first])?;
    assert_ne!(
        fixture.vault.default_facet()?,
        work,
        "precondition: the room's facet is not the vault default"
    );

    let alone = fixture
        .ask(question, first, Vec::new())
        .map_err(|error| format!("an answer on one room MESSAGE lands; it refused: {error}"))?;
    assert_eq!(
        fixture.answer_facet(&alone)?,
        work,
        "an answer on one room MESSAGE sits in the room's facet, where its reader reads it"
    );
    let both = fixture
        .ask(question, first, vec![second])
        .map_err(|error| {
            format!("an answer on two MESSAGEs in one room folds; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&both)?,
        work,
        "an answer on two MESSAGEs said in one room sits in the room's facet"
    );
    Ok(())
}

#[test]
fn an_answer_on_rows_at_two_different_stored_facets_still_refuses() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let question = fixture.question(vec![work])?;

    match fixture.ask(question, work, vec![health]) {
        Ok(result) => panic!(
            "an answer on two different stored facets must refuse; it wrote {} answer(s)",
            result.answers.len()
        ),
        Err(error) => assert!(
            error.contains(NO_SHARED_POSITION),
            "two different stored facets refuse as no shared position; got: {error}"
        ),
    }
    Ok(())
}

#[test]
fn an_answer_on_rows_read_in_several_facets_lands_at_the_lowest() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let (project, room) = fixture.project_room(work)?;
    set_room_facets(
        &fixture.vault,
        &fixture.owner_proof,
        &fixture.vault.owner_project_signer(&fixture.issuer)?,
        project,
        Some(BTreeSet::from([work, health])),
    )?;
    let first = fixture.message_in_room(room, "The clinic moved to Tuesdays.")?;
    let second = fixture.message_in_room(room, "The Tuesday slot is booked.")?;
    let question = fixture.question(vec![first])?;

    let both = fixture
        .ask(question, first, vec![second])
        .map_err(|error| {
            format!("an answer on two MESSAGEs in a room of two facets folds; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&both)?,
        work.min(health),
        "an answer on rows read in two facets lands at the lower facet id"
    );
    Ok(())
}

#[test]
fn an_answer_lands_again_where_its_unchanged_row_is_read_now() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    // The project's slice facet sorts last, so the set's lowest facet is not
    // the one the room keeps once the set is dropped.
    let (slice, other) = (work.max(health), work.min(health));
    let (project, room) = fixture.project_room(slice)?;
    let signer = fixture.vault.owner_project_signer(&fixture.issuer)?;
    set_room_facets(
        &fixture.vault,
        &fixture.owner_proof,
        &signer,
        project,
        Some(BTreeSet::from([slice, other])),
    )?;
    let message = fixture.message_in_room(room, "The ward rota changes on Monday.")?;
    let question = fixture.question(vec![message])?;

    let shared = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;
    assert_eq!(
        fixture.answer_facet(&shared)?,
        other,
        "precondition: an answer on a row read in two facets lands at the lower"
    );

    set_room_facets(&fixture.vault, &fixture.owner_proof, &signer, project, None)?;
    let narrowed = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| {
            format!("an answer on the unchanged MESSAGE lands again; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&narrowed)?,
        slice,
        "once the room reads only its slice facet, the answer on the unchanged MESSAGE lands \
         there, not in the facet the earlier answer took"
    );
    Ok(())
}

#[test]
fn an_answer_in_a_facet_its_room_left_is_marked_stale() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let (project, room) = fixture.project_room_reading(&BTreeSet::from([work, health]))?;
    let (slice, other) = (work.max(health), work.min(health));
    let message = fixture.message_in_room(room, "The night shift starts at ten.")?;
    let question = fixture.question(vec![message])?;
    let shared = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;
    let earlier = Fixture::answer_claim(&shared);
    assert_eq!(
        fixture.answer_facet(&shared)?,
        other,
        "precondition: an answer on a row read in two facets lands at the lower"
    );
    assert!(
        !fixture.answer_stale(earlier)?,
        "precondition: the answer stands"
    );

    fixture.set_room(project, None)?;
    assert!(
        fixture.answer_stale(earlier)?,
        "once the room no longer reads the facet its answer sits in, that answer is stale"
    );
    let narrowed = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| {
            format!("an answer on the unchanged MESSAGE lands again; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&narrowed)?,
        slice,
        "the next answer lands where the room reads the MESSAGE now"
    );
    assert!(
        !fixture.answer_stale(Fixture::answer_claim(&narrowed))?,
        "the next answer stands"
    );
    Ok(())
}

#[test]
fn an_answer_in_a_facet_its_room_still_reads_stays_standing() -> TestResult {
    let fixture = open()?;
    let mut facets = [
        fixture.put_row(ENTITY_TYPE_FACET, "work")?,
        fixture.put_row(ENTITY_TYPE_FACET, "health")?,
        fixture.put_row(ENTITY_TYPE_FACET, "home")?,
    ];
    facets.sort();
    let [low, _middle, slice] = facets;
    let (project, room) = fixture.project_room_reading(&BTreeSet::from(facets))?;
    let message = fixture.message_in_room(room, "The pharmacy closes at six.")?;
    let question = fixture.question(vec![message])?;
    let answer = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;
    assert_eq!(
        fixture.answer_facet(&answer)?,
        low,
        "precondition: the answer lands at the lowest facet the room reads"
    );

    fixture.set_room(project, Some(BTreeSet::from([low, slice])))?;
    assert!(
        !fixture.answer_stale(Fixture::answer_claim(&answer))?,
        "a narrowing that drops only the middle facet keeps the answer the room still reads \
         at the lowest"
    );
    Ok(())
}

#[test]
fn an_answer_lands_once_its_room_reads_the_left_facet_again() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let both = BTreeSet::from([work, health]);
    let (project, room) = fixture.project_room_reading(&both)?;
    let other = work.min(health);
    let message = fixture.message_in_room(room, "The ward meets on Fridays.")?;
    let question = fixture.question(vec![message])?;
    fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;

    fixture.set_room(project, None)?;
    fixture.set_room(project, Some(both))?;
    let again = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| {
            format!(
                "once the room reads both facets again, an answer on the unchanged MESSAGE \
                 lands; it refused: {error}"
            )
        })?;
    assert_eq!(
        fixture.answer_facet(&again)?,
        other,
        "the answer lands at the lower facet the room reads again"
    );
    assert!(
        !fixture.answer_stale(Fixture::answer_claim(&again))?,
        "the answer the unit has once the room reads the facet again stands"
    );
    Ok(())
}

#[test]
fn a_narrowing_queues_the_refresh_of_an_answer_it_marks_stale() -> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let (project, room) = fixture.project_room_reading(&BTreeSet::from([work, health]))?;
    let slice = work.max(health);
    let message = fixture.message_in_room(room, "The ward closes for repairs in May.")?;
    let mut watching = definition(vec![message]);
    watching.refresh.on_arrival = true;
    let question = fixture.question_of(watching)?;
    fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;
    // Whatever the question's creation queued runs first.
    fixture.refresh_due()?;

    fixture.set_room(project, None)?;
    let batch = fixture.refresh_due()?;
    let failures: Vec<String> = batch
        .failures
        .iter()
        .map(|failure| failure.error.to_string())
        .collect();
    assert!(failures.is_empty(), "the queued refresh runs: {failures:?}");
    assert_eq!(
        batch.answers.len(),
        1,
        "a narrowing that marks an answer stale queues its unit's refresh where the question \
         refreshes on arrival"
    );
    let answer = fixture
        .vault
        .get_claim(&batch.answers[0].claim)?
        .ok_or("the refreshed answer reads back")?;
    assert_eq!(
        answer.scope_facet, slice,
        "the refreshed answer lands where the room reads the MESSAGE now"
    );
    assert!(!answer.stale, "the refreshed answer stands");
    Ok(())
}
