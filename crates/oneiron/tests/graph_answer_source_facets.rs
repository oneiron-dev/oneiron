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
//! (FIX STANDING-ANSWER-STAYS-IN-LEFT-FACET, Engine ruling A, 19 Nov 13:29),
//! and the refresh it queues lands where the room reads the row now. A row
//! read only in facets no FACET row holds holds no answer: the vault default
//! takes only a row read in no facet (review round 1 on #9604).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test graph_answer_source_facets`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::llm::decision::questions::{
    AnswerProposal, GraphAnswerer, GraphAskResult, GraphPrediction, GraphQuestionInput,
    GraphQuestionRef, GraphUnitContext, QuestionActivation, QuestionDefinitionInput, RefreshBatch,
    RefreshPolicy, create_question, refresh_due_questions, run_graph_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_ORG,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::room_facet_set::{create_owner_project, set_room_facets};
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
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

    /// A fresh agent holding the owner's live `read` Grant over MESSAGE and
    /// CLAIM rows placed in `facets` alone; every other axis covers every row.
    /// Its read of its own answer goes through that Grant, which holds the
    /// answer inside the Grant's facets.
    fn agent_reading_in(&self, facets: &BTreeSet<EntityId>) -> TestResult<EntityId> {
        let agent = define_agent(&self.vault)?;
        self.grant_reading_in(agent, facets)?;
        Ok(agent)
    }

    /// The owner's live `read` Grant to `agent` over MESSAGE and CLAIM rows
    /// placed in `facets` alone, every other axis covering every row; returns
    /// the Grant's row. This install's live machine profile carries the
    /// owner's agent Grant act, as a serving start or `init` enrols it (FIX
    /// 4648).
    fn grant_reading_in(
        &self,
        agent: EntityId,
        facets: &BTreeSet<EntityId>,
    ) -> TestResult<EntityId> {
        self.vault
            .ensure_serving_install_profile(&self.issuer, MachineRole::Unanswered)
            .map_err(|error| format!("this install's live machine profile: {error:?}"))?;
        let mut authority_scope = Scope::top();
        authority_scope.bands =
            ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_MESSAGE, ENTITY_TYPE_CLAIM]));
        authority_scope.facets = ScopeAxis::Some(facets.iter().copied().map(ScopeId).collect());
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .map_err(|error| format!("the owner mints the agent's read Grant: {error:?}"))?;
        assert!(
            minted.grant.confers,
            "precondition: the agent's Grant confers"
        );
        Ok(minted.grant.grant_ref)
    }

    /// The owner's revoke of the agent Grant `grant`.
    fn revoke_grant(&self, grant: EntityId) -> TestResult {
        let revoked = revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .map_err(|error| format!("the owner revokes the agent's Grant: {error:?}"))?;
        assert!(revoked.changed, "precondition: the revoke lands");
        Ok(())
    }

    /// `agent`'s own saved graph question over `units`.
    fn agent_question(
        &self,
        agent: EntityId,
        units: Vec<EntityId>,
    ) -> TestResult<GraphQuestionRef> {
        let record = create_question(
            &self.vault,
            WriteActor::new(agent, EdgeActorClass::Agent),
            definition(units),
            2,
        )?;
        Ok(GraphQuestionRef {
            id: record.definition.question.id,
            version: record.definition.question.version,
        })
    }

    /// The answer to `agent`'s question on `unit`, written by the owner.
    fn agent_ask(
        &self,
        agent: EntityId,
        question: GraphQuestionRef,
        unit: EntityId,
    ) -> Result<GraphAskResult, String> {
        run_graph_question(
            &self.vault,
            agent,
            self.actor(),
            question,
            &[GraphQuestionInput {
                unit,
                evidence: Vec::new(),
            }],
            &mut ScriptedAnswerer,
            3,
        )
        .map_err(|failure| failure.error.to_string())
    }

    /// Whether `agent`'s own read lane reads `record`: a withheld row reads
    /// as none, or as a not-found or forbidden refusal.
    fn agent_reads(&self, agent: EntityId, record: EntityId) -> bool {
        match self
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .get_entity(&record.to_hex())
        {
            Ok(read) => read
                .value
                .is_some_and(|view| view.id_hex == record.to_hex()),
            Err(refused) => {
                assert!(
                    refused.code == MEMORY_CODE_NOT_FOUND || refused.code == MEMORY_CODE_FORBIDDEN,
                    "the read answers a row or withholds it: {refused:?}"
                );
                false
            }
        }
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

#[test]
fn a_room_reading_only_an_unstored_facet_stales_its_answer_and_lands_none() -> TestResult {
    let fixture = open()?;
    // A room set names scope ids, not FACET rows: the slice facet here is one
    // no FACET row holds, and the set's other facet is the vault default.
    let unstored = EntityId::now();
    let default = fixture.vault.default_facet()?;
    let (project, room) = fixture.project_room(unstored)?;
    fixture.set_room(project, Some(BTreeSet::from([unstored, default])))?;
    let message = fixture.message_in_room(room, "The clinic moves upstairs in June.")?;
    let question = fixture.question(vec![message])?;
    let shared = fixture
        .ask(question, message, Vec::new())
        .map_err(|error| format!("an answer on a room MESSAGE lands; it refused: {error}"))?;
    assert_eq!(
        fixture.answer_facet(&shared)?,
        default,
        "precondition: the answer lands at the one stored facet the room reads"
    );

    // The room now reads only the unstored slice facet: a reader of the
    // default facet no longer reads the MESSAGE.
    fixture.set_room(project, None)?;
    assert!(
        fixture.answer_stale(Fixture::answer_claim(&shared))?,
        "an answer in the default facet the room left is marked stale, though no stored facet \
         replaces it"
    );
    match fixture.ask(question, message, Vec::new()) {
        Err(error) => assert!(
            error.contains(NO_SHARED_POSITION),
            "an answer on a row read only in a facet no FACET row holds refuses as having no \
             shared position: {error}"
        ),
        Ok(again) => panic!(
            "no answer lands on a row read only in a facet no FACET row holds; {} landed",
            again.answers.len()
        ),
    }
    Ok(())
}

#[test]
fn an_agents_fresh_answer_lands_in_a_facet_its_grant_reads() -> TestResult {
    let fixture = open()?;
    let mut facets = [
        fixture.put_row(ENTITY_TYPE_FACET, "work")?,
        fixture.put_row(ENTITY_TYPE_FACET, "health")?,
        fixture.put_row(ENTITY_TYPE_FACET, "home")?,
    ];
    facets.sort();
    let [low, middle, high] = facets;
    let (project, room) = fixture.project_room_reading(&BTreeSet::from(facets))?;
    let message = fixture.message_in_room(room, "The ward rota is posted on Sundays.")?;
    // The agent reads the MESSAGE through its Grant's `high`, and its answers
    // only in `low` and `high`.
    let agent = fixture.agent_reading_in(&BTreeSet::from([low, high]))?;
    let question = fixture.agent_question(agent, vec![message])?;
    let first = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| {
            format!("the agent's answer on a room MESSAGE lands; it refused: {error}")
        })?;
    assert_eq!(
        fixture.answer_facet(&first)?,
        low,
        "precondition: the agent's first answer lands at the lowest facet the room reads"
    );

    fixture.set_room(project, Some(BTreeSet::from([middle, high])))?;
    assert!(
        fixture.answer_stale(Fixture::answer_claim(&first))?,
        "precondition: the answer in the facet the room left is marked stale"
    );
    let again = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| format!("the agent's fresh answer lands; it refused: {error}"))?;
    assert_eq!(
        fixture.answer_facet(&again)?,
        high,
        "the fresh answer lands where the room reads the MESSAGE and the agent's Grant reads \
         the answer, not at the lower facet its Grant does not read"
    );
    assert!(
        fixture.agent_reads(agent, Fixture::answer_claim(&again)),
        "the agent reads its fresh answer back"
    );
    Ok(())
}

/// FIX STANDING-ANSWER-FACET-LIMITED-REPLAY-TEST: a facet-limited agent's
/// answer on a row read in two facets lands at the lower, which its Grant
/// reads, and a second ask replays it. Once the agent's only Grant reads the
/// higher facet alone, it no longer reads that answer, and its next ask does
/// not replay it: a fresh answer lands at the higher facet, and that one
/// replays.
#[test]
fn a_facet_limited_agent_replays_its_answer_only_while_its_grant_reads_the_answers_facet()
-> TestResult {
    let fixture = open()?;
    let work = fixture.put_row(ENTITY_TYPE_FACET, "work")?;
    let health = fixture.put_row(ENTITY_TYPE_FACET, "health")?;
    let (low, high) = (work.min(health), work.max(health));
    let (_project, room) = fixture.project_room_reading(&BTreeSet::from([low, high]))?;
    let message = fixture.message_in_room(room, "The ward rota is posted on Mondays.")?;
    let agent = define_agent(&fixture.vault)?;
    let lower = fixture.grant_reading_in(agent, &BTreeSet::from([low]))?;
    let question = fixture.agent_question(agent, vec![message])?;
    let first = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| {
            format!("the agent's answer on a room MESSAGE lands; it refused: {error}")
        })?;
    let recorded = Fixture::answer_claim(&first);
    assert_eq!(
        fixture.answer_facet(&first)?,
        low,
        "precondition: the answer on a row read in two facets lands at the lower, which the \
         agent's Grant reads"
    );

    let replayed = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| {
            format!(
                "a second ask under a Grant over the answer's facet replays the recorded \
                 answer; it refused: {error}"
            )
        })?;
    assert_eq!(
        Fixture::answer_claim(&replayed),
        recorded,
        "a second ask on the unchanged MESSAGE under a Grant over the answer's facet replays \
         the recorded answer"
    );
    assert!(
        fixture.agent_reads(agent, recorded),
        "the agent reads its recorded answer back"
    );

    // Control: the agent's only Grant now reads the higher facet alone.
    fixture.revoke_grant(lower)?;
    fixture.grant_reading_in(agent, &BTreeSet::from([high]))?;
    assert!(
        !fixture.agent_reads(agent, recorded),
        "a Grant over the higher facet alone does not read the answer at the lower"
    );
    let again = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| {
            format!(
                "the agent's answer under a Grant over the higher facet lands; it refused: \
                 {error}"
            )
        })?;
    let fresh = Fixture::answer_claim(&again);
    assert_ne!(
        fresh, recorded,
        "an ask under a Grant that does not read the recorded answer's facet does not replay it"
    );
    assert_eq!(
        fixture.answer_facet(&again)?,
        high,
        "the fresh answer lands at the facet the agent's Grant reads"
    );
    assert!(
        fixture.agent_reads(agent, fresh),
        "the agent reads its fresh answer back"
    );
    let replayed_fresh = fixture
        .agent_ask(agent, question, message)
        .map_err(|error| format!("a further ask replays the fresh answer; it refused: {error}"))?;
    assert_eq!(
        Fixture::answer_claim(&replayed_fresh),
        fresh,
        "a further ask under the Grant over the higher facet replays the answer there"
    );
    Ok(())
}
