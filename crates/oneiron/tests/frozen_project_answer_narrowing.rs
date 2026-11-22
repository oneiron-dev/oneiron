//! A frozen project's saved view can stop being served while the record
//! itself stays the same, and a standing answer its home room placed must
//! then go stale (FIX STANDING-ANSWER-FROZEN-CHILD-PARENT-NARROWING-TEST;
//! review rounds 1 and 2 on #9709, fixed there with no test).
//!
//! - A frozen child bound by its parent serves its saved view only while
//!   that view still fits the parent's; the owner's seal that narrows the
//!   parent leaves the child serving nothing, and the child's answer goes
//!   stale (red before 70288ca777d: an unchanged frozen record queued no
//!   room).
//! - In a chain A <- B <- C, a frozen B that no longer fits A serves
//!   nothing, so C reads no parent and its answer goes stale (red before
//!   18c830e0a02: B's unchanged record never woke C).
//! - A project frozen at one of two equally ranked sibling states serves
//!   that sibling alone; the owner's raised budget folds both and meets
//!   them narrower, and the answer the wider view placed goes stale in the
//!   budget's own write (red before 18c830e0a02: the setter only stored the
//!   budget).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test frozen_project_answer_narrowing`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, SlipCaveat};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphAskResult, GraphPrediction, GraphQuestionInput, GraphQuestionRef,
    GraphUnitContext, QuestionActivation, QuestionDefinitionInput, RefreshPolicy, create_question,
    run_graph_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::project_replicated_revision::put_replicated_project_state;
use oneiron::test_doors::room_facet_set::{
    create_owner_project, set_room_facets, with_room_facets,
};
use oneiron::workspace_roster::{
    ProjectAnchorLink, ProjectDisposition, ProjectFrontier, ProjectHistoryPolicy, ProjectRecord,
    ProjectWriteOutcome, ProjectWriteProof,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

/// The key the owner signs as its projects' leader with: the slip the host
/// mints for it binds this key.
fn leader_key(leader: EntityId) -> SigningKey {
    SigningKey::from_bytes(blake3::hash(leader.as_bytes()).as_bytes())
}

impl Fixture {
    fn actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    /// Two fresh FACET rows, the lower id first. A home room reading both
    /// places an answer at the lower one, and a project's slice facet, the
    /// room set's anchor, is the higher one, so the lower facet is the one a
    /// narrowing can drop.
    fn two_facets(&self) -> TestResult<(EntityId, EntityId)> {
        let mut facets = Vec::new();
        for name in ["work", "health"] {
            let id = EntityId::now();
            self.vault.put_entity(
                &id,
                ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({ "name": name }))?,
            )?;
            facets.push(id);
        }
        let (low, high) = (facets[0].min(facets[1]), facets[0].max(facets[1]));
        assert_ne!(
            self.vault.default_facet()?,
            low,
            "precondition: the facet an answer lands in is not the vault default"
        );
        Ok((low, high))
    }

    /// An owner-born project under `parent`, led by the owner, sliced to
    /// `slice` with `depth_remaining` levels left below it, whose home room
    /// then reads `room`; returns the project and its home room.
    fn project_under(
        &self,
        parent: EntityId,
        slice: EntityId,
        depth_remaining: u64,
        room: &BTreeSet<EntityId>,
    ) -> TestResult<(EntityId, EntityId)> {
        let id = EntityId::now();
        let mut record =
            ProjectRecord::new(id, Some(parent), self.vault.root_project()?, self.owner)?;
        record.slice.facet = Some(slice);
        record.depth_remaining = depth_remaining;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
            self.owner,
            id,
            &record,
        )?;
        self.set_room(id, room)?;
        Ok((id, EntityId::from_hex(&record.home_room)?))
    }

    /// The owner's set door signs `facets` as `project`'s room facet set.
    fn set_room(&self, project: EntityId, facets: &BTreeSet<EntityId>) -> TestResult {
        set_room_facets(
            &self.vault,
            &self.owner_proof,
            &self.vault.owner_project_signer(&self.issuer)?,
            project,
            Some(facets.clone()),
        )?;
        Ok(())
    }

    /// Signs `body`, carrying room facet set `room`, as the vault host over
    /// `anchor`, with a fresh slip from the host root. A host-signed state
    /// ranks with the board.
    fn sign_as_host_over(
        &self,
        project: EntityId,
        body: &mut ProjectRecord,
        room: &BTreeSet<EntityId>,
        anchor: Vec<ProjectAnchorLink>,
    ) -> TestResult {
        let mut claims = self.vault.ensure_host_root_slip(&self.issuer)?.claims;
        claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = "host".into();
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        let signed_at = slip.claims.issued_at;
        let version = with_room_facets(body, Some(room.clone()));
        let challenge = body
            .authority_at(version)
            .write_challenge(project, version, signed_at, &anchor)?;
        body.write_proof = Some(ProjectWriteProof {
            slip_wire: slip.to_token()?,
            holder_signature: self.issuer.binding_proof(&slip, &challenge)?,
            signed_at,
            anchor,
            version,
        });
        Ok(())
    }

    /// The host's next state of `project` over its current head, its room
    /// still reading `room`, written through the owner's
    /// `vault.projects.roster.write`.
    fn write_as_host(&self, project: EntityId, room: &BTreeSet<EntityId>) -> TestResult {
        let mut body = self.vault.project(project)?.ok_or("the project reads")?;
        let anchor = body.anchor()?;
        self.sign_as_host_over(project, &mut body, room, anchor)?;
        let written = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .projects_write_roster(project, &body)
            .map_err(|error| format!("the host's write lands; it refused: {error:?}"))?;
        assert!(written.installed, "precondition: the host's write installs");
        Ok(())
    }

    /// The owner's next state of `project` signed as its leader over its
    /// current head, nothing else changed. A leader-signed head is bound by
    /// its parents: it is served only while it fits their views.
    fn write_as_leader(&self, project: EntityId) -> TestResult {
        let key = leader_key(self.owner);
        let mut claims = self.vault.ensure_host_root_slip(&self.issuer)?.claims;
        claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = self.owner.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        let mut slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        let mut scope = Scope::top();
        scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["project.write".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &key,
        )?;
        let mut body = self.vault.project(project)?.ok_or("the project reads")?;
        let anchor = body.anchor()?;
        let signed_at = slip.claims.issued_at;
        let room = body.room_facets.clone();
        let version = with_room_facets(&mut body, room);
        let challenge = body
            .authority_at(version)
            .write_challenge(project, version, signed_at, &anchor)?;
        body.write_proof = Some(ProjectWriteProof {
            slip_wire: slip.to_token()?,
            holder_signature: key
                .sign(&slip.binding_transcript(&challenge)?)
                .to_bytes()
                .to_vec(),
            signed_at,
            anchor,
            version,
        });
        let written = self
            .vault
            .write_project(project, &body, self.vault.now_recorded_at())
            .map_err(|error| format!("the leader's write lands; it refused: {error:?}"))?;
        assert!(
            matches!(written, ProjectWriteOutcome::Installed(_)),
            "precondition: the leader's write installs"
        );
        assert!(
            self.frontier(project)?
                .effective
                .is_some_and(|view| view.bound_by_parents),
            "precondition: the leader's state is the head, bound by its parents"
        );
        Ok(())
    }

    /// The owner's seal of `project`'s head with its room set narrowed to
    /// `facets`, everything else kept.
    fn seal_room(&self, project: EntityId, facets: &BTreeSet<EntityId>) -> TestResult {
        let witness = self
            .frontier(project)?
            .witness
            .ok_or("precondition: the project serves a head")?;
        let mut authority = witness.authority()?.clone();
        authority.room_facets = Some(facets.clone());
        self.vault
            .seal_project(
                &self.owner_proof,
                &self.vault.owner_project_signer(&self.issuer)?,
                project,
                authority,
                witness.head,
            )
            .map_err(|error| format!("the owner's seal installs; it refused: {error:?}"))?;
        Ok(())
    }

    /// The owner's per-project history budget of `max_revisions` revisions.
    fn set_history_budget(&self, max_revisions: u64) -> TestResult {
        self.vault.set_project_history_policy(
            &self.owner_proof,
            ProjectHistoryPolicy {
                max_revisions,
                ..ProjectHistoryPolicy::default()
            },
        )?;
        Ok(())
    }

    /// How many revisions each of `projects` holds against the history
    /// budget, as a budget of one reports them; every one of them holds two
    /// or more. The budget stays at one.
    fn revision_counts(&self, projects: &[EntityId]) -> TestResult<Vec<u64>> {
        self.set_history_budget(1)?;
        let mut counts = Vec::new();
        for project in projects {
            match self.frontier(*project)?.disposition {
                ProjectDisposition::OverBudget { state, .. } => counts.push(state.held),
                other => {
                    panic!("precondition: past a budget of one the project is frozen: {other:?}")
                }
            }
        }
        Ok(counts)
    }

    /// The frontier `project` serves now.
    fn frontier(&self, project: EntityId) -> TestResult<ProjectFrontier> {
        Ok(self
            .vault
            .project_frontier(project)?
            .ok_or("the project serves a frontier")?)
    }

    /// Whether `project` serves a view at all.
    fn serves(&self, project: EntityId) -> TestResult<bool> {
        Ok(self.frontier(project)?.effective.is_some())
    }

    /// The room facet set of the view `project` serves; `None` when it
    /// serves no view or its room reads by slice alone.
    fn served_room(&self, project: EntityId) -> TestResult<Option<BTreeSet<EntityId>>> {
        Ok(self
            .frontier(project)?
            .effective
            .and_then(|view| view.room_facets))
    }

    /// Whether `project` serves a frozen view past its history budget.
    fn frozen(&self, project: EntityId) -> TestResult<bool> {
        Ok(matches!(
            self.frontier(project)?.disposition,
            ProjectDisposition::OverBudget { .. }
        ))
    }

    /// The owner's one-MESSAGE turn said in the project home room `room`;
    /// returns the MESSAGE.
    fn message_in_room(&self, room: EntityId, text: &str) -> TestResult<EntityId> {
        let message = EntityId::now();
        let turn = WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            project: None,
            occurred_at: self.vault.now_recorded_at(),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
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
        };
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&turn)?;
        Ok(message)
    }

    /// The owner's saved standing question on `message`, answered once;
    /// returns the answer CLAIM and the facet it sits in.
    fn answer_on(&self, message: EntityId) -> TestResult<(EntityId, EntityId)> {
        let record = create_question(&self.vault, self.actor(), definition(vec![message]), 2)?;
        let question = GraphQuestionRef {
            id: record.definition.question.id,
            version: record.definition.question.version,
        };
        let result: GraphAskResult = run_graph_question(
            &self.vault,
            self.owner,
            self.actor(),
            question,
            &[GraphQuestionInput {
                unit: message,
                evidence: Vec::new(),
            }],
            &mut ScriptedAnswerer,
            3,
        )
        .map_err(|failure| {
            format!(
                "an answer on the room MESSAGE lands; it refused: {}",
                failure.error
            )
        })?;
        assert_eq!(result.answers.len(), 1, "one answer is written");
        let claim = result.answers[0].claim;
        let facet = self
            .vault
            .get_claim(&claim)?
            .ok_or("the written answer reads back")?
            .scope_facet;
        assert!(
            !self.answer_stale(claim)?,
            "precondition: the fresh answer stands"
        );
        Ok((claim, facet))
    }

    /// Whether the answer CLAIM `claim` is marked stale.
    fn answer_stale(&self, claim: EntityId) -> TestResult<bool> {
        Ok(self
            .vault
            .get_claim(&claim)?
            .ok_or("the written answer reads back")?
            .stale)
    }
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
fn a_frozen_child_its_sealed_parent_no_longer_fits_stales_its_rooms_answer() -> TestResult {
    let fixture = open()?;
    let (low, high) = fixture.two_facets()?;
    let both = BTreeSet::from([low, high]);
    let root = fixture.vault.root_project()?;

    // Parent P (birth, room set) and its child C, whose leader-signed head,
    // one revision more, is bound by P.
    let (parent, _) = fixture.project_under(root, high, 2, &both)?;
    let (child, room) = fixture.project_under(parent, high, 1, &both)?;
    fixture.write_as_leader(child)?;

    // A budget of P's revisions freezes C at the view it serves and leaves
    // P live.
    let counts = fixture.revision_counts(&[parent, child])?;
    assert!(
        counts[1] > counts[0],
        "precondition: the child holds more revisions than its parent: {counts:?}"
    );
    fixture.set_history_budget(counts[0])?;
    assert!(
        fixture.frozen(child)?,
        "precondition: past its budget the child is frozen"
    );
    assert!(
        !fixture.frozen(parent)?,
        "precondition: within its budget the parent folds live"
    );
    assert_eq!(
        fixture.served_room(child)?,
        Some(both.clone()),
        "precondition: the frozen child's room reads both facets"
    );
    let message = fixture.message_in_room(room, "The lab closes at six on Fridays.")?;
    let (answer, facet) = fixture.answer_on(message)?;
    assert_eq!(
        facet, low,
        "precondition: an answer on a row the frozen room reads in two facets lands at the lower"
    );

    // The owner's seal narrows P's room to the anchor alone. C's saved
    // record is unchanged, but it no longer fits P, so C serves nothing.
    fixture.seal_room(parent, &BTreeSet::from([high]))?;
    assert_eq!(
        fixture.served_room(parent)?,
        Some(BTreeSet::from([high])),
        "precondition: the sealed parent's room reads the anchor alone"
    );
    assert!(
        !fixture.serves(child)?,
        "precondition: the frozen child that no longer fits its parent serves nothing"
    );
    assert!(
        fixture.answer_stale(answer)?,
        "once the frozen child serves nothing, the answer its room placed is stale, though the \
         child's saved record never changed"
    );
    Ok(())
}

#[test]
fn a_frozen_middle_project_that_stops_fitting_stales_its_childs_answer() -> TestResult {
    let fixture = open()?;
    let (low, high) = fixture.two_facets()?;
    let both = BTreeSet::from([low, high]);
    let root = fixture.vault.root_project()?;

    // The chain A <- B <- C, each born and given its room set. B's
    // leader-signed head, one revision more, is bound by A.
    let (top, _) = fixture.project_under(root, high, 2, &both)?;
    let (middle, _) = fixture.project_under(top, high, 1, &both)?;
    fixture.write_as_leader(middle)?;
    let (bottom, room) = fixture.project_under(middle, high, 0, &both)?;

    // A budget of A's and C's revisions freezes B alone.
    let counts = fixture.revision_counts(&[top, middle, bottom])?;
    let budget = counts[0].max(counts[2]);
    assert!(
        counts[1] > budget,
        "precondition: the middle project holds the most revisions: {counts:?}"
    );
    fixture.set_history_budget(budget)?;
    assert!(
        fixture.frozen(middle)?,
        "precondition: past its budget the middle project is frozen"
    );
    assert!(
        !fixture.frozen(top)? && !fixture.frozen(bottom)?,
        "precondition: within their budgets the top and bottom projects fold live"
    );
    assert_eq!(
        fixture.served_room(bottom)?,
        Some(both.clone()),
        "precondition: the bottom project's room reads both facets"
    );
    // Only C's room holds the row the answer rests on.
    let message = fixture.message_in_room(room, "The kiln is booked through March.")?;
    let (answer, facet) = fixture.answer_on(message)?;
    assert_eq!(
        facet, low,
        "precondition: an answer on a row the room reads in two facets lands at the lower"
    );

    // The owner's seal narrows A's room to the anchor alone: B's unchanged
    // frozen record no longer fits A, so B serves nothing, and C, whose
    // parent serves no view, serves none either.
    fixture.seal_room(top, &BTreeSet::from([high]))?;
    assert!(
        !fixture.serves(middle)?,
        "precondition: the frozen middle project that no longer fits its parent serves nothing"
    );
    assert!(
        !fixture.serves(bottom)?,
        "precondition: under a parent that serves nothing the bottom project serves nothing"
    );
    assert!(
        fixture.answer_stale(answer)?,
        "once the bottom project serves nothing, the answer its room placed is stale, though no \
         record above it changed but the top's"
    );
    Ok(())
}

#[test]
fn a_raised_budget_that_meets_two_siblings_narrower_stales_the_answer() -> TestResult {
    let fixture = open()?;
    let (low, high) = fixture.two_facets()?;
    let both = BTreeSet::from([low, high]);
    let root = fixture.vault.root_project()?;

    // The owner's birth and room set S1, then the host's state X over S1
    // keeping both facets; the budget admits exactly those revisions.
    let (project, room) = fixture.project_under(root, high, 1, &both)?;
    let set_state = fixture.vault.project(project)?.ok_or("the project reads")?;
    fixture.write_as_host(project, &both)?;
    let held = fixture.revision_counts(&[project])?[0];
    fixture.set_history_budget(held)?;
    assert!(
        !fixture.frozen(project)?,
        "precondition: within its budget the project folds live"
    );
    let message = fixture.message_in_room(room, "The archive moves to the east wing.")?;
    let (answer, facet) = fixture.answer_on(message)?;
    assert_eq!(
        facet, low,
        "precondition: an answer on a row the room reads in two facets lands at the lower"
    );

    // A peer's state Y over S1, equally ranked with X, keeping the anchor
    // alone: one revision past the budget, it freezes the project at X, and
    // the frozen view applies only X's descendants.
    let mut sibling = set_state.clone();
    fixture.sign_as_host_over(
        project,
        &mut sibling,
        &BTreeSet::from([high]),
        set_state.anchor()?,
    )?;
    put_replicated_project_state(
        &fixture.vault,
        project,
        &sibling,
        fixture.vault.now_recorded_at(),
    )?;
    assert!(
        fixture.frozen(project)?,
        "precondition: the sibling's revision takes the project past its budget"
    );
    assert_eq!(
        fixture.served_room(project)?,
        Some(both.clone()),
        "precondition: frozen at X, the room still reads both facets"
    );
    assert!(
        !fixture.answer_stale(answer)?,
        "precondition: the frozen view still reads the answer's facet"
    );

    // The raised budget folds both siblings again; their tie meets the room
    // down to the anchor.
    fixture.set_history_budget(held + 1)?;
    assert!(
        !fixture
            .served_room(project)?
            .is_some_and(|facets| facets.contains(&low)),
        "precondition: the live fold of both siblings no longer reads the answer's facet"
    );
    assert!(
        fixture.answer_stale(answer)?,
        "once the raised budget's fold leaves the room without the answer's facet, the answer is \
         stale"
    );
    Ok(())
}
