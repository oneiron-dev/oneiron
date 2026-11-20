//! A project's current leader may answer a person's turn that names no agent
//! in the project's home room and that room's threads
//! (PROJECT-LEADER-WAKE-NO-REPLY-STANDING = B, Engine 21 Nov 00:02, under
//! canon ARCH-0067:485; LEADER-WAKE-STANDING-ORDER = A, 02:44). The claim
//! door (`rooms.claim`) and the witness's reply admission read the same
//! rule, with the leader read live in the writing transaction. A turn that
//! names another agent stays that agent's, an agent's own turn never counts,
//! and a replaced leader is refused at once. Nothing wakes the leader for
//! such a turn yet (the wake follows UNBUILT3-22), so these tests drive the
//! reply door directly: the agent claims the turn, then speaks its answer.
//!
//! Fixture: owen, the vault's owner, and two agents made through the
//! agent-definition door, `lead` and `other`, each asking under its own Auto
//! ceiling and reading the home room's MESSAGEs under a grant. A project
//! whose leader is `lead` seats owen and `other` too; `@other` names `other`
//! in its home room.
//!
//! Red on main (by assertion): there `lead`'s claim of owen's unaddressed
//! turn settles NotAddressed, so the two answer tests and the replaced-leader
//! test fail at that claim. The other-agent test passes on both.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test project_leader_home_room_reply`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{ProjectRecord, RoomClaimOutcome};
use oneiron::{EdgeActorClass, EntityId, MemoryError, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owen: EntityId,
    lead: EntityId,
    other: EntityId,
    project: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        // `open_owned` holds the writer lease the owner's doors ask for.
        let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
        let owen = vault.ensure_embedded_owner_actor()?;
        let lead = create_agent(&vault, owen, "lead")?;
        let other = create_agent(&vault, owen, "other")?;
        grant_reads(&vault, owen, &[lead, other])?;
        let root_project = vault.root_project()?;
        let project = EntityId::now();
        let mut record = ProjectRecord::new(project, Some(root_project), root_project, lead)?;
        record.roster.extend([owen.to_hex(), other.to_hex()]);
        vault.put_project(project, &record, vault.now_recorded_at())?;
        let room = EntityId::from_hex(&record.home_room)?;
        for agent in [lead, other] {
            grant_messages(&vault, room, agent)?;
        }
        vault.bind_room_handle(room, "@other", other)?;
        let fixture = Self {
            vault,
            owen,
            lead,
            other,
            project,
            room,
            _directory: directory,
        };
        assert_eq!(
            fixture.leader()?,
            lead.to_hex(),
            "fixture: the project's leader is lead"
        );
        Ok(fixture)
    }

    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }

    fn agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// The project's stored leader.
    fn leader(&self) -> TestResult<String> {
        Ok(self
            .vault
            .project(self.project)?
            .ok_or("the project reads")?
            .leader)
    }

    /// The owner makes `other` the project's leader; `lead` keeps its seat.
    fn replace_leader(&self) -> TestResult {
        let mut record = self
            .vault
            .project(self.project)?
            .ok_or("the project reads")?;
        record.leader = self.other.to_hex();
        self.vault
            .put_project(self.project, &record, self.vault.now_recorded_at())?;
        assert_eq!(
            self.leader()?,
            self.other.to_hex(),
            "fixture: the owner's write replaces the leader"
        );
        Ok(())
    }

    /// owen's witness turn in the home room, one MESSAGE carrying
    /// `metadata`. Returns the turn's id.
    fn owen_speaks(&self, metadata: serde_json::Value) -> TestResult<EntityId> {
        let turn = EntityId::now();
        self.owen()
            .rooms_speak(&self.turn(turn, WitnessAuthor::User, metadata))?;
        Ok(turn)
    }

    /// `agent` claims `turn` in the home room.
    fn claim(&self, agent: EntityId, turn: EntityId) -> TestResult<RoomClaimOutcome> {
        Ok(self
            .agent(agent)
            .rooms_claim(self.room, turn, self.vault.now_recorded_at())?)
    }

    /// `agent` speaks its answer to `parent`. Returns the answer's turn id.
    fn reply(&self, agent: EntityId, parent: EntityId) -> Result<EntityId, MemoryError> {
        let turn = EntityId::now();
        self.agent(agent).rooms_speak(&self.turn(
            turn,
            WitnessAuthor::Companion,
            serde_json::json!({"room_reply_to": parent.to_hex()}),
        ))?;
        Ok(turn)
    }

    fn turn(
        &self,
        turn: EntityId,
        author: WitnessAuthor,
        metadata: serde_json::Value,
    ) -> WitnessTurn {
        WitnessTurn {
            conversation_ref: self.room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author,
                message_type: "text".into(),
                content: "room message".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: self.vault.now_recorded_at(),
            assertions: Default::default(),
        }
    }

    /// Whether owen's room history holds `turn`, spoken by `actor`.
    fn landed(&self, turn: EntityId, actor: EntityId) -> TestResult<bool> {
        Ok(self
            .owen()
            .rooms_messages(self.room)?
            .iter()
            .any(|row| row.turn_id == turn.to_hex() && row.actor == actor.to_hex()))
    }
}

/// Whether `outcome` is a claim `agent` holds.
fn claimed_by(outcome: &RoomClaimOutcome, agent: EntityId) -> bool {
    matches!(outcome, RoomClaimOutcome::Claimed(receipt) if receipt.actor == agent.to_hex())
}

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Each agent asks under its own Auto ceiling, and owen and the agents read
/// the vault's records: rows added to the default policy manifest, the
/// shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agents: &[EntityId]) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    for agent in agents {
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
    }
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in std::iter::once(&owen).chain(agents) {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// `agent` reads `room`'s MESSAGEs under an active grant: a room read admits
/// a row only when every reader of its audience may.
fn grant_messages(vault: &Vault, room: EntityId, agent: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: agent,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

/// Ruled test 1: owen's trunk turn names no agent, so the project's leader
/// claims it and its answer lands. `other`, seated in the same room but not
/// the leader, is still not spoken to by it.
///
/// Red on main: the leader's claim settles NotAddressed.
#[test]
fn the_leader_answers_a_person_turn_that_names_no_agent() -> TestResult {
    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let claimed = fixture.claim(fixture.lead, asked)?;
    assert!(
        claimed_by(&claimed, fixture.lead),
        "the leader claims owen's unaddressed turn: {claimed:?}"
    );
    let answer = fixture.reply(fixture.lead, asked)?;
    assert!(
        fixture.landed(answer, fixture.lead)?,
        "the leader's answer lands on the trunk"
    );
    assert_eq!(
        fixture.claim(fixture.other, asked)?,
        RoomClaimOutcome::NotAddressed,
        "a seated agent that does not lead is not spoken to by an unaddressed turn"
    );
    Ok(())
}

/// The same standing in one of the home room's threads: owen's reply inside
/// a room-wide thread names no agent, and the leader answers it there.
///
/// Red on main: the leader's claim settles NotAddressed.
#[test]
fn the_leader_answers_a_person_turn_in_a_home_room_thread() -> TestResult {
    let fixture = Fixture::open()?;
    let anchor = fixture.owen_speaks(serde_json::json!({}))?;
    let root = fixture.owen_speaks(serde_json::json!({"room_thread_of": anchor.to_hex()}))?;
    let asked = fixture.owen_speaks(serde_json::json!({"room_reply_to": root.to_hex()}))?;
    let claimed = fixture.claim(fixture.lead, asked)?;
    assert!(
        claimed_by(&claimed, fixture.lead),
        "the leader claims owen's unaddressed thread turn: {claimed:?}"
    );
    fixture.reply(fixture.lead, asked)?;
    Ok(())
}

/// Ruled test 2: a turn that names another agent stays that agent's. The
/// leader is not spoken to by it at either door, and the named agent claims
/// and answers it. That answer is an agent's turn naming no one, which never
/// counts: the leader is not spoken to by it either.
///
/// Green on main and on the head (a guard on the new standing).
#[test]
fn a_turn_naming_another_agent_stays_that_agents() -> TestResult {
    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({"room_mentions": ["@other"]}))?;
    assert_eq!(
        fixture.claim(fixture.lead, asked)?,
        RoomClaimOutcome::NotAddressed,
        "the leader claims no turn that names another agent"
    );
    let refused = EntityId::now();
    assert!(
        fixture
            .agent(fixture.lead)
            .rooms_speak(&fixture.turn(
                refused,
                WitnessAuthor::Companion,
                serde_json::json!({"room_reply_to": asked.to_hex()}),
            ))
            .is_err(),
        "the leader's answer to a turn naming another agent is refused"
    );
    assert!(!fixture.landed(refused, fixture.lead)?, "nothing landed");
    let claimed = fixture.claim(fixture.other, asked)?;
    assert!(
        claimed_by(&claimed, fixture.other),
        "the named agent claims its turn: {claimed:?}"
    );
    let answer = fixture.reply(fixture.other, asked)?;
    assert!(fixture.landed(answer, fixture.other)?, "its answer lands");
    assert_eq!(
        fixture.claim(fixture.lead, answer)?,
        RoomClaimOutcome::NotAddressed,
        "an agent's turn never speaks to the leader"
    );
    assert!(
        fixture.reply(fixture.lead, answer).is_err(),
        "the leader's answer to an agent's turn is refused"
    );
    Ok(())
}

/// Ruled test 3: a replaced leader is refused at once. `lead` claims owen's
/// unaddressed turn while it leads; the owner then makes `other` the leader.
/// `lead`'s answer, whose write reads the leader again, is refused, and it
/// claims no new unaddressed turn. The new leader claims and answers one.
///
/// Red on main: `lead`'s first claim settles NotAddressed.
#[test]
fn a_replaced_leader_is_refused_at_once() -> TestResult {
    let fixture = Fixture::open()?;
    let asked = fixture.owen_speaks(serde_json::json!({}))?;
    let claimed = fixture.claim(fixture.lead, asked)?;
    assert!(
        claimed_by(&claimed, fixture.lead),
        "the leader claims owen's unaddressed turn: {claimed:?}"
    );
    fixture.replace_leader()?;
    let refused = EntityId::now();
    assert!(
        fixture
            .agent(fixture.lead)
            .rooms_speak(&fixture.turn(
                refused,
                WitnessAuthor::Companion,
                serde_json::json!({"room_reply_to": asked.to_hex()}),
            ))
            .is_err(),
        "the replaced leader's answer on its earlier claim is refused"
    );
    assert!(!fixture.landed(refused, fixture.lead)?, "nothing landed");
    let later = fixture.owen_speaks(serde_json::json!({}))?;
    assert_eq!(
        fixture.claim(fixture.lead, later)?,
        RoomClaimOutcome::NotAddressed,
        "the replaced leader claims no new unaddressed turn"
    );
    let claimed = fixture.claim(fixture.other, later)?;
    assert!(
        claimed_by(&claimed, fixture.other),
        "the new leader claims the unaddressed turn: {claimed:?}"
    );
    let answer = fixture.reply(fixture.other, later)?;
    assert!(
        fixture.landed(answer, fixture.other)?,
        "the new leader's answer lands"
    );
    Ok(())
}
