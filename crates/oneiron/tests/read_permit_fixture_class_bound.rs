//! The read-permit fixture grants room reads like the production grant does
//! (READ-PERMIT-FIXTURE-CLASS-BOUND): a room read as one member, with an AGENT
//! member permitted through `install_read_permits_for_test`, reads the room rows
//! it reads when that member is permitted by the production path (an
//! owner-authored class-agnostic row). Class-bound fixture rows never match the
//! classless peer key a room read conjoins for every other member, so the read
//! dropped every row.
//!
//! Fixture: two identical vaults, each with the root project's seeded leader
//! (an agent) and owen (the owner) seated in the root home room, and two trunk
//! turns with fixed ids. One vault permits both members through the fixture,
//! the other through the production owner door; owen's room read must match
//! between them and hold both turns.
//!
//! Public paths only; no test door.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test read_permit_fixture_class_bound`.

use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// How the rig grants its members their room read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// `install_read_permits_for_test`.
    Fixture,
    /// An owner-authored class-agnostic row through the production door.
    Production,
}

/// Class-agnostic `core:read` rows for `members` through the production owner
/// door, added to the default policy manifest, the shipped rows kept. Bare
/// census keys carry no actor class.
fn grant_production_reads(vault: &Vault, owen: EntityId, members: &[EntityId]) -> TestResult {
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
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in members {
        rows.push(PolicyScopedGrantRow {
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

/// One trunk turn in `room`, spoken by `speaker` under fixed ids, so both rigs
/// hold the same rows. Returns the turn id.
fn speak(
    vault: &Vault,
    room: EntityId,
    speaker: EntityId,
    class: EdgeActorClass,
    turn_seed: u8,
    message_seed: u8,
    text: &str,
    at: u64,
) -> TestResult<EntityId> {
    let turn = EntityId::from_bytes([turn_seed; 16]).expect("fixed turn id");
    let message = EntityId::from_bytes([message_seed; 16]).expect("fixed message id");
    vault.memory(speaker, class).rooms_speak(&WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: if class == EdgeActorClass::Human {
                WitnessAuthor::User
            } else {
                WitnessAuthor::Companion
            },
            message_type: "text".into(),
            content: text.into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: at,
        assertions: Default::default(),
    })?;
    Ok(turn)
}

struct Rig {
    vault: Vault,
    owen: EntityId,
    agent: EntityId,
    room: EntityId,
    turns: Vec<EntityId>,
    _directory: tempfile::TempDir,
}

impl Rig {
    /// The turn ids owen's room read holds, sorted.
    fn owner_turns(&self) -> TestResult<Vec<String>> {
        let mut turns: Vec<String> = self
            .vault
            .memory(self.owen, EdgeActorClass::Human)
            .rooms_messages(self.room)?
            .iter()
            .map(|turn| turn.turn_id.clone())
            .collect();
        turns.sort_unstable();
        Ok(turns)
    }

    /// The turn ids the agent's own room read holds, sorted.
    fn agent_turns(&self) -> TestResult<Vec<String>> {
        let mut turns: Vec<String> = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .rooms_messages(self.room)?
            .iter()
            .map(|turn| turn.turn_id.clone())
            .collect();
        turns.sort_unstable();
        Ok(turns)
    }

    /// The turn ids the rig spoke, sorted.
    fn expected_turns(&self) -> Vec<String> {
        let mut turns: Vec<String> = self.turns.iter().map(EntityId::to_hex).collect();
        turns.sort_unstable();
        turns
    }
}

/// The root project's leader and owen seated in the root home room, both
/// granted by `grant`, with two trunk turns owen speaks once the grants
/// stand (the leader stays a seated member who has not spoken: an agent
/// speaks in a room only when spoken to, ARCH-0006a).
fn open_rig(grant: Grant) -> TestResult<Rig> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let project = vault.root_project()?;
    let mut spec = vault
        .project(project)?
        .ok_or("the vault seeds a root project")?;
    let agent = EntityId::from_hex(&spec.leader)?;
    let owen = vault.ensure_embedded_owner_actor()?;
    spec.roster.push(owen.to_hex());
    vault.put_project(project, &spec, 2)?;
    let room = EntityId::from_hex(&spec.home_room)?;
    match grant {
        Grant::Fixture => {
            vault.install_read_permits_for_test(&[
                WriteActor::new(agent, EdgeActorClass::Agent),
                WriteActor::new(owen, EdgeActorClass::Human),
            ])?;
        }
        Grant::Production => {
            grant_production_reads(&vault, owen, &[agent, owen])?;
        }
    }
    let first = speak(
        &vault,
        room,
        owen,
        EdgeActorClass::Human,
        0xC1,
        0xB1,
        "owen opens",
        100,
    )?;
    let second = speak(
        &vault,
        room,
        owen,
        EdgeActorClass::Human,
        0xC2,
        0xB2,
        "owen goes on",
        101,
    )?;
    Ok(Rig {
        vault,
        owen,
        agent,
        room,
        turns: vec![first, second],
        _directory: directory,
    })
}

#[test]
fn fixture_permitted_agent_reads_room_as_production_permitted_agent() -> TestResult {
    let fixture = open_rig(Grant::Fixture)?;
    let production = open_rig(Grant::Production)?;
    let baseline = production.owner_turns()?;
    for turn in production.expected_turns() {
        assert!(
            baseline.contains(&turn),
            "the production baseline reads both spoken turns"
        );
    }
    assert_eq!(
        fixture.owner_turns()?,
        baseline,
        "the fixture-permitted room read matches the production-permitted one"
    );
    Ok(())
}

#[test]
fn fixture_still_grants_the_agent_its_own_room_read() -> TestResult {
    let fixture = open_rig(Grant::Fixture)?;
    let reads = fixture.agent_turns()?;
    for turn in fixture.expected_turns() {
        assert!(
            reads.contains(&turn),
            "the agent reads its own room through the fixture"
        );
    }
    Ok(())
}
