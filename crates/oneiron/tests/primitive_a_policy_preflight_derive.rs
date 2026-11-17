//! Primitive A, slice 6.4e-2 (ENGINE CALL S64E-JUDGE = A; S64-5):
//! `vault.policy.preflight` with the acts `derive` and `archive` shows, on
//! each ref the caller reads, the derive verdict that a `vault.derive.commit`
//! item changing the row meets. The verdict comes from the one judge
//! (`gate::derive_verdict_in_txn`), with its stable tokens, asked as the
//! actor the caller writes as. A withheld ref carries no verdict, and the act
//! `read` answers as before, with no verdict. On main the acts `derive` and
//! `archive` do not exist.
//!
//! Each verdict is compared with the judge's own answer through the door
//! `test_doors::derive::derive_verdict`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test primitive_a_policy_preflight_derive`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::federation::{Scope, ScopeAxis, Sensitivity, SensitivityCeiling};
use oneiron::memory::{Memory, WitnessAssertions};
use oneiron::snapshot_read::{
    PolicyPreflight, PolicyPreflightAct, PolicyPreflightRef, PolicyPreflightRequest,
    PolicyPreflightVerdict,
};
use oneiron::test_doors::derive::derive_verdict;
use oneiron::test_doors::steward::{STEWARD_READ_VERB, stand_steward_grant};
use oneiron::verbs::AgentGrantMintRequest;
use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OUTSIDE_GRANT: &str = "gate.deny.derive.outside_grant";
const GRANT_LACKS_ARCHIVE: &str = "gate.deny.derive.grant_lacks_archive";

/// A vault whose install is rooted and profiled, so the owner's agent Grant
/// act has a machine profile to carry it (as in
/// `primitive_a_skill_reader.rs`).
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    assert_eq!(
        vault.profile_local_open(Some(b"primitive-a-policy-preflight-derive"), true)?,
        oneiron::authority::LocalOpenProfile::RootedAndProfiled,
    );
    Ok((dir, vault))
}

/// The agent definition a fresh default-base dispatch spawns: an ordinary
/// agent, not a base agent such as the Dreamer.
fn dispatched_agent(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    Ok(status.input.target.agent_definition_ref()?)
}

/// The owner grants `agent` reads of PERSON rows, and no other kind.
fn grant_person_reads(owner: &Memory<'_>, agent: EntityId) -> TestResult {
    oneiron::verbs::vault_agents_grants_mint(
        owner,
        AgentGrantMintRequest {
            agent,
            authority_scope: Scope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::All,
                bands: ScopeAxis::Some(BTreeSet::from([oneiron::registry::ENTITY_TYPE_PERSON])),
                audience: ScopeAxis::All,
                verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
                sensitivity: SensitivityCeiling::AtMost(Sensitivity::Sensitive),
            },
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )?;
    Ok(())
}

/// A PERSON row; its id.
fn put_person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"someone",
    )?;
    Ok(id)
}

/// The owner witnesses one TURN of one MESSAGE row: a row an agent granted
/// PERSON reads alone does not read.
fn witnessed_turn(owner: &Memory<'_>) -> Result<EntityId, Box<dyn std::error::Error>> {
    Ok(owner
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "a private line".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })?
        .turn_id)
}

/// An owner, an ordinary agent granted PERSON reads, and a PERSON row it
/// reads.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_actor: EntityId,
    agent: EntityId,
    person: EntityId,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (dir, vault) = open_vault()?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let agent = dispatched_agent(&vault)?;
    grant_person_reads(&vault.memory(owner_actor, EdgeActorClass::Human), agent)?;
    let person = put_person(&vault)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner_actor,
        agent,
        person,
    })
}

fn preflight(
    memory: &Memory<'_>,
    act: PolicyPreflightAct,
    refs: Vec<EntityId>,
) -> Result<PolicyPreflight, Box<dyn std::error::Error>> {
    let answer =
        oneiron::verbs::vault_policy_preflight(memory, PolicyPreflightRequest { refs, act })?.value;
    assert_eq!(answer.act, act);
    Ok(answer)
}

/// The verdict a preflight shows on its first ref, which the caller must
/// read.
fn verdict_on(
    answer: &PolicyPreflight,
    entity: EntityId,
) -> Result<Option<PolicyPreflightVerdict>, Box<dyn std::error::Error>> {
    match answer.refs.first() {
        Some(PolicyPreflightRef::Readable {
            entity: read,
            verdict,
            ..
        }) if *read == entity => Ok(verdict.clone()),
        other => Err(format!("the caller reads {entity:?}; the preflight said {other:?}").into()),
    }
}

/// The judge's own answer for `agent` on `target`, as a preflight shows it.
fn judged(
    vault: &Vault,
    agent: EntityId,
    archive: bool,
    target: EntityId,
) -> Result<PolicyPreflightVerdict, Box<dyn std::error::Error>> {
    Ok(
        match derive_verdict(vault, agent, EdgeActorClass::Agent, archive, Some(target))? {
            Ok(grant) => PolicyPreflightVerdict::Allowed { grant },
            Err(reason) => PolicyPreflightVerdict::Refused {
                reason: reason.to_owned(),
            },
        },
    )
}

/// The keys of one ref's answer on the wire, sorted.
fn wire_keys(answer: &PolicyPreflightRef) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let json = serde_json::to_value(answer)?;
    let mut keys: Vec<String> = json
        .as_object()
        .ok_or("a ref answer is an object")?
        .keys()
        .cloned()
        .collect();
    keys.sort_unstable();
    Ok(keys)
}

#[test]
fn a_readable_ref_carries_the_verdict_the_commit_meets() -> TestResult {
    let fixture = fixture()?;
    let (vault, agent, person) = (&fixture.vault, fixture.agent, fixture.person);
    let reader = vault.memory(agent, EdgeActorClass::Agent);

    // With no Steward grant, no stored row is in an ordinary agent's reach:
    // an item that changes the row it reads is refused, as the commit
    // refuses it.
    for (act, archive) in [
        (PolicyPreflightAct::Derive, false),
        (PolicyPreflightAct::Archive, true),
    ] {
        let shown = verdict_on(&preflight(&reader, act, vec![person])?, person)?;
        assert_eq!(
            shown,
            Some(PolicyPreflightVerdict::Refused {
                reason: OUTSIDE_GRANT.to_owned()
            }),
            "{act:?}"
        );
        assert_eq!(
            shown,
            Some(judged(vault, agent, archive, person)?),
            "{act:?}"
        );
    }

    // A Steward grant that names `derive` and not `archive`: the archive is
    // refused for the verb, and `derive` shows what the judge says of it.
    stand_steward_grant(vault, agent, &[STEWARD_READ_VERB, "derive"])?;
    let archive = verdict_on(
        &preflight(&reader, PolicyPreflightAct::Archive, vec![person])?,
        person,
    )?;
    assert_eq!(
        archive,
        Some(PolicyPreflightVerdict::Refused {
            reason: GRANT_LACKS_ARCHIVE.to_owned()
        })
    );
    assert_eq!(archive, Some(judged(vault, agent, true, person)?));
    let derive = verdict_on(
        &preflight(&reader, PolicyPreflightAct::Derive, vec![person])?,
        person,
    )?;
    assert_eq!(derive, Some(judged(vault, agent, false, person)?));
    assert_ne!(derive, archive, "the grant names `derive`");
    Ok(())
}

#[test]
fn a_withheld_ref_and_the_read_act_carry_no_verdict() -> TestResult {
    let fixture = fixture()?;
    let (vault, agent, person) = (&fixture.vault, fixture.agent, fixture.person);
    let owner = vault.memory(fixture.owner_actor, EdgeActorClass::Human);
    let turn = witnessed_turn(&owner)?;
    let absent = EntityId::now();
    let reader = vault.memory(agent, EdgeActorClass::Agent);

    // A row the agent does not read and an id that names no row answer
    // alike: the id and the status, with no reason, audience or verdict.
    for act in [PolicyPreflightAct::Derive, PolicyPreflightAct::Archive] {
        let answer = preflight(&reader, act, vec![person, turn, absent])?;
        assert!(verdict_on(&answer, person)?.is_some(), "{act:?}");
        assert_eq!(
            wire_keys(&answer.refs[0])?,
            ["audience", "entity", "status", "verdict", "version"],
            "{act:?}"
        );
        assert_eq!(
            answer.refs[1..],
            [
                PolicyPreflightRef::Withheld { entity: turn },
                PolicyPreflightRef::Withheld { entity: absent },
            ],
            "{act:?}"
        );
        for withheld in &answer.refs[1..] {
            assert_eq!(wire_keys(withheld)?, ["entity", "status"], "{act:?}");
        }
    }

    // The act `read` shows no verdict, and its answer on the wire is the
    // one it gave before.
    let read = preflight(&reader, PolicyPreflightAct::Read, vec![person])?;
    assert_eq!(verdict_on(&read, person)?, None);
    assert_eq!(
        wire_keys(&read.refs[0])?,
        ["audience", "entity", "status", "version"]
    );
    Ok(())
}
