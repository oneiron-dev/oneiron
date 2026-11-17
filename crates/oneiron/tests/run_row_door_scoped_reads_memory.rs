//! The memory run rows' scoped reads, through the code-mode door: a
//! `HostSelfDispatcher` whose host door admits each call on one read key.
//!
//! Three rows read on the key their door admitted the call with (FIX
//! [RUN-ROW-DOOR-TESTS-ABSENT]; the reads moved to `task_verb/run_rows` and
//! `gate/record_references` as code moves, with no behaviour test):
//!
//! - `vault.search`: the keyed branch serves only the hits the key's lane
//!   reads, claims of every status where the door says so (FIX 5976).
//! - `vault.claims.supersede` and `vault.edges.put`: every record the write
//!   names must resolve for the key (OF-063, FIX 1214). A record the key does
//!   not read answers as a record that does not exist, and nothing lands.
//!
//! Two fixtures, each copied from a test on main: the owner's code run under
//! a policy that lets its `self.memory.*` writes land
//! (`gate_pins_claim_producers.rs`), and a paired agent whose Grant names one
//! world of two (`agent_grant_read_ceiling.rs`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_row_door_scoped_reads_memory`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::code_run::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
    RunCall, SELF_MEMORY_SEARCH_MAX_RESULTS, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, SelfEffect, SelfFailedResult, SelfMemoryEdgeWriteResult,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteResult,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_INVENTED_REFERENCE,
    ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::{provision_engine_machines, put_policy_manifest_bytes};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The run every dispatcher of this file is bound to.
const RUN_REF: &str = "run-row-door-run";
/// The one word every indexed row's text holds, so one search scores them all.
const WORD: &str = "lighthouse";
/// When the Grant fixture's rows were written and learned.
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:run-row-door-scoped-reads";

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// The host's door for a run's own calls: every call is admitted on `key`'s
/// lane, as a host admits its caller on the caller's credential.
struct KeyedDoor {
    key: ScopedReadActorKey,
    /// Whether the run's keyed search keeps claims of every status the key
    /// reads (the live-run door), or surfaceable claims only (the default).
    search_keeps_every_claim_status: bool,
}

impl KeyedDoor {
    /// A door whose keyed search is filtered by the key's authorization alone.
    fn recording(key: ScopedReadActorKey) -> Self {
        Self {
            key,
            search_keeps_every_claim_status: true,
        }
    }

    /// A door that keeps the trait's default: surfaceable claims only.
    fn surfaceable_only(key: ScopedReadActorKey) -> Self {
        Self {
            key,
            search_keeps_every_claim_status: false,
        }
    }
}

impl AgentVerbDoor for KeyedDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &oneiron::memory::HostWriteOrigin,
        _: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
            hook_notice: None,
        }))
    }

    fn admit_run_call(&self, _: RunCall) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(Some(self.key.clone()))
    }

    fn keyed_search_surfaceable_only(&self) -> bool {
        !self.search_keeps_every_claim_status
    }
}

/// A dispatcher for `actor`'s run whose own calls `door` admits.
fn keyed_dispatcher(
    vault: &Vault,
    actor: WriteActor,
    door: KeyedDoor,
) -> TestResult<HostSelfDispatcher<'_>> {
    Ok(HostSelfDispatcher::new(vault, actor, RUN_REF)
        .map_err(at("the keyed dispatcher"))?
        .with_agent_verb_door(Arc::new(door)))
}

/// The ids the run's `vault.search` for [`WORD`] serves through `dispatcher`.
fn searched_ids(dispatcher: &HostSelfDispatcher<'_>) -> TestResult<Vec<EntityId>> {
    let outcome = dispatcher
        .dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
            WORD,
            SELF_MEMORY_SEARCH_MAX_RESULTS,
        )))
        .map_err(at("the run's search"))?;
    match outcome {
        SelfDispatchOutcome::MemorySearch(found) => {
            Ok(found.results.iter().map(|hit| hit.id).collect())
        }
        other => Err(format!("the run's search answered {other:?}").into()),
    }
}

/// The ids an unkeyed text search for [`WORD`] scores: what the index holds,
/// before any reader's lane.
fn indexed_ids(vault: &Vault) -> TestResult<Vec<EntityId>> {
    Ok(vault
        .search_text(WORD, SELF_MEMORY_SEARCH_MAX_RESULTS)
        .map_err(at("the unkeyed text search"))?
        .iter()
        .map(|hit| hit.id)
        .collect())
}

/// Indexes each row's text for text search, as the retrieval fixtures do.
fn index_text(vault: &Vault, rows: &[(EntityId, &str)]) -> TestResult {
    let mut batch = vault.batch();
    for (id, text) in rows {
        batch = batch.text(id, &[("body", *text)]);
    }
    batch.commit().map_err(at("index the rows' text"))
}

/// The reply of a run row whose write names a record that does not resolve
/// for its key: the code alone, never the record.
fn invented_reference(effect: SelfEffect) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect,
        error: MEMORY_CODE_INVENTED_REFERENCE.to_owned(),
        code: None,
        disk_floor: None,
    })
}

// ---------------------------------------------------------------------------
// Fixture 1: the owner's code run, under a policy that lands its writes.
// ---------------------------------------------------------------------------

/// A policy manifest that lets `actor`, a human, write `self.memory.*` at
/// Auto from the code run's Generated source (`gate_pins_claim_producers.rs`).
fn self_memory_policy(actor: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("run-row-door-code-run")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("self.memory.")),
                (Value::from("axes"), axes()),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (
            Value::from("source_trust"),
            Value::Map(vec![(
                Value::from(ClaimSource::Generated.as_str()),
                Value::Map(vec![
                    (Value::from("max_auto_sensitivity"), Value::from(2_u64)),
                    (Value::from("receipted"), Value::Boolean(true)),
                    (Value::from("warned"), Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)?;
    Ok(data)
}

/// A PERSON row at a fresh id.
fn person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .map_err(at("put a PERSON"))?;
    Ok(id)
}

/// The owner's vault after its code run wrote two claims about one PERSON.
struct OwnerRun {
    vault: Vault,
    owner: EntityId,
    subject: EntityId,
    edge_target: EntityId,
    earlier_claim: EntityId,
    later_claim: EntityId,
    _dir: tempfile::TempDir,
}

impl OwnerRun {
    fn writer(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    /// The owner's own read key: it reads every record of this vault.
    fn owner_key(&self) -> TestResult<ScopedReadActorKey> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .read_key()
            .map_err(at("the owner's read key"))
    }

    /// A key that reads no row: its holder is a fresh PERSON row of this
    /// vault, classed as an agent.
    fn key_that_reads_nothing(&self) -> TestResult<ScopedReadActorKey> {
        let holder = person(&self.vault)?;
        Ok(ScopedReadActorKey::read_nothing(holder.to_hex(), "agent")
            .ok_or("a key that reads nothing")?)
    }

    /// The owner's run with no host door: each call reads on the owner's own
    /// key, as `gate_pins_claim_producers.rs` runs it.
    fn unkeyed(&self) -> TestResult<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::new(&self.vault, self.writer(), RUN_REF)
            .map_err(at("the unkeyed dispatcher"))
    }

    fn supersede_later_over_earlier(&self) -> SelfCall {
        SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(
            self.later_claim,
            self.earlier_claim,
            20,
        ))
    }

    fn edge_from_subject_to_target(&self) -> SelfCall {
        SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            self.subject,
            EdgeKind::Mentions,
            self.edge_target,
            0.7,
        ))
    }
}

fn owner_run() -> TestResult<OwnerRun> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).map_err(at("open unseeded"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    put_policy_manifest_bytes(&vault, EntityId::now(), &self_memory_policy(owner)?)
        .map_err(at("install the policy"))?;
    let subject = person(&vault)?;
    let edge_target = person(&vault)?;
    let earlier_claim = EntityId::now();
    let later_claim = EntityId::now();
    {
        let unkeyed = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(owner, EdgeActorClass::Human),
            RUN_REF,
        )
        .map_err(at("the unkeyed dispatcher"))?;
        for (id, drink, confidence, at_time) in [
            (earlier_claim, "sencha", 0.8, 10),
            (later_claim, "matcha", 0.9, 12),
        ] {
            unkeyed
                .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                    id,
                    ClaimCandidate::new(
                        "profile.favorite_drink",
                        ClaimSubject::Entity(subject),
                        Value::from(drink),
                        confidence,
                    ),
                    range(at_time),
                    at_time + 1,
                )))
                .map_err(at("the run's claim put"))?;
        }
    }
    Ok(OwnerRun {
        vault,
        owner,
        subject,
        edge_target,
        earlier_claim,
        later_claim,
        _dir: dir,
    })
}

#[test]
fn a_keyed_supersede_lands_when_its_door_key_reads_both_claims() -> TestResult {
    let run = owner_run()?;
    let dispatcher = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.owner_key()?),
    )?;

    let superseded = dispatcher
        .dispatch(run.supersede_later_over_earlier())
        .map_err(at("the keyed supersede"))?;

    assert_eq!(
        superseded,
        SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: run.later_claim
        })
    );
    let earlier = run
        .vault
        .get_claim(&run.earlier_claim)
        .map_err(at("read the earlier claim"))?
        .ok_or("the superseded claim reads nothing")?;
    assert_eq!(earlier.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(earlier.valid_to, Some(20));
    assert_eq!(
        run.vault
            .targets(&run.later_claim, EdgeKind::Supersedes, None)
            .map_err(at("read the supersedes edge"))?,
        vec![run.earlier_claim]
    );
    Ok(())
}

#[test]
fn a_keyed_supersede_naming_a_claim_its_door_key_does_not_read_supersedes_nothing() -> TestResult {
    let run = owner_run()?;
    let before = run
        .vault
        .get_claim(&run.earlier_claim)
        .map_err(at("read the earlier claim"))?;
    assert!(before.is_some(), "the run's first claim landed");

    // Both claims exist; the door's key reads neither.
    let unread = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.key_that_reads_nothing()?),
    )?
    .dispatch(run.supersede_later_over_earlier())
    .map_err(at("the supersede on a key that reads nothing"))?;
    // The door's key reads the new claim; the old one does not exist.
    let absent = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.owner_key()?),
    )?
    .dispatch(SelfCall::MemorySupersedeClaim(
        SelfMemorySupersedeClaimCall::new(run.later_claim, EntityId::now(), 20),
    ))
    .map_err(at("the supersede of an absent claim"))?;

    assert_eq!(unread, invented_reference(SelfEffect::MemorySupersedeClaim));
    assert_eq!(
        unread, absent,
        "a claim the key does not read answers exactly as a claim that does not exist"
    );
    assert_eq!(
        run.vault
            .get_claim(&run.earlier_claim)
            .map_err(at("read the earlier claim again"))?,
        before,
        "a refused supersede leaves the old claim as it was"
    );
    assert!(
        run.vault
            .targets(&run.later_claim, EdgeKind::Supersedes, None)
            .map_err(at("read the supersedes edge"))?
            .is_empty(),
        "a refused supersede writes no supersedes edge"
    );
    Ok(())
}

#[test]
fn a_keyed_edge_lands_when_its_door_key_reads_both_ends() -> TestResult {
    let run = owner_run()?;
    let dispatcher = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.owner_key()?),
    )?;

    let put_edge = dispatcher
        .dispatch(run.edge_from_subject_to_target())
        .map_err(at("the keyed edge put"))?;

    assert_eq!(
        put_edge,
        SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
            src: run.subject,
            kind: EdgeKind::Mentions,
            tgt: run.edge_target,
        })
    );
    assert_eq!(
        run.vault
            .targets(&run.subject, EdgeKind::Mentions, None)
            .map_err(at("read the edge"))?,
        vec![run.edge_target]
    );
    Ok(())
}

#[test]
fn a_keyed_edge_naming_a_record_its_door_key_does_not_read_puts_no_edge() -> TestResult {
    let run = owner_run()?;

    // Both ends exist; the door's key reads neither.
    let unread = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.key_that_reads_nothing()?),
    )?
    .dispatch(run.edge_from_subject_to_target())
    .map_err(at("the edge put on a key that reads nothing"))?;
    // The door's key reads the source; the target does not exist.
    let absent = keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.owner_key()?),
    )?
    .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        run.subject,
        EdgeKind::Mentions,
        EntityId::now(),
        0.7,
    )))
    .map_err(at("the edge put to an absent record"))?;

    assert_eq!(unread, invented_reference(SelfEffect::MemoryPutEdge));
    assert_eq!(
        unread, absent,
        "a record the key does not read answers exactly as a record that does not exist"
    );
    assert!(
        run.vault
            .targets(&run.subject, EdgeKind::Mentions, None)
            .map_err(at("read the edge"))?
            .is_empty(),
        "a refused edge put writes no edge"
    );
    Ok(())
}

#[test]
fn a_keyed_search_keeps_a_proposed_claim_only_on_a_door_that_reads_every_status() -> TestResult {
    let run = owner_run()?;
    // Code mode asks Proposed of the gates, so the run's own claims are
    // recorded and not surfaceable. (A superseded claim cannot stand in: its
    // text leaves the index at the supersede.)
    for claim in [run.earlier_claim, run.later_claim] {
        let body = run
            .vault
            .get_claim(&claim)
            .map_err(at("read the run's claim"))?
            .ok_or("the run's claim reads nothing")?;
        assert_eq!(
            body.approval,
            ClaimApprovalStatus::Proposed,
            "the run's own claim is proposed"
        );
    }
    index_text(
        &run.vault,
        &[
            (run.earlier_claim, "sencha lighthouse"),
            (run.later_claim, "matcha lighthouse"),
        ],
    )?;
    let indexed = indexed_ids(&run.vault)?;
    assert!(
        indexed.contains(&run.earlier_claim) && indexed.contains(&run.later_claim),
        "the index holds both claims; seen {indexed:?}"
    );

    let every_status = searched_ids(&keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.owner_key()?),
    )?)?;
    let surfaceable = searched_ids(&keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::surfaceable_only(run.owner_key()?),
    )?)?;

    assert!(
        every_status.contains(&run.earlier_claim) && every_status.contains(&run.later_claim),
        "the door that reads every status keeps the run's proposed claims; seen {every_status:?}"
    );
    assert!(
        !surfaceable.contains(&run.earlier_claim) && !surfaceable.contains(&run.later_claim),
        "the default door keeps no proposed claim; seen {surfaceable:?}"
    );
    Ok(())
}

#[test]
fn a_keyed_search_serves_nothing_to_a_key_that_reads_nothing() -> TestResult {
    let run = owner_run()?;
    index_text(
        &run.vault,
        &[
            (run.earlier_claim, "sencha lighthouse"),
            (run.later_claim, "matcha lighthouse"),
        ],
    )?;
    let indexed = indexed_ids(&run.vault)?;
    assert!(
        indexed.contains(&run.earlier_claim) && indexed.contains(&run.later_claim),
        "the index holds both claims; seen {indexed:?}"
    );

    let served = searched_ids(&keyed_dispatcher(
        &run.vault,
        run.writer(),
        KeyedDoor::recording(run.key_that_reads_nothing()?),
    )?)?;

    assert!(
        served.is_empty(),
        "a key that reads no row is served no hit; seen {served:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture 2: a paired agent whose one Grant names the base world only.
// ---------------------------------------------------------------------------

/// A vault whose owner wrote one claim in the base world and one in a second
/// world, and whose agent holds a read Grant for the base world alone.
struct GrantRun {
    vault: Vault,
    agent: EntityId,
    base_claim: EntityId,
    other_claim: EntityId,
    agent_key: ScopedReadActorKey,
    _dir: tempfile::TempDir,
}

impl GrantRun {
    /// The agent's run, each call admitted on the agent's own credential key.
    fn dispatcher(&self) -> TestResult<HostSelfDispatcher<'_>> {
        keyed_dispatcher(
            &self.vault,
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            KeyedDoor::recording(self.agent_key.clone()),
        )
    }
}

fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    binding_seed: u8,
) -> VerifiedSlip {
    // Only the verbs axis narrows the pairing Scope: the Grant, not the
    // pairing request, imposes the agent's world ceiling.
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its credential")
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a claim in the requested world");
    id
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Run row door reader",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    agent
}

fn grant_run() -> TestResult<GrantRun> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).map_err(at("open"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(at("this install's live machine profile"))?;
    let (owner, owner_proof) =
        embedded_owner(&vault).map_err(at("authenticated embedded owner"))?;
    let other_world = vault
        .create_world(&owner_proof, "Grant-excluded world", OCCURRED_AT)
        .map_err(at("owner creates the second world"))?;
    let base_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        base_world_id(),
        "base-world claim",
    );
    let other_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        other_world,
        "grant-excluded-world claim",
    );
    index_text(
        &vault,
        &[
            (base_claim, "base lighthouse"),
            (other_claim, "excluded lighthouse"),
        ],
    )?;

    let agent = create_enabled_agent(&vault, &owner_proof, "run_row_door_reader");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
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
    .map_err(at("owner mints the agent a read Grant"))?;
    assert!(
        minted.grant.confers,
        "the agent's base-world read Grant is live"
    );
    let slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0x47);
    let agent_key = vault
        .credential_read_key(&slip)
        .map_err(at("agent credential read key"))?
        .ok_or("the agent's credential grants no read")?;
    Ok(GrantRun {
        vault,
        agent,
        base_claim,
        other_claim,
        agent_key,
        _dir: dir,
    })
}

#[test]
fn a_keyed_search_serves_only_the_claims_the_readers_grant_covers() -> TestResult {
    let run = grant_run()?;
    let indexed = indexed_ids(&run.vault)?;
    assert!(
        indexed.contains(&run.base_claim) && indexed.contains(&run.other_claim),
        "the index holds the claim of each world; seen {indexed:?}"
    );

    let served = searched_ids(&run.dispatcher()?)?;

    assert!(
        served.contains(&run.base_claim),
        "the agent's search serves the claim in its Grant's world; seen {served:?}"
    );
    assert!(
        !served.contains(&run.other_claim),
        "the agent's search serves no claim of a world its Grant does not name; seen {served:?}"
    );
    Ok(())
}

/// Whether `reply` is the invented-reference refusal.
fn is_invented_reference(reply: &oneiron::Result<SelfDispatchOutcome>) -> bool {
    matches!(
        reply,
        Ok(SelfDispatchOutcome::Failed(failed)) if failed.error == MEMORY_CODE_INVENTED_REFERENCE
    )
}

#[test]
fn a_keyed_supersede_naming_a_claim_outside_the_readers_grant_supersedes_nothing() -> TestResult {
    let run = grant_run()?;
    let before = run
        .vault
        .get_claim(&run.other_claim)
        .map_err(at("read the second-world claim"))?;
    assert!(before.is_some(), "the owner's second-world claim landed");
    let supersede = |new_id: EntityId, old_id: EntityId| -> TestResult<SelfDispatchOutcome> {
        run.dispatcher()?
            .dispatch(SelfCall::MemorySupersedeClaim(
                SelfMemorySupersedeClaimCall::new(new_id, old_id, OCCURRED_AT + 1),
            ))
            .map_err(at("the keyed supersede"))
    };

    // The control: on the same key, a call that names only the claim the
    // Grant covers passes the reference check, whatever the gates then rule
    // on the write. So each refusal below is the second-world claim's.
    let covered = run.dispatcher()?.dispatch(SelfCall::MemorySupersedeClaim(
        SelfMemorySupersedeClaimCall::new(run.base_claim, run.base_claim, OCCURRED_AT + 1),
    ));
    assert!(
        !is_invented_reference(&covered),
        "a supersede naming only the claim the Grant covers resolves its references; seen {covered:?}"
    );

    let as_old_claim = supersede(run.base_claim, run.other_claim)?;
    let as_new_claim = supersede(run.other_claim, run.base_claim)?;

    assert_eq!(
        as_old_claim,
        invented_reference(SelfEffect::MemorySupersedeClaim)
    );
    assert_eq!(
        as_new_claim,
        invented_reference(SelfEffect::MemorySupersedeClaim)
    );
    assert_eq!(
        run.vault
            .get_claim(&run.other_claim)
            .map_err(at("read the second-world claim again"))?,
        before,
        "a refused supersede leaves the claim outside the Grant as it was"
    );
    assert!(
        !run.vault
            .targets(&run.base_claim, EdgeKind::Supersedes, None)
            .map_err(at("read the base claim's supersedes edges"))?
            .contains(&run.other_claim),
        "a refused supersede writes no supersedes edge to the claim outside the Grant"
    );
    assert!(
        run.vault
            .targets(&run.other_claim, EdgeKind::Supersedes, None)
            .map_err(at("read the second-world claim's supersedes edges"))?
            .is_empty(),
        "a refused supersede writes no supersedes edge from the claim outside the Grant"
    );
    Ok(())
}

#[test]
fn a_keyed_edge_naming_a_claim_outside_the_readers_grant_puts_no_edge() -> TestResult {
    let run = grant_run()?;
    let put_edge = |src: EntityId, tgt: EntityId| -> TestResult<SelfDispatchOutcome> {
        run.dispatcher()?
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .map_err(at("the keyed edge put"))
    };

    // The control: on the same key, an edge whose two ends are the claim the
    // Grant covers passes the reference check, whatever the gates then rule
    // on the write. So each refusal below is the second-world claim's.
    let covered = run
        .dispatcher()?
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            run.base_claim,
            EdgeKind::Mentions,
            run.base_claim,
            0.7,
        )));
    assert!(
        !is_invented_reference(&covered),
        "an edge naming only the claim the Grant covers resolves its references; seen {covered:?}"
    );

    let as_target = put_edge(run.base_claim, run.other_claim)?;
    let as_source = put_edge(run.other_claim, run.base_claim)?;

    assert_eq!(as_target, invented_reference(SelfEffect::MemoryPutEdge));
    assert_eq!(as_source, invented_reference(SelfEffect::MemoryPutEdge));
    assert!(
        !run.vault
            .targets(&run.base_claim, EdgeKind::Mentions, None)
            .map_err(at("read the base claim's edges"))?
            .contains(&run.other_claim),
        "a refused edge put writes no edge to the claim outside the Grant"
    );
    assert!(
        run.vault
            .targets(&run.other_claim, EdgeKind::Mentions, None)
            .map_err(at("read the second-world claim's edges"))?
            .is_empty(),
        "a refused edge put writes no edge from the claim outside the Grant"
    );
    Ok(())
}
