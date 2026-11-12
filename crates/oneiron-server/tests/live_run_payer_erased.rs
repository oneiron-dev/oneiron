//! [LIVE-RUN-PAYER-REQUIRED] (the Engine's ruling of 12 Nov 22:44, OF-531):
//! a live run's model doors read its payer as its steps read theirs,
//! `requires_payer` with the run's leased try and that try's room. An actor
//! erase that clears a room-bound run's payer while the run still holds its
//! lease refuses the run's next model call, typed `payer_missing`; it never
//! bills the vault owner's default. A run no room binds keeps the owner's
//! default, as before.
//!
//! Reaches the meter a live run's entry opens through
//! `oneiron_server::test_doors::live_run_payer`, and the erase's spend-scope
//! hook through `oneiron::test_doors::spend`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test live_run_payer_erased`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendPayer, SpendScopeId, decode_agent_dispatch_input,
    encode_agent_dispatch_input,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::spend::erase_actor_from_spend_scopes;
use oneiron::workspace_roster::RoomWork;
use oneiron::{AttemptQueue, EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::live_run_payer::entry_meter_payer;

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// A root roomy enough that no call here meets its cap.
const ROOT_UNITS: u64 = 1_000_000;
/// The lease owner this test claims rows as, as a pump holds a live run.
const WORKER: &str = "live-run-payer-erased";

/// A process-owned vault at `dir`, as an embedded owner opens it.
fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// A live PERSON who is not one of the vault's Owners, with the billing
/// account they filed as their own (FIX 3332). A fresh UUIDv7 id: the
/// seeded system agents hold `[0xA1; 16]` through `[0xA6; 16]`.
fn payer_person(vault: &Vault) -> Result<EntityId, TestError> {
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"payer",
    )?;
    vault.file_own_billing_account(person, "payer-account-1")?;
    Ok(person)
}

/// A hard root `name` that `payer` funds (OF-531): shown its cap, they
/// accepted it themselves.
fn paid_root(vault: &Vault, name: &str, payer: EntityId) -> Result<SpendScopeId, TestError> {
    let root = SpendScopeId::launch(name)?;
    AgentDispatcher::new(vault).open_root_spend_scope_for_payer(
        root.clone(),
        DeclaredMaximum {
            units: ROOT_UNITS,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown { at_ms: 12_000 }),
        SpendPayer {
            party: payer,
            granted_by: Some(payer),
            at_ms: 12_000,
        },
        12,
    )?;
    Ok(root)
}

/// The leased try of a root run of the seeded default agent under `run`, as
/// the pump holds it while the run is live.
fn leased_run(vault: &Vault, run: &str) -> Result<AttemptRecord, TestError> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now: 12,
            },
            AgentSpawnContext::default(),
        )?
    else {
        return Err("expected one fresh root run".into());
    };
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == status.attempt.id {
            return Ok(queue.get(row.id)?.ok_or("a claimed row reads back")?);
        }
    }
    Err("the run's try is ready to claim".into())
}

/// `leased` as a room launch's dispatch writes it: the same try, its input
/// naming the room it works in. The join a room launch re-proves before it
/// enqueues is not what a live run's doors read; the room is.
fn in_room(leased: &AttemptRecord, room: EntityId) -> Result<AttemptRecord, TestError> {
    let mut payload = decode_dreamer_attempt_payload(&leased.payload)?;
    let mut input = decode_agent_dispatch_input(&payload.input)?;
    input.room = Some(RoomWork { room, branch: None });
    payload.input = encode_agent_dispatch_input(&input)?;
    let mut bound = leased.clone();
    bound.payload = encode_dreamer_attempt_payload(&payload)?;
    Ok(bound)
}

/// Erases `payer` from every spend scope, as the actor erase's hook does, and
/// checks that `root` names no payer after it.
fn erase_payer(vault: &Vault, payer: EntityId, root: &SpendScopeId) -> TestResult {
    erase_actor_from_spend_scopes(vault, &payer)?;
    assert!(
        AgentDispatcher::new(vault).root_payer(root)?.is_none(),
        "the erase clears the root's payer"
    );
    Ok(())
}

#[test]
fn a_room_bound_runs_next_model_call_is_refused_once_its_payer_is_erased() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let payer = payer_person(&vault)?;
    let root = paid_root(&vault, "live-run-payer-room", payer)?;
    let leased = in_room(&leased_run(&vault, "run-live-payer-room")?, EntityId::now())?;

    assert_eq!(
        entry_meter_payer(&vault, &leased, &root),
        Ok(Some(payer)),
        "while the run holds its lease, its calls bill the payer who funds its root"
    );

    erase_payer(&vault, payer, &root)?;

    let next = entry_meter_payer(&vault, &leased, &root);
    assert!(
        next.as_ref()
            .is_err_and(|refusal| refusal.starts_with("payer_missing")),
        "a room-bound run's next model call after its payer is erased is refused typed, \
         not billed to the vault owner's default: {next:?}"
    );
    Ok(())
}

#[test]
fn a_run_no_room_binds_keeps_the_owner_default_once_the_payer_is_erased() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let payer = payer_person(&vault)?;
    let root = paid_root(&vault, "live-run-payer-unbound", payer)?;
    let leased = leased_run(&vault, "run-live-payer-unbound")?;

    assert_eq!(
        entry_meter_payer(&vault, &leased, &root),
        Ok(Some(payer)),
        "while its root names a payer, an unbound run's calls bill that payer"
    );

    erase_payer(&vault, payer, &root)?;

    assert_eq!(
        entry_meter_payer(&vault, &leased, &root),
        Ok(None),
        "a run no room or member binds keeps the vault owner's default"
    );
    Ok(())
}
