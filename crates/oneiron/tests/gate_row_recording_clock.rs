//! UC-03 PR 4-1 (one clock; FIX GATE-ROW-WALL-CLOCK-CREATED-AT): a Gate row's `created_at`
//! is whole seconds on the vault's recording clock, read by the mint in the write
//! transaction (fable/21 DESIGN section 1.4). The vault here runs on a manual recording clock
//! set about two months past the wall clock, so a row stamped from the wall clock falls
//! before it.
//!
//! - `an_owner_policy_hold_ruling_row_reads_the_recording_clock`: a named moderator clears a
//!   policy hold (`policy_model/hold_queue.rs`). Red on the base: the ruling's row kept its
//!   wall-clock second.
//! - `a_foreign_agent_widen_row_reads_the_recording_clock`: the owner asks to widen a foreign
//!   agent's ceiling (`gate/foreign_agent.rs`). Red on the base: the row kept the wall clock.
//!
//! Public doors only. Neutral fixtures; vaults in tempdirs.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test gate_row_recording_clock`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_def::AgentCeiling;
use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_model::{PolicyClassifyRequest, PolicyEnforcementAction, PolicyHoldResolution};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::ports::ManualClock;
use oneiron::store::{GateDecisionId, GateDecisionRecord};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The manual recording clock's second: past the wall clock of any run before 2027.
const T0: u64 = 1_800_000_000;

/// The moderator principal the owner row names for its holds.
const MODERATOR: &str = "moderator:offline";

/// A vault on a manual recording clock at `T0`. The vault drops before its directory.
struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("a vault on its manual clock");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Fixture {
        vault,
        _clock: clock,
        _dir: dir,
    }
}

fn put_person(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("put person");
}

/// The rows of `kind` whose grant_ref is `grant_ref`.
fn rows(vault: &Vault, kind: &str, grant_ref: &str) -> Vec<GateDecisionRecord> {
    vault
        .gate_decisions(256)
        .expect("gate decisions")
        .into_iter()
        .filter(|row| row.content_kind == kind && row.grant_ref.as_deref() == Some(grant_ref))
        .collect()
}

/// Whether `created_at` is the manual recording clock's second, not the wall clock's.
fn assert_recording_clock(row: &GateDecisionRecord, what: &str) {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the wall clock is past the epoch")
        .as_secs();
    assert!(
        wall < T0,
        "the fixture needs a recording clock past the wall clock ({wall})"
    );
    assert!(
        (T0..T0 + 60).contains(&row.created_at),
        "{what}: created_at {} is not the recording clock {T0} (wall clock {wall})",
        row.created_at
    );
}

/// An owner plane switched on with one row, `owner:spoilers`, whose action is `warn` and which
/// names `MODERATOR` for its holds, and one `decide` pattern on it: the plane concludes
/// without a model and holds the content for that moderator.
fn moderated_spoiler_manifest() -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "policy-model-test",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "ceiling": "auto"}],
        "owner_policy_enabled": true,
        "owner_policy_rows": [{
            "row_ref": "owner:spoilers",
            "text": "Avoid spoilers in outbound content.",
            "action": "warn",
            "active": true,
            "human": MODERATOR,
        }],
        "owner_policy_patterns": [{
            "id": "owner.spoilers",
            "pattern": "(?i)spoiler",
            "category": "owner:spoilers",
            "role": "decide",
        }],
    });
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

#[test]
fn an_owner_policy_hold_ruling_row_reads_the_recording_clock() -> TestResult {
    let fx = fixture();
    let vault = &fx.vault;
    let moderator = EntityId::from_bytes([0x70; 16]).expect("a fixture id");
    put_person(vault, &moderator);
    let assigned: AuthenticatedOwner =
        vault.authenticate_owner(moderator, MODERATOR, true, GateDecisionId::now())?;
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        EntityId::from_bytes([0x78; 16]).expect("a fixture id"),
        &moderated_spoiler_manifest(),
    )?;

    let held =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("a spoiler, held"))?;
    assert_eq!(held.action, PolicyEnforcementAction::Hold, "{held:?}");
    let reference = held
        .moderation_ref
        .clone()
        .expect("a held verdict names its hold");
    vault.resolve_policy_hold(&assigned, &reference, PolicyHoldResolution::Cleared)?;

    let rulings = rows(vault, "policy_hold", &reference);
    assert_eq!(rulings.len(), 1, "one ruling, one row: {rulings:?}");
    assert_eq!(rulings[0].outcome, "approved", "the moderator's yes");
    assert_recording_clock(&rulings[0], "the hold ruling's row");
    Ok(())
}

#[test]
fn a_foreign_agent_widen_row_reads_the_recording_clock() -> TestResult {
    let fx = fixture();
    let vault = &fx.vault;
    let owner = vault.ensure_embedded_owner_actor()?;
    let introducer = EntityId::from_bytes([0x64; 16]).expect("a fixture id");
    let foreign = EntityId::from_bytes([0x65; 16]).expect("a fixture id");
    for id in [introducer, foreign] {
        put_person(vault, &id);
    }
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.register_foreign_agent(
        &proof,
        foreign,
        WriteActor::new(introducer, EdgeActorClass::Agent),
        AgentCeiling::Auto,
    )?;

    vault.request_foreign_agent_widen(&proof, foreign, AgentCeiling::Auto)?;

    let widens = rows(vault, "claim", &format!("foreign:{}", foreign.to_hex()));
    assert_eq!(widens.len(), 1, "one request, one row: {widens:?}");
    assert_recording_clock(&widens[0], "the widen request's row");
    Ok(())
}
