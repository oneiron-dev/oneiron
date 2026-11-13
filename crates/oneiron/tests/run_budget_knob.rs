//! The owner's `on_budget_exhausted` knob reaches the vault's policy meters
//! (ARCH-0026 depletion ladder, policy knob: "A paid overdraft runs only when
//! the owner configured `Overdraft{cap}`"; Engine ruling RUNBUDGET-KNOB = A,
//! 13 Nov 17:30). A configured `Overdraft{cap}` widens a meter's paid cap by
//! `cap`, so the run goes on with no ask while it fits; with no knob the meter
//! suspends at its cap; a caller's own overdraft stands over the knob.
//!
//! Doors main already has, so the file runs red on main:
//! `cargo test --locked -p oneiron --all-features --test run_budget_knob`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::BudgetDenied;
use oneiron::store::GateDecisionId;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

/// One call's reservation, and the meter's line: one call fits.
const LINE: u64 = 8_000;

fn open() -> (tempfile::TempDir, Vault, AuthenticatedOwner, WriteActor) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault opens");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    (
        dir,
        vault,
        proof,
        WriteActor::new(owner, EdgeActorClass::Human),
    )
}

/// Sets the stored default manifest's `on_budget_exhausted` knob to `knob`,
/// as the owner.
fn set_knob(vault: &Vault, proof: &AuthenticatedOwner, knob: Value) {
    let id = oneiron_store::policy_record::default_policy_manifest_id().expect("manifest id");
    let body = vault
        .get(&id)
        .expect("manifest read")
        .expect("the default policy manifest is stored");
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("manifest decodes")
    else {
        panic!("the default policy manifest is a map");
    };
    fields.retain(|(key, _)| key.as_str() != Some("on_budget_exhausted"));
    fields.push((Value::from("on_budget_exhausted"), knob));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields)).expect("manifest encodes");
    vault
        .install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())
        .expect("the owner installs the manifest");
}

fn overdraft(cap: u64) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("overdraft")),
        (Value::from("cap"), Value::from(cap)),
    ])
}

/// The meter after one call spent its whole line.
fn spent_meter(vault: &Vault, actor: WriteActor, chosen: BudgetExhaustionPolicy) -> BudgetGuard {
    let meter = vault
        .policy_budget_guard("run-budget-knob", LINE, LINE, chosen, actor)
        .expect("the policy meter");
    let first = meter.admit().expect("the line admits one call");
    meter
        .settle_reserved(&first.lease)
        .expect("the call settles");
    meter
}

/// Canon: a paid overdraft runs when the owner configured `Overdraft{cap}`.
/// His knob widens the meter: a second call fits in the cap past the line.
#[test]
fn the_owners_overdraft_knob_widens_a_policy_meter() {
    let (_dir, vault, proof, actor) = open();
    set_knob(&vault, &proof, overdraft(LINE));
    let meter = spent_meter(&vault, actor, BudgetExhaustionPolicy::Suspend);
    meter
        .admit()
        .expect("the owner's overdraft admits one more call");
    assert!(
        matches!(meter.admit(), Err(BudgetDenied::Exhausted)),
        "and no more than its cap"
    );
}

/// With no knob, or the knob at `suspend`, the meter suspends at its line.
#[test]
fn with_no_overdraft_knob_a_policy_meter_suspends_at_its_line() {
    let (_dir, vault, proof, actor) = open();
    let meter = spent_meter(&vault, actor, BudgetExhaustionPolicy::Suspend);
    assert!(matches!(meter.admit(), Err(BudgetDenied::Exhausted)));

    set_knob(&vault, &proof, Value::from("suspend"));
    let meter = spent_meter(&vault, actor, BudgetExhaustionPolicy::Suspend);
    assert!(matches!(meter.admit(), Err(BudgetDenied::Exhausted)));
}

/// A caller's own overdraft (the owner's one-off overdraft of a held run)
/// stands over a knob that names none.
#[test]
fn a_callers_own_overdraft_stands_over_the_knob() {
    let (_dir, vault, proof, actor) = open();
    set_knob(&vault, &proof, Value::from("continue_on_local"));
    let meter = spent_meter(
        &vault,
        actor,
        BudgetExhaustionPolicy::Overdraft { cap: LINE },
    );
    meter
        .admit()
        .expect("the caller's overdraft admits one more call");
}
