//! The write cost of a run's change journal (L8-48, ARCH-0040 #revert-run):
//! each claim a run writes adds one journal row in the claim's own write.
//! This measures the rows and their stored bytes for one run of 3 claims and
//! prints them as `## JOURNAL` lines. A measurement on the head, not a
//! red/green pin: its door exists only beside the journal.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_journal_cost -- --nocapture`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::run_changes::journal_row_sizes;
use oneiron::test_support::{bind_host_owner, put_policy_manifest_bytes, test_host_issuer};
use oneiron::{
    ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig, WriteActor,
};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Defaults that land the owner's Generated claims (as run_changes_list.rs).
fn run_policy(actor: EntityId) -> TestResult<Vec<u8>> {
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
        (
            Value::from("pack_id"),
            Value::from("run-changes-journal-cost"),
        ),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (Value::from("rules"), Value::Array(Vec::new())),
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

/// A run of 3 claims under a run id 36 bytes long (a UUID's length) keeps
/// exactly 3 journal rows; each row's key and value sizes are printed.
#[test]
fn run_changes_journal_keeps_one_row_per_claim() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).map_err(at("open"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    bind_host_owner(&vault, &test_host_issuer(), owner).map_err(at("owner host binding"))?;
    put_policy_manifest_bytes(&vault, EntityId::now(), &run_policy(owner)?)
        .map_err(at("install the policy"))?;
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .map_err(at("put a PERSON"))?;
    let run_id = "0b6f3c1e-5a7d-4e2b-9c8f-1d2e3f4a5b6c";
    let run = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        run_id,
    )
    .map_err(at("the run's dispatcher"))?;
    for (value, at_time) in [("sencha", 10), ("matcha", 12), ("genmaicha", 14)] {
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            EntityId::now(),
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.8,
            ),
            range(at_time),
            at_time + 1,
        )))
        .map_err(at("the run's claim put"))?;
    }
    let sizes = journal_row_sizes(&vault, run_id).map_err(at("the journal rows"))?;
    for (index, (key, value)) in sizes.iter().enumerate() {
        println!(
            "## JOURNAL row={index} key_bytes={key} value_bytes={value} total={}",
            key + value
        );
    }
    let total: usize = sizes.iter().map(|(key, value)| key + value).sum();
    println!(
        "## JOURNAL rows={} run_id_bytes={} total_bytes={total}",
        sizes.len(),
        run_id.len()
    );
    assert_eq!(sizes.len(), 3, "one journal row per claim the run wrote");
    Ok(())
}
