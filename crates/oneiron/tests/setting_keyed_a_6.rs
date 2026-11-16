//! DESIGN 15-setting-primitive, stage 4, lane SETTING-KEYED-A, PR K2b: a reader's weave digest
//! rhythm and recipe (OF-499, `WEAVE_DIGEST_SCHEDULE`) become a setting (Engine RULING
//! SETTING-KEYED-A-K2B-WEAVE-SPLIT = A). `weave.digest.owner_schedule` sits at the owner's person
//! scope, `weave.digest.reader_schedule` at a person's or an agent's; the value is
//! `{cadence, recipe, starts_at}`. The due state stays in the table, and the key's hook keeps it.
//! - the owner sets his own digest with `vault.settings.set`, and `vault.weave.schedules.list`
//!   shows it due at `starts_at`; a rhythm change keeps the clock, a new `starts_at` moves it, and
//!   a clear stops the digest;
//! - a reader's row sits at its own scope: a vault row, an owner row for a person who is no
//!   owner, and a section the weave report policy refuses that reader are refused, and the
//!   schedule in force stays;
//! - the verbs `vault.weave.schedules.{put,clear}` are gone.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_6`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const LIST: &str = "vault.weave.schedules.list";
const T0: u64 = 1_790_000_000;

const OWNER_KEY: &str = "weave.digest.owner_schedule";
const READER_KEY: &str = "weave.digest.reader_schedule";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn person(id: EntityId) -> Value {
    json!({ "kind": "person", "id": id.to_hex() })
}

fn agent(id: EntityId) -> Value {
    json!({ "kind": "agent", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

/// A schedule value: `cadence`, one section of `kind`, first due at `starts_at`.
fn schedule(cadence: &str, kind: &str, starts_at: u64) -> Value {
    json!({ "cadence": cadence, "recipe": [{ "kind": kind }], "starts_at": starts_at })
}

fn listed(memory: &Memory<'_>) -> Vec<Value> {
    call(memory, LIST, json!({}))
        .as_array()
        .expect("the schedules list")
        .clone()
}

#[test]
fn the_owner_sets_his_digest_schedule_as_a_setting_and_its_due_state_follows() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    assert!(
        listed(&me).is_empty(),
        "no digest before the owner sets one"
    );

    let applied = call(
        &me,
        SET,
        set(
            OWNER_KEY,
            person(fx.owner),
            schedule("weekly", "sieve_score", T0 + 3_600),
        ),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let rows = listed(&me);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["reader"]["kind"], json!("owner"), "{rows:?}");
    assert_eq!(
        rows[0]["reader"]["reader_ref"],
        json!(fx.owner.to_hex()),
        "{rows:?}"
    );
    assert_eq!(rows[0]["cadence"], json!("weekly"), "{rows:?}");
    assert_eq!(rows[0]["next_due_at"], json!(T0 + 3_600), "{rows:?}");
    assert_eq!(
        rows[0]["sections"][0]["kind"],
        json!("sieve_score"),
        "{rows:?}"
    );

    // A rhythm change keeps the clock where it is.
    let applied = call(
        &me,
        SET,
        set(
            OWNER_KEY,
            person(fx.owner),
            schedule("daily", "sieve_score", T0 + 3_600),
        ),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let rows = listed(&me);
    assert_eq!(rows[0]["cadence"], json!("daily"), "{rows:?}");
    assert_eq!(rows[0]["next_due_at"], json!(T0 + 3_600), "{rows:?}");

    // A new clock start moves it.
    call(
        &me,
        SET,
        set(
            OWNER_KEY,
            person(fx.owner),
            schedule("daily", "sieve_score", T0 + 7_200),
        ),
    );
    assert_eq!(listed(&me)[0]["next_due_at"], json!(T0 + 7_200));

    // A clear stops the digest.
    let cleared = call(&me, SET, set(OWNER_KEY, person(fx.owner), Value::Null));
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    assert!(listed(&me).is_empty(), "the stopped digest is not listed");
}

#[test]
fn a_reader_schedule_sits_at_its_readers_scope_and_its_recipe_is_checked() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let reader = fx.vault.new_entity_id().expect("agent id");

    let applied = call(
        &me,
        SET,
        set(
            READER_KEY,
            agent(reader),
            schedule("daily", "digest", T0 + 60),
        ),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let rows = listed(&me);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["reader"]["kind"], json!("agent"), "{rows:?}");
    assert_eq!(
        rows[0]["reader"]["reader_ref"],
        json!(reader.to_hex()),
        "{rows:?}"
    );

    // A section the weave report policy does not let an agent read is refused.
    let error = refused(
        &me,
        SET,
        set(
            READER_KEY,
            agent(reader),
            schedule("daily", "budgets", T0 + 60),
        ),
    );
    assert!(error.contains("recipe"), "{error}");
    assert_eq!(listed(&me)[0]["sections"][0]["kind"], json!("digest"));

    // No row sits at the vault scope, and an owner row is a live owner's own.
    refused(
        &me,
        SET,
        set(
            READER_KEY,
            json!({ "kind": "vault" }),
            schedule("daily", "digest", T0 + 60),
        ),
    );
    refused(
        &me,
        SET,
        set(
            OWNER_KEY,
            json!({ "kind": "vault" }),
            schedule("daily", "sieve_score", T0 + 60),
        ),
    );
    refused(
        &me,
        SET,
        set(
            OWNER_KEY,
            person(reader),
            schedule("daily", "sieve_score", T0 + 60),
        ),
    );
    assert_eq!(listed(&me).len(), 1, "only the agent's digest stands");
}

#[test]
fn the_schedule_put_and_clear_verbs_are_gone() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let reader = fx.vault.new_entity_id().expect("agent id");
    let reader_ref = json!({ "kind": "agent", "reader_ref": reader.to_hex() });
    for (verb, input) in [
        (
            "vault.weave.schedules.put",
            json!({
                "reader": reader_ref,
                "cadence": "daily",
                "next_due_at": T0 + 60,
                "sections": [{ "kind": "digest" }],
            }),
        ),
        ("vault.weave.schedules.clear", reader_ref.clone()),
    ] {
        assert!(
            invoke(&me, verb, input).is_err(),
            "{verb} is no longer a verb: a schedule is a setting"
        );
    }
    assert!(listed(&me).is_empty(), "nothing was scheduled");
}
