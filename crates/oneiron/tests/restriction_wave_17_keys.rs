//! Restriction wave 17: the five owner keys move their reader, and at the
//! default each reader behaves as before.
//! - `attempt_queue.landing.max_reserve_percent`: a raised cap admits a
//!   landing reserve past half the budget; at the default it is refused;
//! - `attempt_queue.lease.warning_percent`: a lowered warning warns a leased
//!   worker earlier; at the default a lease at 60 % is not yet warned;
//! - `code_run.result_search.max_context`: a raised bound shows more context
//!   on each side of a match; at the default a search shows 1024 bytes;
//! - `maintain.report.facet_receipts_shown` (sync): a raised count names
//!   every held receipt; at the default the report names 100 and counts the
//!   total whole;
//! - out-of-range values are refused and the defaults still read.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restriction_wave_17_keys`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, DialLandingReserve, EnqueueAttempt,
    EnqueueOutcome, LeaseWarningOutcome, WarnAttemptLeaseExpiry,
};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{ArtifactError, Error};
use oneiron::setting::{SetSetting, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const WORKER: &str = "worker:restriction-wave-17";
/// The lease timeout every warning call here passes; the warning window
/// opens at 80 % of it by default.
const TIMEOUT: u64 = 100;
const NEEDLE: &str = "needle-wave17";
/// The context the search tests ask for: past the default bound of 1024,
/// inside the raised bound of 4096.
const CONTEXT_ASK: usize = 3000;

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner
    /// bound, opened owned: the writer lease is what lets the owner's
    /// handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer: HostSlipIssuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            _dir: dir,
            owner_proof,
        }
    }

    /// The owner sets `key` to `value` at the vault scope.
    fn set(&self, key: &str, value: Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting {
                    key: key.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(value),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                },
            )
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error:?}"));
    }
}

/// The owner's refused change of `key` to `value`, as its debug text.
fn refused_set(fx: &Fixture, key: &str, value: Value) -> String {
    format!(
        "{:?}",
        fx.vault
            .set_setting(
                SettingCaller::Owner(&fx.owner_proof),
                SetSetting {
                    key: key.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(value),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                },
            )
            .expect_err("an out-of-range value is refused")
    )
}

fn enqueue(queue: &AttemptQueue<'_>, dedupe: &str, now: u64) -> AttemptRecord {
    match queue
        .enqueue(EnqueueAttempt {
            kind: "sync".to_owned(),
            payload: format!("payload:{dedupe}").into_bytes(),
            dedupe_key: Some(dedupe.to_owned()),
            run_id: Some(format!("run:{dedupe}")),
            now,
        })
        .expect("enqueue")
    {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
        other => panic!("an enqueue answers the queued attempt, not {other:?}"),
    }
}

fn claim(queue: &AttemptQueue<'_>, now: u64) -> AttemptRecord {
    match queue
        .claim(ClaimAttempt {
            lease_owner: WORKER.to_owned(),
            now,
        })
        .expect("claim")
    {
        ClaimOutcome::Claimed(record) => record,
        ClaimOutcome::Empty => panic!("the queued attempt is claimed"),
        other => panic!("a claim answers the queued attempt, not {other:?}"),
    }
}

/// A leased attempt whose lease the vault clock puts at 60 % of its
/// timeout: claimed at `T0`, warned at `T0 + 60` against a timeout of 100.
fn leased_at_sixty_percent(fx: &Fixture, queue: &AttemptQueue<'_>, dedupe: &str) -> AttemptRecord {
    enqueue(queue, dedupe, T0);
    let leased = claim(queue, T0);
    assert_eq!(leased.updated_at, T0, "the lease starts at the vault clock");
    fx.clock.set(T0 + 60);
    leased
}

fn warn(queue: &AttemptQueue<'_>, leased: &AttemptRecord) -> LeaseWarningOutcome {
    queue
        .warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: leased.id,
            lease_timeout_secs: TIMEOUT,
            now: T0 + 60,
        })
        .expect("the warning door answers")
}

/// A match with 3000 bytes of text on each side: 3000 `x`, the needle,
/// 3000 `y`.
fn search_text() -> String {
    format!("{}{NEEDLE}{}", "x".repeat(3000), "y".repeat(3000))
}

/// The bytes of `before` and `after` the first match of a search asking
/// `CONTEXT_ASK` shows.
fn search_lengths(vault: &Vault, text: &str) -> (usize, usize) {
    let out = oneiron::test_doors::code_result_search::search_text(
        vault,
        text,
        json!({"pattern": NEEDLE, "context": CONTEXT_ASK}),
    )
    .expect("the search door answers");
    let first = &out["matches"][0];
    (
        first["before"].as_str().expect("before text").len(),
        first["after"].as_str().expect("after text").len(),
    )
}

#[test]
fn a_raised_reserve_cap_admits_a_landing_reserve_past_half_the_budget() {
    let fx = Fixture::rooted();
    fx.set("attempt_queue.landing.max_reserve_percent", json!(80));
    let queue = AttemptQueue::new(&fx.vault);
    let attempt = enqueue(&queue, "wave17-reserve-raised", T0);
    let dialed = queue
        .dial_landing_reserve(DialLandingReserve {
            id: attempt.id,
            limit_units: 1000,
            reserve_percent: Some(70),
            now: T0,
        })
        .expect("a 70 percent reserve dials under a cap of 80");
    let reserve = dialed.landing_reserve();
    assert!(reserve.is_dialed(), "the dial is durably applied");
    assert_eq!(reserve.limit_units, 1000);
    assert_eq!(reserve.reserve_units, 700, "70 percent of 1000");
}

#[test]
fn at_the_default_a_landing_reserve_past_half_the_budget_is_refused() {
    let fx = Fixture::rooted();
    let queue = AttemptQueue::new(&fx.vault);
    let attempt = enqueue(&queue, "wave17-reserve-guard", T0);
    let refused = queue
        .dial_landing_reserve(DialLandingReserve {
            id: attempt.id,
            limit_units: 1000,
            reserve_percent: Some(70),
            now: T0,
        })
        .expect_err("a 70 percent reserve is refused under the default cap of 50");
    assert!(
        matches!(
            refused,
            Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "landing reserve percent must be in 1..=50"
            ))
        ),
        "the range refusal names the bound: {refused:?}"
    );
}

#[test]
fn a_lowered_lease_warning_warns_a_worker_earlier() {
    let fx = Fixture::rooted();
    fx.set("attempt_queue.lease.warning_percent", json!(50));
    let queue = AttemptQueue::new(&fx.vault);
    let leased = leased_at_sixty_percent(&fx, &queue, "wave17-warn-lowered");
    let outcome = warn(&queue, &leased);
    assert!(
        matches!(outcome, LeaseWarningOutcome::LandingRequested(_)),
        "at 60 percent of the lease a warning rung of 50 has fired: {outcome:?}"
    );
}

#[test]
fn at_the_default_a_lease_at_sixty_percent_is_not_yet_warned() {
    let fx = Fixture::rooted();
    let queue = AttemptQueue::new(&fx.vault);
    let leased = leased_at_sixty_percent(&fx, &queue, "wave17-warn-guard");
    let outcome = warn(&queue, &leased);
    assert!(
        matches!(outcome, LeaseWarningOutcome::NotDue(_)),
        "at 60 percent of the lease the default rung of 80 has not fired: {outcome:?}"
    );
}

#[test]
fn a_raised_search_context_bound_shows_more_context() {
    let fx = Fixture::rooted();
    fx.set("code_run.result_search.max_context", json!(4096));
    assert_eq!(
        search_lengths(&fx.vault, &search_text()),
        (3000, 3000),
        "the raised bound shows the whole 3000 bytes asked each side"
    );
}

#[test]
fn at_the_default_a_search_shows_1024_context_bytes() {
    let fx = Fixture::rooted();
    assert_eq!(
        search_lengths(&fx.vault, &search_text()),
        (1024, 1024),
        "the default bound clamps the 3000 bytes asked each side"
    );
}

#[test]
#[cfg(feature = "sync")]
fn a_raised_receipt_count_names_every_held_receipt() {
    let fx = Fixture::rooted();
    fx.set("maintain.report.facet_receipts_shown", json!(150));
    let (shown, total) =
        oneiron::test_doors::maintenance_facet_receipts::report_facet_receipts_after_planting(
            &fx.vault, 120,
        )
        .expect("the report door answers");
    assert_eq!((shown, total), (120, 120), "every held receipt is named");
}

#[test]
#[cfg(feature = "sync")]
fn at_the_default_the_report_names_100_held_receipts() {
    let fx = Fixture::rooted();
    let (shown, total) =
        oneiron::test_doors::maintenance_facet_receipts::report_facet_receipts_after_planting(
            &fx.vault, 120,
        )
        .expect("the report door answers");
    assert_eq!((shown, total), (100, 120), "100 named, the total whole");
}

#[test]
fn out_of_range_values_are_refused() {
    let fx = Fixture::rooted();
    for (key, value, fragment) in [
        (
            "attempt_queue.landing.max_reserve_percent",
            json!(5),
            "from 10 (the default reserve) to 100",
        ),
        (
            "attempt_queue.landing.max_reserve_percent",
            json!(101),
            "from 10 (the default reserve) to 100",
        ),
        (
            "attempt_queue.lease.warning_percent",
            json!(0),
            "from 1 to 100",
        ),
        (
            "attempt_queue.lease.warning_percent",
            json!(101),
            "from 1 to 100",
        ),
        (
            "code_run.result_search.max_context",
            json!(40000),
            "at most 32768 bytes of context",
        ),
    ] {
        let refused = refused_set(&fx, key, value);
        assert!(refused.contains("InvalidConfig"), "{key}: {refused}");
        assert!(refused.contains(fragment), "{key}: {refused}");
    }
    // No row stands, so the defaults still read: the guard acts behave as
    // on main.
    let queue = AttemptQueue::new(&fx.vault);
    enqueue(&queue, "wave17-range-warn", T0);
    let leased = claim(&queue, T0);
    let dial_target = enqueue(&queue, "wave17-range-dial", T0);
    assert!(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: dial_target.id,
                limit_units: 1000,
                reserve_percent: Some(70),
                now: T0,
            })
            .is_err(),
        "the default cap of 50 still refuses a 70 percent reserve"
    );
    fx.clock.set(T0 + 60);
    assert!(
        matches!(warn(&queue, &leased), LeaseWarningOutcome::NotDue(_)),
        "the default rung of 80 still waits past 60 percent"
    );
    assert_eq!(
        search_lengths(&fx.vault, &search_text()),
        (1024, 1024),
        "the default bound still clamps the search"
    );
}
