//! Big-value bound fixtures for crate conflict pack checks.
//!
//! Bound attempts use the large values in `crates/oneiron/tests/extraction_read_layout.rs`:
//! two 50,000-character candidates drive both read kinds, and two large listed
//! claims drive a correction final's two-name shortlist. Each builder keeps
//! the vault and binding alive and serves its operands through the bound
//! inputs page, so crate packs rebuild against the same rows native rebuilds.

use std::sync::Arc;

use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::memory::MemoryResult;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::land_extraction_verdict_listing_claim;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_dreamer::conflict_decisions::{ExtractionPack, ExtractionRead};
use oneiron_dreamer::extraction_selection::ExtractionSelectionConfig;
use oneiron_remote::OneironClient;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

/// Returns fixture values or the underlying fixture error.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Holds one bound big-value attempt with its served operands.
pub(crate) struct BigFixture {
    /// Holds the bound Dreamer attempt client.
    pub(crate) client: OneironClient,
    /// Names the bound attempt as lowercase hex.
    pub(crate) attempt: String,
    /// Holds the attempt clock in Unix milliseconds.
    pub(crate) now_ms: u64,
    /// Holds the served candidate operands in pack order.
    pub(crate) operands: Vec<Value>,
    /// Holds the effective selection configuration.
    pub(crate) config: ExtractionSelectionConfig,
    /// Holds the effective policy pin.
    pub(crate) policy_pin: String,
    /// Retains the vault directory for the fixture lifetime.
    _directory: tempfile::TempDir,
    /// Retains the vault for the fixture lifetime.
    _vault: Arc<Vault>,
}

/// Builds an exactly 50,000-character value over `prefix`.
///
/// Native forces paging with the same size
/// (`crates/oneiron/tests/extraction_read_layout.rs:33`).
fn big_value(prefix: &str) -> Value {
    json!(prefix.chars().cycle().take(50_000).collect::<String>())
}

/// Opens a bound vault with steward grant and ready selection.
///
/// Soak zero and evidence minimum one match the observed fixture
/// (`crates/oneiron-driver/tests/extraction_verdict_observed/support.rs:104-105`),
/// so each cited turn qualifies its candidate.
fn open_bound_vault(directory: &tempfile::TempDir) -> TestResult<Arc<Vault>> {
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    Ok(vault)
}

/// Binds one admitted attempt over `turns` and reads its inputs page.
fn bind_attempt(
    vault: &Arc<Vault>,
    turns: &[EntityId],
) -> TestResult<(
    OneironClient,
    String,
    u64,
    Value,
    ExtractionSelectionConfig,
    String,
)> {
    let (id, admitted) = enqueue_admitted_extraction_attempt(vault, turns, 1_000)?;
    let attempt: String = id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt}),
    )?;
    let page = inputs["value"].clone();
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    Ok((client, attempt, now_ms, page, config, policy_pin))
}

/// Reads served turn refs with versions from a bound inputs page.
fn page_turns(page: &Value) -> TestResult<Vec<(String, Value)>> {
    let served = page["turns"].as_array().ok_or("missing turns")?;
    let mut turns = Vec::with_capacity(served.len());
    for row in served {
        let turn = row["turn"].as_str().ok_or("missing turn")?.to_owned();
        turns.push((turn, row["version"].clone()));
    }
    Ok(turns)
}

/// Builds the resolution paging fixture with two 50,000-character candidates.
///
/// Native refuses its Whole with `[[0], [1]]` and waits on each page loan
/// (`crates/oneiron/tests/extraction_read_layout.rs:78-120,136-171`).
pub(crate) fn big_resolution_fixture() -> TestResult<BigFixture> {
    big_candidate_fixture(false)
}

/// Builds correction paging over two 50,000-character candidates and one listed head.
pub(crate) fn big_candidate_correction_fixture() -> TestResult<BigFixture> {
    big_candidate_fixture(true)
}

fn big_candidate_fixture(with_listed: bool) -> TestResult<BigFixture> {
    let directory = tempfile::tempdir()?;
    let vault = open_bound_vault(&directory)?;
    let subject = if with_listed {
        land_extraction_verdict_listing_claim(&vault)?.0
    } else {
        let subject = EntityId::now();
        seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
        subject
    };
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (client, attempt, now_ms, page, config, policy_pin) =
        bind_attempt(&vault, &witnessed.turns)?;
    let turns = page_turns(&page)?;
    if turns.len() != 2 {
        return Err("the bound attempt must serve both turns".into());
    }
    let subject_hex = subject.to_hex();
    let operands = vec![
        json!({
            "subject": subject_hex, "predicate": "profile.hobby",
            "value": big_value("tea"),
            "evidence": [{"turn": turns[0].0.clone(), "version": turns[0].1.clone()}],
        }),
        json!({
            "subject": subject_hex, "predicate": "profile.hobby",
            "value": big_value("coffee"),
            "evidence": [{"turn": turns[1].0.clone(), "version": turns[1].1.clone()}],
        }),
    ];
    Ok(BigFixture {
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
        _directory: directory,
        _vault: vault,
    })
}

/// Lands two 50,000-character listed claims about one subject at one clock.
///
/// Both values share one learned clock, so the newest-first listing breaks
/// the tie by ascending claim identifier
/// (`crates/oneiron/tests/extraction_read_layout.rs:52-72`).
fn land_two_big_listed(vault: &Vault) -> TestResult<(EntityId, EntityId, EntityId)> {
    let (subject, first) = land_extraction_verdict_listing_claim(vault)?;
    let mut body = vault
        .get_claim(&first)?
        .ok_or("the listing fixture landed its claim")?;
    body.value = RmpValue::from("owen".chars().cycle().take(50_000).collect::<String>());
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault.put_claim(&first, &body, occurred, now)?;
    let second = EntityId::now();
    body.predicate = "profile.hobby".to_owned();
    body.value = RmpValue::from("yuki".chars().cycle().take(50_000).collect::<String>());
    vault.put_claim(&second, &body, occurred, now)?;
    let mut listed = [first, second];
    listed.sort();
    Ok((subject, listed[0], listed[1]))
}

/// Builds the correction paging fixture with two 50,000-character listed claims.
///
/// Native refuses its Whole with two pair pages and waits on each page loan
/// (`crates/oneiron/tests/extraction_read_layout.rs:219-284`).
pub(crate) fn big_correction_fixture() -> TestResult<BigFixture> {
    let directory = tempfile::tempdir()?;
    let vault = open_bound_vault(&directory)?;
    let (subject, _, _) = land_two_big_listed(&vault)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (client, attempt, now_ms, page, config, policy_pin) =
        bind_attempt(&vault, &witnessed.turns)?;
    let turns = page_turns(&page)?;
    if turns.len() != 1 {
        return Err("the bound attempt must serve its turn".into());
    }
    let operands = vec![json!({
        "subject": subject.to_hex(), "predicate": "profile.name",
        "value": json!("yuki"),
        "evidence": [{"turn": turns[0].0.clone(), "version": turns[0].1.clone()}],
    })];
    Ok(BigFixture {
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
        _directory: directory,
        _vault: vault,
    })
}

/// Calls the bound verdict with `pack` as its state.
///
/// The wording matches the read and the Choice contract equals question zero
/// options in order, as the bound handler requires
/// (`crates/oneiron/src/dreamer_runner/attempt_binding/extraction_decisions.rs:44-81`).
pub(crate) fn verdict_for_pack(
    client: &OneironClient,
    pack: &ExtractionPack,
) -> MemoryResult<Value> {
    let question = match pack.read {
        ExtractionRead::Correction | ExtractionRead::CorrectionFinal => "correction",
        ExtractionRead::Resolution | ExtractionRead::ResolutionFinal => "resolution",
        ExtractionRead::IdentityFinal => "identity",
    };
    let first = pack
        .questions
        .first()
        .map(|asked| asked.options.clone())
        .unwrap_or_default();
    let state = serde_json::to_value(pack).map_err(|error| {
        oneiron::memory::MemoryError::bad_request(format!("the pack does not encode: {error}"))
    })?;
    client.agent_verb(
        "ai.verdict",
        json!({
            "question": question,
            "contract": {"kind": "choice", "options": first},
            "evidence": [],
            "state": state,
            "ceiling": "big",
            "reversibility": "reversible_read",
            "routine": false,
            "misses": 0,
        }),
    )
}
