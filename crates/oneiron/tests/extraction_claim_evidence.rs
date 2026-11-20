//! Pinned claim evidence on a bound extraction operand is checked under the job's
//! live read. A restatement removes only its own correction pair, and a claim
//! can be the candidate's only evidence.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_claim_evidence`
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryResult};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::slice::from_ref;
use std::sync::Arc;
use verdict_support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction as bind_listing,
    extraction_attempt_hex as listing_attempt_hex, extraction_candidate as listing_candidate,
    extraction_verdict_request as listing_verdict_request, invoke_bound_verdict,
    open_extraction_verdict_vault as open_listing_vault, page_turns_with_versions,
    read_bound_extraction_page as read_bound_inputs_page,
};

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the stored heads and the proposed values.
const FOOD: &str = "preference.food";

/// Opens the listing vault, grants the Dreamer Steward reach, and seeds the named subject.
fn open_claim_vault(
    dir: &tempfile::TempDir,
) -> ExtractionVerdictTestResult<(Arc<Vault>, EntityId)> {
    let vault = Arc::new(open_listing_vault(dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    Ok((vault, subject))
}

/// Lands a separate public, active food preference with Auto approval on the default facet.
fn land_food_claim(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: ClaimSource,
) -> ExtractionVerdictTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.scope = Some(RmpValue::Map(vec![(
        RmpValue::from("sensitivity"),
        RmpValue::from(0u64),
    )]));
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(id)
}

/// Pins a claim using the source version served to the Dreamer, not an owner read.
fn claim_pin(vault: &Vault, claim: EntityId) -> ExtractionVerdictTestResult<Value> {
    let version = dreamer_extraction_verdict_source_version(vault, claim)?
        .expect("The Dreamer reads the fixture claim at its current version.");
    Ok(json!({"claim": claim.to_hex(), "version": serde_json::to_value(version)?}))
}

/// Holds one admitted extraction binding and the served TURN used in the mixed evidence requests.
struct Observations {
    binding: DreamerAttemptBinding,
    attempt: String,
    turn: String,
    turn_version: Value,
}

impl Observations {
    /// Queues turns that name Owen, then reads the pin of the first witnessed turn.
    fn start(vault: &Arc<Vault>) -> ExtractionVerdictTestResult<Self> {
        let witnessed = witness_extraction_turns(
            vault,
            &[
                "owen savors green tea",
                "owen cooks daily",
                "owen walks daily",
            ],
        )?;
        let (id, admitted) =
            enqueue_admitted_extraction_attempt(vault, &witnessed.turns, QUEUE_NOW)?;
        let binding = bind_listing(vault, &admitted)?;
        let attempt = listing_attempt_hex(id);
        let inputs = read_bound_inputs_page(&binding, &attempt)?;
        let cited = witnessed.turns[0].to_hex();
        let (turn, turn_version) = page_turns_with_versions(&inputs)
            .into_iter()
            .find(|(turn, _)| turn == &cited)
            .expect("The inputs page serves the first witnessed turn with its version.");
        Ok(Self {
            binding,
            attempt,
            turn,
            turn_version,
        })
    }

    /// Builds a food preference citing the fixture's served TURN.
    fn turn_candidate(&self, subject: EntityId, value: &str) -> Value {
        listing_candidate(
            &subject.to_hex(),
            FOOD,
            json!(value),
            &self.turn,
            self.turn_version.clone(),
        )
    }

    /// Reads one bound observations page for these operands.
    fn invoke_observations(&self, candidates: &[Value]) -> MemoryResult<Value> {
        self.binding
            .invoke(
                OBSERVATIONS_PAGE_VERB,
                json!({
                    "attempt": self.attempt,
                    "now_ms": OBSERVATION_NOW_MS,
                    "candidates": candidates,
                }),
                None,
            )
            .map(|answer| answer["value"].clone())
    }
}

/// Adds a single claim pin to an operand without changing its TURN evidence.
fn with_claim_evidence(mut candidate: Value, pin: &Value) -> Value {
    candidate["claim_evidence"] = json!([pin]);
    candidate
}

/// Returns the candidate at the requested operand position.
fn page_candidate(page: &Value, index: u64) -> &Value {
    page["candidates"]
        .as_array()
        .expect("The page has a candidate rows array.")
        .iter()
        .find(|row| row["index"] == json!(index))
        .expect("The page serves the requested candidate row.")
}

/// Returns the listed claim hexes with their zero-based positions on the page.
fn listed_indexes(page: &Value) -> BTreeMap<&str, u64> {
    let rows = page["listed"]
        .as_array()
        .expect("The page has a listed rows array.");
    let indexes: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let claim = row["claim"]
                .as_str()
                .expect("The listed row names its claim.");
            (claim, index as u64)
        })
        .collect();
    assert_eq!(
        indexes.len(),
        rows.len(),
        "Each claim is listed at most once."
    );
    indexes
}

/// Reads the correction indexes in sorted order, without hiding repeated indexes.
fn correctable_indexes(row: &Value) -> Vec<u64> {
    let mut indexes: Vec<_> = row["correctable"]
        .as_array()
        .expect("The candidate row has a correctable indexes array.")
        .iter()
        .map(|index| index.as_u64().expect("Each correctable index is a number."))
        .collect();
    indexes.sort_unstable();
    indexes
}

/// Builds the whole correction read for one candidate and one option group.
fn correction_request(candidate: &Value, pins: &[Value], options: Value) -> Value {
    let pack = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": [candidate],
        "listed": pins,
        "priors": [],
        "questions": [{"key": ["0", "0"], "options": options}],
        "earlier": [],
    });
    listing_verdict_request("correction", options, pack)
}

/// Checks that a request refuses for the specified operand or pack error.
fn assert_bad_request(result: MemoryResult<Value>, message: &str) {
    let error = result.expect_err("The request is refused.");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "The request is invalid: {error:?}."
    );
    assert!(
        error.message.contains(message),
        "The refusal should contain {message:?}; it was {:?}.",
        error.message,
    );
}

/// A restatement is skipped only for its own candidate, and the verdict checks the reduced pin set.
#[test]
fn a_restated_cited_claim_is_not_asked_and_the_others_are() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, subject) = open_claim_vault(&dir)?;
    let first = land_food_claim(&vault, subject, "green tea", ClaimSource::UserStated)?;
    let second = land_food_claim(&vault, subject, "black coffee", ClaimSource::UserStated)?;
    let observations = Observations::start(&vault)?;
    let first_pin = claim_pin(&vault, first)?;
    let second_pin = claim_pin(&vault, second)?;
    let first_hex = first.to_hex();
    let second_hex = second.to_hex();
    let restated = with_claim_evidence(
        observations.turn_candidate(subject, "green tea"),
        &first_pin,
    );
    let changed = with_claim_evidence(observations.turn_candidate(subject, "jasmine"), &first_pin);

    let page = observations
        .invoke_observations(&[restated.clone(), changed])
        .expect("The observations page accepts the live claim pin beside a TURN.");
    let listed = listed_indexes(&page);
    assert_eq!(
        listed.len(),
        2,
        "The two candidates keep both listed claims."
    );
    let first_at = listed[first_hex.as_str()];
    let second_at = listed[second_hex.as_str()];
    assert_eq!(
        correctable_indexes(page_candidate(&page, 0)),
        vec![second_at],
        "The restating candidate is asked only about the other claim.",
    );
    let mut both = vec![first_at, second_at];
    both.sort_unstable();
    assert_eq!(
        correctable_indexes(page_candidate(&page, 1)),
        both,
        "The candidate with a different value is asked about both claims.",
    );

    let page = observations
        .invoke_observations(from_ref(&restated))
        .expect("The observations page accepts a single restating candidate.");
    assert_eq!(
        listed_indexes(&page),
        BTreeMap::from([(second_hex.as_str(), 0)]),
        "The remaining question leaves only the second claim listed.",
    );
    assert_eq!(
        page["listed"][0]["version"], second_pin["version"],
        "The remaining listed row serves the second claim's current pin.",
    );
    assert_eq!(
        correctable_indexes(page_candidate(&page, 0)),
        vec![0],
        "The restating candidate is asked about the only remaining row.",
    );

    let request = correction_request(
        &restated,
        from_ref(&second_pin),
        json!(["none", second_hex]),
    );
    let error = invoke_bound_verdict(&observations.binding, request)
        .expect_err("The checked correction read has no model loan.");
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "The reduced pack passes the checks and reaches the model loan: {error:?}.",
    );

    let request = correction_request(
        &restated,
        &[first_pin, second_pin],
        json!(["none", first_hex, second_hex]),
    );
    assert_bad_request(
        invoke_bound_verdict(&observations.binding, request),
        "the extraction pack claim pins differ from the engine's rebuilt set",
    );
    Ok(())
}

/// A claim alone counts as evidence, but it cannot create a correction question about itself.
#[test]
fn a_claim_only_restatement_reads_no_correction() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, subject) = open_claim_vault(&dir)?;
    let head = land_food_claim(&vault, subject, "green tea", ClaimSource::UserStated)?;
    let observations = Observations::start(&vault)?;
    let operand = json!({
        "subject": subject.to_hex(),
        "predicate": FOOD,
        "value": "green tea",
        "evidence": [],
        "claim_evidence": [claim_pin(&vault, head)?],
    });
    let page = observations
        .invoke_observations(&[operand])
        .expect("The observations page accepts claim evidence without TURN evidence.");
    assert!(
        listed_indexes(&page).is_empty(),
        "No claim is listed for correction."
    );
    let candidate = page_candidate(&page, 0);
    assert!(
        correctable_indexes(candidate).is_empty(),
        "No correction pair is asked."
    );
    assert_eq!(
        candidate["evidence_count"],
        json!(1),
        "The cited claim counts as evidence."
    );
    assert_eq!(
        candidate["diversity"],
        json!(1),
        "The claim contributes its own diversity key."
    );
    Ok(())
}

/// A generated head can be a correction target, but it cannot serve as evidence.
#[test]
fn a_generated_head_is_refused_as_claim_evidence() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, subject) = open_claim_vault(&dir)?;
    let head = land_food_claim(&vault, subject, "green tea", ClaimSource::Generated)?;
    let observations = Observations::start(&vault)?;
    let pin = claim_pin(&vault, head)?;
    let candidate = observations.turn_candidate(subject, "jasmine");
    let control = observations.invoke_observations(from_ref(&candidate))?;
    assert!(
        listed_indexes(&control).contains_key(head.to_hex().as_str()),
        "The generated head is shown as a correction target without a claim citation.",
    );
    assert_bad_request(
        observations.invoke_observations(&[with_claim_evidence(candidate, &pin)]),
        "generated claim cannot corroborate",
    );
    Ok(())
}

/// A live claim about an unmentioned person cannot serve as evidence for this listing.
#[test]
fn an_unlisted_claim_is_refused_as_claim_evidence() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, subject) = open_claim_vault(&dir)?;
    let other = EntityId::now();
    seed_named_person(&vault, &other, "yuki", vault.now_recorded_at())?;
    let head = land_food_claim(&vault, other, "green tea", ClaimSource::UserStated)?;
    let observations = Observations::start(&vault)?;
    let pin = claim_pin(&vault, head)?;
    let candidate = with_claim_evidence(observations.turn_candidate(subject, "jasmine"), &pin);
    assert_bad_request(
        observations.invoke_observations(&[candidate]),
        "extracted evidence names an unlisted claim",
    );
    Ok(())
}

/// A live version of a different claim cannot pin the cited claim.
#[test]
fn a_claim_pin_of_another_row_is_refused() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, subject) = open_claim_vault(&dir)?;
    let first = land_food_claim(&vault, subject, "green tea", ClaimSource::UserStated)?;
    let second = land_food_claim(&vault, subject, "black coffee", ClaimSource::UserStated)?;
    let observations = Observations::start(&vault)?;
    let mut pin = claim_pin(&vault, second)?;
    pin["claim"] = json!(first.to_hex());
    let candidate = with_claim_evidence(observations.turn_candidate(subject, "jasmine"), &pin);
    assert_bad_request(
        observations.invoke_observations(&[candidate]),
        "an extraction pin names another row",
    );
    Ok(())
}
