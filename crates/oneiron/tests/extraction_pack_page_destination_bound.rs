//! The observations page and the verdict pack check of a bound extraction attempt list for the
//! destination bound its lender states, as the lent step does (FIX row
//! BOUND-PACK-AND-PAGE-DESTINATION-NO-TEST). #9718 proved the bound on the lent generation step
//! only (`tests/extraction_step_destination_bound.rs`). The page
//! (`snapshot_read/extraction_observations.rs`) and the pack check
//! (`dreamer_runner/attempt_binding/extraction_evidence.rs`) take the same accessor,
//! `DreamerAttemptBinding::destination_bound`, and pass it to the shared operand check.
//!
//! The fixture adapts #9718's kept world: a stated food head about owen sits in a world the owner
//! keeps on this machine, and the one witnessed turn that names owen sits in that world too, so
//! the head matches the branch's world. A listing read for this device shows the head as a
//! correctable prior; a listing read for a destination nobody proved does not. So:
//! - the page asks a candidate about owen whether it corrects the head when the lender states
//!   this device, and lists no head when it states none;
//! - a correction pack whose listed pin is that head passes the check when the lender states
//!   this device (it then answers that no verdict loan is lent: the lender lends steps only),
//!   and is refused for pins that differ from the engine's rebuilt set when it states none.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_pack_page_destination_bound`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryResult};
use oneiron::registry::{ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD};
use oneiron::settings::ReadDestination;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use step_support::{CapturingStepBackend, step_plain_reply};
use verdict_support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction, extraction_attempt_hex,
    extraction_candidate, extraction_verdict_request, invoke_bound_verdict,
    open_extraction_verdict_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the stored head and the proposed value.
const FOOD: &str = "preference.food";

/// The value of the stored head about owen.
const HEAD_VALUE: &str = "green tea";

/// The value the operand proposes, which may correct the head.
const PROPOSED_VALUE: &str = "black tea";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen likes black tea";

/// The key a TURN body names its world under.
const TURN_BODY_WORLD_REF_KEY: &str = "world_ref";

/// Lands one active, stated food preference about `subject` in `world`: a plain public put on
/// the default facet with Auto approval.
fn land_food_head_in_world(
    vault: &Vault,
    subject: EntityId,
    world: EntityId,
) -> ExtractionVerdictTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(HEAD_VALUE),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope = Some(RmpValue::Map(vec![(
        RmpValue::from("sensitivity"),
        RmpValue::from(0u64),
    )]));
    body.scope_facet = vault.default_facet()?;
    body.world = Some(world);
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

/// Rewrites witnessed `turn`'s body to name `world`, keeping every other key, so the partition
/// planner places the turn's branch in that world.
fn place_turn_in_world(
    vault: &Vault,
    turn: EntityId,
    world: EntityId,
) -> ExtractionVerdictTestResult<()> {
    let raw = vault
        .get(&turn)?
        .ok_or("FIXTURE: the witnessed turn is stored")?;
    let mut body = rmpv::decode::read_value(&mut raw.as_slice())?;
    let RmpValue::Map(entries) = &mut body else {
        return Err("FIXTURE: a TURN body is a map".into());
    };
    entries.retain(|(key, _)| key.as_str() != Some(TURN_BODY_WORLD_REF_KEY));
    entries.push((
        RmpValue::from(TURN_BODY_WORLD_REF_KEY),
        RmpValue::Binary(world.as_bytes().to_vec()),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        TimeRange { start: 10, end: 10 },
        10,
        &bytes,
    )?;
    Ok(())
}

/// One admitted attempt over one turn about owen in a world kept on this machine, with a stated
/// head about owen in that world.
struct KeptWorldHeadFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault each binding binds from.
    vault: Arc<Vault>,
    /// Holds the admission each binding binds from.
    admitted: DreamerAdmittedAttempt,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the stated head about owen in the kept world.
    head: EntityId,
    /// Names the served turn.
    turn: String,
    /// Holds the served turn's pinned version.
    turn_version: Value,
}

/// Seeds owen, stores a world, lands the head about owen in it, witnesses the turn and places
/// it in the world, keeps the world on this machine as its owner does, and admits one attempt.
fn kept_world_head_fixture() -> ExtractionVerdictTestResult<KeptWorldHeadFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let world = EntityId::now();
    vault.put_entity(
        &world,
        ENTITY_TYPE_WORLD,
        TimeRange { start: 1, end: 1 },
        1,
        b"world",
    )?;
    let head = land_food_head_in_world(&vault, subject, world)?;
    let witnessed = witness_extraction_turns(&vault, &[WORDS])?;
    place_turn_in_world(&vault, witnessed.turns[0], world)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = extraction_attempt_hex(attempt);
    let page = read_bound_extraction_page(&bind_extraction(&vault, &admitted)?, &attempt)?;
    let mut turns = page_turns_with_versions(&page);
    assert_eq!(
        turns.len(),
        1,
        "FIXTURE: the inputs page serves the turn in the kept world: {page}"
    );
    let (turn, turn_version) = turns.remove(0);
    Ok(KeptWorldHeadFixture {
        _directory: directory,
        vault,
        admitted,
        attempt,
        subject,
        head,
        turn,
        turn_version,
    })
}

impl KeptWorldHeadFixture {
    /// Binds the attempt with a step lender that states `bound` as its pass's destination bound,
    /// with the backend its steps reach. It lends extraction steps only, never a verdict.
    fn lent(
        &self,
        bound: Option<ReadDestination>,
    ) -> ExtractionVerdictTestResult<(DreamerAttemptBinding, Arc<CapturingStepBackend>)> {
        let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
        let lent = ExtractionStepFixture::new(backend.clone())?;
        lent.set_destination_bound(bound);
        let binding =
            attach_extraction_step_lender(bind_extraction(&self.vault, &self.admitted)?, &lent);
        Ok((binding, backend))
    }

    /// Binds the attempt as [`Self::lent`] does, without the backend.
    fn binding(
        &self,
        bound: Option<ReadDestination>,
    ) -> ExtractionVerdictTestResult<DreamerAttemptBinding> {
        Ok(self.lent(bound)?.0)
    }

    /// Checks the fixture through the lent step, which #9718 proved lists for its lender's
    /// bound: a step whose lender states this device lists owen with the kept world's head.
    fn assert_step_lists_head_for_this_device(&self) -> ExtractionVerdictTestResult<()> {
        let (binding, backend) = self.lent(Some(ReadDestination::on_device()))?;
        // Only the request the step sent matters here: whatever its reply decodes to, the
        // listing it showed is the fixture's.
        let _answer = step_support::invoke_bound_step(
            &binding,
            step_support::extraction_step_request(json!([step_support::extraction_step_evidence(
                &self.turn,
                self.turn_version.clone(),
                None
            )])),
        );
        let texts = backend.request_texts();
        let text = texts
            .first()
            .ok_or("FIXTURE: the lent step asks its model")?;
        assert!(
            text.contains("entity P2 \"owen\"\n")
                && text.contains(&format!("{FOOD} = \"{HEAD_VALUE}\"")),
            "FIXTURE: a step listing for this device shows owen with the kept world's head: {text}"
        );
        Ok(())
    }

    /// The inline operand about owen proposing the corrected value from the served turn.
    fn operand(&self) -> Value {
        extraction_candidate(
            &self.subject.to_hex(),
            FOOD,
            json!(PROPOSED_VALUE),
            &self.turn,
            self.turn_version.clone(),
        )
    }

    /// Reads one observations page for `operand` alone through `binding`.
    fn observe(&self, binding: &DreamerAttemptBinding, operand: Value) -> MemoryResult<Value> {
        binding
            .invoke(
                OBSERVATIONS_PAGE_VERB,
                json!({
                    "attempt": self.attempt,
                    "now_ms": OBSERVATION_NOW_MS,
                    "candidates": [operand],
                }),
                None,
            )
            .map(|answer| answer["value"].clone())
    }

    /// Asks one whole correction verdict through `binding` over the operand, with the head as
    /// the pack's one listed pin and its one question.
    fn ask_correction(
        &self,
        binding: &DreamerAttemptBinding,
    ) -> ExtractionVerdictTestResult<MemoryResult<Value>> {
        let pin = dreamer_extraction_verdict_source_version(&self.vault, self.head)?
            .ok_or("FIXTURE: the Dreamer reads the head")?;
        let head = self.head.to_hex();
        let pack = json!({
            "read": "correction",
            "part": {"kind": "whole"},
            "candidates": [self.operand()],
            "listed": [{"claim": head, "version": serde_json::to_value(pin)?}],
            "priors": [],
            "questions": [{"key": ["0", "0"], "options": ["none", head]}],
            "earlier": [],
        });
        let request = extraction_verdict_request("correction", json!(["none", head]), pack);
        Ok(invoke_bound_verdict(binding, request))
    }
}

/// Checks that `result` is refused with `code` and a message that holds `part`.
fn assert_refused(result: MemoryResult<Value>, code: &str, part: &str, what: &str) {
    let error = match result {
        Ok(answer) => panic!("{what}: the request is refused, yet it answered {answer}"),
        Err(error) => error,
    };
    assert_eq!(error.code, code, "{what}: {error:?}");
    assert!(
        error.message.contains(part),
        "{what}: the refusal holds {part:?}; it was {:?}",
        error.message
    );
}

/// A lender that states this device: the page lists the kept world's head and asks the
/// candidate about it.
#[test]
fn the_page_lists_a_kept_world_head_for_the_bound_its_lender_states()
-> ExtractionVerdictTestResult<()> {
    let fixture = kept_world_head_fixture()?;
    fixture.assert_step_lists_head_for_this_device()?;
    let binding = fixture.binding(Some(ReadDestination::on_device()))?;
    let page = fixture
        .observe(&binding, fixture.operand())
        .expect("the page reads the operand");
    let listed = page["listed"]
        .as_array()
        .expect("the page has a listed rows array");
    let at = listed
        .iter()
        .position(|row| row["claim"] == json!(fixture.head.to_hex()))
        .unwrap_or_else(|| {
            panic!(
                "the page lists the head a kept world holds when its lender states this device, \
                 yet it lists: {page}"
            )
        });
    assert_eq!(
        page["candidates"][0]["correctable"],
        json!([at]),
        "the candidate is asked about the kept world's head: {page}"
    );
    Ok(())
}

/// A lender that states no bound: the page lists for a destination nobody proved, so the kept
/// world's head is listed for no candidate, and an operand that names it as its correction is
/// refused.
#[test]
fn the_page_with_no_stated_bound_lists_no_kept_world_head() -> ExtractionVerdictTestResult<()> {
    let fixture = kept_world_head_fixture()?;
    let binding = fixture.binding(None)?;
    let page = fixture
        .observe(&binding, fixture.operand())
        .expect("the page reads the operand");
    assert_eq!(page["listed"], json!([]), "no head is listed: {page}");
    assert_eq!(page["candidates"][0]["correctable"], json!([]));
    let mut correcting = fixture.operand();
    correcting["corrects"] = json!(fixture.head.to_hex());
    assert_refused(
        fixture.observe(&binding, correcting),
        MEMORY_CODE_BAD_REQUEST,
        "extracted correction names an unlisted claim",
        "a correction of the unlisted head",
    );
    Ok(())
}

/// A lender that states this device: the correction pack whose listed pin is the kept world's
/// head matches the engine's rebuilt set and passes the check; the step lender lends no
/// verdict, so the call then answers model unavailable.
#[test]
fn the_pack_check_accepts_a_kept_world_pin_for_the_bound_its_lender_states()
-> ExtractionVerdictTestResult<()> {
    let fixture = kept_world_head_fixture()?;
    fixture.assert_step_lists_head_for_this_device()?;
    let binding = fixture.binding(Some(ReadDestination::on_device()))?;
    assert_refused(
        fixture.ask_correction(&binding)?,
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "no extraction loan is lent to this attempt",
        "the pack whose pin a listing for this device holds passes the check",
    );
    Ok(())
}

/// A lender that states no bound: the same pack names a pin the engine's rebuilt set, listed
/// for a destination nobody proved, does not hold, so it is refused before any loan.
#[test]
fn the_pack_check_with_no_stated_bound_refuses_a_kept_world_pin() -> ExtractionVerdictTestResult<()>
{
    let fixture = kept_world_head_fixture()?;
    let binding = fixture.binding(None)?;
    assert_refused(
        fixture.ask_correction(&binding)?,
        MEMORY_CODE_BAD_REQUEST,
        "the extraction pack claim pins differ from the engine's rebuilt set",
        "the pack whose pin no listing for an unproved destination holds",
    );
    Ok(())
}
