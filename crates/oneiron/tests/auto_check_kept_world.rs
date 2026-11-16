//! Census L5-32, the LLM gate (DEC-0005:592; Engine RULING
//! L5-32-LLM-GATE-KEPT-WORLD = A, 13 Nov 20:24 JST): the host's auto check
//! never sends a candidate whose world stays on this device to a model off
//! it. For such a candidate the hosted rung is not asked, the check answers
//! Unavailable, and the write fails closed as with a dead checker (DEC-0005
//! fix 6: the world's model order covers every model call on it; the owner's
//! fail-closed ruling L9, 2026-07-13). A rung whose provider runs on this
//! device still checks it, and a base-reality candidate still reaches the
//! hosted rung.
//!
//! Before the fix (the seam alone: the candidate's world, the world hold and
//! `DecisionProvider::runs_on_device`, none of them read), the two kept-world
//! tests fail: the hosted rung reads the kept candidate's value, and the
//! claim door's kept-world claim lands Auto on the hosted checker's word.
//! The gate fixtures go through `oneiron::test_doors::live_run_claim_put`,
//! built only under `--cfg oneiron_test_support` (the oneiron lib test target
//! does not compile).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test auto_check_kept_world`.
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::claim::base_world_id;
use oneiron::claim_check::AutoCheckNotes;
use oneiron::error::GateError;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::llm::{
    AutoCheckCandidate, AutoCheckDecisions, AutoCheckOutcome, AutoCheckSignals, AutoCheckWorldHold,
    BoundedAutoChecker,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::live_run_claim_put as doors;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, Error,
    Result, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const CHECKER_REF: &str = "host-checker-v1";
/// The value of the candidate in base reality.
const BASE_VALUE: &str = "Ada Lovelace";
/// The value of the candidate a kept world holds.
const KEPT_VALUE: &str = "Grace Hopper";
/// The provenance key and value the live-run claim put door stamps on the
/// Auto request it marks, as `tests/live_run_claim_put.rs` writes them.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

fn at() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}

fn gate_rejection_parts(err: Error) -> (&'static str, Vec<&'static str>) {
    match err {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => (outcome, reason_codes),
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// A checker rung that answers every auto check `allow` and records the
/// value preview each consult showed it. `on_device` is what it says of
/// where it computes ([`DecisionProvider::runs_on_device`]).
struct RecordingChecker {
    on_device: bool,
    previews: Mutex<Vec<String>>,
}

impl RecordingChecker {
    /// A model reached off this device, as a hosted seat's is.
    fn hosted() -> Arc<Self> {
        Arc::new(Self {
            on_device: false,
            previews: Mutex::new(Vec::new()),
        })
    }

    /// A model this device computes on.
    fn on_this_device() -> Arc<Self> {
        Arc::new(Self {
            on_device: true,
            previews: Mutex::new(Vec::new()),
        })
    }

    fn previews(&self) -> Vec<String> {
        self.previews.lock().expect("checker log").clone()
    }
}

impl DecisionProvider for RecordingChecker {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn runs_on_device(&self) -> bool {
        self.on_device
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let preview = call.state["value_preview"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        self.previews.lock().expect("checker log").push(preview);
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice("allow".to_owned()),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// No hold reasons: every rung here allows.
struct NoNotes;

impl AutoCheckNotes for NoNotes {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// A world hold that keeps one world on this device and records each world
/// it was asked about.
struct RecordingWorldHold {
    kept: EntityId,
    asked: Mutex<Vec<EntityId>>,
}

impl RecordingWorldHold {
    fn keeping(kept: EntityId) -> Arc<Self> {
        Arc::new(Self {
            kept,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<EntityId> {
        self.asked.lock().expect("hold log").clone()
    }
}

impl AutoCheckWorldHold for RecordingWorldHold {
    fn keeps_on_device(&self, world: EntityId) -> Result<bool> {
        self.asked.lock().expect("hold log").push(world);
        Ok(world == self.kept)
    }
}

/// The host's bounded checker as `decision_host` assembles it: `rung` on the
/// Big rung, the dial at Big, and `world_hold` judging each candidate's world.
fn bounded(
    rung: Arc<RecordingChecker>,
    world_hold: Arc<dyn AutoCheckWorldHold>,
) -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(rung as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        principal: test_id(0x51),
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write land without the owner's review?".to_owned(),
        notes: Arc::new(NoNotes),
        calibrated: None,
        world_hold: Some(world_hold),
    })
}

/// An agent's Generated `profile.name` candidate in `world`.
fn candidate(value_preview: &str, world: EntityId) -> AutoCheckCandidate<'_> {
    AutoCheckCandidate {
        predicate: "profile.name",
        value_preview,
        source: ClaimSource::Generated,
        lineage: None,
        actor_class: "agent",
        sensitivity_band: Some(0),
        burst: None,
        signals: AutoCheckSignals::default(),
        world,
    }
}

/// A device vault with one WORLD row its owner keeps on this machine.
fn kept_world_vault() -> Result<(tempfile::TempDir, Arc<Vault>, EntityId)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let world = test_id(0x90);
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at(), 1, b"world")?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    Ok((dir, Arc::new(vault), world))
}

/// A caller's live-run claim put asking Auto (FIX 3983), as
/// `tests/live_run_claim_put.rs` builds it: the agent the checker manifest
/// ceilings at Auto, a Generated source and the door's marker. The actor and
/// the claim's subject are seeded as PERSON rows.
fn live_run_put_envelope(vault: &Vault, body: &ClaimBody) -> Result<WriteEnvelope> {
    vault.put_entity(
        &doors::first_party_connector_actor_id(),
        ENTITY_TYPE_PERSON,
        at(),
        1,
        b"dreamer actor",
    )?;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, at(), 1, b"dreamer subject")?;
    }
    Ok(WriteEnvelope::new(
        WriteActor::new(
            doors::first_party_connector_actor_id(),
            EdgeActorClass::Agent,
        ),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("self.*")),
            (
                Value::from(CHECKED_PRODUCER_PROVENANCE_KEY),
                Value::from(LIVE_RUN_CLAIM_PUT_PRODUCER),
            ),
        ]))?,
        ClaimApprovalStatus::Auto,
    ))
}

/// A hosted rung is never asked about a candidate whose world stays on this
/// device: the check answers Unavailable, so the write fails closed. A verdict
/// the hosted rung gave on the same content in base reality does not answer
/// the kept candidate, and a world this vault cannot place keeps the check on
/// this device too.
#[test]
fn a_hosted_checker_never_reads_a_kept_world_candidate() -> Result<()> {
    let (_dir, vault, world) = kept_world_vault()?;
    assert!(
        vault.keeps_on_device(world)?,
        "the world settings keep the world on this device"
    );
    assert!(
        !vault.keeps_on_device(base_world_id())?,
        "base reality may go to a model off this device"
    );
    let hosted = RecordingChecker::hosted();
    let checker = bounded(
        Arc::clone(&hosted),
        Arc::clone(&vault) as Arc<dyn AutoCheckWorldHold>,
    );

    assert_eq!(
        checker.check(&candidate(BASE_VALUE, base_world_id())),
        AutoCheckOutcome::Allow,
        "a base-reality candidate reaches the hosted checker"
    );
    assert_eq!(hosted.previews(), [BASE_VALUE]);

    let outcome = checker.check(&candidate(KEPT_VALUE, world));
    assert_eq!(
        hosted.previews(),
        [BASE_VALUE],
        "a candidate a kept world holds reached a checker off this device"
    );
    assert_eq!(
        outcome,
        AutoCheckOutcome::Unavailable,
        "with only a hosted checker a kept candidate fails closed"
    );

    assert_eq!(
        checker.check(&candidate(BASE_VALUE, world)),
        AutoCheckOutcome::Unavailable,
        "the hosted verdict on the same content in base reality answered a kept candidate"
    );
    assert_eq!(
        checker.check(&candidate(KEPT_VALUE, test_id(0x9e))),
        AutoCheckOutcome::Unavailable,
        "a world this vault cannot place keeps the check on this device"
    );
    assert_eq!(hosted.previews(), [BASE_VALUE]);
    Ok(())
}

/// A rung whose provider runs on this device still checks a kept candidate,
/// as every rung does today.
#[test]
fn an_on_device_checker_still_checks_a_kept_world_candidate() -> Result<()> {
    let (_dir, vault, world) = kept_world_vault()?;
    let on_device = RecordingChecker::on_this_device();
    let checker = bounded(Arc::clone(&on_device), vault as Arc<dyn AutoCheckWorldHold>);

    assert_eq!(
        checker.check(&candidate(KEPT_VALUE, world)),
        AutoCheckOutcome::Allow,
        "an on-device checker answers for a kept candidate"
    );
    assert_eq!(on_device.previews(), [KEPT_VALUE]);
    Ok(())
}

/// The claim write door names the claim's world to the checker. An agent's
/// Auto claim in a kept world, with only a hosted checker, is held
/// checker-unavailable (the live-run door then resubmits it Proposed), and
/// the hosted checker never reads it.
#[test]
fn the_claim_door_keeps_a_kept_world_claim_from_a_hosted_checker() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let world = test_id(0x90);
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at(), 1, b"world")?;
    let mut body = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    body.world = Some(world);
    let envelope = live_run_put_envelope(&vault, &body)?;
    let hold = RecordingWorldHold::keeping(world);
    let hosted = RecordingChecker::hosted();
    let checker = bounded(
        Arc::clone(&hosted),
        Arc::clone(&hold) as Arc<dyn AutoCheckWorldHold>,
    );

    let result = doors::gate_claim_write(
        &vault,
        &test_id(0x3d),
        &body,
        &envelope,
        Some(&checker),
        false,
    );
    assert_eq!(
        hosted.previews(),
        Vec::<String>::new(),
        "an agent's claim in a kept world reached a checker off this device"
    );
    let (outcome, reason_codes) = gate_rejection_parts(
        result.expect_err("a kept-world claim with only a hosted checker landed Auto"),
    );
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker.unavailable"]);
    assert_eq!(
        hold.asked(),
        [world],
        "the door names the claim's world to the checker"
    );
    Ok(())
}

/// A base-reality claim through the same door still reaches the hosted
/// checker, and its allow lets the write land.
#[test]
fn the_claim_door_still_sends_a_base_reality_claim_to_the_hosted_checker() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let kept = test_id(0x90);
    vault.put_entity(&kept, ENTITY_TYPE_WORLD, at(), 1, b"world")?;
    let body = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    assert_eq!(body.world, None, "the fixture claim is in base reality");
    let envelope = live_run_put_envelope(&vault, &body)?;
    let hosted = RecordingChecker::hosted();
    let checker = bounded(
        Arc::clone(&hosted),
        RecordingWorldHold::keeping(kept) as Arc<dyn AutoCheckWorldHold>,
    );

    doors::gate_claim_write(
        &vault,
        &test_id(0x3e),
        &body,
        &envelope,
        Some(&checker),
        false,
    )?;
    assert_eq!(
        hosted.previews(),
        [BASE_VALUE],
        "a base-reality claim reaches the hosted checker"
    );
    Ok(())
}
