//! AUTO-SIGNALS-RECENT-WRITES-COUNTS-TRAY-CLOSE-RECEIPTS: the auto checker's
//! `recent_writes` signal counts the actor's writes, the gate's own decisions
//! on them, and not the receipt that answers one of them later.
//!
//! An agent's held write A parks in the tray. Its Auto writes B, C and D each
//! reach the host's checker, which records the signals it is shown and holds
//! them. Between C and D the tray lets A go, which writes A's `let_go`
//! receipt in the agent's name. D's count must grow from C's by exactly what
//! C's grew from B's (C's own receipts), so the let-go is no write.
//!
//! HELD-QUESTION-RESTATE-COUNTS-AS-AGENT-WRITE ([`restated_question`]): an
//! engine change to a held claim restates the owner's question with a fresh
//! pending receipt in the writer's name, which is no write by that writer
//! either.
//!
//! The gate fixtures go through `oneiron::test_doors::live_run_claim_put`, as
//! tests/live_run_claim_put.rs does. Built only under
//! `--cfg oneiron_test_support`.
//!
//! Red on main: D sees one write more than the step (A's let-go receipt).
//! Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test auto_signals_recent_writes`
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::claim_check::AutoCheckNotes;
use oneiron::error::GateError;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::llm::{AutoCheckCandidate, AutoCheckDecisions, BoundedAutoChecker};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::live_run_claim_put as doors;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, Error,
    Result, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;
use serde_json::Value as JsonValue;

const CHECKER_REF: &str = "host-checker-v1";
/// A host names its hold reasons in prose.
const HOLD_REASON: &str = "checker: hedged verdict";
/// The provenance key and value the live-run claim put door stamps on the
/// request it marks (`gate::CHECKED_PRODUCER_PROVENANCE_KEY` and
/// `gate::LIVE_RUN_CLAIM_PUT_PRODUCER`), as the wire carries them.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

/// The host's decision head on the checker's Big rung: it answers every auto
/// check `hold`, and records the state of every call it is shown.
struct SignalRecordingChecker {
    states: Mutex<Vec<JsonValue>>,
}

impl SignalRecordingChecker {
    fn hold() -> Self {
        Self {
            states: Mutex::new(Vec::new()),
        }
    }

    fn states(&self) -> Vec<JsonValue> {
        self.states.lock().expect("checker log").clone()
    }
}

impl DecisionProvider for SignalRecordingChecker {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.states
            .lock()
            .expect("checker log")
            .push(call.state.clone());
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice("hold".to_owned()),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The host's hold reasons: one, in prose.
struct HoldReasons;

impl AutoCheckNotes for HoldReasons {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        Ok(vec![HOLD_REASON.to_owned()])
    }
}

/// The host's bounded checker over `head`, assembled as a host assembles it:
/// a decision ladder whose Big rung is the host's head, its dial at Big, and
/// no world kept on the device, so every rung reads the candidate.
fn bounded(head: Arc<SignalRecordingChecker>) -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(head as Arc<dyn DecisionProvider>),
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
        notes: Arc::new(HoldReasons),
        calibrated: None,
        world_hold: None,
    })
}

/// Seeds the actor and the claim's subject as PERSON rows, as the Dreamer
/// fixture does.
fn seed_dreamer_parts(vault: &Vault, body: &ClaimBody) -> Result<()> {
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(
        &doors::first_party_connector_actor_id(),
        ENTITY_TYPE_PERSON,
        at,
        1,
        b"dreamer actor",
    )?;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, at, 1, b"dreamer subject")?;
    }
    Ok(())
}

/// A caller's live-run claim put, marked by the door (FIX 3983): the agent
/// the checker manifest ceilings at Auto, a Generated source, the door's
/// provenance.
fn live_run_put_envelope(
    vault: &Vault,
    body: &ClaimBody,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    seed_dreamer_parts(vault, body)?;
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
        approval,
    ))
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

/// The `recent_writes` signal in a checker call's state, wherever the
/// ladder places the candidate's state.
fn recent_writes_in(state: &JsonValue) -> Option<u64> {
    signal_in(state, "recent_writes")
}

/// The signal `key` in a checker call's state, wherever the ladder places
/// the candidate's state.
fn signal_in(state: &JsonValue, key: &str) -> Option<u64> {
    match state {
        JsonValue::Object(map) => map
            .get(key)
            .and_then(JsonValue::as_u64)
            .or_else(|| map.values().find_map(|value| signal_in(value, key))),
        JsonValue::Array(items) => items.iter().find_map(|item| signal_in(item, key)),
        _ => None,
    }
}

/// The agent's Auto live-run put of `body` as `id`, which the checker holds.
/// Returns the `recent_writes` the checker was shown for it.
fn held_auto_put(
    vault: &Vault,
    checker: &BoundedAutoChecker,
    head: &SignalRecordingChecker,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<u64> {
    let envelope = live_run_put_envelope(vault, body, ClaimApprovalStatus::Auto)?;
    let calls_before = head.states().len();
    let result = doors::gate_claim_write(vault, id, body, &envelope, Some(checker), true);
    let states = head.states();
    assert_eq!(
        states.len(),
        calls_before + 1,
        "the checker is consulted once ({result:?})"
    );
    let (outcome, reason_codes) = gate_rejection_parts(result.expect_err("the checker holds it"));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker"]);
    let state = states.last().expect("the call's state");
    Ok(recent_writes_in(state)
        .unwrap_or_else(|| panic!("the checker is shown recent_writes: {state}")))
}

#[test]
fn an_answer_to_a_held_write_is_not_counted_as_a_recent_write() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let head = Arc::new(SignalRecordingChecker::hold());
    let checker = bounded(head.clone());

    // A: the agent's Proposed live-run put, held checker-unavailable (no
    // checker is lent), parks with its pending review.
    let parked = test_id(0x70);
    let proposed = doors::checker_body(&vault, ClaimApprovalStatus::Proposed)?;
    let resubmitted = live_run_put_envelope(&vault, &proposed, ClaimApprovalStatus::Proposed)?;
    let held = doors::gate_claim_write(&vault, &parked, &proposed, &resubmitted, None, true);
    assert!(
        vault
            .pending_gate_consents(64)?
            .iter()
            .any(|record| record.claim_id == *parked.as_bytes()),
        "the held Proposed put parks a pending review ({held:?})"
    );

    // B, C: the agent's Auto puts, each held by the checker.
    let auto = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let seen_b = held_auto_put(&vault, &checker, &head, &test_id(0x71), &auto)?;
    assert!(seen_b >= 1, "A's held write counts for B ({seen_b})");
    let seen_c = held_auto_put(&vault, &checker, &head, &test_id(0x72), &auto)?;
    let step = seen_c
        .checked_sub(seen_b)
        .expect("the count never falls between two writes");
    assert!(
        step >= 1,
        "B's held write counts for C ({seen_b} -> {seen_c})"
    );

    // The tray lets A go: its let_go receipt answers A in the agent's name.
    let let_go = vault
        .let_go_pending_ask(&parked)?
        .expect("the let-go answers A's pending review");
    assert_eq!(let_go.outcome, "let_go");

    // D: one more Auto put. Since C, only C itself was written.
    let seen_d = held_auto_put(&vault, &checker, &head, &test_id(0x73), &auto)?;
    assert_eq!(
        seen_d,
        seen_c + step,
        "FAILBEFORE AUTO-SIGNALS-RECENT-WRITES-COUNTS-TRAY-CLOSE-RECEIPTS: the let-go answer to A counted as a write ({seen_b} -> {seen_c} -> {seen_d})"
    );
    Ok(())
}

/// HELD-QUESTION-RESTATE-COUNTS-AS-AGENT-WRITE: an engine change to a held
/// claim asks the owner's open question again with a fresh pending receipt
/// in the asked writer's name (`claim::held_question`). The writer wrote
/// nothing, so neither signal the checker reads grows by it.
///
/// An agent's live-run put A is held by the checker and lands Proposed with
/// the checker's review; its puts B and C are held the same way. The engine
/// then decays A, which restates A's question on the decayed body. D's
/// `recent_writes` and `failure_streak` must each grow from C's by exactly
/// what C's grew from B's (C's own receipts).
///
/// The live-run fixture is tests/live_run_claim_put.rs's `lent_checker` one:
/// a person-backed agent the policy ceilings at Auto, with its read
/// credential minted under the vault's host root.
///
/// Red on main: D sees one write more than the step (A's restated receipt).
/// Green on the head.
#[cfg(feature = "test-support")]
mod restated_question {
    use super::{CHECKER_REF, SignalRecordingChecker, bounded, doors, signal_in};
    use oneiron::authority::HostSlipIssuer;
    use oneiron::claim::ScopedReadActorKey;
    use oneiron::code_run::SelfMemoryPutClaimCall;
    use oneiron::llm::BoundedAutoChecker;
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::test_support::put_policy_manifest_bytes;
    use oneiron::write_envelope::claim_body::ClaimDemotionAction;
    use oneiron::{
        ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault,
        VaultConfig, WriteActor,
    };
    use rmpv::Value;
    use std::sync::Arc;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// The checker's hold reason the gate parks a held put's review with.
    const CHECKER_HOLD: &str = "gate.pending.checker";

    /// Maps any error into the test's error with the step that failed.
    fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
        move |error| format!("{step}: {error:?}").into()
    }

    const fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    /// The two signals a checker call was shown.
    #[derive(Debug, Clone, Copy)]
    struct Signals {
        recent_writes: u64,
        failure_streak: u64,
    }

    /// A vault whose shipped policy manifest is replaced at its own id by
    /// [`checked_agent_policy`] for `agent`, a person-backed agent, and that
    /// agent's read credential.
    struct Fixture {
        vault: Vault,
        agent: EntityId,
        reader: ScopedReadActorKey,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn open() -> TestResult<Self> {
            let dir = tempfile::tempdir()?;
            let mut config = VaultConfig::device();
            config.dimensions = 4;
            config.embedding_model = None;
            let vault = Vault::open_owned(dir.path(), config).map_err(at("open owned"))?;
            let agent = person(&vault)?;
            let shipped = oneiron_store::policy_record::default_policy_manifest_id()
                .map_err(at("the shipped manifest's id"))?;
            let policy = checked_agent_policy(agent)?;
            put_policy_manifest_bytes(&vault, shipped, &policy)
                .map_err(at("install the policy"))?;
            let reader = agent_reader(&vault, agent)?;
            Ok(Self {
                vault,
                agent,
                reader,
                _dir: dir,
            })
        }

        /// The decision and the reason codes of the pending review the gate
        /// parked for `id`.
        fn review(&self, id: EntityId) -> TestResult<(String, Vec<String>)> {
            let review = self
                .vault
                .pending_gate_consents(64)
                .map_err(at("read the pending reviews"))?
                .into_iter()
                .find(|record| record.claim_id == *id.as_bytes())
                .ok_or("the claim has no pending review")?;
            Ok((review.decision_id.to_hex(), review.reason_codes))
        }

        /// The agent's run `run`, lent `checker`, puts `value` about a fresh
        /// PERSON at a fresh id. The checker holds it, so it lands Proposed
        /// with the checker's review. Returns the id and the signals the
        /// checker was shown for the put.
        fn held_put(
            &self,
            checker: &BoundedAutoChecker,
            head: &SignalRecordingChecker,
            run: &str,
            value: &str,
        ) -> TestResult<(EntityId, Signals)> {
            let dispatcher = doors::live_run_dispatcher(
                &self.vault,
                WriteActor::new(self.agent, EdgeActorClass::Agent),
                run,
                checker,
            )
            .map_err(at("the live run's dispatcher"))?;
            let id = EntityId::now();
            let call = claim_call(id, person(&self.vault)?, value);
            let calls_before = head.states().len();
            doors::put_claim_as_live_run(&dispatcher, call, Some(&self.reader))
                .map_err(at("the live run's claim put"))?;
            let states = head.states();
            let state = states
                .get(calls_before)
                .ok_or("the lent checker is consulted on the put")?;
            let shown = Signals {
                recent_writes: signal_in(state, "recent_writes")
                    .ok_or_else(|| format!("the checker is shown recent_writes: {state}"))?,
                failure_streak: signal_in(state, "failure_streak")
                    .ok_or_else(|| format!("the checker is shown failure_streak: {state}"))?,
            };
            let (_, reasons) = self.review(id)?;
            assert_eq!(
                reasons,
                vec![CHECKER_HOLD.to_owned()],
                "the checker's hold parks the put with its review"
            );
            Ok((id, shown))
        }
    }

    /// A fresh PERSON.
    fn person(vault: &Vault) -> TestResult<EntityId> {
        let id = EntityId::now();
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .map_err(at("put a PERSON"))?;
        Ok(id)
    }

    /// `holder`'s agent read credential over the whole vault, minted under
    /// the vault's host root as a host mints its caller's.
    fn agent_reader(vault: &Vault, holder: EntityId) -> TestResult<ScopedReadActorKey> {
        let tag = b"auto-signals restated question";
        let issuer = HostSlipIssuer::from_secret(tag).map_err(at("host issuer"))?;
        let mut claims = vault
            .ensure_host_root_slip(&issuer)
            .map_err(at("host root slip"))?
            .claims;
        let mut slip_id = [0u8; 32];
        slip_id[..16].copy_from_slice(holder.as_bytes());
        claims.slip_id = slip_id;
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.actor_class = Some("agent".into());
        let slip = vault
            .mint_capability_slip(&issuer, claims)
            .map_err(at("agent slip"))?;
        let binding = issuer
            .binding_proof(&slip, tag)
            .map_err(at("holder binding"))?;
        let proof = vault
            .verify_capability_slip(&issuer.public_key(), &slip, tag, &binding)
            .map_err(at("verified agent slip"))?;
        ScopedReadActorKey::from_verified_slip(&proof)
            .ok_or_else(|| "the agent slip carries no read credential".into())
    }

    /// The run's `vault.claims.put` of `profile.favorite_drink` with `value`
    /// about `subject`, at `id`.
    fn claim_call(id: EntityId, subject: EntityId, value: &str) -> SelfMemoryPutClaimCall {
        SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.8,
            ),
            range(10),
            11,
        )
    }

    /// tests/live_run_claim_put.rs's checked-agent policy: Generated claims
    /// land at Auto, `agent` is ceilinged at Auto, the host checker is named,
    /// and every predicate is of the normal class.
    fn checked_agent_policy(agent: EntityId) -> TestResult<Vec<u8>> {
        let axes = Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ]);
        let manifest = Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
            ),
            (Value::from("pack_id"), Value::from("auto-signals-restated")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (Value::from("defaults"), axes),
            (Value::from("rules"), Value::Array(Vec::new())),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("actor_ref"), Value::from(agent.to_hex())),
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
            (Value::from("auto_checker"), Value::from(CHECKER_REF)),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)?;
        Ok(data)
    }

    #[test]
    fn a_restated_held_question_is_not_counted_as_a_write() -> TestResult {
        let f = Fixture::open()?;
        let head = Arc::new(SignalRecordingChecker::hold());
        let checker = bounded(head.clone());

        // A: held by the checker, it lands Proposed with the checker's review.
        let (parked, _) = f.held_put(&checker, &head, "run-restated-a", "sencha")?;
        let (asked, _) = f.review(parked)?;

        // B, C: held the same way.
        let (_, seen_b) = f.held_put(&checker, &head, "run-restated-b", "matcha")?;
        let (_, seen_c) = f.held_put(&checker, &head, "run-restated-c", "hojicha")?;
        let writes_step = seen_c
            .recent_writes
            .checked_sub(seen_b.recent_writes)
            .ok_or("the count never falls between two writes")?;
        let streak_step = seen_c
            .failure_streak
            .checked_sub(seen_b.failure_streak)
            .ok_or("the streak never falls between two holds")?;
        assert!(
            writes_step >= 1 && streak_step >= 1,
            "B's held write counts and steps the streak for C ({seen_b:?} -> {seen_c:?})"
        );

        // The engine decays A, which restates A's question on the decayed
        // body: a fresh pending receipt with the checker's reasons.
        let later = f.vault.now_recorded_at() + 1;
        f.vault
            .apply_claim_demotion(
                &parked,
                ClaimDemotionAction::Decay {
                    new_claim_of_weight: 0.5,
                },
                later,
            )
            .map_err(at("the engine decays A"))?;
        let (restated, reasons) = f.review(parked)?;
        assert_ne!(
            restated, asked,
            "FIXTURE: the decay restates A's question with a fresh receipt"
        );
        assert_eq!(
            reasons,
            vec![CHECKER_HOLD.to_owned()],
            "the restated question keeps the checker's reasons"
        );

        // D: since C, only C itself was written.
        let (_, seen_d) = f.held_put(&checker, &head, "run-restated-d", "genmaicha")?;
        assert_eq!(
            seen_d.recent_writes,
            seen_c.recent_writes + writes_step,
            "FAILBEFORE HELD-QUESTION-RESTATE-COUNTS-AS-AGENT-WRITE: A's restated question counted as a write ({seen_b:?} -> {seen_c:?} -> {seen_d:?})"
        );
        assert_eq!(
            seen_d.failure_streak,
            seen_c.failure_streak + streak_step,
            "FAILBEFORE HELD-QUESTION-RESTATE-COUNTS-AS-AGENT-WRITE: A's restated question stepped the streak ({seen_b:?} -> {seen_c:?} -> {seen_d:?})"
        );
        Ok(())
    }
}
