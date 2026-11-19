//! Review 6881 P1 (#6881, FIX 3983): a caller's live-run claim put asking
//! Auto reaches the host's auto checker as a Dreamer write does. Moved from
//! `gate/tests/auto_checker.rs` (the oneiron lib test target does not
//! compile); the gate fixtures go through
//! `oneiron::test_doors::live_run_claim_put`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

const CHECKER_REF: &str = "host-checker-v1";
/// A host names its hold reasons in prose.
const HOLD_REASON: &str = "checker: hedged verdict";
/// The provenance key and value the live-run claim put door stamps on the
/// Auto request it marks (`gate::CHECKED_PRODUCER_PROVENANCE_KEY` and
/// `gate::LIVE_RUN_CLAIM_PUT_PRODUCER`), as the wire carries them, so this
/// file also builds on main for the red run.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
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

/// The host's decision head on the checker's Big rung: it answers its first
/// auto check with `answer` and every later one with `later`, and counts
/// each consult.
struct RecordingAutoChecker {
    answer: &'static str,
    later: &'static str,
    calls: AtomicUsize,
}

impl RecordingAutoChecker {
    fn hold() -> Self {
        Self {
            answer: "hold",
            later: "hold",
            calls: AtomicUsize::new(0),
        }
    }

    fn allow() -> Self {
        Self {
            answer: "allow",
            later: "allow",
            calls: AtomicUsize::new(0),
        }
    }

    /// Holds its first consult and allows every later one, as a checker
    /// does whose next request the first hold changed (the failure streak
    /// it raised).
    fn hold_then_allow() -> Self {
        Self {
            answer: "hold",
            later: "allow",
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl DecisionProvider for RecordingAutoChecker {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let answer = if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
            self.answer
        } else {
            self.later
        };
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice(answer.to_owned()),
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

/// The host's bounded checker over `head`, assembled as a host assembles it
/// (`oneiron-server` `decision_host`): a decision ladder whose Big rung is the
/// host's head, its dial at Big.
fn bounded(head: Arc<RecordingAutoChecker>) -> BoundedAutoChecker {
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

/// Seeds the rows the Dreamer fixture's `dreamer_parts` seeds, the actor and
/// the claim's subject, as PERSON rows.
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

/// A caller's live-run claim put (FIX 3983) as the gate sees it: the agent the checker manifest ceilings at
/// Auto, a Generated source, and the door's provenance, with or without the marker its Auto request carries.
fn live_run_put_envelope(
    vault: &Vault,
    body: &ClaimBody,
    marked: bool,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    // The Dreamer fixture seeds the actor and the subject; the envelope below replaces its provenance.
    seed_dreamer_parts(vault, body)?;
    let mut provenance = vec![(Value::from("surface"), Value::from("self.*"))];
    if marked {
        provenance.push((
            Value::from(CHECKED_PRODUCER_PROVENANCE_KEY),
            Value::from(LIVE_RUN_CLAIM_PUT_PRODUCER),
        ));
    }
    Ok(WriteEnvelope::new(
        WriteActor::new(
            doors::first_party_connector_actor_id(),
            EdgeActorClass::Agent,
        ),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(provenance))?,
        approval,
    ))
}

/// Review 6881 P1: a caller's live-run claim put asking Auto is a Generated producer the host's auto checker
/// reviews, as it reviews a Dreamer write. With a checker named and none injected the write is held
/// checker-unavailable (the door then resubmits it Proposed), and a checker that holds parks it. The same agent
/// write without the door's marker is not consulted: the checker's scope widens by this one producer only.
#[test]
fn a_live_run_claim_put_asking_auto_reaches_the_checker() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let body = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let marked = live_run_put_envelope(&vault, &body, true, ClaimApprovalStatus::Auto)?;

    let result = doors::gate_claim_write(&vault, &test_id(0x3d), &body, &marked, None, false);
    let (outcome, reason_codes) =
        gate_rejection_parts(result.expect_err(
            "FAILBEFORE 6881 P1: the live-run put landed Auto with no checker consulted",
        ));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker.unavailable"]);

    let holding = Arc::new(RecordingAutoChecker::hold());
    let bounded_holding = bounded(holding.clone());
    let result = doors::gate_claim_write(
        &vault,
        &test_id(0x3e),
        &body,
        &marked,
        Some(&bounded_holding),
        false,
    );
    assert_eq!(holding.calls(), 1, "the checker is consulted once");
    let (outcome, reason_codes) = gate_rejection_parts(result.expect_err("the checker holds it"));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker"]);

    let unmarked = live_run_put_envelope(&vault, &body, false, ClaimApprovalStatus::Auto)?;
    let untouched = Arc::new(RecordingAutoChecker::hold());
    let bounded_untouched = bounded(untouched.clone());
    doors::gate_claim_write(
        &vault,
        &test_id(0x3f),
        &body,
        &unmarked,
        Some(&bounded_untouched),
        false,
    )?;
    assert_eq!(
        untouched.calls(),
        0,
        "an unmarked agent write is not consulted"
    );
    Ok(())
}

/// Review 6908 P1: the door resubmits a held Auto request Proposed, with the same marker. With the checker still
/// unavailable, the resubmission pends at Proposed and parks with a pending review the owner rules on, instead of
/// landing Proposed with no review. Code mode's Proposed put carries no marker and is not consulted.
#[test]
fn a_held_live_run_put_resubmitted_proposed_parks_with_a_pending_review() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let body = doors::checker_body(&vault, ClaimApprovalStatus::Proposed)?;
    let resubmitted = live_run_put_envelope(&vault, &body, true, ClaimApprovalStatus::Proposed)?;
    let held = test_id(0x40);

    let result = doors::gate_claim_write(&vault, &held, &body, &resubmitted, None, true);
    let reviews: Vec<_> = vault
        .pending_gate_consents(64)?
        .into_iter()
        .filter(|record| record.claim_id == *held.as_bytes())
        .collect();
    assert_eq!(
        reviews.len(),
        1,
        "FAILBEFORE 6908 P1: the held resubmission parks with no pending review ({result:?})"
    );
    assert_eq!(
        reviews[0].reason_codes,
        vec!["gate.pending.checker.unavailable"]
    );

    let code_mode = live_run_put_envelope(&vault, &body, false, ClaimApprovalStatus::Proposed)?;
    let untouched = Arc::new(RecordingAutoChecker::hold());
    let bounded_untouched = bounded(untouched.clone());
    let plain = test_id(0x41);
    doors::gate_claim_write(
        &vault,
        &plain,
        &body,
        &code_mode,
        Some(&bounded_untouched),
        true,
    )?;
    assert_eq!(
        untouched.calls(),
        0,
        "a code-mode Proposed put is not consulted"
    );
    assert!(
        vault
            .pending_gate_consents(64)?
            .iter()
            .all(|record| record.claim_id != *plain.as_bytes()),
        "a code-mode Proposed put parks no review"
    );
    Ok(())
}

/// FIX LIVE-RUN-CHECKER-INJECT (UNBUILT3-11, review 6881 P1): the live-run
/// door lends its run the host's auto checker, as the Dreamer's writes are
/// lent it, so a live-run claim put in a vault that names a checker gets the
/// checker's verdict instead of a checker-unavailable hold.
///
/// The run is an agent's (the gate reviews only an agent's or the system's
/// live-run put), on a vault whose policy ceilings that agent at Auto,
/// permits Generated claims Auto (as tests/run_revert_unsettled.rs's policy
/// does for the owner) and names the checker. The run is built as the
/// live-run door builds it (`test_doors::live_run_claim_put::live_run_dispatcher`)
/// and puts as `put_claim_from_host` asks (`put_claim_as_live_run`); its
/// subject resolves under the agent's read credential over the whole vault,
/// minted as tests/it/code_consent.rs mints it.
///
/// Red on main: the door lends no checker, so the Auto ask pends
/// `gate.pending.checker.unavailable`, the put parks Proposed with that
/// review, and the checker is never asked. Green on the head.
///
/// `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test live_run_claim_put`
#[cfg(feature = "test-support")]
mod lent_checker {
    use super::{RecordingAutoChecker, bounded, doors};
    use oneiron::authority::HostSlipIssuer;
    use oneiron::claim::ScopedReadActorKey;
    use oneiron::code_run::SelfMemoryPutClaimCall;
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::test_support::put_policy_manifest_bytes;
    use oneiron::{
        ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault,
        VaultConfig, WriteActor,
    };
    use rmpv::Value;
    use std::sync::Arc;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// Maps any error into the test's error with the step that failed.
    fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
        move |error| format!("{step}: {error:?}").into()
    }

    const fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
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
            put_policy_manifest_bytes(&vault, shipped, &checked_agent_policy(agent)?)
                .map_err(at("install the policy"))?;
            let reader = agent_reader(&vault, agent)?;
            Ok(Self {
                vault,
                agent,
                reader,
                _dir: dir,
            })
        }

        /// The claim's approval as stored.
        fn approval(&self, id: EntityId) -> TestResult<String> {
            let body = self
                .vault
                .get_claim(&id)
                .map_err(at("read the claim"))?
                .ok_or("the claim reads nothing")?;
            Ok(body.approval.as_str().to_owned())
        }

        /// The reason codes of each pending review the gate parked for `id`.
        fn reviews(&self, id: EntityId) -> TestResult<Vec<Vec<String>>> {
            Ok(self
                .vault
                .pending_gate_consents(64)
                .map_err(at("read the pending reviews"))?
                .into_iter()
                .filter(|record| record.claim_id == *id.as_bytes())
                .map(|record| record.reason_codes)
                .collect())
        }

        /// The agent's run `run`, as the live-run door builds it, lent
        /// `checker`, puts `value` about a fresh PERSON at a fresh id.
        fn put(
            &self,
            checker: &oneiron::llm::BoundedAutoChecker,
            run: &str,
            value: &str,
        ) -> TestResult<EntityId> {
            let (id, put) = self.put_predicate(checker, run, PREDICATE, value)?;
            put.map_err(at("the live run's claim put"))?;
            Ok(id)
        }

        /// As [`Self::put`], of `predicate`: the claim's id and the put's
        /// own answer.
        fn put_predicate(
            &self,
            checker: &oneiron::llm::BoundedAutoChecker,
            run: &str,
            predicate: &str,
            value: &str,
        ) -> TestResult<(
            EntityId,
            oneiron::Result<oneiron::code_run::SelfDispatchOutcome>,
        )> {
            let dispatcher = doors::live_run_dispatcher(
                &self.vault,
                WriteActor::new(self.agent, EdgeActorClass::Agent),
                run,
                checker,
            )
            .map_err(at("the live run's dispatcher"))?;
            let id = EntityId::now();
            let call = claim_call(id, predicate, person(&self.vault)?, value);
            Ok((
                id,
                doors::put_claim_as_live_run(&dispatcher, call, Some(&self.reader)),
            ))
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
        let tag = b"live-run checker loan";
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

    /// The predicate every put but the credential one asks.
    const PREDICATE: &str = "profile.favorite_drink";

    /// A GitHub personal token the write door's provider rule places
    /// (`ghp_` and 36 token characters, lowercase letters and digits, so it
    /// is also a valid predicate segment), spelled in parts so no scanner of
    /// this source reads a token.
    fn provider_token() -> String {
        ["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }

    /// The run's `vault.claims.put` of `predicate` with `value` about
    /// `subject`, at `id`.
    fn claim_call(
        id: EntityId,
        predicate: &str,
        subject: EntityId,
        value: &str,
    ) -> SelfMemoryPutClaimCall {
        SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                predicate,
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.8,
            ),
            range(10),
            11,
        )
    }

    /// tests/run_revert_unsettled.rs's policy, which lands Generated claims at
    /// Auto, with its actor ceiling for `agent` and the host checker named.
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
            (Value::from("pack_id"), Value::from("live-run-checker-loan")),
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
            (Value::from("auto_checker"), Value::from(super::CHECKER_REF)),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)?;
        Ok(data)
    }

    /// A checker that allows the put lands it Auto after one consult: the
    /// gate asks the lent checker, and the landing reuses that verdict
    /// rather than ask again.
    #[test]
    fn a_live_run_claim_put_lands_auto_when_the_lent_checker_allows() -> TestResult {
        let f = Fixture::open()?;
        let allowing = Arc::new(RecordingAutoChecker::allow());
        let checker = bounded(allowing.clone());
        let id = f.put(&checker, "run-checker-allows", "sencha")?;
        assert_eq!(
            f.approval(id)?,
            "auto",
            "FAILBEFORE LIVE-RUN-CHECKER-INJECT: the door lent no checker, so the put parked \
             (reviews {:?})",
            f.reviews(id)?
        );
        assert_eq!(
            allowing.calls(),
            1,
            "the lent checker is consulted once; the landing reuses its verdict"
        );
        assert!(f.reviews(id)?.is_empty(), "an allowed put parks no review");
        Ok(())
    }

    /// A checker that holds the put parks it Proposed with the checker's own
    /// pending review (`gate.pending.checker`), the hold the owner rules on,
    /// not a checker-unavailable one.
    #[test]
    fn a_live_run_claim_put_held_by_the_lent_checker_parks_proposed_with_its_review() -> TestResult
    {
        let f = Fixture::open()?;
        let holding = Arc::new(RecordingAutoChecker::hold());
        let checker = bounded(holding.clone());
        let id = f.put(&checker, "run-checker-holds", "matcha")?;
        assert_eq!(
            f.reviews(id)?,
            vec![vec!["gate.pending.checker".to_owned()]],
            "FAILBEFORE LIVE-RUN-CHECKER-INJECT: the door lent no checker, so the put parked \
             checker-unavailable"
        );
        assert_eq!(f.approval(id)?, "proposed", "the held put lands Proposed");
        assert!(holding.calls() >= 1, "the lent checker was asked");
        Ok(())
    }

    /// A checker that holds the Auto request once and would allow a second
    /// ask is asked once: its hold lands the put Proposed in the same
    /// transaction with the checker's own pending review, and no Proposed
    /// resubmission asks it again (review 9216 round 2 P1). Red at the PR's
    /// round-2 head: the hold commits alone, the resubmission asks again, is
    /// allowed, and parks no review.
    #[test]
    fn a_live_run_claim_put_the_lent_checker_holds_once_parks_that_hold() -> TestResult {
        let f = Fixture::open()?;
        let head = Arc::new(RecordingAutoChecker::hold_then_allow());
        let checker = bounded(head.clone());
        let id = f.put(&checker, "run-checker-holds-once", "hojicha")?;
        assert_eq!(
            f.reviews(id)?,
            vec![vec!["gate.pending.checker".to_owned()]],
            "LEAK: the checker's hold of the Auto request was dropped (checker asked {} times)",
            head.calls()
        );
        assert_eq!(f.approval(id)?, "proposed", "the held put lands Proposed");
        assert_eq!(head.calls(), 1, "the lent checker is asked once per put");
        Ok(())
    }

    /// A put whose predicate holds a credential the write door's rules
    /// detect never reaches the checker, whose request carries the predicate
    /// as written: no checker is asked, and the put never lands Auto (review
    /// 9216 round 2 P1). Red at the PR's round-2 head: the checker is asked
    /// with the raw token in the predicate.
    #[test]
    fn a_live_run_claim_put_whose_predicate_holds_a_credential_never_reaches_the_checker()
    -> TestResult {
        let f = Fixture::open()?;
        let head = Arc::new(RecordingAutoChecker::allow());
        let checker = bounded(head.clone());
        let predicate = format!("profile.{}", provider_token());
        let (id, put) =
            f.put_predicate(&checker, "run-credential-predicate", &predicate, "sencha")?;
        assert_eq!(
            head.calls(),
            0,
            "LEAK: the checker was asked with a credential in the predicate (put {:?})",
            put.as_ref().map(drop)
        );
        if put.is_ok() {
            assert_ne!(
                f.approval(id)?,
                "auto",
                "a put no checker reviewed never lands Auto"
            );
        }
        Ok(())
    }
}
