//! MAP-6.9 row 6.9i (untangle 6.9i PR 2): the Dreamer's Psych Mirror job.
//!
//! The home timer's daily sweep enqueues one `dreamer.psych_profile`
//! attempt per due profile key; the host's job adapter runs the crate job
//! over the attempt's bound client, with the pass's narrative role lent for
//! its one bound step. A PERSON with surfaced claims gets one PSYCH_PROFILE
//! whose every source carries the claim, the exact revision read and the
//! content hash of its words; a claim erased after landing withdraws the
//! profile; a profile citing a claim the reader cannot see reads as none.
//! The engine checks the reply: a reply over its caps or with a `compact`
//! tier no shorter than `text` is refused, paid, and lands nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_psych_profile`
#![cfg(oneiron_test_support)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::dreamer_consolidation::{DREAMER_NARRATIVE_ROLE, DREAMER_VERDICT_ROLE, RoleBackend};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::dreamer_runner::maintenance::psych_profile::{
    PSYCH_PROFILE_REGENERATE_SECS, enqueue_due_psych_profiles,
};
use oneiron::psych_profile::{
    PsychProfile, PsychProfileKey, PsychProfileSourceWords, PsychProfileState,
    psych_profile_entity_id,
};
use oneiron::registry::ENTITY_TYPE_PSYCH_PROFILE;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::claim_subject;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::psych_profile::{
    admit_psych_profile_attempt, claim_words_hash, claim_words_hash_at,
    companion_profile_under_dreamer_read, companion_profile_under_reader_of_nothing,
    psych_profile_keys,
};
use oneiron::test_doors::run_lifecycle::defer_enqueued;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::{
    AccessGrant, BudgetLease, ContentPart, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, EdgeActorClass, EntityId, FatalLlmError, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
    UnsupportedCapability, Vault, VaultConfig, WakeAttemptContext, WriteActor,
};
use oneiron_driver::{ConsolidationExecutorFactory, ExtractionDecisionGate, PassExecutorFactory};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::json;

/// Returns fixture failures without hiding their source.
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const COMPACT: &str = "Owen: one known fact, his name; no scores judged.";
const TEXT: &str = "Owen is a person on the roster. The facts give his name and nothing about how \
he thinks, decides or behaves, so no OCEAN, Enneagram or Schwartz score is judged.";
const NARRATIVE: &str = "Owen. One fact is known about him: his name. Nothing listed shows how he \
thinks, what he values or how he acts, so this sheet judges no score and names no contradiction.";

/// The extraction reply that lands one fact about a new person, Owen.
fn extraction_reply() -> String {
    json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// Answers the narrative role with one fixed reply, counting the calls and
/// keeping each request's message texts.
struct NarrativeBackend {
    reply: String,
    calls: AtomicUsize,
    messages: Mutex<Vec<Vec<String>>>,
}

impl NarrativeBackend {
    fn new(compact: &str, text: &str, narrative: &str) -> Arc<Self> {
        Arc::new(Self {
            reply: json!({"compact": compact, "text": text, "narrative": narrative}).to_string(),
            calls: AtomicUsize::new(0),
            messages: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn messages(&self) -> Vec<Vec<String>> {
        self.messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LlmBackend for NarrativeBackend {
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.messages
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(
                    request
                        .messages
                        .iter()
                        .map(|message| {
                            message
                                .content
                                .iter()
                                .filter_map(|part| match part {
                                    ContentPart::Text { text, .. } => Some(text.as_str()),
                                    _ => None,
                                })
                                .collect::<String>()
                        })
                        .collect(),
                );
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "psych-profile-step",
                    ScriptedBackend::digest_of(&request),
                    self.reply.clone(),
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the narrative scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            self.calls
                .fetch_add(backend.finish().len(), Ordering::SeqCst);
            response
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// Refuses every call: the profile job asks no verdict.
struct RefusingVerdictBackend;

impl LlmBackend for RefusingVerdictBackend {
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            Err(LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                message: "the profile job must never call its verdict backend".to_owned(),
                code: None,
            }))
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// Admits the narrative step loan while open; admits no verdict or
/// extraction loan.
struct NarrativeGate {
    open: AtomicBool,
}

impl ExtractionDecisionGate for NarrativeGate {
    fn admits(&self) -> oneiron::Result<bool> {
        Ok(false)
    }

    fn admits_narrative_step(&self) -> oneiron::Result<bool> {
        Ok(self.open.load(Ordering::SeqCst))
    }
}

/// A Dreamer vault holding one surfaced claim about the PERSON Owen.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    person: EntityId,
    claim: EntityId,
    key: PsychProfileKey,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let (person, claim) = {
        let vault = open_dreamer_vault(dir.path(), "owen")?;
        let pass =
            consolidate_unbound_turn(&vault, "call me Owen", None, None, &extraction_reply())?;
        let [claim] = pass.landed.as_slice() else {
            return Err(format!("one landed claim, found {}", pass.landed.len()).into());
        };
        let person = claim_subject(&vault, *claim)?.ok_or("the fact is about the person")?;
        (person, *claim)
    };
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let keys = psych_profile_keys(&vault, person)?;
    let [key] = keys.as_slice() else {
        return Err(format!("one profile key for the person, found {}", keys.len()).into());
    };
    Ok(Fixture {
        _dir: dir,
        vault,
        person,
        claim,
        key: *key,
    })
}

/// Defers every queued attempt, then runs the production sweep at the
/// vault's clock, which enqueues the person's one profile attempt; returns
/// that clock.
fn queue_profile(fixture: &Fixture) -> TestResult<u64> {
    let now = fixture.vault.now_recorded_at();
    for record in AttemptQueue::new(&fixture.vault).list()? {
        if matches!(record.state, AttemptState::Queued) {
            defer_enqueued(&fixture.vault, record.id, now + 7 * 86_400)?;
        }
    }
    assert_eq!(
        enqueue_due_psych_profiles(&fixture.vault, now)?,
        1,
        "the sweep enqueues the one key with no profile"
    );
    Ok(now)
}

/// Sweeps, admits the profile attempt and runs it through the production
/// factory's job adapter, with `narrative` routed as the narrative role and
/// the step gate `open`.
fn run_profile_attempt(
    fixture: &Fixture,
    narrative: &Arc<NarrativeBackend>,
    open: bool,
) -> TestResult<DreamerAttemptExecution> {
    let now = queue_profile(fixture)?;
    let admitted = admit_psych_profile_attempt(&fixture.vault, now)?;
    let verdict_fixture = ExtractionVerdictFixture::new(Arc::new(RefusingVerdictBackend))?;
    let pass = verdict_fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, model, binding) = verdict_fixture.extraction_route();
    let narrative_route: Arc<dyn LlmBackend> = narrative.clone();
    let roles = pass.roles.clone().with(
        DREAMER_NARRATIVE_ROLE,
        RoleBackend {
            backend: narrative_route,
            model,
            binding,
            sourced: None,
        },
    );
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        WriteActor::new(dreamer(&fixture.vault)?, EdgeActorClass::System),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&fixture.vault))),
    )
    .with_role_backends(roles)
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&fixture.vault))
    .with_extraction_decisions(
        Arc::new(NarrativeGate {
            open: AtomicBool::new(open),
        }),
        pass.runtime.clone(),
    );
    let mut executor = factory.executor(&pass.guard)?;
    let mut context = WakeAttemptContext {
        vault: &fixture.vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    Ok(runtime.block_on(executor.execute(&admitted, &mut context))?)
}

/// The profile stored at the fixture's key, if it reads.
fn stored_profile(fixture: &Fixture) -> TestResult<Option<PsychProfile>> {
    Ok(match fixture.vault.psych_profile_for(&fixture.key)? {
        PsychProfileState::Fresh(profile) => Some(profile),
        PsychProfileState::Missing => None,
        PsychProfileState::Stale { .. } => return Err("the profile reads stale".into()),
    })
}

/// A companion principal holding the owner's grant to read the fixture's
/// profile.
fn granted_principal(fixture: &Fixture) -> TestResult<EntityId> {
    let principal = EntityId::now();
    fixture.vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant::companion_profile_read(principal, fixture.person, fixture.key.facet, 1),
    )?;
    Ok(principal)
}

#[test]
fn a_person_with_surfaced_claims_gets_one_profile_whose_every_source_carries_claim_revision_and_content_hash()
-> TestResult<()> {
    let fixture = fixture()?;
    let narrative = NarrativeBackend::new(COMPACT, TEXT, NARRATIVE);
    let execution = run_profile_attempt(&fixture, &narrative, true)?;
    assert!(
        matches!(execution, DreamerAttemptExecution::Completed { completed_units, .. } if completed_units == 150),
        "the attempt completes with its one step's spend: {execution:?}"
    );
    assert_eq!(narrative.calls(), 1, "one bound step for all three tiers");
    let messages = narrative.messages();
    let texts = messages.first().ok_or("the step sent its request")?;
    assert!(
        texts.iter().any(|text| text.starts_with("# Psych Mirror")),
        "the engine renders the psych-mirror skill's body: {texts:?}"
    );
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("profile.name: Owen (")),
        "the engine renders the served claim's words, marked with its source: {texts:?}"
    );
    assert_eq!(
        fixture.vault.entities_by_type(ENTITY_TYPE_PSYCH_PROFILE)?,
        vec![psych_profile_entity_id(&fixture.key)],
        "one PSYCH_PROFILE row, at the person's key"
    );
    let profile = stored_profile(&fixture)?.ok_or("the profile landed")?;
    assert_eq!(profile.subject_ref, fixture.person);
    assert_eq!(
        (
            profile.compact.as_str(),
            profile.text.as_str(),
            profile.narrative.as_str()
        ),
        (COMPACT, TEXT, NARRATIVE)
    );
    assert_eq!(profile.source_revision_ids, vec![fixture.claim]);
    assert_eq!(profile.sources.len(), 1);
    for source in &profile.sources {
        assert_eq!(
            source.document_ref, fixture.claim,
            "the source names the claim"
        );
        assert_eq!(source.revision_ref, fixture.claim);
        let PsychProfileSourceWords::Record { content } = source.words else {
            return Err("a claim source names its record's words".into());
        };
        assert_eq!(
            Some(content),
            claim_words_hash(&fixture.vault, fixture.claim)?,
            "the source pins the content hash of the claim's words"
        );
        assert_eq!(
            Some(content),
            claim_words_hash_at(&fixture.vault, fixture.claim, source.document_revision)?,
            "the source's revision holds exactly those words"
        );
    }
    let confidence = profile.confidence;
    assert!(confidence.compact > 0.0 && confidence.compact <= 1.0);
    assert_eq!(confidence.compact.to_bits(), confidence.text.to_bits());
    assert_eq!(confidence.text.to_bits(), confidence.narrative.to_bits());
    let now = fixture.vault.now_recorded_at();
    assert_eq!(
        enqueue_due_psych_profiles(&fixture.vault, now)?,
        0,
        "a fresh profile is not regenerated the same day"
    );
    assert_eq!(
        enqueue_due_psych_profiles(&fixture.vault, now + PSYCH_PROFILE_REGENERATE_SECS)?,
        1,
        "a day later the key is due again"
    );
    Ok(())
}

#[test]
fn a_claim_erased_after_landing_withdraws_the_profile() -> TestResult<()> {
    let fixture = fixture()?;
    let narrative = NarrativeBackend::new(COMPACT, TEXT, NARRATIVE);
    run_profile_attempt(&fixture, &narrative, true)?;
    assert!(stored_profile(&fixture)?.is_some(), "the profile landed");
    assert!(
        fixture.vault.delete_entity(&fixture.claim)?,
        "the claim is erased"
    );
    assert!(
        stored_profile(&fixture)?.is_none(),
        "the erase of its source withdraws the profile"
    );
    assert!(
        fixture
            .vault
            .get_psych_profile(&psych_profile_entity_id(&fixture.key))?
            .is_none(),
        "a withdrawn profile reads as none"
    );
    let principal = granted_principal(&fixture)?;
    assert!(
        companion_profile_under_dreamer_read(&fixture.vault, principal, &fixture.key)?.is_none(),
        "a companion read of a withdrawn profile returns none"
    );
    Ok(())
}

#[test]
fn a_profile_citing_a_claim_the_reader_cannot_see_reads_as_none() -> TestResult<()> {
    let fixture = fixture()?;
    let narrative = NarrativeBackend::new(COMPACT, TEXT, NARRATIVE);
    run_profile_attempt(&fixture, &narrative, true)?;
    let principal = granted_principal(&fixture)?;
    assert!(
        companion_profile_under_dreamer_read(&fixture.vault, principal, &fixture.key)?.is_some(),
        "a reader who reads the cited claim reads the profile"
    );
    assert!(
        companion_profile_under_reader_of_nothing(
            &fixture.vault,
            principal,
            &fixture.key,
            EntityId::now(),
        )?
        .is_none(),
        "a reader who cannot see the cited claim reads none"
    );
    Ok(())
}

#[test]
fn a_reply_whose_compact_tier_does_not_compress_its_text_is_refused_and_lands_nothing()
-> TestResult<()> {
    let fixture = fixture()?;
    let narrative = NarrativeBackend::new(TEXT, COMPACT, NARRATIVE);
    let execution = run_profile_attempt(&fixture, &narrative, true)?;
    assert!(
        matches!(execution, DreamerAttemptExecution::Failed { completed_units, .. } if completed_units == 150),
        "a refused reply is paid and fails the attempt: {execution:?}"
    );
    assert_eq!(narrative.calls(), 1, "one generation per submit");
    assert!(
        stored_profile(&fixture)?.is_none(),
        "a refused reply lands nothing"
    );
    Ok(())
}

#[test]
fn with_no_step_lent_the_attempt_parks_and_calls_no_model() -> TestResult<()> {
    let fixture = fixture()?;
    let narrative = NarrativeBackend::new(COMPACT, TEXT, NARRATIVE);
    let execution = run_profile_attempt(&fixture, &narrative, false)?;
    let DreamerAttemptExecution::ParkWithSpend { reason, .. } = &execution else {
        return Err(format!("an unlent step parks the attempt: {execution:?}").into());
    };
    assert!(
        reason.contains("MODEL_UNAVAILABLE"),
        "the park says no step was lent: {reason}"
    );
    assert_eq!(narrative.calls(), 0);
    assert!(stored_profile(&fixture)?.is_none());
    Ok(())
}
