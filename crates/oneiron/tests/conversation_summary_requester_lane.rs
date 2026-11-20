//! A conversation summary queued under a narrowed lane is composed and
//! landed only while that lane reads its sources (blind review P1 of #9583).
//!
//! The owner pairs their own device and witnesses a conversation. The device
//! narrows its own credential (`CapabilitySlip::attenuate`): its lane keeps
//! the owner's exemption and reads the conversation's TURN, but freezes as a
//! narrowed lane, so the summary it declares carries that lane. The
//! declaration's door judged its sources under the live lane (FIX 11829);
//! the Dreamer's plan, at composition and again at landing, re-resolved the
//! scope with no lane, read the TURN as the Dreamer, and minted the SUMMARY
//! (`as_record = false` lands no reply, so no reply lane was checked). Each
//! plan now rebuilds the declared lane over the requester's base read, as a
//! NOTE set's plan does (FIX 6322), and refuses a source it does not read.
//!
//! Red at #9583's head fcbc264c20c: the summary whose credential was revoked
//! before the Dreamer ran, and the one revoked while the model wrote, each
//! composed and landed. Guard: with the credential live, the summary
//! composes and lands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test conversation_summary_requester_lane`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::ScopedRead;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::dreamer_consolidation::ScopeSummaryExecutor;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::federation::Scope;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, ReplyAssertions};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::scope_summary::{ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallPurpose, ContentPart,
    DreamerAttemptExecution, DreamerAttemptExecutor, EdgeActorClass, EntityId, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, Vault, VaultConfig, WakeAttemptContext,
    WakePassDeadline, WriteActor,
};
use serde_json::json;

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:conversation-summary-requester-lane";
/// The binding key seed of the owner's paired device.
const DEVICE_BINDING_SEED: u8 = 0x4D;
/// The caveat that narrows only the credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;
/// The words of the conversation's one MESSAGE.
const SOURCE_TEXT: &str = "We moved the review to Thursday.";
/// The summary the scripted model writes.
const SUMMARY_TEXT: &str = "The review moved to Thursday.";
/// The plan's refusal of a source its declared lane does not read.
const LANE_REFUSAL: &str = "summary source outside the requester's read lane";

/// A vault whose owner paired their own device and witnessed a
/// conversation of one TURN.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    device_slip: CapabilitySlip,
    conversation: EntityId,
    turn: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let device_slip = paired_device_slip(&vault, &issuer, &owner_proof, owner);
    // The scripted model is the host's own: the summary call may leave.
    let mut defaults = vault.purpose_default_table().expect("inference defaults");
    defaults.extraction_max_locality = ModelLocality::OwnServer;
    defaults
        .purposes
        .get_mut(&CallPurpose::Extraction)
        .expect("extraction defaults")
        .locality = ModelLocality::OwnServer;
    vault
        .set_purpose_default_table(&defaults)
        .expect("scripted inference policy");
    let (conversation, turn) = witness_conversation(&vault, owner);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        device_slip,
        conversation,
        turn,
    }
}

/// The owner's own device pairs on a link the owner issues for themselves.
fn paired_device_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &oneiron::consent::AuthenticatedOwner,
    owner: EntityId,
) -> CapabilitySlip {
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                // The owner's device pairs as the human it is (see
                // saved_lane_owner_basis.rs).
                actor_class: Some("human".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link for their own device");
    let signing_key = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the device's pairing transcript");
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the owner's device redeems the link")
}

fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    }
}

/// The owner witnesses one txt-less TURN, its words in its MESSAGE.
fn witness_conversation(vault: &Vault, owner: EntityId) -> (EntityId, EntityId) {
    let conversation = EntityId::now();
    let turn = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: SOURCE_TEXT.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's conversation");
    assert_eq!(
        vault
            .resolve_dag_scope(&canonical(conversation))
            .expect("scope")
            .records,
        vec![turn],
        "FIXTURE: the conversation resolves to its one TURN"
    );
    (conversation, turn)
}

/// The device's credential narrowed by the device itself, kept on its key:
/// its lane keeps the owner's exemption and freezes as a narrowed lane.
fn attenuated_lane(fixture: &Fixture) -> ScopedRead<'_> {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            ..Default::default()
        },
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential");
    let proof = verified(fixture, &slip);
    assert_eq!(
        proof.claims().slip_id,
        fixture.device_slip.claims.slip_id,
        "FIXTURE: the narrowed credential keeps its mint's id, which the revocation names"
    );
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("the credential's read key")
        .expect("the credential grants read");
    let lane = fixture.vault.scoped_read(key);
    assert!(
        !lane
            .freeze()
            .expect("the narrowed lane freezes")
            .is_principal(),
        "FIXTURE: the narrowed credential's lane rides the declaration frozen"
    );
    lane
}

fn verified(fixture: &Fixture, slip: &CapabilitySlip) -> VerifiedSlip {
    let signature = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32])
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the holder's request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            slip,
            REQUEST_CHALLENGE,
            &signature,
        )
        .expect("the device proves possession of its credential")
}

/// The owner, through the narrowed lane, declares a summary of the
/// conversation that lands on no turn. The door reads the TURN under the
/// live lane (FIX 11829), so the declaration is admitted.
fn declare_in_lane(fixture: &Fixture, lane: &ScopedRead<'_>) -> ScopeSummaryQueued {
    let queued = fixture
        .vault
        .request_scope_summary_in_lane(
            &ScopeSummaryRequest {
                target: ScopeSummaryTarget::Scope {
                    scope: canonical(fixture.conversation),
                    land_on: None,
                    as_record: false,
                },
                requester: WriteActor::new(fixture.owner, EdgeActorClass::Human),
            },
            None,
            lane,
        )
        .expect("FIXTURE: the live narrowed lane reads the TURN, so the summary is declared");
    assert!(!queued.coalesced, "FIXTURE: a fresh summary declaration");
    queued
}

/// Revokes the device's credential, the one the declared lane froze.
fn revoke_device_credential(fixture: &Fixture) {
    let id = fixture.device_slip.claims.slip_id;
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, id)
        .expect("the device's credential is revoked");
    assert!(
        !fixture
            .vault
            .capability_slip_id_is_live(&id)
            .expect("the credential's liveness"),
        "FIXTURE: the revoked credential is no longer live"
    );
}

struct NoInner;

impl DreamerAttemptExecutor for NoInner {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!("FIXTURE: only the declared scope-summary attempt runs")
    }
}

/// A scripted, network-free summary model: it answers once with
/// [`SUMMARY_TEXT`], counts its calls, and, when told to, revokes the
/// device's credential while it writes.
struct ScriptedSummaryModel<'f> {
    fixture: &'f Fixture,
    revoke_while_writing: bool,
    calls: AtomicUsize,
}

impl<'f> ScriptedSummaryModel<'f> {
    fn new(fixture: &'f Fixture, revoke_while_writing: bool) -> Self {
        Self {
            fixture,
            revoke_while_writing,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ScriptedSummaryModel<'_> {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.revoke_while_writing {
            revoke_device_credential(self.fixture);
        }
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: json!({ "text": SUMMARY_TEXT, "keep": "" }).to_string(),
                    signature: None,
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
            reply_assertions: ReplyAssertions::default(),
            token_scores: None,
        };
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

/// The scripted model is immediately ready.
fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("FIXTURE: the scripted executor unexpectedly waited"),
    }
}

fn allow_egress(_: &LlmRequest) -> bool {
    true
}

/// The Dreamer admits and runs the declared summary once with `model`.
fn run_summary(
    fixture: &Fixture,
    queued: ScopeSummaryQueued,
    model: &ScriptedSummaryModel<'_>,
) -> oneiron::Result<DreamerAttemptExecution> {
    let vault = &fixture.vault;
    let now = vault.now_recorded_at();
    let admitted = match DreamerRunnerStore::new(vault)
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "fixture".to_owned(),
                now,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })
        .expect("admit summary")
    {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => *admitted,
        other => panic!("FIXTURE: summary was not admitted: {other:?}"),
    };
    assert_eq!(
        admitted.status.attempt.id, queued.attempt,
        "FIXTURE: the admitted attempt is this summary's declaration"
    );
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let model_id = ModelId::new("test/model@r1").expect("model");
    let inference = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: model_id.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        },
        extraction_egress: Some(&allow_egress),
    };
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0u64));
    let mut executor = ScopeSummaryExecutor::new(
        NoInner,
        model,
        &guard,
        vault.dreamer_authority().expect("Dreamer authority"),
        model_id,
        inference,
        Some("Summarize the supplied records."),
    );
    let mut context = WakeAttemptContext {
        vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: now.saturating_mul(1000),
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    block_on_ready(executor.execute(&admitted, &mut context))
}

/// The refusal a run ended on: its error, park or failure reason; `None`
/// for a run that completed.
fn refusal(run: &oneiron::Result<DreamerAttemptExecution>) -> Option<String> {
    match run {
        Err(error) => Some(format!("{error} ({error:?})")),
        Ok(
            DreamerAttemptExecution::Park { reason, .. }
            | DreamerAttemptExecution::ParkWithSpend { reason, .. }
            | DreamerAttemptExecution::Failed { reason, .. },
        ) => Some(reason.clone()),
        Ok(_) => None,
    }
}

/// The summary the declaration landed, if any.
fn landed(fixture: &Fixture, queued: ScopeSummaryQueued) -> Option<String> {
    fixture
        .vault
        .scope_summary_status(queued.attempt)
        .expect("summary status")
        .result
        .map(|result| result.summary)
}

#[test]
fn a_conversation_summary_whose_credential_ends_before_the_dreamer_runs_is_not_composed() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let queued = declare_in_lane(&fixture, &lane);
    revoke_device_credential(&fixture);
    let model = ScriptedSummaryModel::new(&fixture, false);
    let run = run_summary(&fixture, queued, &model);
    let reason = refusal(&run);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains(LANE_REFUSAL)),
        "actor=the owner's device under a narrowed credential, revoked after it declared a summary of conversation {} (TURN {}); expected the Dreamer's plan to refuse the TURN its lane no longer reads; run {run:?}",
        fixture.conversation.to_hex(),
        fixture.turn.to_hex()
    );
    assert_eq!(
        model.calls(),
        0,
        "actor=the owner's device under a revoked credential; expected no model call to read the TURN's words"
    );
    assert_eq!(
        landed(&fixture, queued),
        None,
        "actor=the owner's device under a revoked credential; expected no SUMMARY to land"
    );
}

#[test]
fn a_conversation_summary_whose_credential_ends_while_the_model_writes_does_not_land() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let queued = declare_in_lane(&fixture, &lane);
    let model = ScriptedSummaryModel::new(&fixture, true);
    let run = run_summary(&fixture, queued, &model);
    assert_eq!(
        model.calls(),
        1,
        "FIXTURE: the summary composed once, its credential live at composition"
    );
    let reason = refusal(&run);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains(LANE_REFUSAL)),
        "actor=the owner's device under a narrowed credential, revoked while the model wrote its summary of conversation {}; expected the landing's plan to refuse the TURN its lane no longer reads; run {run:?}",
        fixture.conversation.to_hex()
    );
    assert_eq!(
        landed(&fixture, queued),
        None,
        "actor=the owner's device under a credential revoked before the landing; expected no SUMMARY to land"
    );
}

/// Guard: the rebuilt lane reads what the live lane read, so a summary
/// whose credential stays live composes and lands.
#[test]
fn a_conversation_summary_whose_credential_stays_live_composes_and_lands() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let queued = declare_in_lane(&fixture, &lane);
    let model = ScriptedSummaryModel::new(&fixture, false);
    let run = run_summary(&fixture, queued, &model);
    assert!(
        matches!(run, Ok(DreamerAttemptExecution::Completed { .. })),
        "actor=the owner's device under a live narrowed credential; expected its summary of conversation {} to compose; run {run:?}",
        fixture.conversation.to_hex()
    );
    assert_eq!(model.calls(), 1, "expected one model call");
    assert!(
        landed(&fixture, queued).is_some(),
        "actor=the owner's device under a live narrowed credential; expected its SUMMARY to land"
    );
}
