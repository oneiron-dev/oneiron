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
//! Round 2 of #9583 and #9590 found three more ways past that lane, each red
//! at stack #9591's top eaacb131486:
//! - FIX SUMMARY-REDERIVATION-DROPS-FROZEN-LANE: the landed summary's
//!   projection kept no lane, so the TURN the owner appends after the
//!   credential is revoked re-queued it as the owner's own, and the Dreamer
//!   composed and landed it.
//! - FIX SUMMARY-PLAN-JUDGES-TURNS-NOT-MESSAGES: a credential whose records
//!   caveat names the TURN alone reads the TURN, not its MESSAGE; the plan
//!   judged the TURN, and the Dreamer gave the MESSAGE's words to the model.
//! - FIX ARC-SUMMARY-PLAN-SKIPS-DECLARED-LANE: an Arc plan returned before the
//!   declared-lane check, so an Arc declared under a narrowed lane was
//!   queued, composed and landed with no lane judging it. A narrowed lane now
//!   declares no Arc; the owner's own declaration of the same Arc stands.
//!
//! Round 1 of #9683 found two more, each red at #9683's head 11ceb00fa49:
//! - P1 requester_lane.rs:192: the owner edits the landed summary with words
//!   from a MESSAGE outside the device's lane and names it as the row the
//!   edit read. The re-derivation pinned that MESSAGE as an editor source
//!   and gave the edited text to the model; the lane judged only the
//!   evidence's own MESSAGEs. Guard: a lane that reads the edit's source
//!   re-derives the edited summary.
//! - P1 derivation.rs:209: the owner reverts a summary whose credential has
//!   since been revoked. The rollback re-registered the predecessor under
//!   the reverted summary's lane, its observation refused the revoked lane,
//!   and the revert failed before it archived the summary. A rollback now
//!   restores the predecessor under its own declaration's lane, and leaves
//!   it unobserved when that lane no longer reads its sources.
//!
//! #9683's post-merge proof (r1-green at 3467fd125c7) found three faults
//! that kept five cases from their assertions:
//! - The records-caveat lanes rode the paired device's credential, which
//!   names its pairing grant. Such a lane is not saved (FIX 12059), so it
//!   never froze. They now ride the owner's host-minted read credential,
//!   which names no grant.
//! - The owner's edit carried no owner proof, so it waited in a proposal,
//!   unmerged. It now carries the owner's authorship.
//! - FIX DREAMER-REVERT-DECODES-SUMMARY-POINTER-ROW: the owner's revert
//!   judged a SUMMARY's writer from its stored row. A summary with a
//!   document stores a pointer row there, which never decodes as a summary,
//!   so every landed summary read as not the Dreamer's and none could be
//!   reverted. The revert now reads the summary's resolved body.
//!
//! Round 1 of #9808 found three more, each red at #9808's head 8a75c5cf0c2:
//! - P1 revert.rs:469: the owner's edit leaves a summary's text blank. The
//!   revert decoded the whole body, which refuses a blank text, so the owner's
//!   list of the Dreamer's changes left the summary out and the revert said
//!   the Dreamer did not write it. The revert now reads only its producer.
//! - P1 revert.rs:286: a header the owner lands for a summary after its
//!   declaration (`Vault::land_header`) stood after the revert archived the
//!   summary; only the header the declaration landed was retracted. The
//!   revert now retracts every standing header that lands the summary.
//! - P1 derivation.rs:325: the revert restored the predecessor of a summary
//!   declared over another source set with the reverted summary's set, so
//!   the predecessor re-derived from the reverted summary's records. A
//!   rollback now restores the predecessor's own declaration.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test conversation_summary_requester_lane`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::ScopedRead;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::dreamer_consolidation::{DreamerChangeKind, ScopeSummaryExecutor};
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerAdmittedAttempt, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, ReplyAssertions};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::scope_summary::{
    ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget, SummaryEdit, SummaryPatchRequest,
    SummaryReadRequest, SummarySpan,
};
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
/// The binding key seed of the owner's paired device, which also holds the
/// owner's host-minted read credential.
const DEVICE_BINDING_SEED: u8 = 0x4D;
/// The id of the owner's host-minted read credential.
const OWNER_READ_SLIP_ID: [u8; 32] = [0x4F; 32];
/// The caveat that narrows only the credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;
/// The words of the conversation's one MESSAGE.
const SOURCE_TEXT: &str = "We moved the review to Thursday.";
/// The summary the scripted model writes.
const SUMMARY_TEXT: &str = "The review moved to Thursday.";
/// The words of the TURN the owner appends after the first summary landed.
const LATER_TEXT: &str = "Thursday's review now starts at noon.";
/// The words of a MESSAGE in another conversation of the owner's.
const OTHER_TEXT: &str = "The offsite budget doubled.";
/// What the owner's edit adds to a landed summary, from [`OTHER_TEXT`].
const EDIT_TEXT: &str = " The offsite budget doubled too.";
/// The plan's refusal of a source its declared lane does not read.
const LANE_REFUSAL: &str = "summary source outside the requester's read lane";
/// The refusal of an Arc declared under a narrowed lane.
const ARC_LANE_REFUSAL: &str = "an arc summary is not declared under a narrowed read lane";

/// A vault whose owner paired their own device and witnessed a
/// conversation of one TURN.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    /// The owner's proof, which their revert of a Dreamer change presents.
    owner_proof: oneiron::consent::AuthenticatedOwner,
    device_slip: CapabilitySlip,
    /// The owner's read credential, minted by the host and naming no grant:
    /// its lane, narrowed by a records caveat, freezes as a narrowed lane.
    /// The paired device's credential names its pairing grant, and a
    /// grant-naming credential's records-caveat lane is not saved (FIX
    /// 12059), so a summary is never declared under it.
    owner_read_slip: CapabilitySlip,
    conversation: EntityId,
    turn: EntityId,
    /// The TURN's one MESSAGE, which holds its words.
    message: EntityId,
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
    let owner_read_slip = mint_owner_read_slip(&vault, &issuer, owner);
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
    let (conversation, turn, message) = witness_conversation(&vault, owner);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        owner_proof,
        device_slip,
        owner_read_slip,
        conversation,
        turn,
        message,
    }
}

/// The host mints the owner a read credential that names no grant, bound
/// to the device's key.
fn mint_owner_read_slip(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> CapabilitySlip {
    let root = vault
        .ensure_host_root_slip(issuer)
        .expect("the host's root credential");
    let mut claims = root.claims;
    claims.slip_id = OWNER_READ_SLIP_ID;
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.binding_key = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32])
        .verifying_key()
        .to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    assert_eq!(
        claims.grant_ref, None,
        "FIXTURE: the owner's host-minted read credential names no grant"
    );
    vault
        .mint_capability_slip(issuer, claims)
        .expect("the host mints the owner a read credential")
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

/// The owner witnesses a conversation of one txt-less TURN, its words in its
/// MESSAGE: the conversation, the TURN and the MESSAGE.
fn witness_conversation(vault: &Vault, owner: EntityId) -> (EntityId, EntityId, EntityId) {
    let conversation = EntityId::now();
    let (turn, message) = witness_turn(vault, owner, conversation, SOURCE_TEXT);
    assert_eq!(
        vault
            .resolve_dag_scope(&canonical(conversation))
            .expect("scope")
            .records,
        vec![turn],
        "FIXTURE: the conversation resolves to its one TURN"
    );
    (conversation, turn, message)
}

/// The owner witnesses one txt-less TURN of `conversation` whose one MESSAGE
/// says `content`: the TURN and the MESSAGE.
fn witness_turn(
    vault: &Vault,
    owner: EntityId,
    conversation: EntityId,
    content: &str,
) -> (EntityId, EntityId) {
    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        })
        .expect("the owner's TURN");
    (turn, message)
}

/// The device's credential narrowed by the device itself, kept on its key:
/// its lane keeps the owner's exemption and freezes as a narrowed lane.
fn attenuated_lane(fixture: &Fixture) -> ScopedRead<'_> {
    narrowed_lane(
        fixture,
        &fixture.device_slip,
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            ..Default::default()
        },
    )
}

/// The owner's read credential narrowed by its holder to the
/// conversation's TURN alone: a records caveat holds a row only as named, so
/// its lane reads the TURN and not the MESSAGE that holds its words.
fn turn_only_lane(fixture: &Fixture) -> ScopedRead<'_> {
    let lane = narrowed_lane(
        fixture,
        &fixture.owner_read_slip,
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            records: Some([fixture.turn.to_hex()].into()),
            ..Default::default()
        },
    );
    assert!(
        lane.is_ref_readable(&fixture.turn)
            .expect("the TURN's readability"),
        "FIXTURE: the credential's records caveat names the TURN, so its lane reads it"
    );
    assert!(
        attenuated_lane(fixture)
            .is_ref_readable(&fixture.message)
            .expect("the MESSAGE's readability"),
        "FIXTURE: the MESSAGE is a row the device's lane reads when no records caveat binds it"
    );
    assert!(
        !lane
            .is_ref_readable(&fixture.message)
            .expect("the MESSAGE's readability"),
        "FIXTURE: the records caveat does not name the MESSAGE, so the lane does not read its words"
    );
    lane
}

/// The owner's read credential narrowed by its holder to the
/// conversation's TURN and its MESSAGE: its lane reads the conversation's
/// words, and not `outside`, a row its records caveat does not name.
fn conversation_records_lane(fixture: &Fixture, outside: EntityId) -> ScopedRead<'_> {
    let lane = narrowed_lane(
        fixture,
        &fixture.owner_read_slip,
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            records: Some([fixture.turn.to_hex(), fixture.message.to_hex()].into()),
            ..Default::default()
        },
    );
    for row in [fixture.turn, fixture.message] {
        assert!(
            lane.is_ref_readable(&row).expect("the row's readability"),
            "FIXTURE: the records caveat names the conversation's row {}, so its lane reads it",
            row.to_hex()
        );
    }
    assert!(
        !lane
            .is_ref_readable(&outside)
            .expect("the outside row's readability"),
        "FIXTURE: the records caveat does not name row {}, so the lane does not read it",
        outside.to_hex()
    );
    lane
}

/// `base`, a credential the device's key holds, narrowed by `caveat`, kept
/// on its key.
fn narrowed_lane<'f>(
    fixture: &'f Fixture,
    base: &CapabilitySlip,
    caveat: SlipCaveat,
) -> ScopedRead<'f> {
    let mut slip = base.clone();
    slip.attenuate(caveat, &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]))
        .expect("the device narrows its own credential");
    let proof = verified(fixture, &slip);
    assert_eq!(
        proof.claims().slip_id,
        base.claims.slip_id,
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
    let (admitted, run) = run_next(fixture, model);
    assert_eq!(
        admitted.attempt, queued.attempt,
        "FIXTURE: the admitted attempt is this summary's declaration"
    );
    run
}

/// The Dreamer admits the next queued attempt and runs it once with
/// `model`: the attempt it admitted, and the run.
fn run_next(
    fixture: &Fixture,
    model: &ScriptedSummaryModel<'_>,
) -> (ScopeSummaryQueued, oneiron::Result<DreamerAttemptExecution>) {
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
    let queued = ScopeSummaryQueued {
        attempt: admitted.status.attempt.id,
        coalesced: false,
    };
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
    (
        queued,
        block_on_ready(executor.execute(&admitted, &mut context)),
    )
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

/// The SUMMARY `run` of `queued` landed, once it composed.
fn landed_summary(
    fixture: &Fixture,
    queued: ScopeSummaryQueued,
    run: &oneiron::Result<DreamerAttemptExecution>,
) -> EntityId {
    assert!(
        matches!(run, Ok(DreamerAttemptExecution::Completed { .. })),
        "FIXTURE: with its credential live, the summary composes; run {run:?}"
    );
    let summary = landed(fixture, queued).expect("FIXTURE: the composed summary lands");
    EntityId::from_hex(&summary).expect("the landed SUMMARY's id")
}

/// The summary `lane` declares, composed by `model` and landed: its
/// declaration and its SUMMARY.
fn landed_in_lane(
    fixture: &Fixture,
    lane: &ScopedRead<'_>,
    model: &ScriptedSummaryModel<'_>,
) -> (ScopeSummaryQueued, EntityId) {
    let queued = declare_in_lane(fixture, lane);
    let run = run_summary(fixture, queued, model);
    (queued, landed_summary(fixture, queued, &run))
}

/// The owner appends a TURN of [`LATER_TEXT`], and the Dreamer re-derives
/// the landed summary with `model`: the new declaration and its SUMMARY.
fn rederived_after_later_turn(
    fixture: &Fixture,
    model: &ScriptedSummaryModel<'_>,
) -> (ScopeSummaryQueued, EntityId) {
    witness_turn(
        &fixture.vault,
        fixture.owner,
        fixture.conversation,
        LATER_TEXT,
    );
    let (rederived, run) = run_next(fixture, model);
    (rederived, landed_summary(fixture, rederived, &run))
}

/// The owner, in person, edits the landed `summary`, adding [`EDIT_TEXT`],
/// and names `source` as the row the edit's words were read from. Without
/// the owner's proof the edit would wait in a proposal, unmerged.
fn owner_edits_summary(fixture: &Fixture, summary: EntityId, source: EntityId) {
    let memory = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.owner_proof);
    let read = |spans| {
        memory
            .read_summary(&SummaryReadRequest {
                summary_ref: summary.to_hex(),
                spans,
            })
            .expect("the owner reads the landed summary")
            .value
            .expect("FIXTURE: the landed summary has its document")
    };
    let text = read(Vec::new()).text;
    let view = read(vec![SummarySpan {
        start: 0,
        end: text.chars().count(),
    }]);
    let anchor = view
        .anchors
        .first()
        .cloned()
        .expect("FIXTURE: an anchor over the summary's text");
    memory
        .patch_summary(&SummaryPatchRequest {
            summary_ref: summary.to_hex(),
            base: view.frontier,
            keep: view.metadata.keep,
            edits: vec![SummaryEdit::InsertAfterAnchor {
                anchor,
                text: EDIT_TEXT.to_owned(),
            }],
            read_refs: vec![source.to_hex()],
        })
        .expect("the owner's edit of the summary");
    let edited = read(Vec::new());
    assert!(
        edited.text.contains(EDIT_TEXT.trim()),
        "FIXTURE: the owner's edit merged into the summary: {:?}",
        edited.text
    );
    assert!(
        edited.read_refs.contains(&source.to_hex()),
        "FIXTURE: the edited summary keeps row {} as a source of its words; read refs {:?}",
        source.to_hex(),
        edited.read_refs
    );
}

/// The owner's revert of the Dreamer's `summary`: the SUMMARY it archived
/// and the one current after it, or the refusal.
fn owner_reverts(
    fixture: &Fixture,
    summary: EntityId,
) -> Result<(Option<EntityId>, Option<EntityId>), String> {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .revert_dreamer_change(
            &fixture.owner_proof,
            summary,
            fixture.vault.now_recorded_ms(),
        )
        .map(|receipt| (receipt.reverted.archived, receipt.reverted.current))
        .map_err(|error| format!("{error} ({error:?})"))
}

/// The owner declares a summary of `target` on their own lane.
fn owner_declares(fixture: &Fixture, target: ScopeSummaryTarget) -> ScopeSummaryQueued {
    fixture
        .vault
        .request_scope_summary(&ScopeSummaryRequest {
            target,
            requester: WriteActor::new(fixture.owner, EdgeActorClass::Human),
        })
        .expect("the owner declares a summary on their own lane")
}

/// The owner's summary of the whole conversation, composed by `model` and
/// landed on no turn: its SUMMARY.
fn owner_landed_summary(fixture: &Fixture, model: &ScriptedSummaryModel<'_>) -> EntityId {
    let queued = owner_declares(
        fixture,
        ScopeSummaryTarget::Scope {
            scope: canonical(fixture.conversation),
            land_on: None,
            as_record: false,
        },
    );
    let run = run_summary(fixture, queued, model);
    landed_summary(fixture, queued, &run)
}

/// The owner, in person, replaces the whole text of `summary` with a space
/// through the document door: the edit merges, and the text is blank.
fn owner_blanks_summary(fixture: &Fixture, summary: EntityId) {
    let vault = &fixture.vault;
    let end = vault
        .entity_text(&summary)
        .expect("the landed summary's text")
        .chars()
        .count();
    vault
        .edit_entity_text(
            &summary,
            &[AnchoredEdit {
                actor: Some(WriteActor::new(fixture.owner, EdgeActorClass::Human)),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: vault
                        .entity_text_anchor(&summary, 0, end)
                        .expect("an anchor over the summary's whole text"),
                    text: " ".to_owned(),
                },
            }],
            &DocAuthorization::Owner(&fixture.owner_proof),
            vault.now_recorded_at(),
        )
        .expect("the owner's edit of the summary's text");
    assert!(
        vault
            .entity_text(&summary)
            .expect("the edited summary's text")
            .trim()
            .is_empty(),
        "FIXTURE: the owner's edit left the summary's text blank"
    );
}

/// Whether the CLAIM `claim` stands.
fn claim_stands(fixture: &Fixture, claim: EntityId) -> bool {
    fixture
        .vault
        .get_claim(&claim)
        .expect("read the claim")
        .is_some_and(|body| body.lifecycle.as_str() == "active")
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

#[test]
fn a_conversation_summary_rederived_after_its_credential_ends_is_not_composed() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let queued = declare_in_lane(&fixture, &lane);
    let first = ScriptedSummaryModel::new(&fixture, false);
    let run = run_summary(&fixture, queued, &first);
    assert!(
        matches!(run, Ok(DreamerAttemptExecution::Completed { .. }))
            && landed(&fixture, queued).is_some(),
        "FIXTURE: with its credential live, the summary composes and lands; run {run:?}"
    );
    revoke_device_credential(&fixture);
    let (later, _) = witness_turn(
        &fixture.vault,
        fixture.owner,
        fixture.conversation,
        LATER_TEXT,
    );
    let model = ScriptedSummaryModel::new(&fixture, false);
    let (rederived, run) = run_next(&fixture, &model);
    assert_ne!(
        rederived.attempt, queued.attempt,
        "FIXTURE: the appended TURN re-queued the landed summary as a new attempt"
    );
    let reason = refusal(&run);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains(LANE_REFUSAL)),
        "actor=the owner's device under a narrowed credential, revoked after its summary of conversation {} landed; the owner appended TURN {}; expected the re-derived summary's plan to refuse the TURNs its lane no longer reads; run {run:?}",
        fixture.conversation.to_hex(),
        later.to_hex()
    );
    assert_eq!(
        model.calls(),
        0,
        "actor=the owner's device under a revoked credential; expected no model call to read the re-derived summary's TURNs"
    );
    assert_eq!(
        landed(&fixture, rederived),
        None,
        "actor=the owner's device under a revoked credential; expected no re-derived SUMMARY to land"
    );
}

#[test]
fn a_conversation_summary_composes_no_message_its_requester_lane_does_not_read() {
    let fixture = fixture();
    let lane = turn_only_lane(&fixture);
    let queued = declare_in_lane(&fixture, &lane);
    let model = ScriptedSummaryModel::new(&fixture, false);
    let run = run_summary(&fixture, queued, &model);
    let reason = refusal(&run);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains(LANE_REFUSAL)),
        "actor=the owner under a read credential whose records caveat names TURN {} alone; expected the plan to refuse MESSAGE {}, which holds the TURN's words and which the lane does not read; run {run:?}",
        fixture.turn.to_hex(),
        fixture.message.to_hex()
    );
    assert_eq!(
        model.calls(),
        0,
        "actor=the owner under a TURN-only read credential; expected no model call to read MESSAGE {}",
        fixture.message.to_hex()
    );
    assert_eq!(
        landed(&fixture, queued),
        None,
        "actor=the owner under a TURN-only read credential; expected no SUMMARY of the MESSAGE's words to land"
    );
}

#[test]
fn an_arc_summary_is_not_declared_under_a_narrowed_lane() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let request = ScopeSummaryRequest {
        target: ScopeSummaryTarget::Arc {
            scope: ScopeSelector {
                include_forks: true,
                ..canonical(fixture.conversation)
            },
        },
        requester: WriteActor::new(fixture.owner, EdgeActorClass::Human),
    };
    let declared = fixture
        .vault
        .request_scope_summary_in_lane(&request, None, &lane);
    assert!(
        declared
            .as_ref()
            .is_err_and(|error| format!("{error} {error:?}").contains(ARC_LANE_REFUSAL)),
        "actor=the owner's device under a narrowed credential; expected its Arc declaration of conversation {} to be refused, as no lane judges an Arc's sources; got {declared:?}",
        fixture.conversation.to_hex()
    );
    // Guard: the refusal is the narrowed lane's. The owner's own declaration
    // of the same Arc stands.
    fixture
        .vault
        .request_scope_summary(&request)
        .expect("the owner's own Arc declaration is admitted");
}

#[test]
fn an_edited_summary_is_not_rederived_from_a_row_the_edit_read_outside_its_lane() {
    let fixture = fixture();
    let (_, outside) = witness_turn(&fixture.vault, fixture.owner, EntityId::now(), OTHER_TEXT);
    let lane = conversation_records_lane(&fixture, outside);
    let model = ScriptedSummaryModel::new(&fixture, false);
    let (queued, summary) = landed_in_lane(&fixture, &lane, &model);
    owner_edits_summary(&fixture, summary, outside);
    let rederive = ScriptedSummaryModel::new(&fixture, false);
    let (rederived, run) = run_next(&fixture, &rederive);
    assert_ne!(
        rederived.attempt, queued.attempt,
        "FIXTURE: the owner's edit re-queued the landed summary as a new attempt"
    );
    let reason = refusal(&run);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains(LANE_REFUSAL)),
        "actor=the owner under a read credential whose records caveat names conversation {}'s TURN and MESSAGE; the owner edited its landed SUMMARY {} with words read from MESSAGE {}, outside that lane; expected the re-derivation's plan to refuse the edited text's source; run {run:?}",
        fixture.conversation.to_hex(),
        summary.to_hex(),
        outside.to_hex()
    );
    assert_eq!(
        rederive.calls(),
        0,
        "actor=the owner under a records-caveat read credential; expected no model call to read the edited text, which quotes MESSAGE {}",
        outside.to_hex()
    );
    assert_eq!(
        landed(&fixture, rederived),
        None,
        "actor=the owner under a records-caveat read credential; expected no re-derived SUMMARY to land"
    );
}

/// Guard: the refusal is the lane's. A lane that reads the edit's source
/// re-derives the edited summary.
#[test]
fn an_edited_summary_is_rederived_under_a_lane_that_reads_the_edits_source() {
    let fixture = fixture();
    let (_, outside) = witness_turn(&fixture.vault, fixture.owner, EntityId::now(), OTHER_TEXT);
    let lane = attenuated_lane(&fixture);
    assert!(
        lane.is_ref_readable(&outside)
            .expect("the edit's source's readability"),
        "FIXTURE: the device's lane reads MESSAGE {}, the edit's source",
        outside.to_hex()
    );
    let model = ScriptedSummaryModel::new(&fixture, false);
    let (queued, summary) = landed_in_lane(&fixture, &lane, &model);
    owner_edits_summary(&fixture, summary, outside);
    let rederive = ScriptedSummaryModel::new(&fixture, false);
    let (rederived, run) = run_next(&fixture, &rederive);
    assert_ne!(
        rederived.attempt, queued.attempt,
        "FIXTURE: the owner's edit re-queued the landed summary as a new attempt"
    );
    assert!(
        matches!(run, Ok(DreamerAttemptExecution::Completed { .. })),
        "actor=the owner's device under a live credential that reads MESSAGE {}; the owner edited SUMMARY {} from it; expected the edited summary to re-derive; run {run:?}",
        outside.to_hex(),
        summary.to_hex()
    );
    assert_eq!(rederive.calls(), 1, "expected one model call");
}

#[test]
fn the_owner_reverts_a_summary_whose_declaring_credential_has_ended() {
    let fixture = fixture();
    let lane = attenuated_lane(&fixture);
    let model = ScriptedSummaryModel::new(&fixture, false);
    let (_, first) = landed_in_lane(&fixture, &lane, &model);
    let (_, second) = rederived_after_later_turn(&fixture, &model);
    revoke_device_credential(&fixture);
    let reverted = owner_reverts(&fixture, second);
    assert_eq!(
        reverted,
        Ok((Some(second), Some(first))),
        "actor=the owner; SUMMARY {} re-derived SUMMARY {} under the device's narrowed credential, since revoked; expected the owner's revert to archive it and restore its predecessor",
        second.to_hex(),
        first.to_hex()
    );
}

#[test]
fn a_reverted_summary_restores_its_predecessor_under_the_predecessors_own_lane() {
    let fixture = fixture();
    let model = ScriptedSummaryModel::new(&fixture, false);
    let request = ScopeSummaryRequest {
        target: ScopeSummaryTarget::Scope {
            scope: canonical(fixture.conversation),
            land_on: None,
            as_record: false,
        },
        requester: WriteActor::new(fixture.owner, EdgeActorClass::Human),
    };
    let queued = fixture
        .vault
        .request_scope_summary(&request)
        .expect("the owner declares a summary on their own lane");
    let run = run_summary(&fixture, queued, &model);
    let first = landed_summary(&fixture, queued, &run);
    // The device's narrowed lane declares the next generation of the same
    // summary, the owner's first its predecessor.
    let lane = attenuated_lane(&fixture);
    let (_, second) = landed_in_lane(&fixture, &lane, &model);
    revoke_device_credential(&fixture);
    let reverted = owner_reverts(&fixture, second);
    assert_eq!(
        reverted,
        Ok((Some(second), Some(first))),
        "actor=the owner; the device declared SUMMARY {} under a narrowed credential, since revoked, after the owner's own SUMMARY {}; expected the owner's revert to archive it and restore the owner's",
        second.to_hex(),
        first.to_hex()
    );
    let (later, _) = witness_turn(
        &fixture.vault,
        fixture.owner,
        fixture.conversation,
        LATER_TEXT,
    );
    let rederive = ScriptedSummaryModel::new(&fixture, false);
    let (_, run) = run_next(&fixture, &rederive);
    assert!(
        matches!(run, Ok(DreamerAttemptExecution::Completed { .. })),
        "actor=the owner; their SUMMARY {} was restored by the revert; the owner appended TURN {}; expected the restored summary to re-derive on the owner's own lane, not the revoked lane of the summary reverted; run {run:?}",
        first.to_hex(),
        later.to_hex()
    );
    assert_eq!(rederive.calls(), 1, "expected one model call");
}

#[test]
fn the_owner_lists_and_reverts_a_summary_whose_text_an_edit_left_blank() {
    let fixture = fixture();
    let model = ScriptedSummaryModel::new(&fixture, false);
    let summary = owner_landed_summary(&fixture, &model);
    owner_blanks_summary(&fixture, summary);
    let listed = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .dreamer_changes(&fixture.owner_proof, 50)
        .expect("the owner's list of the Dreamer's changes");
    assert!(
        listed
            .changes
            .iter()
            .any(|change| change.change == summary && change.kind == DreamerChangeKind::Summary),
        "actor=the owner; their edit left the text of the Dreamer's SUMMARY {} blank; expected their list of the Dreamer's changes to name it; listed {:?}",
        summary.to_hex(),
        listed
            .changes
            .iter()
            .map(|change| (change.change.to_hex(), change.kind))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        owner_reverts(&fixture, summary),
        Ok((Some(summary), None)),
        "actor=the owner; their edit left the text of the Dreamer's SUMMARY {} blank; expected their revert to archive it",
        summary.to_hex()
    );
}

#[test]
fn the_owners_revert_retracts_a_header_landed_after_the_summarys_declaration() {
    let fixture = fixture();
    let model = ScriptedSummaryModel::new(&fixture, false);
    let summary = owner_landed_summary(&fixture, &model);
    let header = fixture
        .vault
        .land_header(
            &summary,
            &fixture.turn,
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
            false,
        )
        .expect("the owner lands the summary's header on the conversation's TURN")
        .claim;
    assert!(
        claim_stands(&fixture, header),
        "FIXTURE: the summary's header {} stands",
        header.to_hex()
    );
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .revert_dreamer_change(
            &fixture.owner_proof,
            summary,
            fixture.vault.now_recorded_ms(),
        )
        .expect("the owner's revert of the summary");
    assert_eq!(
        receipt.reverted.archived,
        Some(summary),
        "FIXTURE: the revert archived the summary"
    );
    assert!(
        !claim_stands(&fixture, header) && receipt.reverted.retracted == vec![header],
        "actor=the owner; SUMMARY {} landed on no turn, then the owner landed its header {} on TURN {}; expected the revert to retract that header with the summary; retracted {:?}",
        summary.to_hex(),
        header.to_hex(),
        fixture.turn.to_hex(),
        receipt
            .reverted
            .retracted
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_reverted_summary_restores_its_predecessor_with_the_predecessors_own_sources() {
    let fixture = fixture();
    let (later, _) = witness_turn(
        &fixture.vault,
        fixture.owner,
        fixture.conversation,
        LATER_TEXT,
    );
    let model = ScriptedSummaryModel::new(&fixture, false);
    // Two source sets of the one conversation: the later set's summary
    // continues the earlier set's, its predecessor (FIX 3198).
    let landed_from = |turn: EntityId| {
        let queued = owner_declares(
            &fixture,
            ScopeSummaryTarget::Sources {
                scope: Some(canonical(fixture.conversation)),
                sources: vec![turn],
            },
        );
        let run = run_summary(&fixture, queued, &model);
        landed_summary(&fixture, queued, &run)
    };
    let first = landed_from(fixture.turn);
    let second = landed_from(later);
    let covers = |summary: EntityId| {
        fixture
            .vault
            .scope_summary_covers(&summary)
            .expect("the summary's covers")
    };
    let (restored, reverted) = (covers(first), covers(second));
    assert!(
        !restored.is_empty() && !restored.iter().any(|id| reverted.contains(id)),
        "FIXTURE: the two source sets' summaries cover different records: {restored:?} and {reverted:?}"
    );
    assert_eq!(
        owner_reverts(&fixture, second),
        Ok((Some(second), Some(first))),
        "FIXTURE: the owner's revert archives SUMMARY {} and restores its predecessor {}",
        second.to_hex(),
        first.to_hex()
    );
    // The owner's edit of the restored summary re-derives it from its
    // projection's declaration.
    owner_edits_summary(&fixture, first, fixture.message);
    let rederive = ScriptedSummaryModel::new(&fixture, false);
    let (rederived, run) = run_next(&fixture, &rederive);
    let third = landed_summary(&fixture, rederived, &run);
    let rederived_covers = covers(third);
    assert!(
        restored.iter().all(|id| rederived_covers.contains(id))
            && !reverted.iter().any(|id| rederived_covers.contains(id)),
        "actor=the owner; SUMMARY {} of TURN {} was restored by the revert of SUMMARY {} of TURN {}; the owner edited it; expected its re-derivation {} to cover {restored:?}, its own source set's records, not {reverted:?}; covers {rederived_covers:?}",
        first.to_hex(),
        fixture.turn.to_hex(),
        second.to_hex(),
        later.to_hex(),
        third.to_hex()
    );
}
