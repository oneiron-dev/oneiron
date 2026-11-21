//! A bound extraction read the provider refuses for its context window (row
//! BOUND-EXTRACTION-READ-WINDOW-REFUSAL-MODEL-UNAVAILABLE; Engine 21 Nov 07:38: a window refusal
//! is no Retry, and the identical input is never sent again).
//!
//! 1. A lent read refused for its window on its first send, in both typed shapes (the window
//!    refusal, and the invalid-request detail naming `context_length_exceeded`), answers
//!    `BAD_REQUEST` naming the window, with no layout field, after exactly one send and with
//!    nothing tallied. A pack with no loan still answers `MODEL_UNAVAILABLE`.
//! 2. A lent read on a backend with no native JSON gets a paid reply the schema refuses, and its
//!    correction is refused for the window: that reply's usage joins the attempt's shared tally
//!    exactly once (150 units), with no terminal binding for the failed read.
//!
//! Red on main 47b5f60c15c: (1) the read answers `MODEL_UNAVAILABLE`, the code a host may wait
//! out and send again; (2) the shared tally stays at 0, since only a charge-record failure
//! accounted a failed lent read's usage. Green on the head. The no-loan control is green on both.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test bound_extraction_read_window_refusal`.
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, attach_extraction_verdict_lender, fixture_charge_binding_count,
    fixture_charge_units,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    BudgetLease, EntityId, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability, Vault,
};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::{Value, json};
use verdict_support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction, extraction_attempt_hex,
    extraction_candidate, extraction_verdict_request, invoke_bound_verdict,
    native_resolution_options, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

/// The provider's window text every refused call carries.
const WINDOW_MESSAGE: &str = "maximum context length is 8192 tokens";

/// The input and output tokens the paid reply declares: 150 units on the tally.
const PAID_TOKENS: (u64, u64) = (100, 50);

/// One admitted extraction attempt and a checked whole resolution pack request over its two
/// witnessed turns. The vault drops before its directory.
struct WindowPack {
    vault: Arc<Vault>,
    admitted: DreamerAdmittedAttempt,
    request: Value,
    _dir: tempfile::TempDir,
}

/// Opens a Dreamer vault with the steward grant, witnesses two turns, admits one extraction
/// attempt over them and builds the whole resolution pack the bound verdict tests read.
fn window_pack() -> ExtractionVerdictTestResult<WindowPack> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let page = read_bound_extraction_page(
        &bind_extraction(&vault, &admitted)?,
        &extraction_attempt_hex(id),
    )?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    Ok(WindowPack {
        vault,
        admitted,
        request: extraction_verdict_request("resolution", native_resolution_options(), pack),
        _dir: dir,
    })
}

/// A verdict backend that answers its first `paid` calls with a reply the schema refuses
/// (declaring [`PAID_TOKENS`]) and refuses every later call with `refusal`. It counts every
/// call, and says it has native JSON only when `native_json` is set.
struct WindowReasoner {
    paid: usize,
    refusal: LlmError,
    native_json: bool,
    calls: AtomicUsize,
}

impl WindowReasoner {
    fn new(paid: usize, refusal: LlmError, native_json: bool) -> Self {
        Self {
            paid,
            refusal,
            native_json,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for WindowReasoner {
    /// Answers every capability, except native JSON when the reasoner has none.
    fn supports(&self, _model: &ModelId, capability: LlmCapability) -> bool {
        self.native_json || !matches!(capability, LlmCapability::JsonResponse)
    }

    /// Serves the paid reply from a scripted backend matching this request's digest, or the
    /// refusal once the paid calls are spent.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let refusal = self.refusal.clone();
        let paid = call < self.paid;
        Box::pin(async move {
            if !paid {
                return Err(refusal);
            }
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "window-paid-reply",
                    digest,
                    "the reply is not JSON".to_owned(),
                )
                .buffered()
                .usage(PAID_TOKENS.0, PAID_TOKENS.1),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the window scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let _seen = backend.finish();
            response
        })
    }

    /// The read never streams; a streamed call fails loudly.
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

/// A lent read the provider refuses for its window on the first send answers `BAD_REQUEST`
/// naming the window, in both typed shapes: no layout field invites another read, the pack
/// went out once, and nothing joined the tally. With no loan the pack still answers
/// `MODEL_UNAVAILABLE`.
#[test]
fn a_window_refused_bound_read_is_a_bad_request_sent_once() -> ExtractionVerdictTestResult<()> {
    let shapes = [
        FatalLlmError::ContextWindowExceeded {
            message: WINDOW_MESSAGE.into(),
        },
        FatalLlmError::InvalidRequestDetail {
            message: WINDOW_MESSAGE.into(),
            code: Some("context_length_exceeded".into()),
        },
    ];
    for shape in shapes {
        let label = shape.to_string();
        let read = window_pack()?;
        let reasoner = Arc::new(WindowReasoner::new(0, shape.into(), true));
        let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
        let binding = attach_extraction_verdict_lender(
            bind_extraction(&read.vault, &read.admitted)?,
            &fixture,
        );
        let Err(refused) = invoke_bound_verdict(&binding, read.request.clone()) else {
            panic!("a window-refused read answers no verdict ({label})");
        };
        assert_eq!(
            refused.code, MEMORY_CODE_BAD_REQUEST,
            "{label}: {}",
            refused.message
        );
        assert!(
            refused.message.contains("context window") && refused.message.contains(WINDOW_MESSAGE),
            "{label}: the refusal names the window: {}",
            refused.message
        );
        assert!(
            serde_json::to_value(&refused)?["extraction_layout"].is_null(),
            "{label}: no layout invites another read"
        );
        assert_eq!(
            reasoner.calls(),
            1,
            "{label}: the refused pack is sent once"
        );
        assert_eq!(
            (
                fixture_charge_units(&fixture),
                fixture_charge_binding_count(&fixture)
            ),
            (0, 0),
            "{label}: an unspent refusal tallies nothing"
        );
    }
    let read = window_pack()?;
    let Err(unlent) = invoke_bound_verdict(
        &bind_extraction(&read.vault, &read.admitted)?,
        read.request.clone(),
    ) else {
        panic!("a pack with no loan answers no verdict");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}

/// A lent read with no native JSON is paid for a reply the schema refuses, and its correction
/// is refused for the window: the reply's 150 units join the attempt's shared tally once, with
/// no terminal binding, and the read answers `BAD_REQUEST`.
#[test]
fn a_paid_reply_before_a_window_refused_correction_joins_the_shared_tally_once()
-> ExtractionVerdictTestResult<()> {
    let read = window_pack()?;
    let refusal = FatalLlmError::ContextWindowExceeded {
        message: WINDOW_MESSAGE.into(),
    };
    let reasoner = Arc::new(WindowReasoner::new(1, refusal.into(), false));
    let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
    let binding =
        attach_extraction_verdict_lender(bind_extraction(&read.vault, &read.admitted)?, &fixture);
    let answered = invoke_bound_verdict(&binding, read.request.clone());
    assert_eq!(
        reasoner.calls(),
        2,
        "the paid reply, then its refused correction"
    );
    assert_eq!(
        fixture_charge_units(&fixture),
        PAID_TOKENS.0 + PAID_TOKENS.1,
        "the paid reply's units join the shared tally once"
    );
    assert_eq!(
        fixture_charge_binding_count(&fixture),
        0,
        "the failed read claims no terminal binding"
    );
    let Err(refused) = answered else {
        panic!("a read whose correction the window refused answers no verdict");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{}", refused.message);
    Ok(())
}
