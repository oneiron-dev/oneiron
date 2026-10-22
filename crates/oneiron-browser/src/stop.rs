//! Why a batch stopped (CUA E2): one typed cause per stop, beside the
//! stable refusal code a program already reads, and the failed step's
//! receipt that goes up with it. A step whose check failed carries the
//! check and what its read found, so the planner repairs from evidence;
//! every other stop names its true cause, never a guess.

use crate::{
    BatchOutput, BrowserDriver, BrowserError, DestinationRefusal, EffectReceipt, ExpectInput,
    ExpectOutput, FieldTextReason, Observation, ObservationBase, ObserveInput, StepStop,
    SubgoalStatus,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What stopped a batch, or a library run's final checks. The batch's
/// `error` is the stop's stable code; this is its cause.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum BatchStopCause {
    /// A batch `expect` step, or a library run's final check, read the page
    /// and found it false.
    PostconditionUnmet,
    /// A step named an element no row of a complete read is: a handle whose
    /// node is gone and whose locator names no row now, or a routine step's
    /// target, after its one wait.
    LocatorMissing,
    /// The read stopped short of the page's end (a desktop tree walk cut at
    /// its longest): a row past the cut was not seen, so it is neither shown
    /// present nor shown absent.
    IncompleteObservation,
    /// A routine step went up to the planner, for `reason`.
    DeciderAskedUp { reason: AskUpReason },
    /// A clock ran out: a `wait_for` step's, a page's load, or the
    /// subgoal's one clock its decisions run under.
    Clock { scope: ClockScope },
    /// The effect needs a person's press.
    PressNeeded,
    /// A person has the desktop or the browser.
    TakenOver,
    /// A Fill step's text was not resolved, or the page did not take it
    /// (CUA E6), for `reason`.
    FieldText { reason: FieldTextReason },
    /// Steps went on and the page did not change (CUA E3).
    NoProgress,
    /// Any other refusal of the browser or its guest, by its stable code.
    Browser { code: String },
}

/// Which clock ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClockScope {
    /// A `wait_for` step's own time.
    Wait,
    /// The time a page has to load, or a desktop app to show its window.
    Navigation,
    /// The subgoal's one clock, which its routine decisions run under.
    Decision,
}

/// Why a routine step went up to the planner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum AskUpReason {
    /// The decider asked up: by its own answer, or, with `ladder`, as the
    /// decision ladder gave none, for the reason the ladder names
    /// (`uncertain`, `disagreement`, `provider_unavailable`, ...).
    Asked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ladder: Option<String>,
    },
    /// The step took no target in its looks ([`crate::ROUTINE_LOOKS`]).
    Looks,
    /// The decider gave no answer: it failed, or the host gives none.
    NoAnswer,
    /// The decider's answer does not answer the step.
    WrongAnswer,
    /// A strict run's step that only a model could answer, denied before
    /// any model ran, at zero tokens.
    Strict { denied: StrictDenial },
    /// The decider asked to look again where there is no page to look at:
    /// a Fill step's choice among its references (CUA E6).
    Reobserve,
}

/// Why a strict run's step needed a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StrictDenial {
    /// The rule rung ran and gave no answer.
    RuleAbstained,
    /// No rule rung takes the step's question.
    NoRule,
    /// The step reads a screenshot, which only a model reads.
    Image,
    /// A Fill step's text only a writer could write (CUA E6): no writer
    /// was asked.
    FieldGenerationRequiresModel,
}

/// A strict run's routine decision that no model was asked (CUA E2): the
/// record a batch's `decisions` keep for it, under `strict_denied`, when no
/// rung gave a receipt. It names no provider and spent no tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StrictDenied {
    pub denied: StrictDenial,
    /// The question the step asked.
    pub question: String,
    /// The tokens the decision spent: none, as no model ran.
    pub tokens: u64,
}

/// The key a batch's `decisions` entry holds a [`StrictDenied`] under.
pub const STRICT_DENIED: &str = "strict_denied";

impl StrictDenied {
    /// The denied decision of `question`, as a batch's `decisions` list
    /// holds it.
    #[must_use]
    pub fn decision(denied: StrictDenial, question: &str) -> serde_json::Value {
        let record = Self {
            denied,
            question: question.to_owned(),
            tokens: 0,
        };
        let mut decision = serde_json::Map::new();
        decision.insert(
            STRICT_DENIED.to_owned(),
            serde_json::to_value(record).unwrap_or_default(),
        );
        serde_json::Value::Object(decision)
    }
}

/// One check a step or a run's postcondition missed, with what its read of
/// the page found: the row it matched, the cut it read under, and the
/// rebindings it made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckReceipt {
    pub expect: ExpectInput,
    pub observed: ExpectOutput,
}

impl CheckReceipt {
    /// Whether the check is unproven rather than false: no row seen, in a
    /// tree still cut (Rule 5).
    #[must_use]
    pub fn unproven(&self) -> bool {
        !self.observed.met && self.observed.row.is_none() && self.observed.partial.is_some()
    }
}

/// The receipt of the step that stopped a batch, or of a library run's
/// final checks: what goes up with `NEEDS_AGENT` (or `NEEDS_YOU`), so the
/// planner repairs from what the page showed.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FailedStepReceipt {
    /// The step, by index; none for a library run's final checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<usize>,
    pub stop_cause: BatchStopCause,
    /// The checks it missed, each with what its read found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missed: Vec<CheckReceipt>,
    /// The page as read at the stop, as an edit of the batch's base; none
    /// when that read was refused (a person has the browser, or the guest
    /// is gone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
    /// The stop's stable code, as the batch's `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The host's refusal of a page request's destination that stopped the
    /// step, in the host's words (FIX 7406): the batch's `error` names only
    /// its code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<DestinationRefusal>,
}

impl BatchStopCause {
    /// The cause a step's refusal names where the step names none of its
    /// own: a press, a person's hold, a gone locator, a cut read, a
    /// decider's failure, else the browser's own refusal by its code.
    #[must_use]
    pub fn of(error: &BrowserError) -> Self {
        match error {
            BrowserError::NeedsPress(_) => Self::PressNeeded,
            BrowserError::TakenOver(_) | BrowserError::BrowserTakenOver(_) => Self::TakenOver,
            BrowserError::StaleRef(_) => Self::LocatorMissing,
            BrowserError::TreeCut(_) => Self::IncompleteObservation,
            BrowserError::AskUp(_) => Self::DeciderAskedUp {
                reason: AskUpReason::Asked { ladder: None },
            },
            BrowserError::Decider(_) => Self::DeciderAskedUp {
                reason: AskUpReason::NoAnswer,
            },
            other => Self::Browser {
                code: other.code().to_owned(),
            },
        }
    }
}

/// A step that stopped its batch: the refusal its stable code comes from,
/// its cause, the checks it missed, and the receipt of an effect it made
/// before it stopped (a Fill whose field the page did not take).
pub(crate) struct Stop {
    pub(crate) error: BrowserError,
    pub(crate) cause: BatchStopCause,
    pub(crate) missed: Vec<CheckReceipt>,
    pub(crate) receipt: Option<EffectReceipt>,
}

impl Stop {
    pub(crate) fn new(cause: BatchStopCause, error: BrowserError) -> Self {
        Self {
            error,
            cause,
            missed: Vec::new(),
            receipt: None,
        }
    }

    /// An `open` step's refusal: a page that did not load in its time is
    /// the navigation's clock.
    pub(crate) fn opening(error: BrowserError) -> Self {
        match error {
            BrowserError::Timeout(_) => Self::new(
                BatchStopCause::Clock {
                    scope: ClockScope::Navigation,
                },
                error,
            ),
            error => error.into(),
        }
    }

    /// A batch `expect` step's answer: met, or its stop with the check and
    /// what its read found.
    pub(crate) fn checked(check: ExpectInput, observed: ExpectOutput) -> Result<(), Self> {
        if observed.met {
            return Ok(());
        }
        let missed = CheckReceipt {
            expect: check,
            observed,
        };
        let (cause, error) = if missed.unproven() {
            // Rule 5: no row seen in a tree still cut is unproven, not unmet.
            let error = BrowserError::TreeCut("the expected row".to_owned());
            (BatchStopCause::IncompleteObservation, error)
        } else {
            let error = BrowserError::Input(EXPECT_UNMET.to_owned());
            (BatchStopCause::PostconditionUnmet, error)
        };
        Err(Self {
            error,
            cause,
            missed: vec![missed],
            receipt: None,
        })
    }

    /// The stop's stable code, as a batch's `error` names it.
    pub(crate) fn code(&self) -> String {
        match &self.error {
            BrowserError::Input(detail) if detail == EXPECT_UNMET => {
                "browser_expect_unmet".to_owned()
            }
            error => error.code().to_owned(),
        }
    }
}

impl From<BrowserError> for Stop {
    fn from(error: BrowserError) -> Self {
        Self::new(BatchStopCause::of(&error), error)
    }
}

/// Notes `stop`, which stopped a `step` step, in `driver`'s history (CUA
/// E7): its cause and code, and the receipt of an effect it made first.
pub(crate) fn noted<D: BrowserDriver + ?Sized>(driver: &mut D, step: &str, stop: &Stop) {
    driver.note_stop(StepStop {
        step: step.to_owned(),
        cause: stop.cause.clone(),
        error: stop.code(),
        receipt: stop.receipt.as_ref().map(|receipt| receipt.seq),
        effect_class: None,
    });
}

/// `output`, its batch started at `started`, stopped at step `step` by
/// `stop`: a press or a person's hold is a person's (`NEEDS_YOU`), any
/// other stop the planner's (`NEEDS_AGENT`), with the step's receipt and
/// the page as it is at the stop, as an edit of `base`, not as the last
/// effect left it: a read the guest refuses leaves none. An effect the
/// step made before it stopped keeps its receipt.
pub(crate) fn stopped<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    mut output: BatchOutput,
    step: usize,
    stop: Stop,
    base: Option<ObservationBase>,
    started: std::time::Instant,
) -> BatchOutput {
    output.status = if matches!(
        stop.error,
        BrowserError::NeedsPress(_)
            | BrowserError::TakenOver(_)
            | BrowserError::BrowserTakenOver(_)
    ) {
        SubgoalStatus::NeedsYou
    } else {
        SubgoalStatus::NeedsAgent
    };
    output.failed_step = Some(step);
    let code = stop.code();
    let observation = driver
        .observe(ObserveInput {
            base,
            ..ObserveInput::default()
        })
        .ok();
    output.receipts.extend(stop.receipt);
    output.error = Some(code.clone());
    output.stop_cause = Some(stop.cause.clone());
    let refusal = match stop.error {
        BrowserError::DestinationRefused(refusal) => Some(refusal),
        _ => None,
    };
    output.failed_receipt = Some(FailedStepReceipt {
        step: Some(step),
        stop_cause: stop.cause,
        missed: stop.missed,
        observation,
        error: Some(code),
        refusal,
    });
    output.elapsed_ms = elapsed_ms(started);
    output
}

/// The detail of a batch `expect` step's unmet refusal.
const EXPECT_UNMET: &str = "expect_unmet";

/// The milliseconds since `since`, on the monotonic clock: an effect's
/// `duration_ms` and a batch's `elapsed_ms`.
pub(crate) fn elapsed_ms(since: std::time::Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}
