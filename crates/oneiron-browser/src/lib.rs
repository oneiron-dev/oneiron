//! Browser verbs for code mode (`self.browser.*`), and the CDP driver
//! behind them (feature `driver`).
//!
//! A program reads the page as an outline of rows. Each row has a live
//! `ref`, a handle bound to its DOM node in its document and never reused
//! within the session, and a `locator` built from its role, its accessible
//! name and its named ancestors, never from its position, which replay
//! programs store (AB-001). An act on a handle whose node is gone acts on
//! the row its locator names now and says so (`rebound`). Every action waits
//! for the page to settle and returns the next observation, whole or as an
//! ordered edit of one the caller holds (AB-002).
//!
//! The same verbs drive a Linux desktop (`self.desktop.*`, OF-523): one
//! window of an isolated desktop guest, read as rows from its accessibility
//! tree through cua-driver, with keys, hotkeys, scrolling and the guest's
//! windows on top.

use crate::observation::rows_named;
use serde::{Deserialize, Serialize};

mod answer;
#[cfg(feature = "driver")]
mod capture;
#[cfg(feature = "driver")]
mod cdp;
mod contract;
mod demonstration;
#[cfg(feature = "driver")]
mod desktop;
#[cfg(feature = "driver")]
mod driver;
mod engine;
mod fact;
mod field;
mod library;
#[cfg(feature = "driver")]
mod mcp;
mod observation;
#[cfg(feature = "driver")]
mod outline;
mod programs;
mod progress;
mod receipt_evidence;
mod replay;
mod request;
mod retention;
mod row;
mod secret;
mod secret_fields;
#[cfg(feature = "driver")]
mod session;
pub mod site;
mod stop;
mod switch;
mod verbs;

pub use answer::{
    BrowserAnswer, DesktopAnswer, SessionFenceProof, SessionManifest, SessionSeccomp,
    TakeoverRecord, WindowSwitch, WindowSwitchCause,
};
pub use demonstration::{
    DemonstrationId, DemonstrationOutput, DemonstrationSource, DemonstrationStartInput,
    DemonstrationStarted, DemonstrationStopCause, DemonstrationStopInput, LocatorGap, RecordedStep,
    RecordingGap, RecordingGapKind,
};
#[cfg(feature = "driver")]
pub use desktop::{AbandonedTakeover, DesktopGuest, DesktopSession, PersonInput, Takeover};
pub use engine::BrowserEngine;
pub use fact::{ActionFact, ActionTarget, DialogAnswerFailure, NoEffectReason, ViewportPoint};
pub use field::{
    FIELD_WRITER, FieldSpec, FieldTextReason, FieldWrite, FieldWriteError, FieldWriter,
    FieldWritten, NoWriter, TextCheck, TextCheckReply, TextProvenance, TextReference, TextSource,
    TextVerdict,
};
pub use library::{
    AdmissionRefusal, Admitted, DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput,
    DraftPage, DraftStep, FiledWorkflow, LibraryCard, LibraryFindInput, LibraryFindOutput,
    LibraryRetireInput, LibraryRetireOutput, LibraryRetiredInput, LibraryRetiredOutput,
    LibraryRunInput, LibraryRunMode, LibraryRunOutput, PressedThrough, ProposeInput, ProposeOutput,
    RecentCounts, ReplayGuest, RetiredCard, RunOutcome, SecretArg, SecretParam, SlotCandidate,
    SlotField, SupersedeOutcome, SupersedeRefusal, WorkflowCheck, WorkflowLibrary, WorkflowProgram,
    WorkflowProof, WorkflowSeed, default_mode, draft_from_steps, effective_mode, model_free,
    site_of, validate_replay_args,
};
#[cfg(feature = "driver")]
pub use library::{filled_checks, program_origin};
pub use observation::{
    HandleInfo, ObservationBase, Rebound, RowSplice, StepRebound, is_live_handle,
};
#[cfg(feature = "driver")]
pub use oneiron_container::{GuestLimits, ImageRef};
pub use progress::NO_PROGRESS_STEPS;
use progress::Progress;
pub use receipt_evidence::{ReceiptEvidence, ReceiptEvidenceSink};
pub use replay::{OperandGap, ReplayAction, StepStop, TypeOperand};
pub use request::DestinationRefusal;
#[cfg(feature = "driver")]
pub use request::{BrowserRequestHandler, RenderedDocument};
pub use retention::HandleRetention;
pub use row::{Row, RowFieldGap, RowGapField, RowGapReason};
pub use secret::{SecretCustody, SecretUse};
pub use secret_fields::{RowSecret, SecretKind, SecretNote};
#[cfg(feature = "driver")]
pub use session::{
    BrowserGuest, BrowserGuestStarter, BrowserSession, CapturedSolvedSpan, FreshGuest, PressGrants,
    SOLVED_PAST_PRESS, SolvedSnapshotGap, StartedGuest,
};
pub use site::{
    OriginError, SeedBody, SeedCandidate, SiteOrigin, SiteSkillError, SiteSkillErrorCode,
    SiteSkillLoader, SiteSkillMatch, SiteSkillQuery,
};
pub use stop::{
    AskUpReason, BatchStopCause, CheckReceipt, ClockScope, FailedStepReceipt, STRICT_DENIED,
    StrictDenial, StrictDenied,
};
use stop::{Stop, elapsed_ms};
pub use switch::{
    EngineSwitchRecord, StoragePhase, SwitchCarried, SwitchComponent, SwitchEngineInput,
    SwitchEngineOutput, SwitchLoss, SwitchNotCarried, SwitchOutcome, SwitchStage,
};

pub use contract::{BrowserDriver, paged};
pub use programs::{
    BatchInput, BatchOutput, BatchStep, BrowserPersonInput, BrowserTab, DecideStep, DesktopWindow,
    EFFECT_ACCOUNT, EFFECT_CLASSES, EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH, EFFECT_SEND,
    EFFECT_UNKNOWN, HandoverInput, HandoverOutput, NoDecider, PressMode, ROUTINE_LOOKS,
    ROUTINE_WAIT_MS, RoutineAnswer, RoutineAsk, RoutineDecider, RoutineReply, SendPolicy,
    SubgoalStatus, WindowInput, WindowsInput, WindowsOutput,
};
pub use verbs::{
    ClickInput, CropInput, EffectReceipt, ExpectInput, ExpectOutput, FindInput, FindOutput,
    HotkeyInput, ImageOutput, KeyInput, Observation, ObservationPage, ObserveInput, OpenInput,
    PartialTree, PointInput, ScreenshotInput, ScreenshotOutput, ScreenshotTrigger, ScrollDirection,
    ScrollInput, SelectInput, TabSwitch, TabSwitchCause, TypeInput, ViewInput, WaitForInput,
    WaitForOutput, ZoomInput,
};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum BrowserError {
    #[error("this run has no browser")]
    Unbound,
    #[error("invalid browser verb input: {0}")]
    Input(String),
    #[error("the browser guest could not start: {0}")]
    Unavailable(String),
    #[error("the browser guest is gone")]
    GuestLost,
    #[error("the browser sandbox was abandoned after its bridge reconnect window")]
    Abandoned,
    #[error("no element has ref {0} now; observe again")]
    StaleRef(String),
    #[error("element {0} is covered by another element")]
    Covered(String),
    #[error("element {0} is not a <select> with that option")]
    NoOption(String),
    #[error("{0} needs a person's press: the action would send, pay, submit or sign in")]
    NeedsPress(String),
    #[error("this session holds no image {0}")]
    NoImage(String),
    #[error("only http and https pages open: {0}")]
    Url(String),
    #[error("navigation failed: {0}")]
    Navigation(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    /// FIX 8046: a protocol call the engine did not answer in its time (a
    /// CDP method, a desktop driver's tool), by its name. Its code is the
    /// timeout's own; a batch names it the protocol's clock.
    #[error("timed out waiting for {0}")]
    CallTimeout(String),
    #[error("browser protocol: {0}")]
    Protocol(String),
    #[error("image {0} no longer shows the page as it is; take a new screenshot")]
    StaleImage(String),
    #[error("the routine step went up to the planner: {0}")]
    AskUp(String),
    #[error("the routine decider gave no answer: {0}")]
    Decider(String),
    #[error("the library holds no workflow {0}")]
    NoWorkflow(String),
    /// FIX 8073: the workflow a run named was retired, as the library's
    /// record of its retire proves; one with no record stays `NoWorkflow`.
    #[error("the library's workflow {0} was retired")]
    WorkflowRetired(String),
    #[error("the workflow library failed: {0}")]
    Library(String),
    #[error("this driver does not serve {0}")]
    Unsupported(String),
    #[error("a person has the desktop ({0}); it answers again once they hand it back")]
    TakenOver(String),
    #[error("a person has the browser ({0}); it answers again once they hand it back")]
    BrowserTakenOver(String),
    /// Rule 5: a cut tree is no proof a row is gone, so an act on a row the
    /// longest walk on never reached answers this, not `StaleRef`.
    #[error(
        "the window's tree walk stopped before its end at its longest and never reached {0}; observe and walk on with walk_next"
    )]
    TreeCut(String),
    /// C013: the host's memory floor will not admit the live handles a
    /// read would add. Nothing was minted; the session and the handles it
    /// already gave out stay.
    #[error(
        "the host's memory floor admits no more live handles for this browser now; handles already given out still work"
    )]
    MemoryFloor,
    /// FIX 7122: the host's request handler refused a page request's
    /// destination by the host's own rule, in the host's own words. It
    /// carries the host's refusal; it is no refusal class of the browser's.
    #[error("the host refused a page request's destination: {0}")]
    DestinationRefused(DestinationRefusal),
    /// FIX 8028: the secret a type or expect named is not one this run's
    /// host holds for it (another run's, erased, or no custody at all); no
    /// byte of it was sent or compared.
    #[error("the browser's host refused the secret: {0}")]
    SecretRefused(String),
    /// CUA E6: a Fill step's text was not resolved, or the page did not
    /// take it; its batch names the cause.
    #[error("the fill step's text: {0}")]
    FieldText(String),
    /// CUA E10: a site skill's seed a proposal named did not resolve, or
    /// its bytes changed since its candidate was listed.
    #[error("the site skill: {0}")]
    SiteSkill(SiteSkillError),
}

/// Candidates one routine Choice offers: the contract's 64 options less
/// NONE, reobserve and "too complicated, ask up". A step with more asks
/// them in pages of this many (Rule 5), never refused or cut.
pub const ROUTINE_MAX_CANDIDATES: usize = 61;

/// A batch's routine steps: the decider, the subgoal's one clock, the NONE
/// and reobserve answers in a row, the decisions taken, the batch's base,
/// and the targets an acting step matched by their locators.
struct Routine<'d> {
    decider: &'d mut dyn RoutineDecider,
    until_ms: Option<u64>,
    no_model: bool,
    misses: u32,
    decisions: Vec<serde_json::Value>,
    base: Option<ObservationBase>,
    rebindings: Vec<Rebound>,
}

impl Routine<'_> {
    /// A step's wait for a row: [`ROUTINE_WAIT_MS`], or what is left of the
    /// subgoal's clock when that ends sooner.
    fn wait_ms(&self) -> u32 {
        let Some(until) = self.until_ms else {
            return ROUTINE_WAIT_MS;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        u32::try_from(until.saturating_sub(now))
            .unwrap_or(u32::MAX)
            .min(ROUTINE_WAIT_MS)
    }

    /// One routine step: look, ask, act. A look reads the outline, and a
    /// screenshot too for a locate step or once the trail says so. A step
    /// that goes up names its cause.
    fn step<D: BrowserDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        step: DecideStep,
    ) -> Result<Observation, Stop> {
        let entries = [
            step.text.is_some(),
            step.secret.is_some(),
            step.option.is_some(),
        ];
        let entered = entries.iter().filter(|named| **named).count();
        if entered > 1 || (step.locate && (entered > 0 || !step.targets.is_empty())) {
            return Err(BrowserError::Input(
                "a decide step types text, types a secret or selects an option, and a locate step only clicks"
                    .to_owned(),
            )
            .into());
        }
        let query = FindInput {
            role: step.role.clone(),
            name: step.name.clone(),
            cursor: None,
        };
        let mut trigger = step.locate.then_some(ScreenshotTrigger::OutlineThin);
        // No row matches the step: unproven past a cut, the subgoal's clock
        // when it left no time to wait (`clock`), else a missing locator.
        let no_row = |page: &Observation, clock: bool| {
            if page.partial.is_some() {
                let error = BrowserError::AskUp(
                    "no row before the cut of the window's tree walk matches the step; observe and walk on with its walk_next".to_owned(),
                );
                return Stop::new(BatchStopCause::IncompleteObservation, error);
            }
            let cause = if clock {
                BatchStopCause::Clock {
                    scope: ClockScope::Decision,
                }
            } else {
                BatchStopCause::LocatorMissing
            };
            let error = BrowserError::AskUp("no row on the page matches the step".to_owned());
            Stop::new(cause, error)
        };
        let mut waited = false;
        let mut looks = 0;
        while looks < ROUTINE_LOOKS {
            // A look the caller never sees: whole, never its base, and
            // never aging out one (FIX 8510).
            let page = driver.observe_hidden()?;
            // A desktop window with no tree is read by its pixels: a step
            // that only clicks locates its target in a screenshot there.
            let blind = page.no_tree
                && step.text.is_none()
                && step.secret.is_none()
                && step.option.is_none()
                && step.targets.is_empty();
            let locate = step.locate || blind;
            let look = match trigger {
                Some(ScreenshotTrigger::DeciderReobserve) => trigger,
                _ if blind => Some(ScreenshotTrigger::NoAccessibilityTree),
                _ => trigger,
            };
            // Named targets match their own rows, or, a handle whose node
            // is gone, the row its locator names now, as a rebinding.
            let (candidates, rebindings): (Vec<(String, Row)>, Vec<Rebound>) = if locate {
                (Vec::new(), Vec::new())
            } else if step.targets.is_empty() {
                let matched = page
                    .rows
                    .iter()
                    .filter(|row| query.matches(row))
                    .map(|row| (candidate(row), row.clone()))
                    .collect();
                (matched, Vec::new())
            } else {
                let (named, rebindings) =
                    rows_named(&step.targets, &page.rows, &page.scope, |target| {
                        driver.handle_info(target)
                    });
                let named = named
                    .into_iter()
                    .map(|row| (candidate(&row), row))
                    .collect();
                (named, rebindings)
            };
            if !locate && candidates.is_empty() {
                // One bounded wait for the step's targets, or its role and
                // name, then a fresh look. A window with no tree grows no
                // rows, so it does not wait.
                let wait = self.wait_ms();
                if waited || page.no_tree || wait == 0 {
                    return Err(no_row(&page, !waited && !page.no_tree && wait == 0));
                }
                waited = true;
                let rows = driver.wait_for(WaitForInput {
                    targets: step.targets.clone(),
                    role: step.role.clone(),
                    name: step.name.clone(),
                    timeout_ms: Some(wait),
                    cursor: None,
                })?;
                if rows.timed_out {
                    return Err(no_row(&page, false));
                }
                continue;
            }
            looks += 1;
            let shot = match look {
                Some(trigger) => {
                    let shot = driver.screenshot(ScreenshotInput {
                        trigger,
                        since_capture: None,
                    })?;
                    let png = driver
                        .image_bytes(&shot.image)
                        .ok_or_else(|| BrowserError::NoImage(shot.image.clone()))?;
                    Some((shot.image, png))
                }
                None => None,
            };
            let labels: Vec<String> = candidates.iter().map(|(label, _)| label.clone()).collect();
            let reply = self.ask(&step.question, &labels, shot.as_ref(), look_state(&page))?;
            match reply.answer {
                RoutineAnswer::Act { candidate } if !locate => {
                    self.misses = 0;
                    let target = candidates
                        .into_iter()
                        .find(|(label, _)| *label == candidate)
                        .map(|(_, row)| row.target)
                        .ok_or_else(|| {
                            let error =
                                BrowserError::Decider(format!("{candidate} is not a candidate"));
                            Stop::new(asked_up(AskUpReason::WrongAnswer), error)
                        })?;
                    self.rebindings.extend(rebindings);
                    let base = self.base.clone();
                    let acted = match (step.text, step.secret, step.option) {
                        (text, secret, _) if text.is_some() || secret.is_some() => driver
                            .type_text(TypeInput {
                                target,
                                text,
                                secret,
                                clear: step.clear,
                                base,
                            }),
                        (_, _, Some(option)) => driver.select(SelectInput {
                            target,
                            option,
                            base,
                        }),
                        (_, _, None) => driver.click(ClickInput { target, base }),
                    };
                    return acted.map_err(Stop::from);
                }
                RoutineAnswer::Point { x, y } if locate => {
                    self.misses = 0;
                    let (image, _) = shot.ok_or_else(|| {
                        let error =
                            BrowserError::Decider("a point without a screenshot".to_owned());
                        Stop::new(asked_up(AskUpReason::WrongAnswer), error)
                    })?;
                    let clicked = driver.click_at(PointInput {
                        image,
                        x,
                        y,
                        base: self.base.clone(),
                    });
                    return clicked.map_err(Stop::from);
                }
                // A window whose tree walk was cut offered only the rows
                // before the cut: none of them fits, so the step goes up
                // rather than look again at the same cut.
                RoutineAnswer::None if !locate && page.partial.is_some() => {
                    let error = BrowserError::AskUp(
                        "the window's tree walk stopped before its end and no row before the cut fits; observe and walk on with its walk_next".to_owned(),
                    );
                    return Err(Stop::new(BatchStopCause::IncompleteObservation, error));
                }
                RoutineAnswer::None | RoutineAnswer::Reobserve => {
                    self.misses = self.misses.saturating_add(1);
                    trigger = if reply.screenshot {
                        Some(ScreenshotTrigger::DeciderReobserve)
                    } else {
                        step.locate.then_some(ScreenshotTrigger::OutlineThin)
                    };
                }
                RoutineAnswer::AskUp { reason } => {
                    let detail = reason.as_deref().unwrap_or("the decider asked up");
                    let detail = detail.to_owned();
                    let reason = AskUpReason::Asked { ladder: reason };
                    return Err(Stop::new(asked_up(reason), BrowserError::AskUp(detail)));
                }
                RoutineAnswer::Denied { denial } => {
                    let error = BrowserError::AskUp(format!(
                        "a strict run's step only a model could answer ({denial:?}); no model was asked"
                    ));
                    let reason = AskUpReason::Strict { denied: denial };
                    return Err(Stop::new(asked_up(reason), error));
                }
                RoutineAnswer::Deadline => {
                    let error = BrowserError::AskUp(
                        "the subgoal's clock ran out before the decider answered".to_owned(),
                    );
                    let scope = ClockScope::Decision;
                    return Err(Stop::new(BatchStopCause::Clock { scope }, error));
                }
                other => {
                    let error =
                        BrowserError::Decider(format!("{other:?} does not answer this step"));
                    return Err(Stop::new(asked_up(AskUpReason::WrongAnswer), error));
                }
            }
        }
        let error = BrowserError::AskUp(format!("no target after {ROUTINE_LOOKS} looks"));
        Err(Stop::new(asked_up(AskUpReason::Looks), error))
    }

    /// One look's ask (Rule 5): the step's candidates, by their labels in
    /// row order, in pages of at most [`ROUTINE_MAX_CANDIDATES`], or none
    /// for a locate step. Many candidates are never refused, cut or
    /// sampled: NONE on a page with more after it asks the next page, and
    /// any other answer, or NONE on the last page, is the look's. Each page
    /// is its own decision, asked under the look's misses, and `state`, the
    /// page the look read, names the page of candidates too.
    fn ask(
        &mut self,
        question: &str,
        candidates: &[String],
        shot: Option<&(String, Vec<u8>)>,
        mut state: serde_json::Value,
    ) -> Result<RoutineReply, BrowserError> {
        let offered: Vec<&[String]> = if candidates.is_empty() {
            vec![candidates]
        } else {
            candidates.chunks(ROUTINE_MAX_CANDIDATES).collect()
        };
        let pages = offered.len();
        for (index, offered) in offered.into_iter().enumerate() {
            if pages > 1 {
                state["candidates"] = serde_json::json!({
                    "page": index + 1,
                    "pages": pages,
                    "rows": candidates.len(),
                });
            }
            let mut reply = self.decider.decide(RoutineAsk {
                question,
                options: offered.to_vec(),
                image: shot.map(|(image, png)| (image.as_str(), png.as_slice())),
                state: state.clone(),
                misses: self.misses,
                until_ms: self.until_ms,
                no_model: self.no_model,
            })?;
            self.until_ms = reply.until_ms.or(self.until_ms);
            self.decisions.push(std::mem::take(&mut reply.decision));
            if index + 1 == pages || !matches!(reply.answer, RoutineAnswer::None) {
                return Ok(reply);
            }
        }
        Err(BrowserError::Decider("the look asked no page".to_owned()))
    }
}

/// What a look's ask reads of `page`: its URL and title, and its cut.
fn look_state(page: &Observation) -> serde_json::Value {
    let mut state = serde_json::json!({"url": page.url, "title": page.title});
    if let Some(partial) = &page.partial {
        state["partial"] = serde_json::json!(partial);
    }
    state
}

/// A routine step's ask-up, for `reason`.
fn asked_up(reason: AskUpReason) -> BatchStopCause {
    BatchStopCause::DeciderAskedUp { reason }
}

/// A row as a routine Choice offers it: its role and name, then its
/// locator, which tells twins apart and reads the same in every session,
/// so a rule standing for the step still answers it. An option holds at
/// most 256 bytes.
fn candidate(row: &Row) -> String {
    let mut label = format!("{} \"{}\"", row.role, row.name);
    if label.len() > 200 {
        let mut end = 200;
        while !label.is_char_boundary(end) {
            end -= 1;
        }
        label.truncate(end);
        label.push('…');
    }
    format!("{label} [{}]", row.locator)
}

impl BrowserError {
    /// The stable code a refused verb call answers with. A program reads only
    /// this; the detail stays in the host's log.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unbound => "browser_unbound",
            Self::Input(_) => "browser_input_invalid",
            Self::Unavailable(_) => "browser_unavailable",
            Self::GuestLost => "browser_guest_lost",
            Self::Abandoned => "browser_guest_abandoned",
            Self::StaleRef(_) => "browser_stale_ref",
            Self::Covered(_) => "browser_covered",
            Self::NoOption(_) => "browser_no_option",
            Self::NeedsPress(_) => "needs_press",
            Self::NoImage(_) => "browser_no_image",
            Self::Url(_) => "browser_url_refused",
            Self::Navigation(_) => "browser_navigation_failed",
            Self::Timeout(_) | Self::CallTimeout(_) => "browser_timeout",
            Self::Protocol(_) => "browser_protocol",
            Self::StaleImage(_) => "browser_stale_image",
            Self::AskUp(_) => "routine_ask_up",
            Self::Decider(_) => "routine_decider_failed",
            Self::NoWorkflow(_) => "browser_no_workflow",
            Self::WorkflowRetired(_) => "workflow_retired",
            Self::Library(_) => "browser_library_failed",
            Self::Unsupported(_) => "browser_unsupported",
            Self::TakenOver(_) => "desktop_taken_over",
            Self::BrowserTakenOver(_) => "browser_taken_over",
            Self::TreeCut(_) => "desktop_tree_cut",
            Self::MemoryFloor => "browser_memory_floor",
            Self::DestinationRefused(_) => "browser_destination_refused",
            Self::SecretRefused(_) => "browser_secret_refused",
            Self::FieldText(_) => "browser_field_text",
            Self::SiteSkill(_) => "browser_site_skill",
        }
    }
}
