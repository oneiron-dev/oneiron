//! A browser session: one browser guest in a container and the CDP driver
//! attached to it, with the host's rules in front of the driver.
//!
//! The browser runs only inside the isolated guest, never as a process on
//! the host. Cookies and the profile live and die in that guest; raw CDP
//! never leaves this crate.
//!
//! An act resolves its target once: the live handle's own node, still in
//! its document, or, once that node is gone, the row its locator names now,
//! which the answer and the receipt name as `rebound`. The same resolved
//! row is classified, pressed, acted on and receipted.
//!
//! A click whose control name says it sends, pays, signs in, publishes or
//! deletes falls in an effect class. The vault's grant for the class, as
//! the host resolved it into a [`SendPolicy`], decides the press: one per
//! send, one for a reviewed batch, or none. A payment keeps a person's
//! press whatever the policy says. Every effect lands a receipt naming the
//! page it acted on, with a masked screenshot as its evidence when one can
//! be captured. A click at a point takes the press of the row the point
//! lands on, as a click on that row would.
//!
//! A batch's routine steps ask the host's decider, when the host gave the
//! session one; without one they go up to the planner.
//!
//! The host's replay library (OF-598) rides the session too: an `open`
//! lists the site's library programs, and the library verbs check, replay
//! and run programs through this session's own gated verbs. A proposal's
//! replay runs on a fresh guest the host starts for it (`fresh`), never on
//! this session's page.
//!
//! A person can take the browser over (CUA-001), asked by the agent's
//! `handover` or not, to sign in or pay inside the same guest. While the
//! agent waits on its ask, and while a person holds the browser, every agent
//! verb refuses `browser_taken_over` and takes no screenshot; the person sees
//! the viewport and drives the page through the same driver. Handing it back
//! ends the takeover with its record, which is its receipt. The person
//! sees every tab: a popup or a tab a link opens (an OAuth sign-in window)
//! is followed, comes to the front at their next look, and can be named to
//! the screen and input; the tab they leave in front is the one the agent
//! reads after. The agent's own verbs follow the tabs too: a tab its act
//! opens comes to the front, and a front tab that closes gives way to its
//! opener, and the next answer names the move.
//!
//! A long outline is answered in pages (Rule 5): each answer carries as
//! many rows as fit one page, and `next` names the cursor `observe` reads
//! the rest from.
//!
//! The session runs the engine its guest names (FIX 6680): Lightpanda, the
//! one an agent starts on, over the WebSocket its guest's relay carries, or
//! Chromium over its debugging pipe; the fence proof, lease and retention
//! are the same for both. Every receipt names the engine, with the act's
//! fact when the page showed no change; such an act is receipted as every
//! act is.
//!
//! The model moves the page to the other engine with `switch_engine`
//! (`switch`): the host's starter starts the target guest, and the target
//! replaces only the session's engine group (`guest`); the run's state
//! stays, the storage snapshots of the origins its tabs visited with it
//! (`storage`).
//!
//! A host may take custody of the session's requests at attach (FIX 7122,
//! `crate::request`): its handler then performs every request of every
//! engine the session runs, and a destination refusal it gives answers the
//! navigation or act it ended, or the host's own take (`request`).
//!
//! The host's secret custody rides the session too (FIX 8028, OF-560,
//! `crate::secret`): every engine it runs, an engine switch's target among
//! them, and the fresh guest a proposal's replay runs on hand the secrets
//! their reads find to it, and type and expect a handle through it.
//!
//! The host's site skills ride the session too (CUA E10, `site`): an
//! `open` carries the loadable skills of the exact site it landed on,
//! `library.find` lists their seeds as candidates, and `library.propose`
//! takes one by its handle.

mod demonstration;
mod draft;
mod fresh;
mod guest;
mod held;
mod lifecycle;
mod press;
mod request;
mod site;
mod solved;
pub(crate) mod storage;
pub(crate) mod switch;
mod trail;

pub use fresh::FreshGuest;
pub use guest::{BrowserGuestStarter, StartedGuest};
pub use held::{HeldPress, PressNeed};
pub use press::PressGrants;
pub use solved::{CapturedSolvedSpan, SOLVED_PAST_PRESS, SolvedSnapshotGap};

use self::guest::EngineGuest;
pub(crate) use self::press::PressBook;
pub(crate) use self::press::effect_class_on;
use self::storage::{Collector, OriginSnapshots};
use self::switch::OriginHistory;
use self::trail::{Acted, Event, typed_action};
use crate::driver::CdpDriver;
use crate::driver::pages::Base;
use crate::request::{BrowserRequestHandler, Custody};
use crate::retention::HandleRetention;
use crate::secret::{Secrets, entry};
use crate::stop::elapsed_ms;
use crate::{
    AbandonedTakeover, ActionFact, BatchInput, BatchOutput, BatchStopCause, BrowserDriver,
    BrowserEngine, BrowserError, BrowserPersonInput, BrowserTab, ClickInput, CropInput,
    DemonstrationOutput, DemonstrationStartInput, DemonstrationStarted, DemonstrationStopCause,
    DemonstrationStopInput, DraftInput, DraftOutput, EFFECT_ACCOUNT, EFFECT_DESTRUCTIVE,
    EFFECT_PAY, EFFECT_PUBLISH, EFFECT_SEND, EFFECT_UNKNOWN, EffectReceipt, ExpectInput,
    ExpectOutput, FieldWriter, FindInput, FindOutput, HandleInfo, HandoverInput, HandoverOutput,
    ImageOutput, LibraryFindInput, LibraryFindOutput, LibraryRetireInput, LibraryRetireOutput,
    LibraryRetiredInput, LibraryRetiredOutput, LibraryRunInput, LibraryRunOutput, NoDecider,
    NoWriter, Observation, ObservationPage, ObserveInput, OpenInput, PointInput, PressMode,
    ProposeInput, ProposeOutput, Rebound, ReceiptEvidenceSink, ReceiptOutcome, ReplayAction,
    RoutineDecider, Row, ScreenshotInput, ScreenshotOutput, ScreenshotTrigger, SecretCustody,
    SecretKind, SelectInput, SendPolicy, StepStop, StoragePhase, SwitchEngineInput,
    SwitchEngineOutput, TabSwitch, Takeover, TakeoverRecord, TextProvenance, TypeInput,
    TypeOperand, ViewInput, WaitForInput, WaitForOutput, WorkflowLibrary, ZoomInput, site_of,
};
use oneiron_container::{
    EgressRelay, GuestLimits, SessionLease, SessionManifest, SessionTransport,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Words in a control's name that mark its effect class.
const EFFECT_PHRASES: &[(&str, &[&str])] = &[
    (EFFECT_PAY, &["pay"]),
    (EFFECT_PAY, &["buy"]),
    (EFFECT_PAY, &["purchase"]),
    (EFFECT_PAY, &["order"]),
    (EFFECT_PAY, &["checkout"]),
    (EFFECT_PAY, &["donate"]),
    (EFFECT_PAY, &["subscribe"]),
    (EFFECT_PAY, &["transfer"]),
    (EFFECT_ACCOUNT, &["sign", "in"]),
    (EFFECT_ACCOUNT, &["log", "in"]),
    (EFFECT_ACCOUNT, &["login"]),
    (EFFECT_ACCOUNT, &["sign", "up"]),
    (EFFECT_ACCOUNT, &["register"]),
    (EFFECT_PUBLISH, &["publish"]),
    (EFFECT_PUBLISH, &["post"]),
    (EFFECT_DESTRUCTIVE, &["delete"]),
    (EFFECT_DESTRUCTIVE, &["remove"]),
    (EFFECT_SEND, &["send"]),
    (EFFECT_SEND, &["submit"]),
    (EFFECT_SEND, &["invite"]),
    (EFFECT_SEND, &["connect"]),
    (EFFECT_SEND, &["accept"]),
    (EFFECT_SEND, &["confirm"]),
    (EFFECT_SEND, &["book"]),
    (EFFECT_SEND, &["reserve"]),
];

/// How the host starts browser guests. Its bounds are the host's manifest rows.
#[derive(Clone, Debug)]
pub struct BrowserGuest {
    pub runtime: PathBuf,
    pub image: String,
    pub limits: GuestLimits,
    /// The longest `wait_for` one call holds the run for.
    pub wait_cap: Duration,
    /// The press each effect class runs under, from the vault's grants.
    pub policy: SendPolicy,
    /// A host directory served read-only on the guest's loopback, for checks.
    pub fixture: Option<PathBuf>,
    /// The one host:port the run relay's fixture origin
    /// (`http://127.0.0.1:8080`) forwards to, host-side; none unless the
    /// host's config names one, and never beside `fixture` (FIX 8061).
    pub fixture_forward: Option<std::net::SocketAddrV4>,
    /// The engine the guest starts and the driver speaks to.
    pub engine: BrowserEngine,
}

pub struct BrowserSession {
    driver: CdpDriver,
    guest: Box<dyn SessionLease>,
    manifest: SessionManifest,
    policy: SendPolicy,
    /// Every effect's receipt and every step that stopped, in order, on
    /// one sequence (`trail`, CUA E7).
    trail: Vec<Event>,
    receipt_seq: u64,
    /// What the next receipt keeps for a replay, set by the verb that
    /// makes it.
    acted: Option<Acted>,
    /// The stop the last failing effect verb noted, for a batch's stop of
    /// the same step to complete; cleared at every verb's entry.
    stop_pending: Option<u64>,
    /// The effect class whose press refused the effect verb running now.
    press_refused: Option<String>,
    /// The act the last refused press held, and the one press an owner's
    /// answer armed (FIX 10423).
    held: held::Holds,
    /// The history seq the last granted press began after (FIX 10511): a
    /// solved capture ends its span there, before that press.
    pre_press: Option<u64>,
    /// The grants' policy as last read, the person's approved batches and
    /// the sends batch presses paid (FIX 4613, 4615).
    presses: PressBook,
    /// The receipt of the input the running verb sent whose page did not
    /// read after (FIX 8010), for its batch's stop to carry.
    unread: Option<EffectReceipt>,
    decider: Option<Box<dyn RoutineDecider>>,
    /// The host's writer of a Fill's text (CUA E6), lent with the decider.
    field_writer: Option<Box<dyn FieldWriter>>,
    /// Where the text the next type receipt names came from, set by the
    /// type that makes it.
    typed: Option<TextProvenance>,
    library: Option<Box<dyn WorkflowLibrary>>,
    receipt_sink: Option<Box<dyn ReceiptEvidenceSink>>,
    /// Who has the browser now.
    takeover: Takeover,
    /// The takeover that ended since the agent's last answer.
    returned: Option<TakeoverRecord>,
    /// How the host starts a switch's target guest; none where the host
    /// gave none (its readiness check), and `switch_engine` is refused.
    starter: Option<Box<dyn BrowserGuestStarter>>,
    /// The top-level origins the session's tabs visited, across switches.
    history: OriginHistory,
    /// Their stores as last read, across switches; none where the host gave
    /// no starter, so no switch.
    snapshots: Option<Collector>,
    /// The host's custody of the session's requests, shared with each
    /// engine's pipe: its handler, if it gave one, and the refusal not yet
    /// delivered.
    custody: Custody,
    /// How the host starts the fresh guest a proposal's replay runs on;
    /// none where the host gave none, and a proposal is refused.
    fresh: Option<Box<dyn FreshGuest>>,
    /// The host's secret custody, shared with each engine's driver; empty
    /// until the host gives it.
    secrets: Secrets,
    /// The demonstration that records, and those that ended and wait to be
    /// given (CUA E9a), across engine switches.
    demos: demonstration::Demonstrations,
    /// The host's site skills, the last open's matches not yet delivered,
    /// and the seed candidates listed (CUA E10).
    sites: site::SiteSkills,
}

/// One effect verb's receipt facts, known before its input is sent.
struct Effect<'a> {
    verb: &'static str,
    target: Option<&'a Row>,
    class: Option<&'a str>,
    press: PressMode,
    started: Instant,
}

/// What a receipt names of the page its act left: its observation's, or,
/// for an input sent whose page did not read after (FIX 8010), the page as
/// it reads then, else where the act began, and the failure's code.
struct Left {
    url: String,
    title: String,
    rebound: Option<Rebound>,
    fact: Option<ActionFact>,
    unread: Option<String>,
    outcome: Option<ReceiptOutcome>,
}

fn no_library() -> BrowserError {
    BrowserError::Library("this browser host keeps no library".to_owned())
}

/// Whether `url` is a page the browser opens: http or https only.
fn web_page(url: &str) -> bool {
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    matches!(scheme.as_deref(), Some("http" | "https"))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Whether an effect of `class` on `row` may run now under `policy`, and
/// under what press. A spent batch falls back to a press per send.
pub(crate) fn press_for(
    policy: &mut SendPolicy,
    class: &str,
    row: &Row,
) -> Result<PressMode, BrowserError> {
    let refused = || BrowserError::NeedsPress(format!("{} \"{}\" ({class})", row.role, row.name));
    if SendPolicy::person_only(class) {
        return Err(refused());
    }
    match policy.mode_for(class) {
        PressMode::PerSend => Err(refused()),
        PressMode::None => Ok(PressMode::None),
        PressMode::PerBatch => {
            let left = policy.batch.entry(class.to_owned()).or_default();
            if *left == 0 {
                Err(refused())
            } else {
                *left -= 1;
                Ok(PressMode::PerBatch)
            }
        }
    }
}

/// The effect class a control's name marks, when it marks one.
pub(crate) fn effect_class(name: &str) -> Option<&'static str> {
    let words: Vec<String> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    EFFECT_PHRASES.iter().find_map(|(class, phrase)| {
        words
            .windows(phrase.len())
            .any(|w| w.iter().zip(*phrase).all(|(a, b)| a == b))
            .then_some(*class)
    })
}

/// The class a click's receipt names: its target's, or [`EFFECT_UNKNOWN`]
/// for a target with no row or no name.
pub(crate) fn receipt_class(
    class: Option<&'static str>,
    row: Option<&Row>,
) -> Option<&'static str> {
    class.or_else(|| {
        row.is_none_or(|row| row.name.trim().is_empty())
            .then_some(EFFECT_UNKNOWN)
    })
}

impl BrowserSession {
    /// `open`, as [`BrowserDriver::open`] runs it.
    fn open_page(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.agent_has()?;
        if !web_page(&input.url) {
            return Err(BrowserError::Url(input.url));
        }
        self.live()?;
        let source = self.source();
        // The URL asked for, kept apart from the page a redirect left.
        let action = ReplayAction::Open {
            url: input.url.clone(),
        };
        let opened = self.driver.open(input);
        let mut observation = self.crossed(opened)?;
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        let effect = Effect {
            verb: "open",
            target: None,
            class: None,
            press: PressMode::None,
            started,
        };
        self.receipt(&effect, &mut observation);
        self.undelivered()?;
        // Repeated work on a site tries the library first. A lookup that
        // fails leaves the page open without its programs.
        if let Some(site) = site_of(&observation.url)
            && let Some(library) = self.library.as_mut()
        {
            observation.library = library.find(&site, None, None).unwrap_or_default();
        }
        self.site_skills_opened();
        Ok(observation)
    }

    /// `click`, as [`BrowserDriver::click`] runs it.
    fn click_row(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        // A send on a payment step is a payment (FIX 8009).
        let class = effect_class_on(&target.row.name, source.url.as_deref());
        let page = source.url.as_deref();
        let press = self.press_or_hold("click", &input, class, Some(&target.row), page)?;
        let action = ReplayAction::Click {
            locator: target.row.locator.clone(),
        };
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        let effect = Effect {
            verb: "click",
            target: Some(&target.row),
            class: receipt_class(class, Some(&target.row)),
            press,
            started,
        };
        let clicked = self.driver.click_target(&target, &Base::of(input.base));
        let mut observation = self.sent(&effect, clicked)?;
        self.receipt(&effect, &mut observation);
        self.undelivered()?;
        Ok(observation)
    }

    /// `click_at`, as [`BrowserDriver::click_at`] runs it: a point, which
    /// no replay step takes (CUA E7).
    fn click_point(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let (x, y) = self.live()?.point(&input)?;
        let source = self.source();
        let row = self.driver.row_at(x, y)?;
        let page = source.url.as_deref();
        let class = row
            .as_ref()
            .and_then(|row| effect_class_on(&row.name, page));
        let press = self.press_or_hold("click_at", &input, class, row.as_ref(), page)?;
        let base = Base::of(input.base);
        self.acted = Some(Acted {
            action: None,
            source,
        });
        let effect = Effect {
            verb: "click_at",
            target: row.as_ref(),
            class: receipt_class(class, row.as_ref()),
            press,
            started,
        };
        let clicked = self.driver.click_point(x, y, row.as_ref(), &base);
        let mut observation = self.sent(&effect, clicked)?;
        self.receipt(&effect, &mut observation);
        self.undelivered()?;
        Ok(observation)
    }

    /// `select`, as [`BrowserDriver::select`] runs it.
    fn select_option(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        let base = Base::of(input.base);
        let action = ReplayAction::Select {
            locator: target.row.locator.clone(),
            option: input.option.clone(),
        };
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        let effect = Effect {
            verb: "select",
            target: Some(&target.row),
            class: None,
            press: PressMode::None,
            started,
        };
        let selected = self.driver.select_target(&target, &input.option, &base);
        let mut observation = self.sent(&effect, selected)?;
        self.receipt(&effect, &mut observation);
        self.undelivered()?;
        Ok(observation)
    }
}

impl BrowserDriver for BrowserSession {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        self.acting("open", |session| session.open_page(input))
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        self.live()?.observe(input)
    }

    fn observe_hidden(&mut self) -> Result<Observation, BrowserError> {
        self.live()?.observe_hidden()
    }

    fn paged(&mut self, mut observation: Observation) -> ObservationPage {
        self.deliver_site_skills(&mut observation);
        self.driver.paged(observation)
    }

    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        self.live()?.observe_page(input)
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        self.live()?.find(input)
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        self.acting("click", |session| session.click_row(input))
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        self.acting("click_at", |session| session.click_point(input))
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        self.acting("type", |session| {
            session.type_as(input, TextProvenance::supplied())
        })
    }

    fn fill_text(
        &mut self,
        input: TypeInput,
        provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        self.acting("type", |session| session.type_as(input, provenance))
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        self.acting("select", |session| session.select_option(input))
    }

    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError> {
        self.live()?.wait_for(input)
    }

    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError> {
        self.live()?.expect(input)
    }

    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError> {
        self.live()?.screenshot(input)
    }

    fn view(&mut self, input: ViewInput) -> Result<ImageOutput, BrowserError> {
        self.live()?.view(input)
    }

    fn crop(&mut self, input: CropInput) -> Result<ImageOutput, BrowserError> {
        self.live()?.crop(input)
    }

    fn zoom(&mut self, input: ZoomInput) -> Result<ImageOutput, BrowserError> {
        self.live()?.zoom(input)
    }

    fn image_bytes(&self, image: &str) -> Option<Vec<u8>> {
        self.driver.image(image).map(<[u8]>::to_vec)
    }

    fn handle_info(&self, handle: &str) -> Option<HandleInfo> {
        self.driver.handle_info(handle)
    }

    fn secret_kind(&self, handle: &str) -> Option<SecretKind> {
        self.secrets.kind_of(handle)
    }

    fn library_find(&mut self, input: LibraryFindInput) -> Result<LibraryFindOutput, BrowserError> {
        self.agent_has()?;
        let (site, page) = self.find_query(input.site.as_deref(), input.url.as_deref())?;
        let library = self.library.as_mut().ok_or_else(no_library)?;
        let workflows = library.find(&site, input.subgoal.as_deref(), input.type_ref.as_deref())?;
        let (candidates, site_skill_notes) = self.find_candidates(page.as_deref());
        Ok(LibraryFindOutput {
            site,
            workflows,
            candidates,
            site_skill_notes,
        })
    }

    fn library_propose(&mut self, input: ProposeInput) -> Result<ProposeOutput, BrowserError> {
        self.agent_has()?;
        let input = self.seeded_proposal(input)?;
        let mut library = self.library.take().ok_or_else(no_library)?;
        let output = self.propose(library.as_mut(), input);
        self.library = Some(library);
        output
    }

    fn library_run(&mut self, input: LibraryRunInput) -> Result<LibraryRunOutput, BrowserError> {
        // A run refused mid-takeover would count as a missed postcondition.
        self.agent_has()?;
        self.stop_pending = None;
        self.site_skills_unsent();
        let mut output = self.with_library(|session, library, decider, writer| {
            crate::library::run(session, library, decider, writer, input)
        })?;
        self.deliver_batch_site_skills(&mut output.batch);
        self.page_batch(&mut output.batch);
        Ok(output)
    }

    fn library_retire(
        &mut self,
        input: LibraryRetireInput,
    ) -> Result<LibraryRetireOutput, BrowserError> {
        self.agent_has()?;
        let library = self.library.as_mut().ok_or_else(no_library)?;
        let retired = library
            .retire(&input.workflow, input.reason.as_deref())?
            .ok_or(BrowserError::NoWorkflow(input.workflow))?;
        Ok(LibraryRetireOutput { retired })
    }

    fn library_retired(
        &mut self,
        input: LibraryRetiredInput,
    ) -> Result<LibraryRetiredOutput, BrowserError> {
        self.agent_has()?;
        let site = match input.site {
            Some(site) => site.trim().to_ascii_lowercase(),
            None => site_of(&self.live()?.url()?).ok_or_else(|| {
                BrowserError::Input("the open page has no site; name one".to_owned())
            })?,
        };
        let library = self.library.as_mut().ok_or_else(no_library)?;
        Ok(LibraryRetiredOutput {
            retired: library.retired(&site)?,
            site,
        })
    }

    fn library_draft(&mut self, input: DraftInput) -> Result<DraftOutput, BrowserError> {
        self.agent_has()?;
        self.draft(input)
    }

    fn note_stop(&mut self, stop: StepStop) {
        self.noted(stop);
    }

    fn sent_receipt(&mut self) -> Option<EffectReceipt> {
        self.unread.take()
    }

    fn typed_operand(&self, target: &str) -> Option<TypeOperand> {
        self.typed_into(target)
    }

    fn viewport_offset(&self) -> Option<(f64, f64)> {
        self.driver.scroll_now().ok()
    }

    fn withdraw_no_progress(&mut self) {
        self.withdraw(&BatchStopCause::NoProgress);
    }

    fn demonstration_start(
        &mut self,
        input: DemonstrationStartInput,
    ) -> Result<DemonstrationStarted, BrowserError> {
        self.demonstration_begin(input)
    }

    fn demonstration_stop(
        &mut self,
        input: DemonstrationStopInput,
    ) -> Result<DemonstrationOutput, BrowserError> {
        self.demonstration_end(input)
    }

    fn handover(&mut self, input: HandoverInput) -> Result<HandoverOutput, BrowserError> {
        self.live()?;
        // The reason stands whole, as given (FIX 8012): blankness alone
        // refuses it, never its length.
        let HandoverInput {
            reason,
            demonstrate,
        } = input;
        if reason.trim().is_empty() {
            return Err(BrowserError::Input(
                "a handover gives its reason".to_owned(),
            ));
        }
        let asked_at_ms = now_ms();
        self.recording_close(DemonstrationStopCause::HandedOver);
        // An ask that opts in records the span of the person who takes it
        // (CUA E9b).
        self.takeover_asked(demonstrate.then(|| reason.clone()));
        self.takeover = Takeover::Waiting {
            reason: reason.clone(),
            asked_at_ms,
        };
        Ok(HandoverOutput {
            reason,
            asked_at_ms,
        })
    }

    fn switch_engine(
        &mut self,
        input: SwitchEngineInput,
    ) -> Result<SwitchEngineOutput, BrowserError> {
        let output = self.switch_to(input)?;
        self.undelivered()?;
        Ok(output)
    }

    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        self.stop_pending = None;
        self.site_skills_unsent();
        let mut decider = self.decider.take();
        let writer = self.field_writer.take();
        let lent: &dyn FieldWriter = match writer.as_deref() {
            Some(writer) => writer,
            None => &NoWriter,
        };
        let output = match decider.as_deref_mut() {
            Some(decider) => self.batch_with(input, decider, lent),
            None => self.batch_with(input, &mut NoDecider, lent),
        };
        self.decider = decider;
        self.field_writer = writer;
        let mut output = output?;
        self.deliver_batch_site_skills(&mut output);
        self.page_batch(&mut output);
        Ok(output)
    }
}
