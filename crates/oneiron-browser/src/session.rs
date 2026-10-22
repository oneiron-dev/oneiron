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

mod demonstration;
mod draft;
mod fresh;
mod guest;
mod request;
pub(crate) mod storage;
pub(crate) mod switch;
mod trail;

pub use fresh::FreshGuest;
pub use guest::{BrowserGuestStarter, StartedGuest};

use self::guest::EngineGuest;
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
    AbandonedTakeover, BatchInput, BatchOutput, BrowserDriver, BrowserEngine, BrowserError,
    BrowserPersonInput, BrowserTab, ClickInput, CropInput, DemonstrationOutput,
    DemonstrationStartInput, DemonstrationStarted, DemonstrationStopCause, DemonstrationStopInput,
    DraftInput, DraftOutput, EFFECT_ACCOUNT, EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH,
    EFFECT_SEND, EFFECT_UNKNOWN, EffectReceipt, ExpectInput, ExpectOutput, FieldWriter, FindInput,
    FindOutput, HandleInfo, HandoverInput, HandoverOutput, ImageOutput, LibraryFindInput,
    LibraryFindOutput, LibraryRetireInput, LibraryRetireOutput, LibraryRetiredInput,
    LibraryRetiredOutput, LibraryRunInput, LibraryRunOutput, NoDecider, NoWriter, Observation,
    ObservationPage, ObserveInput, OpenInput, PointInput, PressMode, ProposeInput, ProposeOutput,
    ReceiptEvidenceSink, ReplayAction, RoutineDecider, Row, ScreenshotInput, ScreenshotOutput,
    ScreenshotTrigger, SecretCustody, SecretKind, SelectInput, SendPolicy, StepStop, StoragePhase,
    SwitchEngineInput, SwitchEngineOutput, TabSwitch, Takeover, TakeoverRecord, TextProvenance,
    TypeInput, ViewInput, WaitForInput, WaitForOutput, WorkflowLibrary, ZoomInput, site_of,
};
use oneiron_container::{
    EgressRelay, GuestLimits, SessionLease, SessionManifest, SessionTransport,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The longest reason a `handover` ask may give, in characters.
const HANDOVER_REASON_CHARS: usize = 500;

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
}

impl BrowserSession {
    /// The engine selects and proves a backend before attaching the browser.
    /// A lower driver crate must never silently select a weaker backend.
    /// The session's live-handle registry is charged to the host's memory
    /// floor through `retention` (C013). A session given the host's
    /// `starter` serves `switch_engine`. A session given the host's
    /// `requests` handler has it perform every request of its pages in
    /// place of `relay`, from before any page loads (FIX 7122); one given
    /// none takes `relay` as always.
    pub fn attach(
        config: &BrowserGuest,
        transport: SessionTransport,
        relay: Arc<dyn EgressRelay>,
        retention: Box<dyn HandleRetention>,
        starter: Option<Box<dyn BrowserGuestStarter>>,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<Self, BrowserError> {
        let started = StartedGuest {
            transport,
            relay,
            retention,
        };
        let snapshots = starter
            .as_ref()
            .map(|starter| OriginSnapshots::collector(starter.state_charge()));
        let sink = snapshots.as_ref().map(OriginSnapshots::sink);
        let custody = Custody::new(requests);
        let secrets = Secrets::default();
        let (engine, wait_cap) = (config.engine, config.wait_cap);
        let attached = EngineGuest::attach(
            engine,
            started,
            wait_cap,
            sink,
            custody.clone(),
            secrets.clone(),
        );
        let EngineGuest {
            driver,
            lease,
            manifest,
        } = attached?;
        Ok(Self {
            driver,
            guest: lease,
            manifest,
            policy: config.policy.clone(),
            trail: Vec::new(),
            receipt_seq: 0,
            acted: None,
            stop_pending: None,
            press_refused: None,
            decider: None,
            field_writer: None,
            typed: None,
            library: None,
            receipt_sink: None,
            takeover: Takeover::Agent,
            returned: None,
            starter,
            history: OriginHistory::default(),
            snapshots,
            custody,
            fresh: None,
            secrets,
            demos: demonstration::Demonstrations::default(),
        })
    }

    /// Gives the session the host's secret custody (FIX 8028): the secrets
    /// its reads find from now on become handles bound to its run, and a
    /// type or expect may name them.
    pub fn set_secret_custody(&mut self, custody: Arc<dyn SecretCustody>) {
        self.secrets.install(custody);
    }

    /// Gives the session the host's replay library.
    pub fn set_library(&mut self, library: Box<dyn WorkflowLibrary>) {
        self.library = Some(library);
    }

    /// Runs `act` over the session with its library, decider and field
    /// writer lent out, so a library verb drives the session's own gated
    /// verbs.
    fn with_library<T>(
        &mut self,
        act: impl FnOnce(
            &mut Self,
            &mut dyn WorkflowLibrary,
            &mut dyn RoutineDecider,
            &dyn FieldWriter,
        ) -> Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let mut library = self.library.take().ok_or_else(no_library)?;
        let mut decider = self.decider.take();
        let writer = self.field_writer.take();
        let lent: &dyn FieldWriter = match writer.as_deref() {
            Some(writer) => writer,
            None => &NoWriter,
        };
        let result = match decider.as_deref_mut() {
            Some(decider) => act(self, library.as_mut(), decider, lent),
            None => act(self, library.as_mut(), &mut NoDecider, lent),
        };
        self.library = Some(library);
        self.decider = decider;
        self.field_writer = writer;
        result
    }

    /// Gives the session's batches the host's routine decider.
    pub fn set_decider(&mut self, decider: Box<dyn RoutineDecider>) {
        self.decider = Some(decider);
    }

    /// Gives the session's Fill steps the host's field writer (CUA E6).
    pub fn set_field_writer(&mut self, writer: Box<dyn FieldWriter>) {
        self.field_writer = Some(writer);
    }

    /// Gives the session the host's keeper of receipt screenshots.
    pub fn set_receipt_sink(&mut self, sink: Box<dyn ReceiptEvidenceSink>) {
        self.receipt_sink = Some(sink);
    }

    /// A browser may only be started through the engine's tier selector.
    pub fn start(_config: &BrowserGuest) -> Result<Self, BrowserError> {
        Err(BrowserError::Unavailable(
            "engine-selected sandbox and egress proxy required".into(),
        ))
    }

    /// What the guest's container proved, for the run's receipt.
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    /// The engine the session attached, which runs its every verb.
    #[must_use]
    pub const fn engine(&self) -> BrowserEngine {
        self.driver.engine()
    }

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.driver.image(image)
    }

    /// Every effect this session receipted, in order.
    pub fn receipts(&self) -> impl Iterator<Item = &EffectReceipt> {
        self.trail.iter().filter_map(Event::receipt)
    }

    /// The press policy as it stands, batch counts spent down.
    #[must_use]
    pub fn policy(&self) -> &SendPolicy {
        &self.policy
    }

    /// Sets the press each effect class runs under, as the vault's grants
    /// stand now: a browser that outlives one door of its run takes the
    /// next door's policy.
    pub fn set_policy(&mut self, policy: SendPolicy) {
        self.policy = policy;
    }

    /// Records a person's press over a reviewed batch of `count` sends of
    /// `class`. Its sends then run without a press each until spent.
    pub fn approve_batch(&mut self, class: &str, count: u32) {
        self.policy
            .modes
            .insert(class.to_owned(), PressMode::PerBatch);
        *self.policy.batch.entry(class.to_owned()).or_default() += count;
    }

    #[must_use]
    pub fn abandoned(&self) -> bool {
        self.guest.abandoned()
    }

    /// Who has the browser now.
    #[must_use]
    pub fn takeover(&self) -> &Takeover {
        &self.takeover
    }

    /// Person `by` takes the browser, asked or not. The caller holds the
    /// session, so the agent's call in flight has ended; its next one
    /// refuses until `by` hands the browser back. Taking it again is a no-op.
    pub fn take_over(&mut self, by: &str) -> Result<&Takeover, BrowserError> {
        self.guest_up()?;
        let asked = match &self.takeover {
            Takeover::Agent => None,
            Takeover::Waiting { reason, .. } => Some(reason.clone()),
            Takeover::Held { by: holder, .. } if holder == by => return Ok(&self.takeover),
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
        };
        // The agent's demonstration ends before a person's input begins.
        self.recording_close(DemonstrationStopCause::HandedOver);
        self.takeover = Takeover::Held {
            by: by.to_owned(),
            asked,
            taken_at_ms: now_ms(),
            inputs: 0,
        };
        Ok(&self.takeover)
    }

    /// The browser's tabs for the person's view, the one in front marked:
    /// a tab or popup opened since is followed, and while a person holds
    /// the browser it comes to the front, as a browser shows a popup.
    pub fn tabs(&mut self) -> Result<Vec<BrowserTab>, BrowserError> {
        self.guest_up()?;
        let held = matches!(self.takeover, Takeover::Held { .. });
        self.driver.tabs(held)
    }

    /// The front tab's viewport as a PNG for the person, or `tab`'s, which
    /// comes to the front: unmasked, never held in the session's images and
    /// never a receipt. Only the person who holds the browser brings
    /// another tab to the front.
    pub fn person_screen(&mut self, tab: Option<&str>) -> Result<Vec<u8>, BrowserError> {
        self.tabs()?;
        self.bring_up(tab)?;
        self.driver.person_screen()
    }

    /// The person's view in one look: the tabs, then the front tab's
    /// viewport, as [`Self::tabs`] and [`Self::person_screen`] give them.
    pub fn person_view(&mut self) -> Result<(Vec<BrowserTab>, Vec<u8>), BrowserError> {
        let tabs = self.tabs()?;
        Ok((tabs, self.driver.person_screen()?))
    }

    /// One input from `by`, who must hold the browser, at the viewport's
    /// pixels of the front tab, or of `tab`, which comes to the front first,
    /// or a page to go to; it counts toward the takeover's record. A tab
    /// opened since the person's last look stays behind: the input goes to
    /// the tab they saw. No press gates it: the person's own input is their
    /// press.
    pub fn person_input(
        &mut self,
        by: &str,
        tab: Option<&str>,
        input: BrowserPersonInput,
    ) -> Result<u64, BrowserError> {
        self.guest_up()?;
        match &self.takeover {
            Takeover::Held { by: holder, .. } if holder == by => {}
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
            Takeover::Agent | Takeover::Waiting { .. } => {
                return Err(BrowserError::Input(
                    "take the browser over first".to_owned(),
                ));
            }
        }
        if let BrowserPersonInput::Navigate { url } = &input
            && !web_page(url)
        {
            return Err(BrowserError::Url(url.clone()));
        }
        self.driver.tabs(false)?;
        self.bring_up(tab)?;
        self.driver.checkpoint(StoragePhase::PreInput);
        self.driver.person_input(input)?;
        let Takeover::Held { inputs, .. } = &mut self.takeover else {
            return Err(BrowserError::GuestLost);
        };
        *inputs += 1;
        Ok(*inputs)
    }

    /// `by` hands the browser back, from holding it or from the agent's ask
    /// it never took: the agent's next read is a whole observation of the
    /// page the person left, and its next answer carries this record once.
    pub fn hand_back(&mut self, by: &str) -> Result<TakeoverRecord, BrowserError> {
        let returned_at_ms = now_ms();
        let record = match &self.takeover {
            Takeover::Held {
                by: holder,
                asked,
                taken_at_ms,
                inputs,
            } if holder == by => TakeoverRecord {
                by: by.to_owned(),
                asked: asked.clone(),
                taken_at_ms: *taken_at_ms,
                returned_at_ms,
                inputs: *inputs,
            },
            Takeover::Held { .. } => {
                return Err(BrowserError::BrowserTakenOver("held".to_owned()));
            }
            Takeover::Waiting { reason, .. } => TakeoverRecord {
                by: by.to_owned(),
                asked: Some(reason.clone()),
                taken_at_ms: returned_at_ms,
                returned_at_ms,
                inputs: 0,
            },
            Takeover::Agent => {
                return Err(BrowserError::Input("the agent has the browser".to_owned()));
            }
        };
        self.takeover = Takeover::Agent;
        self.driver.forget_observations();
        // The agent reads the tab the person left in front; a front tab that
        // closed gives way here. A guest that no longer answers refuses the
        // agent's next call itself. The takeover's record covers where the
        // person left it: no tab they opened, and no move from before,
        // counts as the agent's.
        let _ = self.driver.tabs(false);
        self.driver.checkpoint(StoragePhase::HandBack);
        self.driver.know_tabs();
        self.returned = Some(record.clone());
        Ok(record)
    }

    /// Brings `tab` to the front for the person who holds the browser; the
    /// tab already in front needs no hold.
    fn bring_up(&mut self, tab: Option<&str>) -> Result<(), BrowserError> {
        let Some(tab) = tab else {
            return Ok(());
        };
        if !matches!(self.takeover, Takeover::Held { .. }) {
            let front = self.driver.tabs(false)?.into_iter().find(|t| t.front);
            if front.is_some_and(|front| front.tab == tab) {
                return Ok(());
            }
            return Err(BrowserError::Input(
                "take the browser over to bring another tab to the front".to_owned(),
            ));
        }
        self.driver.bring_to_front(tab)
    }

    /// The takeover that ended since the agent's last answer, once.
    pub fn take_returned(&mut self) -> Option<TakeoverRecord> {
        self.returned.take()
    }

    /// The agent's move to another tab since its last answer, once: a tab
    /// its act opened came to the front, or the tab it drove closed. The
    /// host's door names it on that answer as `switched`.
    pub fn take_switched(&mut self) -> Option<TabSwitch> {
        self.driver.take_switched()
    }

    /// Ends a takeover still asked or held as the browser goes away, with
    /// what it held so far; `None` while the agent has the browser.
    pub fn abandon_takeover(&mut self) -> Option<AbandonedTakeover> {
        match std::mem::replace(&mut self.takeover, Takeover::Agent) {
            Takeover::Agent => None,
            state => Some(AbandonedTakeover {
                state,
                ended_at_ms: now_ms(),
            }),
        }
    }

    /// An agent verb's first check: the agent has the browser. While it
    /// waits on its ask or a person holds it, the verb refuses.
    fn agent_has(&self) -> Result<(), BrowserError> {
        match self.takeover {
            Takeover::Agent => Ok(()),
            Takeover::Waiting { .. } => Err(BrowserError::BrowserTakenOver("asked".to_owned())),
            Takeover::Held { .. } => Err(BrowserError::BrowserTakenOver("held".to_owned())),
        }
    }

    /// The guest still answers; a demonstration recording ends with the
    /// cause of one that does not, with what it kept.
    fn guest_up(&mut self) -> Result<(), BrowserError> {
        if self.guest.abandoned() {
            self.recording_close(DemonstrationStopCause::Abandoned);
            return Err(BrowserError::Abandoned);
        }
        if self.guest.is_running() {
            Ok(())
        } else {
            self.recording_close(DemonstrationStopCause::GuestLost);
            Err(BrowserError::GuestLost)
        }
    }

    /// An agent verb's entry: the agent has the browser and the guest runs.
    /// Its verbs follow the tabs first: a tab opened since its last call
    /// (a popup a script opened late) comes to the front, and a front tab
    /// that closed gives way to its opener. A look at the tabs that fails
    /// leaves the front where it was, for the verb's own answer; a tab a
    /// Lightpanda guest cannot follow is the verb's refusal.
    fn live(&mut self) -> Result<&mut CdpDriver, BrowserError> {
        self.stop_pending = None;
        self.agent_has()?;
        self.guest_up()?;
        if let (_, Some(refused)) = self.driver.follow_or_refusal() {
            return Err(refused);
        }
        self.recording_drain();
        Ok(&mut self.driver)
    }

    /// Pages a batch's last observation, as an answer pages it.
    fn page_batch(&mut self, batch: &mut BatchOutput) {
        if let Some(observation) = batch.observation.take() {
            let page = self.driver.paged(observation);
            batch.observation = Some(page.observation);
            batch.next = page.next;
        }
    }

    fn press_for(&mut self, class: &str, row: &Row) -> Result<PressMode, BrowserError> {
        let pressed = press_for(&mut self.policy, class, row);
        // A refused press ends a draft as the press would (CUA E7).
        if pressed.is_err() {
            self.press_refused = Some(class.to_owned());
        }
        pressed
    }

    /// Types `input`, its receipt naming where the text came from
    /// (`provenance`, CUA E6): a `type` names `supplied`, a Fill its own.
    fn type_as(
        &mut self,
        input: TypeInput,
        mut provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let entry = entry(input.text.as_deref(), input.secret.as_deref())?;
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        let base = Base::of(input.base);
        let typed = self.driver.type_target(&target, entry, input.clear, &base);
        let mut observation = self.crossed(typed)?;
        // The operand as typed, a secret's taken into custody (CUA E7).
        let operand = self.operand(&target.row, entry, source.origin.as_deref());
        let locator = target.row.locator.clone();
        let action = typed_action(locator, operand, input.clear, provenance.fill.take());
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        self.typed = Some(provenance);
        self.receipt(
            "type",
            Some(&target.row),
            None,
            PressMode::None,
            &mut observation,
            started,
        );
        self.undelivered()?;
        Ok(observation)
    }

    /// Stamps `observation` with the receipt of the effect that made it,
    /// which its verb entered at `started`. The receipt's screenshot is
    /// best-effort: an effect that already happened is receipted even when
    /// its evidence could not be captured.
    fn receipt(
        &mut self,
        verb: &str,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        observation: &mut Observation,
        started: Instant,
    ) {
        self.receipt_seq += 1;
        // What the verb kept for a replay, and where it began (CUA E7).
        let (action, source) = self
            .acted
            .take()
            .map_or((None, None), |acted| (acted.action, Some(acted.source)));
        let (source_url, source_origin, tab) = source.map_or((None, None, None), |source| {
            (source.url, source.origin, Some(source.tab))
        });
        // Never compared: each receipt's screenshot is a capture of its own.
        let (screenshot, capture_id) = self
            .driver
            .screenshot(ScreenshotInput {
                trigger: ScreenshotTrigger::EffectReceipt,
                since_capture: None,
            })
            .ok()
            .map(|shot| (shot.image, shot.capture_id))
            .unzip();
        let mut receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: verb.to_owned(),
            url: observation.url.clone(),
            title: observation.title.clone(),
            target: target.map(|row| row.target.clone()),
            target_name: target.map(|row| row.name.clone()),
            target_locator: target.map(|row| row.locator.clone()),
            rebound: observation.rebound.clone(),
            effect_class: effect_class.map(str::to_owned),
            press: press.as_str().to_owned(),
            screenshot,
            capture_id,
            screenshot_evidence: None,
            engine: Some(self.driver.engine()),
            fact: observation.fact.clone(),
            engine_switch: None,
            text_source: None,
            text_ref: None,
            action,
            source_url,
            source_origin,
            tab,
            result_tab: Some(self.driver.front_target().to_owned()),
            // Stamped before the host keeps the screenshot.
            duration_ms: elapsed_ms(started),
        };
        // A type's text provenance, before the host keeps the receipt.
        if let Some(typed) = self.typed.take() {
            typed.stamp(&mut receipt);
        }
        // The pixels are kept before the receipt is stored, while the
        // session still holds them.
        if let Some(mut sink) = self.receipt_sink.take() {
            if let Some(png) = receipt
                .screenshot
                .as_deref()
                .and_then(|image| self.image(image))
            {
                receipt.screenshot_evidence = Some(sink.keep(&receipt, png));
            }
            self.receipt_sink = Some(sink);
        }
        self.keep(receipt.clone());
        self.landed();
        observation.receipt = Some(receipt);
    }
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
        self.receipt(
            "open",
            None,
            None,
            PressMode::None,
            &mut observation,
            started,
        );
        self.undelivered()?;
        // Repeated work on a site tries the library first. A lookup that
        // fails leaves the page open without its programs.
        if let Some(site) = site_of(&observation.url)
            && let Some(library) = self.library.as_mut()
        {
            observation.library = library.find(&site, None, None).unwrap_or_default();
        }
        Ok(observation)
    }

    /// `click`, as [`BrowserDriver::click`] runs it.
    fn click_row(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        let class = effect_class(&target.row.name);
        let press = match class {
            Some(class) => self.press_for(class, &target.row)?,
            None => PressMode::None,
        };
        let clicked = self.driver.click_target(&target, &Base::of(input.base));
        let mut observation = self.crossed(clicked)?;
        let class = receipt_class(class, Some(&target.row));
        let action = ReplayAction::Click {
            locator: target.row.locator.clone(),
        };
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        self.receipt(
            "click",
            Some(&target.row),
            class,
            press,
            &mut observation,
            started,
        );
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
        let class = row.as_ref().and_then(|row| effect_class(&row.name));
        let press = match (class, &row) {
            (Some(class), Some(row)) => self.press_for(class, row)?,
            _ => PressMode::None,
        };
        let base = Base::of(input.base);
        let clicked = self.driver.click_point(x, y, row.as_ref(), &base);
        let mut observation = self.crossed(clicked)?;
        let class = receipt_class(class, row.as_ref());
        self.acted = Some(Acted {
            action: None,
            source,
        });
        self.receipt(
            "click_at",
            row.as_ref(),
            class,
            press,
            &mut observation,
            started,
        );
        self.undelivered()?;
        Ok(observation)
    }

    /// `select`, as [`BrowserDriver::select`] runs it.
    fn select_option(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        let target = self.live()?.resolve_target(&input.target)?;
        let source = self.source();
        let base = Base::of(input.base);
        let selected = self.driver.select_target(&target, &input.option, &base);
        let mut observation = self.crossed(selected)?;
        let action = ReplayAction::Select {
            locator: target.row.locator.clone(),
            option: input.option,
        };
        self.acted = Some(Acted {
            action: Some(action),
            source,
        });
        self.receipt(
            "select",
            Some(&target.row),
            None,
            PressMode::None,
            &mut observation,
            started,
        );
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

    fn paged(&mut self, observation: Observation) -> ObservationPage {
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
        let site = match input.site {
            Some(site) => site.trim().to_ascii_lowercase(),
            None => site_of(&self.live()?.url()?).ok_or_else(|| {
                BrowserError::Input("the open page has no site; name one".to_owned())
            })?,
        };
        let library = self.library.as_mut().ok_or_else(no_library)?;
        Ok(LibraryFindOutput {
            workflows: library.find(&site, input.subgoal.as_deref(), input.type_ref.as_deref())?,
            site,
        })
    }

    fn library_propose(&mut self, input: ProposeInput) -> Result<ProposeOutput, BrowserError> {
        self.agent_has()?;
        let mut library = self.library.take().ok_or_else(no_library)?;
        let output = self.propose(library.as_mut(), input);
        self.library = Some(library);
        output
    }

    fn library_run(&mut self, input: LibraryRunInput) -> Result<LibraryRunOutput, BrowserError> {
        // A run refused mid-takeover would count as a missed postcondition.
        self.agent_has()?;
        self.stop_pending = None;
        let mut output = self.with_library(|session, library, decider, writer| {
            crate::library::run(session, library, decider, writer, input)
        })?;
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
        let reason = input
            .reason
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if reason.is_empty() || reason.chars().count() > HANDOVER_REASON_CHARS {
            return Err(BrowserError::Input(format!(
                "a handover gives its reason in 1 to {HANDOVER_REASON_CHARS} characters"
            )));
        }
        let asked_at_ms = now_ms();
        self.recording_close(DemonstrationStopCause::HandedOver);
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
        self.page_batch(&mut output);
        Ok(output)
    }
}
