//! A browser session: one Chromium guest in a container and the CDP driver
//! attached to it, with the host's rules in front of the driver.
//!
//! The browser runs only inside the isolated guest, never as a process on
//! the host. Cookies and the profile live and die in that guest; raw CDP
//! never leaves this crate.
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
//! and run programs through this session's own gated verbs.

use crate::cdp::Pipe;
use crate::driver::CdpDriver;
use crate::{
    BatchInput, BatchOutput, BrowserDriver, BrowserError, ClickInput, CropInput, EFFECT_ACCOUNT,
    EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH, EFFECT_SEND, EffectReceipt, ExpectInput,
    ExpectOutput, FindInput, FindOutput, ImageOutput, LibraryFindInput, LibraryFindOutput,
    LibraryRunInput, LibraryRunOutput, NoDecider, Observation, ObserveInput, OpenInput, PointInput,
    PressMode, ProposeInput, ProposeOutput, RoutineDecider, Row, ScreenshotInput, ScreenshotOutput,
    ScreenshotTrigger, SelectInput, SendPolicy, TypeInput, ViewInput, WaitForInput, WaitForOutput,
    WorkflowLibrary, ZoomInput, site_of,
};
use oneiron_container::{
    EgressRelay, GuestLimits, SessionLease, SessionManifest, SessionTransport,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
}

pub struct BrowserSession {
    driver: CdpDriver,
    guest: Box<dyn SessionLease>,
    manifest: SessionManifest,
    policy: SendPolicy,
    receipts: Vec<EffectReceipt>,
    receipt_seq: u64,
    decider: Option<Box<dyn RoutineDecider>>,
    library: Option<Box<dyn WorkflowLibrary>>,
}

impl BrowserSession {
    /// The engine selects and proves a backend before attaching the browser.
    /// A lower driver crate must never silently select a weaker backend.
    pub fn attach(
        config: &BrowserGuest,
        transport: SessionTransport,
        relay: Arc<dyn EgressRelay>,
    ) -> Result<Self, BrowserError> {
        if transport.manifest.fence_unproven || transport.manifest.fence_proof.is_none() {
            return Err(BrowserError::Unavailable(
                "browser session fence unproven".to_owned(),
            ));
        }
        let SessionTransport {
            reader,
            writer,
            manifest,
            lease,
        } = transport;
        let driver = CdpDriver::attach(
            Pipe::with_egress(reader, writer, Some(relay)),
            config.wait_cap,
        )?;
        Ok(Self {
            driver,
            guest: lease,
            manifest,
            policy: config.policy.clone(),
            receipts: Vec::new(),
            receipt_seq: 0,
            decider: None,
            library: None,
        })
    }

    /// Gives the session the host's replay library.
    pub fn set_library(&mut self, library: Box<dyn WorkflowLibrary>) {
        self.library = Some(library);
    }

    /// Runs `act` over the session with its library and decider lent out, so
    /// a library verb drives the session's own gated verbs.
    fn with_library<T>(
        &mut self,
        act: impl FnOnce(
            &mut Self,
            &mut dyn WorkflowLibrary,
            &mut dyn RoutineDecider,
        ) -> Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let mut library = self.library.take().ok_or_else(no_library)?;
        let mut decider = self.decider.take();
        let result = match decider.as_deref_mut() {
            Some(decider) => act(self, library.as_mut(), decider),
            None => act(self, library.as_mut(), &mut NoDecider),
        };
        self.library = Some(library);
        self.decider = decider;
        result
    }

    /// Gives the session's batches the host's routine decider.
    pub fn set_decider(&mut self, decider: Box<dyn RoutineDecider>) {
        self.decider = Some(decider);
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

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.driver.image(image)
    }

    /// Every effect this session receipted, in order.
    #[must_use]
    pub fn receipts(&self) -> &[EffectReceipt] {
        &self.receipts
    }

    /// The press policy as it stands, batch counts spent down.
    #[must_use]
    pub fn policy(&self) -> &SendPolicy {
        &self.policy
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

    fn live(&mut self) -> Result<&mut CdpDriver, BrowserError> {
        if self.guest.abandoned() {
            return Err(BrowserError::Abandoned);
        }
        if self.guest.is_running() {
            Ok(&mut self.driver)
        } else {
            Err(BrowserError::GuestLost)
        }
    }

    fn press_for(&mut self, class: &str, row: &Row) -> Result<PressMode, BrowserError> {
        press_for(&mut self.policy, class, row)
    }

    /// Stamps `observation` with the receipt of the effect that made it.
    /// The receipt's screenshot is best-effort: an effect that already
    /// happened is receipted even when its evidence could not be captured.
    fn receipt(
        &mut self,
        verb: &str,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        observation: &mut Observation,
    ) {
        self.receipt_seq += 1;
        let screenshot = self
            .driver
            .screenshot(ScreenshotInput {
                trigger: ScreenshotTrigger::EffectReceipt,
            })
            .ok()
            .map(|shot| shot.image);
        let receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: verb.to_owned(),
            url: observation.url.clone(),
            title: observation.title.clone(),
            target: target.map(|row| row.target.clone()),
            target_name: target.map(|row| row.name.clone()),
            effect_class: effect_class.map(str::to_owned),
            press: press.as_str().to_owned(),
            screenshot,
        };
        self.receipts.push(receipt.clone());
        observation.receipt = Some(receipt);
    }
}

fn no_library() -> BrowserError {
    BrowserError::Library("this browser host keeps no library".to_owned())
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

impl BrowserDriver for BrowserSession {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        let scheme = input
            .url
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase());
        if !matches!(scheme.as_deref(), Some("http" | "https")) {
            return Err(BrowserError::Url(input.url));
        }
        let mut observation = self.live()?.open(input)?;
        self.receipt("open", None, None, PressMode::None, &mut observation);
        // Repeated work on a site tries the library first. A lookup that
        // fails leaves the page open without its programs.
        if let Some(site) = site_of(&observation.url)
            && let Some(library) = self.library.as_mut()
        {
            observation.library = library.find(&site, None).unwrap_or_default();
        }
        Ok(observation)
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        self.live()?.observe(input)
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        self.live()?.find(input)
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let row = self.live()?.row(&input.target)?;
        let class = effect_class(&row.name);
        let press = match class {
            Some(class) => self.press_for(class, &row)?,
            None => PressMode::None,
        };
        let mut observation = self.driver.click(input)?;
        self.receipt("click", Some(&row), class, press, &mut observation);
        Ok(observation)
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        let (x, y) = self.live()?.point(&input)?;
        let row = self.driver.row_at(x, y)?;
        let class = row.as_ref().and_then(|row| effect_class(&row.name));
        let press = match (class, &row) {
            (Some(class), Some(row)) => self.press_for(class, row)?,
            _ => PressMode::None,
        };
        let mut observation = self.driver.click_point(x, y)?;
        self.receipt("click_at", row.as_ref(), class, press, &mut observation);
        Ok(observation)
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        let row = self.live()?.row(&input.target)?;
        let mut observation = self.driver.type_text(input)?;
        self.receipt("type", Some(&row), None, PressMode::None, &mut observation);
        Ok(observation)
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let row = self.live()?.row(&input.target)?;
        let mut observation = self.driver.select(input)?;
        self.receipt(
            "select",
            Some(&row),
            None,
            PressMode::None,
            &mut observation,
        );
        Ok(observation)
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

    fn library_find(&mut self, input: LibraryFindInput) -> Result<LibraryFindOutput, BrowserError> {
        let site = match input.site {
            Some(site) => site.trim().to_ascii_lowercase(),
            None => site_of(&self.live()?.url()?).ok_or_else(|| {
                BrowserError::Input("the open page has no site; name one".to_owned())
            })?,
        };
        let library = self.library.as_mut().ok_or_else(no_library)?;
        Ok(LibraryFindOutput {
            workflows: library.find(&site, input.subgoal.as_deref())?,
            site,
        })
    }

    fn library_propose(&mut self, input: ProposeInput) -> Result<ProposeOutput, BrowserError> {
        self.with_library(|session, library, decider| {
            crate::library::propose(session, library, decider, input)
        })
    }

    fn library_run(&mut self, input: LibraryRunInput) -> Result<LibraryRunOutput, BrowserError> {
        self.with_library(|session, library, decider| {
            crate::library::run(session, library, decider, input)
        })
    }

    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        let mut decider = self.decider.take();
        let output = match decider.as_deref_mut() {
            Some(decider) => self.batch_with(input, decider),
            None => self.batch_with(input, &mut NoDecider),
        };
        self.decider = decider;
        output
    }
}
