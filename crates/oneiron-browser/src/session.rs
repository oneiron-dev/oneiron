//! A browser session: one Chromium guest in a container and the CDP driver
//! attached to it, with the host's rules in front of the driver.
//!
//! The rules here are the pilot's floor until per-action-class send grants
//! land: only http and https pages open, and a click on a control whose name
//! says it sends, pays, submits or signs in stops with `needs_press`.

use crate::cdp::Pipe;
use crate::driver::CdpDriver;
use crate::{
    BrowserDriver, BrowserError, ClickInput, ExpectInput, ExpectOutput, FindInput, FindOutput,
    Observation, ObserveInput, OpenInput, ScreenshotInput, ScreenshotOutput, SelectInput,
    TypeInput, WaitForInput, WaitForOutput,
};
use oneiron_container::{
    GuestLimits, SessionLease, SessionManifest, SessionTransport, EgressRelay,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Words in a control's name that mark an effect a person presses for.
const PRESS_PHRASES: &[&[&str]] = &[
    &["send"],
    &["submit"],
    &["pay"],
    &["buy"],
    &["purchase"],
    &["order"],
    &["checkout"],
    &["connect"],
    &["delete"],
    &["remove"],
    &["sign", "in"],
    &["log", "in"],
    &["login"],
    &["sign", "up"],
    &["register"],
    &["confirm"],
    &["publish"],
    &["post"],
    &["invite"],
    &["accept"],
    &["transfer"],
    &["donate"],
    &["subscribe"],
    &["book"],
    &["reserve"],
];

/// How the host starts browser guests. Its bounds are the host's manifest rows.
#[derive(Clone, Debug)]
pub struct BrowserGuest {
    pub runtime: PathBuf,
    pub image: String,
    pub limits: GuestLimits,
    /// The longest `wait_for` one call holds the run for.
    pub wait_cap: Duration,
    /// A host directory served read-only on the guest's loopback, for checks.
    pub fixture: Option<PathBuf>,
}

pub struct BrowserSession {
    driver: CdpDriver,
    guest: Box<dyn SessionLease>,
    manifest: SessionManifest,
}

impl BrowserSession {
    /// The engine selects and proves a backend before attaching the browser.
    /// A lower driver crate must never silently select a weaker backend.
    pub fn attach(config: &BrowserGuest, transport: SessionTransport, relay: Arc<dyn EgressRelay>) -> Result<Self, BrowserError> {
        if transport.manifest.fence_unproven || transport.manifest.fence_proof.is_none() {
            return Err(BrowserError::Unavailable("browser session fence unproven".to_owned()));
        }
        let SessionTransport { reader, writer, manifest, lease } = transport;
        let driver = CdpDriver::attach(Pipe::with_egress(reader, writer, Some(relay)), config.wait_cap)?;
        Ok(Self { driver, guest: lease, manifest })
    }

    /// A browser may only be started through the engine's tier selector.
    pub fn start(_config: &BrowserGuest) -> Result<Self, BrowserError> {
        Err(BrowserError::Unavailable("engine-selected sandbox and egress proxy required".into()))
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

    #[must_use]
    pub fn abandoned(&self) -> bool { self.guest.abandoned() }

    fn live(&mut self) -> Result<&mut CdpDriver, BrowserError> {
        if self.guest.abandoned() { return Err(BrowserError::Abandoned); }
        if self.guest.is_running() {
            Ok(&mut self.driver)
        } else {
            Err(BrowserError::GuestLost)
        }
    }
}

fn needs_press(name: &str) -> bool {
    let words: Vec<String> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    PRESS_PHRASES.iter().any(|phrase| {
        words
            .windows(phrase.len())
            .any(|w| w.iter().zip(*phrase).all(|(a, b)| a == b))
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
        self.live()?.open(input)
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        self.live()?.observe(input)
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        self.live()?.find(input)
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let driver = self.live()?;
        let row = driver.row(&input.target)?;
        if needs_press(&row.name) {
            return Err(BrowserError::NeedsPress(format!(
                "{} \"{}\"",
                row.role, row.name
            )));
        }
        driver.click(input)
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        self.live()?.type_text(input)
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        self.live()?.select(input)
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
}
