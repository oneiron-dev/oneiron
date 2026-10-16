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
    ContainerRuntime, GuestLimits, GuestSeccomp, GuestSession, GuestSpec, ImageRef, SessionManifest,
};
use std::path::PathBuf;
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

/// The guest user the browser image declares.
const GUEST_USER: (u32, u32) = (10001, 10001);

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
    guest: GuestSession,
}

impl BrowserSession {
    /// Starts a fresh guest with a fresh profile and attaches to its page.
    pub fn start(config: &BrowserGuest) -> Result<Self, BrowserError> {
        let unavailable = |e: oneiron_container::Error| BrowserError::Unavailable(e.to_string());
        let runtime = ContainerRuntime::new(config.runtime.clone()).map_err(unavailable)?;
        let spec = GuestSpec {
            image: ImageRef::pinned(&config.image).map_err(unavailable)?,
            user: GUEST_USER,
            limits: config.limits,
            seccomp: GuestSeccomp::GuestSandbox,
            read_only_mounts: config
                .fixture
                .iter()
                .map(|dir| (dir.clone(), PathBuf::from("/srv/fixture")))
                .collect(),
        };
        let mut guest = runtime.start(&spec).map_err(unavailable)?;
        let (stdin, stdout) = guest.take_stdio().ok_or(BrowserError::GuestLost)?;
        match CdpDriver::attach(Pipe::new(stdout, stdin), config.wait_cap) {
            Ok(driver) => Ok(Self { driver, guest }),
            Err(error) => Err(BrowserError::Unavailable(format!(
                "{error}; guest said: {}",
                guest.stderr_tail()
            ))),
        }
    }

    /// What the guest's container proved, for the run's receipt.
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        self.guest.manifest()
    }

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.driver.image(image)
    }

    fn live(&mut self) -> Result<&mut CdpDriver, BrowserError> {
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
