//! Browser verbs for code mode (`self.memory.browser.*`), and the CDP driver
//! behind them (feature `driver`).
//!
//! A program reads the page as an outline of rows. Each row has a stable
//! `ref` built from its role, its accessible name and its named ancestors,
//! never from its position, so a ref read in one observation still names the
//! same element after the page changes around it. Every action waits for the
//! page to settle and returns the next observation as a diff.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "driver")]
mod cdp;
#[cfg(feature = "driver")]
mod driver;
#[cfg(feature = "driver")]
mod outline;
#[cfg(feature = "driver")]
mod session;

#[cfg(feature = "driver")]
pub use oneiron_container::{GuestLimits, ImageRef};
#[cfg(feature = "driver")]
pub use session::{BrowserGuest, BrowserSession};

/// One element a program can read or act on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    #[serde(rename = "ref")]
    pub target: String,
    pub role: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<String>,
    pub depth: u16,
}

/// The page as rows. With `full` false it is a diff against the observation
/// `since` named: `rows` are new or changed, `removed` are refs now gone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub seq: u64,
    pub url: String,
    pub title: String,
    pub full: bool,
    pub rows: Vec<Row>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObserveInput {
    #[serde(default)]
    pub since: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenInput {
    pub url: String,
}

/// Rows whose role equals `role` and whose name contains `name`, ignoring case.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindOutput {
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClickInput {
    #[serde(rename = "ref")]
    pub target: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeInput {
    #[serde(rename = "ref")]
    pub target: String,
    pub text: String,
    /// Replace the field's text instead of inserting at the caret.
    #[serde(default)]
    pub clear: bool,
}

/// Picks the option of a `<select>` whose label, text or value is `option`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectInput {
    #[serde(rename = "ref")]
    pub target: String,
    pub option: String,
}

/// Waits until some row matches `role` and `name`, as `find` matches them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitForInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitForOutput {
    pub rows: Vec<Row>,
    pub timed_out: bool,
    pub waited_ms: u64,
}

/// A check on the page as it is now: the row named by `ref`, or else the
/// first row `role` and `name` match, is present (or absent) and, when
/// `value` is given, holds exactly that value.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectInput {
    #[serde(default, rename = "ref")]
    pub target: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub absent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectOutput {
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<Row>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotInput {}

/// A screenshot the session holds. It is never captioned: `image` names the
/// bytes for a later image read, and nothing else describes them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScreenshotOutput {
    pub image: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
}

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
    #[error("no element has ref {0} now; observe again")]
    StaleRef(String),
    #[error("element {0} is covered by another element")]
    Covered(String),
    #[error("element {0} is not a <select> with that option")]
    NoOption(String),
    #[error("{0} needs a person's press: the action would send, pay, submit or sign in")]
    NeedsPress(String),
    #[error("only http and https pages open: {0}")]
    Url(String),
    #[error("navigation failed: {0}")]
    Navigation(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("browser protocol: {0}")]
    Protocol(String),
}

/// The verbs a browser serves. The CDP driver implements it for a Chromium
/// guest; a desktop driver (cua-driver-rs) can implement it later.
pub trait BrowserDriver: Send {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError>;
    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError>;
    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError>;
    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError>;
    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError>;
    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError>;
    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError>;
    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError>;
    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError>;
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
            Self::StaleRef(_) => "browser_stale_ref",
            Self::Covered(_) => "browser_covered",
            Self::NoOption(_) => "browser_no_option",
            Self::NeedsPress(_) => "needs_press",
            Self::Url(_) => "browser_url_refused",
            Self::Navigation(_) => "browser_navigation_failed",
            Self::Timeout(_) => "browser_timeout",
            Self::Protocol(_) => "browser_protocol",
        }
    }
}

impl WaitForInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput { role: self.role.clone(), name: self.name.clone() }
    }
}

impl ExpectInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput { role: self.role.clone(), name: self.name.clone() }
    }
}

impl FindInput {
    /// Whether `row` matches: role exactly, name as a case-blind substring.
    #[must_use]
    pub fn matches(&self, row: &Row) -> bool {
        self.role.as_ref().is_none_or(|role| row.role.eq_ignore_ascii_case(role))
            && self
                .name
                .as_ref()
                .is_none_or(|name| row.name.to_lowercase().contains(&name.to_lowercase()))
    }
}
