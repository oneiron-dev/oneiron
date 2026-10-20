//! The engine a browser session drives (FIX 6680, BROWSER-SPLIT): every
//! browser answer and every effect receipt names it, so a program and a
//! receipt reader both know which engine ran each step. The substrate only
//! reports the engine; the model decides what to do about it.
//!
//! One engine value picks both the guest's command and the host's codec:
//! [`BrowserEngine::guest_argv`] starts the browser guest image's entrypoint
//! on it, and the session speaks that engine's CDP transport to it. The
//! command also names the largest CDP message the guest's browser takes,
//! derived from the egress door's largest answer body, so one setting moves
//! both (FIX 6815).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

/// The browser guest image's entrypoint
/// (`crates/oneiron-container/guest/browser/entrypoint.sh`): its first
/// argument names the engine it launches.
const GUEST_ENTRY: &str = "/usr/local/bin/oneiron-browser-guest";
/// What one CDP message from the host carries past a base64 answer body:
/// the `Fetch.fulfillRequest` around it, its JSON, and the answer's headers,
/// which the egress client reads within its 400 KiB head bound.
const CDP_FRAMING: u64 = 1 << 20;

/// A browser engine a session can run its page on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    /// Lightpanda: reads pages at a fraction of Chromium's memory.
    Lightpanda,
    /// Headless Chromium over its debugging pipe.
    Chromium,
}

impl BrowserEngine {
    /// The engine's name, as its JSON says it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lightpanda => "lightpanda",
            Self::Chromium => "chromium",
        }
    }

    /// The engine an agent's browser starts on when the host names none:
    /// Lightpanda (owner ruling, FIX 6680: "Agents start on Lightpanda").
    #[must_use]
    pub const fn agent_default() -> Self {
        Self::Lightpanda
    }

    /// The command that starts a browser guest on this engine: the image's
    /// entrypoint, told the engine and the largest CDP message its browser
    /// takes from the host, for an egress door whose largest answer body is
    /// `max_response_bytes`. A code run's browser, an engine switch's guest
    /// and the host's readiness check all start their guest with it.
    #[must_use]
    pub fn guest_argv(self, max_response_bytes: usize) -> [OsString; 3] {
        [
            GUEST_ENTRY.into(),
            self.as_str().into(),
            cdp_message_bound(max_response_bytes).to_string().into(),
        ]
    }
}

/// The largest CDP message a guest's browser must take from the host (FIX
/// 6815): the egress door's largest answer body in base64, inside the
/// `Fetch.fulfillRequest` that hands it to the page. Lightpanda closes a
/// client whose message passes its bound; Chromium's pipe has none.
const fn cdp_message_bound(max_response_bytes: usize) -> u64 {
    (max_response_bytes as u64)
        .div_ceil(3)
        .saturating_mul(4)
        .saturating_add(CDP_FRAMING)
}
