//! The engine a browser session drives (FIX 6680, BROWSER-SPLIT): every
//! browser answer and every effect receipt names it, so a program and a
//! receipt reader both know which engine ran each step. The substrate only
//! reports the engine; the model decides what to do about it.
//!
//! One engine value picks both the guest's command and the host's codec:
//! [`BrowserEngine::guest_argv`] starts the browser guest image's entrypoint
//! on it, and the session speaks that engine's CDP transport to it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

/// The browser guest image's entrypoint
/// (`crates/oneiron-container/guest/browser/entrypoint.sh`): its first
/// argument names the engine it launches.
const GUEST_ENTRY: &str = "/usr/local/bin/oneiron-browser-guest";

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
    /// entrypoint, told the engine. A code run's browser and the host's
    /// readiness check both start their guest with it.
    #[must_use]
    pub fn guest_argv(self) -> [OsString; 2] {
        [GUEST_ENTRY.into(), self.as_str().into()]
    }
}
