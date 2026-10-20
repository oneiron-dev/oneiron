//! The engine a browser session drives (FIX 6680, BROWSER-SPLIT): every
//! browser answer and every effect receipt names it, so a program and a
//! receipt reader both know which engine ran each step. The substrate only
//! reports the engine; the model decides what to do about it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}
