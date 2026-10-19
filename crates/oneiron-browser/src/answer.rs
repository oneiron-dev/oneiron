//! What the run's door adds to a guest's answer (CUA-001): the record of a
//! person's takeover that ended, and the agent's move to another tab or
//! window, each once, on the agent's next answer. A driver's own answer
//! carries neither; the door writes them beside the answer's own fields, and
//! these types declare them, so a program reads them typed.

use crate::TabSwitch;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One takeover as its receipt keeps it: who held the desktop, what the
/// agent had asked, when they took and returned it, and how many inputs
/// they sent. No screenshot: none was taken for the agent meanwhile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TakeoverRecord {
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    pub taken_at_ms: u64,
    pub returned_at_ms: u64,
    pub inputs: u64,
}

/// The desktop's verbs moved to another window (CUA-001): the window they
/// read is gone (a dialog closed, an app quit), and the session gave way to
/// the window in front. The next answer carries it once, as `switched`;
/// moves before that answer join into one, from the window the agent was
/// last told of. The observations held were of the window before, so the
/// next observation is whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WindowSwitch {
    /// The window the desktop's verbs read now, as `windows` names it.
    pub window: String,
    /// Its app and title when the switch found it.
    pub app: String,
    pub title: String,
    /// The window they read before, gone since.
    pub from: String,
}

/// A browser verb's answer as the run's door gives it: the verb's own
/// answer, and, once each, the takeover a person ended and the agent's move
/// to another tab since its last answer.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BrowserAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    /// The takeover that ended since the agent's last answer: its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverRecord>,
    /// The agent's verbs moved to another tab since its last answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched: Option<TabSwitch>,
}

impl<T> BrowserAnswer<T> {
    /// The verb's own `answer`, as its driver gives it; the door adds the
    /// rest.
    #[must_use]
    pub fn of(answer: T) -> Self {
        Self {
            answer,
            takeover: None,
            switched: None,
        }
    }
}

/// A desktop verb's answer as the run's door gives it: the verb's own
/// answer, and, once each, the takeover a person ended and the agent's move
/// to another window since its last answer.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DesktopAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    /// The takeover that ended since the agent's last answer: its record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverRecord>,
    /// The agent's verbs moved to another window since its last answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched: Option<WindowSwitch>,
}

impl<T> DesktopAnswer<T> {
    /// The verb's own `answer`, as its driver gives it; the door adds the
    /// rest.
    #[must_use]
    pub fn of(answer: T) -> Self {
        Self {
            answer,
            takeover: None,
            switched: None,
        }
    }
}
