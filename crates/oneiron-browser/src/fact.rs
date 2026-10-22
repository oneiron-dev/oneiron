//! What an act proved about its own effect (FIX 6680, BROWSER-SPLIT): a
//! click, type, select or open whose page showed no change within the
//! driver's change window answers at once with a typed fact, instead of
//! waiting for a page that will not move. A fact is only ever the statement
//! that every signal was read and none moved within `window_ms`; a read
//! that failed or did not answer in time proves nothing, and the act then
//! answers as it always did, with no fact.
//!
//! A fact is information, never a refusal: the act still answers its
//! observation and its receipt, and a batch runs on past it. What to do
//! about it (another target, another engine, a person) is the model's call.

use crate::BrowserEngine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A fact one act proved about its effect, on its observation and receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionFact {
    /// A `click` or `click_at` that changed nothing on the page.
    ClickNoEffect {
        engine: BrowserEngine,
        target: ActionTarget,
        reason: NoEffectReason,
        /// The milliseconds from the click to the last read that found
        /// nothing moved: the driver's change window, within one poll.
        window_ms: u64,
    },
    /// A `type` or `select` that changed nothing on the page, its target's
    /// value included.
    TypeNoEffect {
        engine: BrowserEngine,
        target: ActionTarget,
        reason: NoEffectReason,
        /// As a click's.
        window_ms: u64,
    },
    /// An `open` whose navigation started nothing: the browser answered it
    /// with no error and no new document, and no navigation began.
    NavigateNoEffect {
        engine: BrowserEngine,
        url: String,
        reason: NoEffectReason,
        /// The milliseconds from the navigate's answer to the last read
        /// that found nothing moved.
        window_ms: u64,
    },
}

/// A JavaScript dialog a page opened that the driver's answer did not
/// close (FIX 6768): the driver answers each one at once, an alert, confirm
/// or prompt dismissed and a beforeunload accepted, and one whose answer
/// the browser refused is named on the next observation, once, as it
/// stands. Information only: nothing else answers the dialog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DialogAnswerFailure {
    /// The tab whose page opened it, where the driver watches that page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    /// The dialog's type as the browser named it: `alert`, `confirm`,
    /// `prompt` or `beforeunload`.
    pub kind: String,
    /// Whether the answer accepted it.
    pub accept: bool,
    /// The browser's refusal of the answer, in its words.
    pub error: String,
}

/// What an act acted on, as its receipt names it: the row's live handle,
/// name and locator, and, for a `click_at`, the viewport point too.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ActionTarget {
    /// The live handle of the row acted on.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// That row's semantic locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// A `click_at`'s point on the viewport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub point: Option<ViewportPoint>,
}

/// A point on the viewport, in CSS pixels from its top-left.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ViewportPoint {
    pub x: f64,
    pub y: f64,
}

/// Why an act reads as having had no effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoEffectReason {
    /// The URL, the scroll position, the documents shown, the DOM (no
    /// mutation at all), the navigation events, the open tabs and, for a
    /// `type` or `select`, the target's value all read unchanged for
    /// `window_ms` after the input.
    NoObservableChange,
}
