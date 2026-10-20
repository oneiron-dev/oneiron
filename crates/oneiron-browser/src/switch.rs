//! An engine switch (FIX 6680, BROWSER-SPLIT PR3): the model moves the run's
//! browser to the other engine, Lightpanda or Chromium, with the page it is
//! on. The switch carries the page's URL, its cookies, the local and session
//! storage of its current top-level origin, and its scroll; nothing switches
//! by itself, never as a fallback and never on an act's fact.
//!
//! Every switch the session admits is recorded, as one receipt with verb
//! `switch_engine` that carries its [`EngineSwitchRecord`]: what was carried,
//! what was not carried exactly and why, and whether the browser switched.
//! A record names components, origins, cookie names and domains, attributes,
//! counts and reasons; never a cookie's or a stored item's value.

use crate::{BrowserEngine, EffectReceipt, ObservationPage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Moves the run's browser to `engine`, its page carried, for `reason`: the
/// model's own words for why the page needs that engine (for example a
/// click that answered `click_no_effect`). The same engine answers
/// `unchanged`, with its receipt.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchEngineInput {
    pub engine: BrowserEngine,
    pub reason: String,
}

/// A switch's answer: its receipt, which carries the switch's record, and,
/// once the browser switched, the whole observation of the carried page on
/// the new engine. A failed switch leaves the page where it was, on the
/// engine it was on, and answers with no observation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SwitchEngineOutput {
    pub receipt: EffectReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<ObservationPage>,
}

/// One switch, as its receipt records it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EngineSwitchRecord {
    /// The engine the page was on.
    pub from: BrowserEngine,
    /// The engine the model asked for.
    pub to: BrowserEngine,
    /// The model's reason, as it gave it, its whitespace folded.
    pub reason: String,
    /// The page the switch carried: the source page's URL, empty when the
    /// source did not answer it.
    pub url: String,
    /// What the new engine holds as the source held it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carried: Vec<SwitchCarried>,
    /// What the new engine does not hold exactly as the source held it, each
    /// with its reason. The browser switched all the same: the model decides
    /// what to do about it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_carried: Vec<SwitchNotCarried>,
    pub outcome: SwitchOutcome,
}

/// How a switch ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SwitchOutcome {
    /// The page runs on the new engine; the source guest is gone.
    Switched,
    /// The browser already ran the engine asked for: nothing restarted.
    Unchanged,
    /// The new engine could not take the page at `stage`: it is gone, and
    /// the page stays on the source engine as it was. `code` is the
    /// browser's refusal code at that stage, and `detail` its words.
    Failed {
        stage: SwitchStage,
        code: String,
        detail: String,
    },
}

/// The steps at which a switch fails: the new engine's guest did not start,
/// its driver did not attach, it refused the carried cookies, or it did not
/// load the carried URL. Nothing else fails a switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SwitchStage {
    Start,
    Attach,
    Cookies,
    Navigate,
}

/// One part of the page a switch carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SwitchCarried {
    pub component: SwitchComponent,
    /// The origin a store belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// How many cookies or stored items it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// One part of the page the new engine does not hold exactly as the source
/// held it, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SwitchNotCarried {
    pub component: SwitchComponent,
    /// The origin a store, a tab or the URL belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The cookies it covers, each as `name@domain`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<String>,
    /// The cookie attribute the new engine took otherwise or not at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// How many items, cookies or origins it covers, when it counts them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    pub reason: SwitchLoss,
}

/// What a carried or not carried part of the page is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SwitchComponent {
    /// The page's URL.
    Url,
    /// The browser's cookies, as one set.
    Cookies,
    /// Some cookies, by name and domain.
    Cookie,
    /// One origin's local storage.
    LocalStorage,
    /// One origin's session storage, of the carried tab.
    SessionStorage,
    /// One origin's local and session storage, both.
    Storage,
    /// The page's scroll position.
    Scroll,
    /// A tab other than the one in front, which a switch does not carry.
    Tab,
}

/// Why a part of the page was not carried exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SwitchLoss {
    /// The storage of an origin the tab visited before the current one:
    /// this switch carries the current top-level origin's only.
    NotCollected,
    /// The new engine refuses this cookie attribute, so the cookie went in
    /// without it (Lightpanda 1.0.0: a priority other than Medium,
    /// `sameParty`, `sourceScheme`, `sourcePort`).
    EngineRefuses,
    /// The new engine takes this cookie attribute and ignores it
    /// (Lightpanda 1.0.0: `partitionKey`, so a partitioned cookie is no
    /// longer partitioned).
    EngineIgnores,
    /// Past the switch's bounds on cookies, stored items or origins.
    Limit,
    /// The host's retained memory would not hold it while the switch ran.
    HostCapacity,
    /// The source page did not answer its read, or threw.
    ReadFailed,
    /// The new engine did not load the origin's seed document, or it loaded
    /// under another origin.
    SeedFailed,
    /// The new engine read it back otherwise than it was written.
    ReadbackMismatch,
    /// The carried URL landed on another origin.
    Redirected,
    /// The page is no http or https page, so it has no web origin to carry.
    NotWebPage,
    /// Another tab: a switch carries the tab in front only.
    OtherTab,
}
