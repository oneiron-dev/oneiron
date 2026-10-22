//! The engine switch's transaction (FIX 6680, BROWSER-SPLIT PR3, PR3b),
//! under the seat lock the call already holds, so no person's look or input
//! meets a half-made switch.
//!
//! The model asks; nothing here switches by itself, falls back, or reads an
//! act's fact. The agent must have the browser and give its reason; the
//! engine already running answers `unchanged`. Otherwise the source page's
//! state is read (its URL, scroll, cookies, and the local and session
//! storage of its current top-level origin, within [`switch_state_limits`]),
//! every other origin the tab visited is taken from the session's snapshots
//! (`storage`), all charged to the host's retained line, a guest is started
//! on the target engine through the host's starter and attached as every
//! guest is, the cookies go in first, each carried origin's stores are
//! seeded into a one-shot inert document of that origin before any page
//! script runs, one origin after another and the current one last, the
//! carried URL loads, the scroll is set and read back, and the target is
//! read whole. Only then does the target replace the source's engine group,
//! and the source guest goes. A target that does not start, attach, take
//! the cookies or load the URL is dropped and the source stays as it was:
//! the switch answers `failed`, with the stage. Whatever is carried
//! inexactly is listed in the record's `not_carried`, and the switch stands.
//!
//! The run keeps its press policy and spent batch counts, its receipts and
//! their sequence, its decider, library and receipt sink, its takeover
//! record, and the origin history and storage snapshots of the tab it
//! carries. The target's driver starts anew: its handles, tabs,
//! observations, images and pending tab move, and its change check, which
//! runs anew on the target.

use super::BrowserSession;
use super::guest::{BrowserGuestStarter, EngineGuest};
use super::storage::{
    Items, OriginSnapshots, STORES, Sink, SwitchStateLimits, export_stores, not_held, store_bytes,
    store_loss, switch_state_limits, switch_storage_scope,
};
use crate::cdp::{Visits, web_origin};
use crate::driver::CdpDriver;
use crate::request::Custody;
use crate::retention::HandleRetention;
use crate::secret::Secrets;
use crate::stop::elapsed_ms;
use crate::{
    BrowserDriver, BrowserEngine, BrowserError, EffectReceipt, EngineSwitchRecord, Observation,
    PressMode, ScreenshotInput, ScreenshotTrigger, SwitchCarried, SwitchComponent,
    SwitchEngineInput, SwitchEngineOutput, SwitchLoss, SwitchNotCarried, SwitchOutcome,
    SwitchStage,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// The verb a switch's receipt names.
const SWITCH_VERB: &str = "switch_engine";
/// The page a guest starts on: nothing to carry.
const BLANK: &str = "about:blank";

/// The longest reason a switch may give, in characters, as a handover's
/// (`SWITCH_REASON_CHARS`, CALLS row, open).
const SWITCH_REASON_CHARS: usize = 500;

/// Whether a switch from `from` to `to` restarts the browser
/// (`switch_request_policy`, CALLS row, open; owner ruling FIX 6680 = B):
/// the model's ask alone decides, with no fallback and no fact required;
/// the engine already running answers `unchanged`, with its receipt.
fn switch_request_policy(from: BrowserEngine, to: BrowserEngine) -> bool {
    from != to
}

/// A step that went wrong at `stage` fails the switch: the target is
/// dropped and the source stays as it was (`switch_commit_policy`, CALLS
/// row, open; Engine 10-21 01:3x). Only the target's start, attach, cookies
/// and URL load fail a switch, its first whole read counted with the load;
/// every other loss is listed in the record's `not_carried`, and the switch
/// stands.
fn switch_commit_policy<T>(stage: SwitchStage, step: Result<T, BrowserError>) -> Result<T, Halt> {
    step.map_err(|error| Halt { stage, error })
}

/// One source cookie as `Network.setCookies` takes it on `target`, and the
/// attributes the target does not take exactly (`switch_cookie_policy`,
/// CALLS row, open). A host-only cookie goes in by its URL, so it stays
/// host-only; a session cookie keeps no expiry. Chromium takes every
/// attribute. Lightpanda 1.0.0 refuses a priority other than Medium,
/// `sameParty` and `sourceScheme`, has no `sourcePort`, and ignores
/// `partitionKey`: the cookie goes in without them, and each is reported.
fn switch_cookie_policy(
    cookie: &Value,
    target: BrowserEngine,
) -> (Value, Vec<(&'static str, SwitchLoss)>) {
    let mut param = Map::new();
    for field in ["name", "value", "path", "secure", "httpOnly", "sameSite"] {
        if let Some(value) = cookie.get(field).filter(|value| !value.is_null()) {
            param.insert(field.to_owned(), value.clone());
        }
    }
    let domain = cookie["domain"].as_str().unwrap_or("");
    if domain.starts_with('.') {
        param.insert("domain".to_owned(), Value::from(domain));
    } else {
        let secure = cookie["secure"].as_bool() == Some(true);
        let scheme = if secure { "https" } else { "http" };
        let host = if domain.contains(':') {
            format!("[{domain}]")
        } else {
            domain.to_owned()
        };
        let path = cookie["path"].as_str().unwrap_or("/");
        param.insert(
            "url".to_owned(),
            Value::from(format!("{scheme}://{host}{path}")),
        );
    }
    let expires = cookie["expires"].as_f64().filter(|expires| *expires > 0.0);
    if cookie["session"].as_bool() != Some(true)
        && let Some(expires) = expires
    {
        param.insert("expires".to_owned(), Value::from(expires));
    }
    let mut losses = Vec::new();
    for field in [
        "priority",
        "sameParty",
        "sourceScheme",
        "sourcePort",
        "partitionKey",
    ] {
        let Some(value) = cookie.get(field).filter(|value| !value.is_null()) else {
            continue;
        };
        if target == BrowserEngine::Chromium {
            param.insert(field.to_owned(), value.clone());
            continue;
        }
        let exact = match field {
            "priority" => value.as_str() == Some("Medium"),
            "sameParty" => value.as_bool() == Some(false),
            "sourceScheme" => value.as_str() == Some("Unset"),
            "sourcePort" => value.as_i64() == Some(-1),
            _ => false,
        };
        if !exact {
            let loss = if field == "partitionKey" {
                SwitchLoss::EngineIgnores
            } else {
                SwitchLoss::EngineRefuses
            };
            losses.push((field, loss));
        }
    }
    (Value::Object(param), losses)
}

/// A switch's hard step that went wrong, and its stage.
pub(super) struct Halt {
    pub(super) stage: SwitchStage,
    pub(super) error: BrowserError,
}

/// The top-level web origins each tab of the session committed, as the
/// session drained them from its engine's pipe: kept by the session, outside
/// its engine group, so the tab a switch carries keeps its history on the
/// target.
#[derive(Default)]
pub(crate) struct OriginHistory {
    tabs: HashMap<String, Visits>,
}

impl OriginHistory {
    /// Adds what the pipe queued since the last drain, page by page.
    fn absorb(&mut self, drained: HashMap<String, Visits>, bound: usize) {
        for (tab, visits) in drained {
            let kept = self.tabs.entry(tab).or_default();
            kept.evicted += visits.evicted;
            for origin in visits.origins {
                kept.add(origin, bound);
            }
        }
    }

    /// The carried tab's history, now tab `to`'s on the target; the other
    /// tabs stayed with the source.
    fn carry(&mut self, from: &str, to: String) {
        let carried = self.tabs.remove(from).unwrap_or_default();
        self.tabs.clear();
        self.tabs.insert(to, carried);
    }
}

/// What a switch read off its source page, and took of its snapshots. Its
/// values stay here, in memory: never logged, never recorded.
pub(super) struct Exported {
    url: String,
    title: String,
    /// The page's web origin, when it is an http or https page.
    origin: Option<String>,
    scroll: Option<(f64, f64)>,
    /// None when the cookies were not read or not held.
    cookies: Option<Vec<Value>>,
    /// The origin's local and session store, as [`STORES`] orders them,
    /// none when not carried.
    stores: [Option<Items>; 2],
    /// Every other origin the tab visited with a store its snapshots hold,
    /// in the order they are seeded.
    others: Vec<(String, [Option<Items>; 2])>,
}

impl Exported {
    /// The stores this switch carries for `origin`.
    fn stores_of(&self, origin: &str) -> [Option<&Items>; 2] {
        let stores = if self.origin.as_deref() == Some(origin) {
            Some(&self.stores)
        } else {
            let other = self.others.iter().find(|(other, _)| other == origin);
            other.map(|(_, stores)| stores)
        };
        stores.map_or([None, None], |stores| {
            [stores[0].as_ref(), stores[1].as_ref()]
        })
    }
}

/// The origins a switch seeds into the target, in order
/// (`switch_storage_seed_policy`, CALLS row, open): one at a time, each
/// through its own one-shot inert document in the target's tab, the other
/// origins oldest read first and the current one last, before the carried
/// URL loads. An origin whose carried stores are empty needs no document;
/// each written store is read back, every key with its value, and a store
/// or a document that does not stand is listed, the switch going on.
fn switch_storage_seed_policy(state: &Exported) -> impl Iterator<Item = &str> {
    let others = state.others.iter().map(|(origin, _)| origin.as_str());
    others.chain(state.origin.as_deref())
}

fn lost(
    component: SwitchComponent,
    origin: Option<String>,
    reason: SwitchLoss,
) -> SwitchNotCarried {
    SwitchNotCarried {
        component,
        origin,
        cookies: Vec::new(),
        attribute: None,
        count: None,
        phase: None,
        after_receipt: None,
        reason,
    }
}

fn carried(component: SwitchComponent, origin: Option<&str>, count: Option<u64>) -> SwitchCarried {
    SwitchCarried {
        component,
        origin: origin.map(str::to_owned),
        count,
        phase: None,
        after_receipt: None,
    }
}

/// A cookie as a record names it: `name@domain`, never its value.
fn cookie_id(cookie: &Value) -> String {
    let field = |name: &str| cookie[name].as_str().unwrap_or("").to_owned();
    format!("{}@{}", field("name"), field("domain"))
}

/// Reads the source page's state, its scroll only `with_scroll`, within
/// `limits`, after receipt `after`; what it cannot read, or what is past a
/// bound, is listed in `losses`.
fn export(
    driver: &CdpDriver,
    limits: &SwitchStateLimits,
    after: u64,
    with_scroll: bool,
    losses: &mut Vec<SwitchNotCarried>,
) -> Exported {
    let (url, title) = driver.page_now().unwrap_or_else(|_| {
        losses.push(lost(SwitchComponent::Url, None, SwitchLoss::ReadFailed));
        (String::new(), String::new())
    });
    let origin = web_origin(&url);
    if origin.is_none() && !url.is_empty() && url != BLANK {
        losses.push(lost(SwitchComponent::Url, None, SwitchLoss::NotWebPage));
    }
    let read = origin.as_ref().filter(|_| with_scroll);
    let scroll = match read.map(|_| driver.scroll_now()) {
        Some(Ok(at)) => Some(at),
        Some(Err(_)) => {
            losses.push(lost(SwitchComponent::Scroll, None, SwitchLoss::ReadFailed));
            None
        }
        None => None,
    };
    let cookies = match driver.all_cookies() {
        Ok(listed) => Some(bound_cookies(listed, limits, losses)),
        Err(_) => {
            losses.push(lost(SwitchComponent::Cookies, None, SwitchLoss::ReadFailed));
            None
        }
    };
    let stores = match &origin {
        Some(origin) => export_stores(driver, origin, limits, after, losses),
        None => [None, None],
    };
    Exported {
        url,
        title,
        origin,
        scroll,
        cookies,
        stores,
        others: Vec::new(),
    }
}

/// The cookies within the switch's bounds, in the order listed; the rest
/// are listed in `losses`.
fn bound_cookies(
    listed: Vec<Value>,
    limits: &SwitchStateLimits,
    losses: &mut Vec<SwitchNotCarried>,
) -> Vec<Value> {
    let mut kept = Vec::new();
    let mut over = Vec::new();
    let mut bytes = 0;
    for cookie in listed {
        let size: usize = ["name", "value", "domain", "path"]
            .iter()
            .map(|field| cookie[*field].as_str().map_or(0, str::len))
            .sum();
        if kept.len() < limits.cookies && bytes + size <= limits.cookie_bytes {
            bytes += size;
            kept.push(cookie);
        } else {
            over.push(cookie_id(&cookie));
        }
    }
    if !over.is_empty() {
        losses.push(SwitchNotCarried {
            count: Some(over.len() as u64),
            cookies: over,
            ..lost(SwitchComponent::Cookie, None, SwitchLoss::Limit)
        });
    }
    kept
}

/// Charges what the switch holds of the page to the host's retained line.
/// What the line will not hold is not carried: the other origins' stores
/// first, then the current one's, then the cookies.
pub(super) fn hold(
    state: &mut Exported,
    charge: &mut dyn HandleRetention,
    losses: &mut Vec<SwitchNotCarried>,
) {
    let cookie_bytes: usize = state
        .cookies
        .iter()
        .flatten()
        .map(|cookie| cookie.to_string().len())
        .sum();
    let current = store_bytes(&state.stores);
    let others: usize = state
        .others
        .iter()
        .map(|(_, stores)| store_bytes(stores))
        .sum();
    if charge.resize(cookie_bytes + current + others) {
        return;
    }
    for (origin, stores) in std::mem::take(&mut state.others) {
        not_held(&origin, stores, losses);
    }
    if charge.resize(cookie_bytes + current) {
        return;
    }
    if let Some(origin) = &state.origin {
        let stores = std::mem::replace(&mut state.stores, [None, None]);
        not_held(origin, stores, losses);
    }
    if charge.resize(cookie_bytes) {
        return;
    }
    if let Some(cookies) = state.cookies.take() {
        losses.push(SwitchNotCarried {
            count: Some(cookies.len() as u64),
            ..lost(SwitchComponent::Cookies, None, SwitchLoss::HostCapacity)
        });
    }
}

/// The source's cookies as the target takes them, and each attribute the
/// target does not take exactly, with the cookies it covers.
fn adapt(cookies: &[Value], to: BrowserEngine) -> (Vec<Value>, Vec<SwitchNotCarried>) {
    let mut params = Vec::with_capacity(cookies.len());
    let mut inexact: BTreeMap<&'static str, (SwitchLoss, Vec<String>)> = BTreeMap::new();
    for cookie in cookies {
        let (param, losses) = switch_cookie_policy(cookie, to);
        for (attribute, reason) in losses {
            let entry = inexact.entry(attribute).or_insert((reason, Vec::new()));
            entry.1.push(cookie_id(cookie));
        }
        params.push(param);
    }
    let losses = inexact
        .into_iter()
        .map(|(attribute, (reason, cookies))| SwitchNotCarried {
            component: SwitchComponent::Cookie,
            origin: None,
            count: Some(cookies.len() as u64),
            cookies,
            attribute: Some(attribute.to_owned()),
            phase: None,
            after_receipt: None,
            reason,
        });
    (params, losses.collect())
}

/// Starts and readies the target, everything after the export up to its
/// whole read, filling `record`'s lists; its pipe's storage reads go to
/// `sink`, kept from its commit. Its pipe holds the session's `custody`
/// from its attach, before any of its pages loads: the host's request
/// handler, if any, takes its every request as the source's (FIX 7122).
/// Its driver holds the session's `secrets`, so its first read's secrets
/// become handles of the same run (FIX 8028). A hard step that went wrong
/// halts it, and the target drops with it.
fn stage(
    starter: &mut dyn BrowserGuestStarter,
    wait_cap: Duration,
    state: &Exported,
    sink: Option<Sink>,
    (custody, secrets): (&Custody, &Secrets),
    record: &mut EngineSwitchRecord,
) -> Result<(EngineGuest, Observation), Halt> {
    let started = switch_commit_policy(SwitchStage::Start, starter.start(record.to))?;
    let attached = EngineGuest::attach(
        record.to,
        started,
        wait_cap,
        sink,
        custody.clone(),
        secrets.clone(),
    );
    let mut target = switch_commit_policy(SwitchStage::Attach, attached)?;
    target.driver.book_inbound(starter.state_charge());
    let (kept, losses) = (&mut record.carried, &mut record.not_carried);
    seed_state(&target.driver, record.to, state, kept, losses)?;
    if state.origin.is_some() {
        let landed = switch_commit_policy(SwitchStage::Navigate, target.driver.land(&state.url))?;
        if landed == state.url {
            let item = carried(SwitchComponent::Url, None, None);
            record.carried.push(item);
        } else {
            let elsewhere = web_origin(&landed);
            let redirected = lost(SwitchComponent::Url, elsewhere, SwitchLoss::Redirected);
            record.not_carried.push(redirected);
        }
    }
    if let Some((x, y)) = state.scroll {
        match target.driver.scroll_back(x, y) {
            Ok((at_x, at_y)) if (at_x - x).abs() < 1.0 && (at_y - y).abs() < 1.0 => {
                let item = carried(SwitchComponent::Scroll, None, None);
                record.carried.push(item);
            }
            _ => {
                let differs = lost(SwitchComponent::Scroll, None, SwitchLoss::ReadbackMismatch);
                record.not_carried.push(differs);
            }
        }
    }
    let observation = switch_commit_policy(SwitchStage::Navigate, target.driver.whole())?;
    Ok((target, observation))
}

/// Puts `state`'s cookies into the target's `driver` on engine `to`, then
/// seeds each carried origin's stores, in [`switch_storage_seed_policy`]'s
/// order, listing what went in (`kept`) and what did not (`losses`). The
/// cookies the target refuses halt it.
pub(super) fn seed_state(
    driver: &CdpDriver,
    to: BrowserEngine,
    state: &Exported,
    kept: &mut Vec<SwitchCarried>,
    losses: &mut Vec<SwitchNotCarried>,
) -> Result<(), Halt> {
    if let Some(cookies) = &state.cookies {
        let (params, inexact) = adapt(cookies, to);
        let count = params.len() as u64;
        losses.extend(inexact);
        switch_commit_policy(SwitchStage::Cookies, driver.set_cookies(params))?;
        kept.push(carried(SwitchComponent::Cookies, None, Some(count)));
    }
    for origin in switch_storage_seed_policy(state) {
        seed(driver, origin, state, kept, losses);
    }
    Ok(())
}

/// Seeds `origin`'s carried stores into the target through its one-shot
/// inert document; a store that does not read back as written, key by key,
/// or a document that did not stand, is listed. An origin whose carried
/// stores are empty needs no document: the target's stores start empty.
fn seed(
    driver: &CdpDriver,
    origin: &str,
    state: &Exported,
    kept: &mut Vec<SwitchCarried>,
    losses: &mut Vec<SwitchNotCarried>,
) {
    let stores = state.stores_of(origin);
    let empty = stores.iter().flatten().all(|items| items.pairs.is_empty());
    let written = if empty {
        Ok([Some((0, 0, true)), Some((0, 0, true))])
    } else {
        let pairs = stores.map(|store| store.map(|items| items.pairs.as_slice()));
        driver.seed_origin(origin, pairs)
    };
    for (at, (_, component)) in STORES.into_iter().enumerate() {
        let Some(items) = stores[at] else {
            continue;
        };
        let count = items.pairs.len() as u64;
        let reason = match &written {
            Err(_) => SwitchLoss::SeedFailed,
            Ok(readback) if readback[at] == Some((count, items.chars, true)) => {
                kept.push(SwitchCarried {
                    phase: Some(items.phase),
                    after_receipt: Some(items.after),
                    ..carried(component, Some(origin), Some(count))
                });
                continue;
            }
            Ok(_) => SwitchLoss::ReadbackMismatch,
        };
        let when = (items.phase, items.after);
        let item = store_loss(component, origin, reason, Some(count), when);
        losses.push(item);
    }
}

impl BrowserSession {
    /// `switch_engine`: its gate, then its transaction, with the host's
    /// starter lent out. A refused gate is no switch and lands no receipt.
    pub(super) fn switch_to(
        &mut self,
        input: SwitchEngineInput,
    ) -> Result<SwitchEngineOutput, BrowserError> {
        let started = Instant::now();
        self.agent_has()?;
        let reason = input
            .reason
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if reason.is_empty() || reason.chars().count() > SWITCH_REASON_CHARS {
            return Err(BrowserError::Input(format!(
                "a switch gives its reason in 1 to {SWITCH_REASON_CHARS} characters"
            )));
        }
        let mut record = EngineSwitchRecord {
            from: self.driver.engine(),
            to: input.engine,
            reason,
            url: String::new(),
            carried: Vec::new(),
            not_carried: Vec::new(),
            outcome: SwitchOutcome::Unchanged,
        };
        if !switch_request_policy(record.from, record.to) {
            let (url, title) = self.driver.page_now().unwrap_or_default();
            record.url.clone_from(&url);
            let receipt = self.switch_record_policy(record, url, title, false, started);
            return Ok(SwitchEngineOutput {
                receipt,
                observation: None,
            });
        }
        self.guest_up()?;
        let mut starter = self
            .starter
            .take()
            .ok_or_else(|| BrowserError::Unsupported(SWITCH_VERB.to_owned()))?;
        let output = self.carry(starter.as_mut(), record, started);
        self.starter = Some(starter);
        Ok(output)
    }

    /// The transaction: export, stage the target, then commit it, or keep
    /// the source and record the stage that failed. The switch's verb
    /// entered at `started`.
    fn carry(
        &mut self,
        starter: &mut dyn BrowserGuestStarter,
        mut record: EngineSwitchRecord,
        started: Instant,
    ) -> SwitchEngineOutput {
        let (tab, mut state) = self.read_state(true, &mut record.not_carried);
        let mut charge = starter.state_charge();
        hold(&mut state, charge.as_mut(), &mut record.not_carried);
        record.url.clone_from(&state.url);
        for url in self.driver.other_tabs() {
            let other = lost(SwitchComponent::Tab, web_origin(&url), SwitchLoss::OtherTab);
            record.not_carried.push(other);
        }
        let wait_cap = self.driver.wait_cap();
        let sink = self.snapshots.as_ref().map(OriginSnapshots::sink);
        let staged = stage(
            starter,
            wait_cap,
            &state,
            sink.clone(),
            (&self.custody, &self.secrets),
            &mut record,
        );
        drop(charge);
        match staged {
            Ok((target, observation)) => {
                self.commit(record, &tab, sink, (target, observation), started)
            }
            Err(Halt { stage, error }) => {
                // Nothing moved: the page stays on the source as it was.
                record.carried.clear();
                record.not_carried.clear();
                record.outcome = SwitchOutcome::Failed {
                    stage,
                    code: error.code().to_owned(),
                    detail: error.to_string(),
                };
                let (url, title) = (state.url, state.title);
                let receipt = self.switch_record_policy(record, url, title, false, started);
                SwitchEngineOutput {
                    receipt,
                    observation: None,
                }
            }
        }
    }

    /// Reads the front tab's state for a carry, its scroll only
    /// `with_scroll`: the tab, then what [`export`] reads, with every other
    /// origin the tab visited taken from the session's snapshots
    /// (`storage`); what is not carried is listed in `losses`.
    pub(super) fn read_state(
        &mut self,
        with_scroll: bool,
        losses: &mut Vec<SwitchNotCarried>,
    ) -> (String, Exported) {
        let limits = switch_state_limits();
        let tab = self.driver.front_target().to_owned();
        let drained = self.driver.drain_visits();
        let shown = drained.get(&tab).map(|shown| shown.origins.clone());
        self.history.absorb(drained, limits.origins);
        let after = self.landed_seq();
        let mut state = export(&self.driver, &limits, after, with_scroll, losses);
        let visited = self.history.tabs.get(&tab);
        if let Some(collector) = &self.snapshots {
            let current = state.origin.as_deref();
            let shown = shown.unwrap_or_default();
            let plan = switch_storage_scope(collector, &tab, current, visited, &shown);
            state.others = plan.seed;
            losses.extend(plan.losses);
        }
        let evicted = visited.map_or(0, |visited| visited.evicted);
        if evicted > 0 {
            losses.push(SwitchNotCarried {
                count: Some(evicted),
                ..lost(SwitchComponent::Storage, None, SwitchLoss::Limit)
            });
        }
        (tab, state)
    }

    /// Replaces the source's engine group with `target`'s; the source guest
    /// goes with its lease. The carried tab's history is the target tab's,
    /// and so are its snapshots, kept through `sink`'s pipe from now on.
    fn commit(
        &mut self,
        mut record: EngineSwitchRecord,
        tab: &str,
        sink: Option<Sink>,
        (target, observation): (EngineGuest, Observation),
        started: Instant,
    ) -> SwitchEngineOutput {
        // A demonstration never runs on into the new guest (CUA E9a).
        self.recording_close(crate::DemonstrationStopCause::EngineSwitched);
        let EngineGuest {
            driver,
            lease,
            manifest,
        } = target;
        let source = EngineGuest {
            driver: std::mem::replace(&mut self.driver, driver),
            lease: std::mem::replace(&mut self.guest, lease),
            manifest: std::mem::replace(&mut self.manifest, manifest),
        };
        drop(source);
        let carried_to = self.driver.front_target().to_owned();
        if let (Some(collector), Some(sink)) = (&self.snapshots, &sink) {
            OriginSnapshots::carry(collector, tab, carried_to.clone(), sink);
        }
        self.history.carry(tab, carried_to);
        record.outcome = SwitchOutcome::Switched;
        let (url, title) = (observation.url.clone(), observation.title.clone());
        let receipt = self.switch_record_policy(record, url, title, true, started);
        SwitchEngineOutput {
            receipt,
            observation: Some(self.driver.paged(observation)),
        }
    }

    /// Lands one switch's receipt (`switch_record_policy`, CALLS row, open):
    /// one per admitted switch, switched, unchanged or failed, with verb
    /// `switch_engine`, on the session's one sequence; never coalesced, and
    /// never a batch step. A switched one's screenshot is of the target's
    /// page, kept as every effect receipt's is; its duration runs from the
    /// verb's entry at `started`.
    fn switch_record_policy(
        &mut self,
        record: EngineSwitchRecord,
        url: String,
        title: String,
        shot: bool,
        started: Instant,
    ) -> EffectReceipt {
        self.receipt_seq += 1;
        let screenshot = ScreenshotInput {
            trigger: ScreenshotTrigger::EffectReceipt,
            since_capture: None,
        };
        let (screenshot, capture_id) = if shot {
            let taken = self.driver.screenshot(screenshot).ok();
            taken.map(|shot| (shot.image, shot.capture_id)).unzip()
        } else {
            (None, None)
        };
        let mut receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: SWITCH_VERB.to_owned(),
            url,
            title,
            target: None,
            target_name: None,
            target_locator: None,
            rebound: None,
            effect_class: None,
            press: PressMode::None.as_str().to_owned(),
            screenshot,
            capture_id,
            screenshot_evidence: None,
            engine: Some(self.driver.engine()),
            fact: None,
            engine_switch: Some(record),
            text_source: None,
            text_ref: None,
            // No replay step switches engines: a draft names it a gap.
            action: None,
            source_url: None,
            source_origin: None,
            tab: None,
            result_tab: None,
            // Stamped before the host keeps the screenshot.
            duration_ms: elapsed_ms(started),
        };
        if let Some(mut sink) = self.receipt_sink.take() {
            if let Some(png) = receipt
                .screenshot
                .as_deref()
                .and_then(|image| self.driver.image(image))
            {
                receipt.screenshot_evidence = Some(sink.keep(&receipt, png));
            }
            self.receipt_sink = Some(sink);
        }
        self.keep(receipt.clone());
        self.landed();
        receipt
    }
}
