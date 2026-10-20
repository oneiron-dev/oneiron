//! A page's state as an engine switch reads it off the source and writes it
//! into the target (FIX 6680, BROWSER-SPLIT PR3), over the same CDP calls on
//! both engines: the URL (`Target.getTargetInfo`, then `Page.navigate`), the
//! cookies (`Network.getAllCookies`, then `Network.setCookies`), the current
//! origin's local and session storage (`Runtime.evaluate` both ways) and the
//! scroll (`Runtime.evaluate`). Neither engine serves a storage domain for a
//! departed document, so storage is read off the live page and written into
//! a one-shot inert document of its origin, which the pipe answers locally
//! through the target's own `Fetch` handler, before the real URL loads.
//!
//! A store is read within the switch's bounds in the page itself, before
//! its items cross, and checked again here. What crosses to the target goes
//! in pieces no larger than [`IMPORT_PIECE_BYTES`], well inside the CDP
//! message bound a Lightpanda guest takes. Values are read and written here
//! only: never logged, never in an error.

use super::pages::{Base, session_token};
use super::{CALL, CdpDriver, LOAD, page_targets, target_id};
use crate::cdp::Visits;
use crate::session::switch::SwitchStateLimits;
use crate::{BrowserError, Observation};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The most bytes of one piece of a store's items, as JSON, that one call
/// writes into the seed document, and of the cookies one
/// `Network.setCookies` carries: with its escaping, a piece stays well under
/// the one MiB of CDP framing a Lightpanda guest's bound keeps past its
/// largest answer body.
const IMPORT_PIECE_BYTES: usize = 64 << 10;

/// One store of a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Store {
    Local,
    Session,
}

impl Store {
    const fn global(self) -> &'static str {
        match self {
            Self::Local => "localStorage",
            Self::Session => "sessionStorage",
        }
    }
}

/// One store as the source page answered it.
pub(crate) enum StoreRead {
    /// Its items, key and value, with their length in UTF-16 code units.
    Items {
        pairs: Vec<(String, String)>,
        chars: u64,
    },
    /// Past the switch's bounds, holding `count` items.
    Over { count: u64 },
    /// The page did not answer it, threw, or no longer stood at the origin.
    Failed,
}

/// One store's items, as the page reads them, within its bounds: the page's
/// origin, how many items it holds, the items (null past a bound), and the
/// UTF-16 code units of their keys and values. A store the page cannot read
/// answers a count of -1.
const STORE_READ: &str = "(() => { try { const s = window.__STORE__; const n = s.length; if (n > __ITEMS__) return [location.origin, n, null, 0]; const p = []; let c = 0; for (let i = 0; i < n; i++) { const k = s.key(i); if (k === null) continue; const v = s.getItem(k); if (v === null) continue; c += k.length + v.length; if (c > __CHARS__) return [location.origin, n, null, c]; p.push([k, v]); } return [location.origin, n, p, c]; } catch (e) { return [location.origin, -1, null, 0]; } })()";

/// Clears one store of the seed document, sets the items its pieces
/// spelled, and reads it back: how many items, and their UTF-16 code units.
const STORE_SEED: &str = "(() => { const s = window.__STORE__; const t = window.__oneironSeed; delete window.__oneironSeed; s.clear(); if (t) { for (const [k, v] of JSON.parse(t)) s.setItem(k, v); } let c = 0; for (let i = 0; i < s.length; i++) { const k = s.key(i); c += k.length + s.getItem(k).length; } return [s.length, c]; })()";

/// UTF-16 code units of `text`, as a page counts a string's length.
fn utf16(text: &str) -> u64 {
    text.encode_utf16().count() as u64
}

impl CdpDriver {
    /// The tab in front: the one a switch carries.
    pub(crate) fn front_target(&self) -> &str {
        &self.target
    }

    /// The longest `wait_for` this driver holds a run for.
    pub(crate) const fn wait_cap(&self) -> Duration {
        self.wait_cap
    }

    /// The page's URL and title as they are now.
    pub(crate) fn page_now(&self) -> Result<(String, String), BrowserError> {
        self.page_info()
    }

    /// The page's scroll offset as it is now, in CSS pixels.
    pub(crate) fn scroll_now(&self) -> Result<(f64, f64), BrowserError> {
        self.scroll_offset()
    }

    /// Every page's committed top-level origins since the last drain.
    pub(crate) fn drain_visits(&self) -> HashMap<String, Visits> {
        self.pipe.drain_visits()
    }

    /// The URLs of the tabs other than the one in front.
    pub(crate) fn other_tabs(&self) -> Vec<String> {
        let mut others = Vec::new();
        for info in page_targets(&self.pipe).unwrap_or_default() {
            let id = target_id(&info);
            if id.is_empty() || id == self.target || self.ignored.contains(&id) {
                continue;
            }
            let url = info.get("url").and_then(Value::as_str);
            others.push(url.unwrap_or("").to_owned());
        }
        others
    }

    /// Every cookie of the browser, as CDP lists them: the page session's
    /// `Network.getAllCookies`, else the browser's `Storage.getCookies`.
    pub(crate) fn all_cookies(&self) -> Result<Vec<Value>, BrowserError> {
        let pipe = &self.pipe;
        let mut listed = match self.page("Network.getAllCookies", json!({})) {
            Ok(listed) => listed,
            Err(_) => pipe.call(None, "Storage.getCookies", json!({}), Instant::now() + CALL)?,
        };
        match listed.get_mut("cookies").map(Value::take) {
            Some(Value::Array(cookies)) => Ok(cookies),
            _ => Err(BrowserError::Protocol("reply without cookies".to_owned())),
        }
    }

    /// `store` of the page in front, at `origin`, read within `limits`.
    pub(crate) fn read_store(
        &self,
        store: Store,
        origin: &str,
        limits: &SwitchStateLimits,
    ) -> StoreRead {
        let expression = STORE_READ
            .replace("__STORE__", store.global())
            .replace("__ITEMS__", &limits.items.to_string())
            .replace("__CHARS__", &limits.store_chars.to_string());
        let Ok(answer) = self.page(
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
        ) else {
            return StoreRead::Failed;
        };
        if answer.get("exceptionDetails").is_some() {
            return StoreRead::Failed;
        }
        let read = answer.pointer("/result/value").unwrap_or(&Value::Null);
        if read[0].as_str() != Some(origin) {
            return StoreRead::Failed;
        }
        let Some(count) = read[1].as_u64() else {
            return StoreRead::Failed;
        };
        let Some(items) = read[2].as_array() else {
            return StoreRead::Over { count };
        };
        let mut pairs = Vec::with_capacity(items.len());
        let mut chars = 0;
        for item in items {
            let (Some(key), Some(value)) = (item[0].as_str(), item[1].as_str()) else {
                return StoreRead::Failed;
            };
            chars += utf16(key) + utf16(value);
            pairs.push((key.to_owned(), value.to_owned()));
        }
        // The page's own count of what it sent, checked again here.
        let bound = u64::try_from(limits.store_chars).unwrap_or(u64::MAX);
        if pairs.len() > limits.items || chars > bound {
            return StoreRead::Over { count };
        }
        StoreRead::Items { pairs, chars }
    }

    /// Sets `cookies`, each as `Network.setCookies` takes it, on the page in
    /// front, in batches.
    pub(crate) fn set_cookies(&self, cookies: Vec<Value>) -> Result<(), BrowserError> {
        let mut batch = Vec::new();
        let mut bytes = 0;
        for cookie in cookies {
            let size = cookie.to_string().len();
            if !batch.is_empty() && bytes + size > IMPORT_PIECE_BYTES {
                let full = std::mem::take(&mut batch);
                self.page("Network.setCookies", json!({"cookies": full}))?;
                bytes = 0;
            }
            bytes += size;
            batch.push(cookie);
        }
        if !batch.is_empty() {
            self.page("Network.setCookies", json!({"cookies": batch}))?;
        }
        Ok(())
    }

    /// Loads a one-shot inert document of `origin` in the tab in front,
    /// answered by the pipe and never fetched, checks it stands at
    /// `origin`, then clears each store and writes the items `stores` names
    /// for it (local, then session; none clears it only). Answers each
    /// store's readback, its items and their UTF-16 code units, or none
    /// where the write failed; or why the document did not stand.
    pub(crate) fn seed_origin(
        &self,
        origin: &str,
        stores: [Option<&[(String, String)]>; 2],
    ) -> Result<[Option<(u64, u64)>; 2], String> {
        let frame = self
            .page("Page.getFrameTree", json!({}))
            .ok()
            .and_then(|tree| {
                tree.pointer("/frameTree/frame/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let url = format!("{origin}/.oneiron-seed/{}", session_token());
        let answered = self.pipe.arm_seed(&self.session, frame, &url);
        let navigated = self.page("Page.navigate", json!({"url": url}));
        let fulfilled = answered.recv_timeout(CALL);
        self.pipe.disarm_seed();
        match navigated {
            Ok(navigated) if navigated.get("errorText").is_none() => {}
            Ok(_) => return Err("the seed document did not load".to_owned()),
            Err(error) => return Err(error.code().to_owned()),
        }
        match fulfilled {
            Ok(Ok(())) => {}
            Ok(Err(why)) => return Err(why),
            Err(_) => return Err("the seed request was never asked for".to_owned()),
        }
        if !self.loaded(Instant::now() + LOAD).unwrap_or(false) {
            return Err("the seed document did not finish loading".to_owned());
        }
        let stands = self
            .page(
                "Runtime.evaluate",
                json!({"expression": "location.origin", "returnByValue": true}),
            )
            .ok()
            .and_then(|answer| answer.pointer("/result/value").cloned());
        if stands.as_ref().and_then(Value::as_str) != Some(origin) {
            return Err("the seed document stands at another origin".to_owned());
        }
        Ok([
            self.seed_store(Store::Local, stores[0]),
            self.seed_store(Store::Session, stores[1]),
        ])
    }

    /// Writes `pairs` into `store` of the seed document, in pieces, and
    /// reads it back.
    fn seed_store(&self, store: Store, pairs: Option<&[(String, String)]>) -> Option<(u64, u64)> {
        if let Some(pairs) = pairs.filter(|pairs| !pairs.is_empty()) {
            let text = serde_json::to_string(pairs).ok()?;
            let mut rest = text.as_str();
            // The first piece starts the text afresh: nothing an earlier
            // store left behind joins it.
            let mut join = "=";
            while !rest.is_empty() {
                let mut end = rest.len().min(IMPORT_PIECE_BYTES);
                while !rest.is_char_boundary(end) {
                    end -= 1;
                }
                let (piece, after) = rest.split_at(end);
                rest = after;
                let piece = serde_json::to_string(piece).ok()?;
                let expression = format!("window.__oneironSeed {join} {piece}; 0");
                join = "+=";
                let answer = self
                    .page(
                        "Runtime.evaluate",
                        json!({"expression": expression, "returnByValue": true}),
                    )
                    .ok()?;
                if answer.get("exceptionDetails").is_some() {
                    return None;
                }
            }
        }
        let expression = STORE_SEED.replace("__STORE__", store.global());
        let answer = self
            .page(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )
            .ok()?;
        if answer.get("exceptionDetails").is_some() {
            return None;
        }
        let read = answer.pointer("/result/value")?;
        Some((read[0].as_u64()?, read[1].as_u64()?))
    }

    /// Loads `url` in the tab in front and lets it settle; answers the URL
    /// the tab stands at then. A page still loading once its time is up is
    /// on its URL all the same.
    pub(crate) fn land(&self, url: &str) -> Result<String, BrowserError> {
        let navigated = self.page("Page.navigate", json!({"url": url}))?;
        if let Some(error) = navigated.get("errorText").and_then(Value::as_str) {
            return Err(BrowserError::Navigation(error.to_owned()));
        }
        let _ = self.loaded(Instant::now() + LOAD);
        if let Ok(before) = self.fingerprint() {
            let _ = self.settle(before, Instant::now());
        }
        Ok(self.page_info()?.0)
    }

    /// Scrolls the page in front to (`x`, `y`), in CSS pixels, and reads
    /// where it stands then.
    pub(crate) fn scroll_back(&self, x: f64, y: f64) -> Result<(f64, f64), BrowserError> {
        let expression = format!("window.scrollTo({x}, {y}); 0");
        self.page(
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
        )?;
        self.scroll_offset()
    }

    /// The page in front, whole.
    pub(crate) fn whole(&mut self) -> Result<Observation, BrowserError> {
        self.observation(&Base::Whole)
    }
}
