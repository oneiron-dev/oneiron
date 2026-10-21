//! What the driver reads for a host's rendered document, and its load wait
//! with the host's custody of the session's requests (FIX 7122).
//!
//! The markup is read in pieces, each well inside the bound on one CDP
//! message, so a page of any size reads whole: the page serializes it once
//! into an array the driver holds by reference, out of reach of the page's
//! scripts, then answers it piece by piece, never splitting a surrogate
//! pair, and the reference is released. The status is the one the session
//! noted for the main frame's document request (`cdp::requests`), only
//! while the main frame shows the URL that request asked.

use super::{CdpDriver, POLL};
use crate::{BrowserError, RenderedDocument};
use serde_json::{Value, json};
use std::time::Instant;

/// The page's markup, serialized once: its doctype, then its root element,
/// held in a one-item array the driver reads by reference.
const DOCUMENT_HTML: &str = "(() => { const d = document; const t = d.doctype ? '<!DOCTYPE ' + d.doctype.name + '>' : ''; const e = d.documentElement; return [t + (e ? e.outerHTML : '')]; })()";
/// One piece of the held markup from UTF-16 code unit `a`, at most `n` of
/// them, never ending inside a surrogate pair: the piece, and where the
/// next one starts.
const DOCUMENT_PIECE: &str = "function(a, n) { const s = this[0]; let b = Math.min(a + n, s.length); if (b < s.length && b > a + 1) { const c = s.charCodeAt(b - 1); if (c >= 0xd800 && c <= 0xdbff) b -= 1; } return [s.slice(a, b), b]; }";
/// UTF-16 code units one piece carries: at six bytes each as JSON at worst,
/// one piece's answer stays well inside the host's 32 MiB bound on one CDP
/// message.
const PIECE_CHARS: u64 = 1 << 20;

impl CdpDriver {
    /// The page in front as rendered now: its markup, the URL it stands at,
    /// and its main-frame document's status where the session knows it.
    pub(crate) fn document(&self) -> Result<RenderedDocument, BrowserError> {
        let tree = self.page("Page.getFrameTree", json!({}))?;
        let frame = tree.pointer("/frameTree/frame").unwrap_or(&Value::Null);
        let html = self.markup()?;
        let final_url = self.page_info()?.0;
        let status = match (frame["id"].as_str(), frame["url"].as_str()) {
            (Some(id), Some(url)) => self.pipe.document_status(&self.session, id, url),
            _ => None,
        };
        Ok(RenderedDocument {
            html,
            final_url,
            status,
        })
    }

    /// The page's markup, read whole in pieces; its held copy released.
    fn markup(&self) -> Result<String, BrowserError> {
        let held = self.page(
            "Runtime.evaluate",
            json!({"expression": DOCUMENT_HTML, "returnByValue": false}),
        )?;
        let object = held
            .pointer("/result/objectId")
            .filter(|_| held.get("exceptionDetails").is_none())
            .cloned()
            .ok_or_else(|| BrowserError::Protocol("the page did not serialize".to_owned()))?;
        let node = json!({"objectId": object});
        let read = self.pieces(&node);
        let _ = self.page("Runtime.releaseObject", json!({"objectId": object}));
        read
    }

    /// The held markup `node`, piece by piece, to its end.
    fn pieces(&self, node: &Value) -> Result<String, BrowserError> {
        let mut html = String::new();
        let mut at: u64 = 0;
        loop {
            let args = json!([{"value": at}, {"value": PIECE_CHARS}]);
            let piece = self.call_on(node, DOCUMENT_PIECE, args)?;
            let (Some(text), Some(next)) = (piece[0].as_str(), piece[1].as_u64()) else {
                return Err(BrowserError::Protocol(
                    "a piece of the page's markup did not read".to_owned(),
                ));
            };
            if next <= at {
                return Ok(html);
            }
            html.push_str(text);
            at = next;
        }
    }

    /// Waits until an open's document has loaded, up to `deadline`, as
    /// every load wait does: whether it did. A destination refusal the
    /// host's handler gave a request of the session meanwhile, not yet
    /// delivered, ends the wait and answers, never hidden behind the load's
    /// time. A session the host gave no handler waits as always.
    pub(super) fn loaded_or_refused(&self, deadline: Instant) -> Result<bool, BrowserError> {
        loop {
            if let Some(refused) = self.pipe.refusal_pending() {
                return Err(BrowserError::DestinationRefused(refused));
            }
            if self.loaded(Instant::now())? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL);
        }
    }
}
