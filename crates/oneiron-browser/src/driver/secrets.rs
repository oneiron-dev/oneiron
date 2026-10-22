//! A page read's secrets (FIX 8028, OF-560; ARCH-0069): found on the
//! outline's own candidates, before any row is built, and held where they
//! are found.
//!
//! Each candidate row is classified (`secret_fields`) on what the tree and
//! the capture's DOM read give it: its role, the tree's `protected`
//! property, its input type and autocomplete tokens, its label and
//! description, and its value as the tree holds it, whole (a text row's,
//! its text). A field the session typed a secret into reads as that
//! secret's kind from then on. A classified value is handed to the
//! session's custody whole, before any clipping, and its row shows the
//! handle it became; mask glyphs are no value and become none. The read's
//! rows are then built through those [`Masks`], so no row, page, delta,
//! locator, candidate or receipt of the session ever holds the value.
//!
//! A screenshot masks the same rows (each one a secret shows in, by its DOM
//! node, in whatever frame or shadow tree the tree reached it, an
//! out-of-process frame's on that frame's own session, FIX 8336) and, for
//! fields no read has classified yet, every input a password, card or
//! one-time-code autocomplete token names in the front document and in
//! each of its out-of-process frames, before the image is taken; every mask
//! comes off after it.

use super::row_metadata::DomRead;
use super::{CALL, CdpDriver};
use crate::outline::{self, Line, Masked, Masks};
use crate::secret_fields::{FieldFacts, SECRET_MARK, classify, masked, secret_display_policy};
use crate::{BrowserError, RowSecret, SecretKind, SecretNote};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Instant;
use url::Url;

/// Masks every input the front document marks secret by its type or an
/// autocomplete token (any card field, one-time code or password), keeping
/// each one's style to restore.
const MASK_FIELDS: &str = "document.querySelectorAll('input[type=password],[autocomplete*=\"cc-\"],[autocomplete~=\"one-time-code\"],[autocomplete~=\"current-password\"],[autocomplete~=\"new-password\"]').forEach(e => { if (e.dataset.oneironMask !== undefined) return; e.dataset.oneironMask = e.style.cssText; e.style.setProperty('background', '#000', 'important'); e.style.setProperty('color', '#000', 'important'); e.style.setProperty('-webkit-text-security', 'disc', 'important'); })";

/// Restores what [`MASK_FIELDS`] masked in the front document.
const UNMASK_FIELDS: &str = "document.querySelectorAll('[data-oneiron-mask]').forEach(e => { e.style.cssText = e.dataset.oneironMask; delete e.dataset.oneironMask; })";

/// Masks one secret row's element (a text row's, its parent element),
/// keeping its style to restore.
const MASK_NODE: &str = "function() { const e = this.nodeType === 1 ? this : this.parentElement; if (!e || !e.style || !e.dataset || e.dataset.oneironMask !== undefined) return false; e.dataset.oneironMask = e.style.cssText; e.style.setProperty('background', '#000', 'important'); e.style.setProperty('color', '#000', 'important'); e.style.setProperty('-webkit-text-security', 'disc', 'important'); return true; }";

/// Restores what [`MASK_NODE`] masked.
const UNMASK_NODE: &str = "function() { const e = this.nodeType === 1 ? this : this.parentElement; if (e && e.dataset && e.dataset.oneironMask !== undefined) { e.style.cssText = e.dataset.oneironMask; delete e.dataset.oneironMask; } return true; }";

impl CdpDriver {
    /// The secrets of one read, `lines` as the tree named them on `ax`
    /// with `dom` the read's DOM: each secret row's own, held through the
    /// session's custody, and what shows in each one's place.
    pub(super) fn secret_masks(&self, ax: &[Value], lines: &[Line], dom: &DomRead) -> Masks {
        let by_id: HashMap<&str, &Value> = ax
            .iter()
            .filter_map(|node| Some((node.get("nodeId")?.as_str()?, node)))
            .collect();
        let mut masks = Masks::default();
        let mut origin: Option<String> = None;
        // One custody ask per secret a read shows, however many rows show it.
        let mut taken: HashMap<(SecretKind, &str), Result<String, SecretNote>> = HashMap::new();
        for line in lines {
            let Some((id, node)) = line
                .ax_id
                .as_deref()
                .and_then(|id| Some((id, *by_id.get(id)?)))
            else {
                continue;
            };
            let role = line.row.role.as_str();
            let name = outline::field(node, "name").unwrap_or("");
            let own = outline::field(node, "value").filter(|value| !value.is_empty());
            // A text row's secret is its own text.
            let text = own.is_none() && outline::is_read(role);
            let value = match own {
                Some(value) => value,
                None if text => name,
                None => "",
            };
            let (input_type, autocomplete) = dom.field_attributes(line);
            let facts = FieldFacts {
                role,
                protected: outline::protected(node),
                input_type,
                autocomplete,
                label: name,
                description: outline::field(node, "description").unwrap_or(""),
                value,
            };
            let typed = line
                .backend_node
                .and_then(|backend| self.typed.get(&backend).copied());
            let Some(kind) = classify(&facts).or(typed) else {
                continue;
            };
            let (shown, secret) = if value.trim().is_empty() {
                let secret = RowSecret {
                    kind,
                    handle: None,
                    note: None,
                };
                (None, secret)
            } else if masked(value) {
                let secret = RowSecret {
                    kind,
                    handle: None,
                    note: Some(SecretNote::Concealed),
                };
                (Some(SECRET_MARK.to_owned()), secret)
            } else {
                let held = taken
                    .entry((kind, value))
                    .or_insert_with(|| {
                        let origin = origin.get_or_insert_with(|| self.page_origin());
                        self.secrets.acquire(kind, value, origin)
                    })
                    .clone();
                let (handle, note) = match held {
                    Ok(handle) => (Some(handle), None),
                    Err(note) => (None, Some(note)),
                };
                let display = secret_display_policy(kind, value, handle.as_deref());
                masks
                    .echoes
                    .push((value.trim().to_owned(), display.clone()));
                (Some(display), RowSecret { kind, handle, note })
            };
            let shown = if text { None } else { shown };
            masks.fields.insert(id.to_owned(), Masked { shown, secret });
        }
        masks
    }

    /// The front page's origin, as a secret found on it names where it
    /// was found; empty when the page cannot say.
    fn page_origin(&self) -> String {
        self.url()
            .ok()
            .and_then(|url| Url::parse(&url).ok())
            .map_or_else(String::new, |url| url.origin().ascii_serialization())
    }

    /// Masks the front tab's secrets for a screenshot: the fields its
    /// front document marks secret, then each element the last read showed
    /// a secret in that the page still has. Answers what it masked by
    /// element, for [`Self::unmask_secrets`], and whether every mask took:
    /// a screenshot is taken only once they all did.
    pub(super) fn mask_secrets(&self) -> (Vec<Value>, Result<(), BrowserError>) {
        let mut masked = Vec::new();
        for session in std::iter::once(self.session.clone()).chain(self.oopif_sessions()) {
            if let Err(error) = self.evaluate_in(&session, MASK_FIELDS) {
                return (masked, Err(error));
            }
        }
        for (frame, backend) in &self.secret_nodes {
            let session = self.frame_session(frame.as_deref());
            // A node the page no longer has shows nothing.
            let resolved = self.pipe.call(
                Some(&session),
                "DOM.resolveNode",
                json!({"backendNodeId": backend}),
                Instant::now() + CALL,
            );
            let Ok(resolved) = resolved else {
                continue;
            };
            let Some(object) = resolved.pointer("/object/objectId").cloned() else {
                continue;
            };
            let element = json!({"objectId": object, "sessionId": session});
            if let Err(error) = self.call_in(&element, MASK_NODE) {
                return (masked, Err(error));
            }
            masked.push(element);
        }
        (masked, Ok(()))
    }

    /// Evaluates `expression` on page or frame `session`, by value.
    fn evaluate_in(&self, session: &str, expression: &str) -> Result<Value, BrowserError> {
        self.pipe.call(
            Some(session),
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
            Instant::now() + CALL,
        )
    }

    /// Calls `function` on `element`, on the session it was resolved on.
    fn call_in(&self, element: &Value, function: &str) -> Result<(), BrowserError> {
        let session = element["sessionId"].as_str().unwrap_or(&self.session);
        let answer = self.pipe.call(
            Some(session),
            "Runtime.callFunctionOn",
            json!({"objectId": element["objectId"], "functionDeclaration": function, "arguments": [], "returnByValue": true}),
            Instant::now() + CALL,
        )?;
        match answer.get("exceptionDetails") {
            Some(error) => Err(BrowserError::Protocol(
                error
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("script error")
                    .to_owned(),
            )),
            None => Ok(()),
        }
    }

    /// Takes off every mask [`Self::mask_secrets`] put on: the front
    /// document's, then each element's it names. Every one is tried; the
    /// first failure is the answer.
    pub(super) fn unmask_secrets(&self, masked: &[Value]) -> Result<(), BrowserError> {
        let mut restored = Ok(());
        for session in std::iter::once(self.session.clone()).chain(self.oopif_sessions()) {
            let undone = self.evaluate_in(&session, UNMASK_FIELDS).map(drop);
            if restored.is_ok() {
                restored = undone;
            }
        }
        for element in masked {
            let undone = self.call_in(element, UNMASK_NODE);
            if restored.is_ok() {
                restored = undone;
            }
        }
        restored
    }
}
