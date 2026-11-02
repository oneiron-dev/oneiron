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
use crate::secret_fields::{
    FieldFacts, SECRET_MARK, classify, masked, prose_codes, secret_display_policy,
    secret_echo_policy,
};
use crate::{BrowserError, RowSecret, SecretKind, SecretNote};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Instant;
use url::Url;

/// Masks every input the front document marks secret by its type or an
/// autocomplete token (any card field, one-time code or password), keeping
/// each one's style to restore.
const MASK_FIELDS: &str = "document.querySelectorAll('input[type=password],[autocomplete*=\"cc-\"],[autocomplete~=\"one-time-code\"],[autocomplete~=\"current-password\"],[autocomplete~=\"new-password\"]').forEach(e => { if (e.dataset.oneironMask !== undefined) return; e.dataset.oneironMask = e.style.cssText; e.style.setProperty('background', '#000', 'important'); e.style.setProperty('color', '#000', 'important'); e.style.setProperty('-webkit-text-security', 'disc', 'important'); })";

/// The query and fragment parameters whose value a URL's display shows as
/// a one-time code's handle (FIX 8340, `url_code_policy`, CALLS row, open):
/// a magic link's or a verification link's code, by its parameter's name.
/// The URL itself stays the page's identity; only its display changes.
const URL_CODE_PARAMS: &[&str] = &[
    "otp",
    "code",
    "one_time_code",
    "verification_code",
    "passcode",
    "magic",
    "magic_link",
    "login_token",
    "auth_token",
    "access_token",
    "token",
];

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
                // A text row naming a one-time code in its prose holds that
                // code, the rest of its text its own (FIX 8337).
                if text {
                    for code in prose_codes(value) {
                        let held = taken
                            .entry((SecretKind::Otp, code))
                            .or_insert_with(|| {
                                let origin = origin.get_or_insert_with(|| self.page_origin());
                                self.secrets.acquire(SecretKind::Otp, code, origin)
                            })
                            .clone();
                        let handle = held.as_ref().ok().map(String::as_str);
                        let display = secret_display_policy(SecretKind::Otp, code, handle);
                        if !masks.echoes.iter().any(|(secret, _)| secret == code) {
                            masks.echoes.push((code.to_owned(), display));
                        }
                    }
                }
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
        // What earlier reads of the run took, shown again in this read's
        // rows, shows its handle too: the run-scoped matcher (FIX 8337).
        for line in lines {
            let Some(node) = line.ax_id.as_deref().and_then(|id| by_id.get(id)) else {
                continue;
            };
            for field in ["name", "value", "description"] {
                let text = outline::field(node, field).unwrap_or("");
                for (secret, shown) in self.secrets.known_in(text) {
                    if !masks.echoes.iter().any(|(held, _)| *held == secret) {
                        masks.echoes.push((secret, shown));
                    }
                }
            }
        }
        masks
    }

    /// The page's URL and title as an observation shows them (FIX 8340):
    /// each secret the run's reads took shows its handle, as do the
    /// one-time codes the title names in prose and the URL carries in a
    /// code's parameter ([`URL_CODE_PARAMS`]). The browser's own URL stays
    /// the page's identity everywhere else.
    pub(super) fn shown_page(&self, url: String, title: String) -> (String, String) {
        let origin = Url::parse(&url)
            .map_or_else(|_| String::new(), |url| url.origin().ascii_serialization());
        let mut echoes: Vec<(String, String)> = Vec::new();
        for code in prose_codes(&title) {
            let handle = self.secrets.acquire(SecretKind::Otp, code, &origin).ok();
            let display = secret_display_policy(SecretKind::Otp, code, handle.as_deref());
            echoes.push((code.to_owned(), display));
        }
        let pairs: Vec<(&str, &str)> = echoes
            .iter()
            .map(|(secret, shown)| (secret.as_str(), shown.as_str()))
            .collect();
        let title = secret_echo_policy(&title, &pairs).unwrap_or(title);
        let title = self.secrets.mask_known(&title).unwrap_or(title);
        (self.url_shown(&url), title)
    }

    /// `url` as an observation shows it (FIX 8340): each code parameter's
    /// value and each secret the run's reads took show their handles. A
    /// receipt's page and a recording's pages show the same (FIX 10331);
    /// the raw URL stays only for the host's own lookups.
    pub(crate) fn url_shown(&self, url: &str) -> String {
        let origin = Url::parse(url)
            .map_or_else(|_| String::new(), |url| url.origin().ascii_serialization());
        let url = self.shown_url(url, &origin);
        self.secrets.mask_known(&url).unwrap_or(url)
    }

    /// `url` with each code parameter's value, in its query and in a
    /// fragment of parameters, shown as its handle.
    fn shown_url(&self, url: &str, origin: &str) -> String {
        let (head, fragment) = url
            .split_once('#')
            .map_or((url, None), |(h, f)| (h, Some(f)));
        let (path, query) = head
            .split_once('?')
            .map_or((head, None), |(p, q)| (p, Some(q)));
        let mut shown = path.to_owned();
        if let Some(query) = query {
            shown.push('?');
            shown.push_str(&self.shown_params(query, origin));
        }
        if let Some(fragment) = fragment {
            shown.push('#');
            if fragment.contains('=') {
                shown.push_str(&self.shown_params(fragment, origin));
            } else {
                shown.push_str(fragment);
            }
        }
        shown
    }

    /// `params` (`name=value` pairs, `&` between) with each code
    /// parameter's value shown as its handle.
    fn shown_params(&self, params: &str, origin: &str) -> String {
        let shown: Vec<String> = params
            .split('&')
            .map(|pair| {
                let Some((name, _)) = pair.split_once('=') else {
                    return pair.to_owned();
                };
                let decoded = url::form_urlencoded::parse(pair.as_bytes()).next();
                let Some((key, value)) = decoded.filter(|(_, value)| !value.is_empty()) else {
                    return pair.to_owned();
                };
                if !URL_CODE_PARAMS
                    .iter()
                    .any(|code| key.eq_ignore_ascii_case(code))
                {
                    return pair.to_owned();
                }
                let handle = self.secrets.acquire(SecretKind::Otp, &value, origin).ok();
                let display = secret_display_policy(SecretKind::Otp, &value, handle.as_deref());
                format!("{name}={display}")
            })
            .collect();
        shown.join("&")
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
            if let Err(error) = self.call_on_element(&element, MASK_NODE) {
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
    fn call_on_element(&self, element: &Value, function: &str) -> Result<(), BrowserError> {
        let session = element["sessionId"].as_str().unwrap_or(&self.session);
        let answer = self.pipe.call(
            Some(session),
            "Runtime.callFunctionOn",
            json!({"objectId": element["objectId"], "functionDeclaration": function, "arguments": [], "returnByValue": true}),
            Instant::now() + CALL,
        )?;
        match answer.get("exceptionDetails") {
            Some(error) => Err(BrowserError::Protocol(self.thrown_text(error))),
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
            let undone = self.call_on_element(element, UNMASK_NODE);
            if restored.is_ok() {
                restored = undone;
            }
        }
        restored
    }
}
