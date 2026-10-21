//! What comes back from a send that presented a custody value, cleared of
//! that value (FIX 7646, FIX 7647).
//!
//! Every send that presents a custody record's value, whether a `self.use`
//! handle, a secret grant or a connector route's own secret selected it,
//! makes one [`SentPresentation`]: the record, the generation its door
//! released and the release policy its reply takes. Its reply is cleared
//! INSIDE that door's callback, with the bytes the door released
//! ([`SECRET_USE_CLEAR_VALUE_SOURCE`]), before any answer, error, question
//! or raw copy leaves it; never by reading the value again after the send,
//! which a rotation landing in between would make the wrong value. The
//! clearing is the one an explicit credential's reply always had: each raw
//! or trimmed copy of the value, in a string or a key at any depth, becomes
//! the record's handle text. Nothing is withheld for it. Ids, generation and
//! policy only: a presentation holds no value.

use std::fmt;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Result, SecretError};
use crate::vault::Vault;

/// Which value a reply is cleared of (FIX 7647). One constant, so a later
/// ruling changes one line.
pub const SECRET_USE_CLEAR_VALUE_SOURCE: SecretClearValueSource =
    SecretClearValueSource::SentSnapshot;

/// Where the value a reply is cleared of comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretClearValueSource {
    /// The bytes the send's own door released, inside that door's callback,
    /// before anything that came back leaves it.
    SentSnapshot,
}

/// How the reply to one custody presentation is released (FIX 7646).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretReleasePolicy {
    /// Released whole, with each copy of the presented value replaced by the
    /// record's handle text, the value taken from the named source.
    Cleared(SecretClearValueSource),
}

/// One send's actual custody presentation, as its door released it: the
/// record, the generation sent and the release policy its reply took. Kept
/// apart from the record a call names as its credential: a route's own
/// secret presents one too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentPresentation {
    pub custody: EntityId,
    /// The record's rotation generation the door released.
    pub generation: u32,
    pub policy: SecretReleasePolicy,
}

impl SentPresentation {
    /// A presentation of `custody` at `generation`, its reply cleared with
    /// the bytes the door released.
    #[must_use]
    pub const fn cleared(custody: EntityId, generation: u32) -> Self {
        Self {
            custody,
            generation,
            policy: SecretReleasePolicy::Cleared(SECRET_USE_CLEAR_VALUE_SOURCE),
        }
    }
}

/// One send's value as its door released it, and the text each copy of it
/// becomes. It borrows the door's own bytes, so it lives no longer than the
/// door's callback.
pub struct SentValue<'a> {
    value: &'a [u8],
    text: &'a str,
}

impl<'a> SentValue<'a> {
    /// The value `value` the door released, cleared to `text`.
    #[must_use]
    pub const fn new(value: &'a [u8], text: &'a str) -> Self {
        Self { value, text }
    }
}

impl SentValue<'_> {
    /// Each copy of the value in `json`, in a string or a key at any depth.
    pub fn clear_json(&self, json: &mut Value) {
        clear_value(json, self.value, self.text);
    }

    /// Each copy of the value in `string`.
    pub fn clear_string(&self, string: &mut String) {
        clear_text(string, self.value, self.text);
    }

    /// Each copy of the value in a raw reply body. A JSON body is cleared
    /// as its parsed strings and keys are, and written again only when that
    /// changed it; any other body is cleared byte for byte.
    pub fn clear_bytes(&self, bytes: &mut Vec<u8>) {
        if let Ok(mut parsed) = serde_json::from_slice::<Value>(bytes) {
            let before = parsed.clone();
            self.clear_json(&mut parsed);
            if parsed != before
                && let Ok(cleared) = serde_json::to_vec(&parsed)
            {
                *bytes = cleared;
            }
            return;
        }
        let Ok(value) = std::str::from_utf8(self.value) else {
            return;
        };
        let trimmed = value.trim();
        for form in [value, trimmed] {
            if !form.is_empty() {
                *bytes = replace_bytes(bytes, form.as_bytes(), self.text.as_bytes());
            }
            if trimmed == value {
                break;
            }
        }
    }

    /// A copy a live exchange's worker keeps to clear what the connector
    /// says after its send returned, as its session keeps the credential
    /// header; scrubbed when the worker drops it.
    #[must_use]
    pub fn keep(&self) -> KeptSentValue {
        KeptSentValue {
            value: Zeroizing::new(self.value.to_vec()),
            text: self.text.to_owned(),
        }
    }
}

impl fmt::Debug for SentValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentValue")
            .field("text", &self.text)
            .finish_non_exhaustive()
    }
}

/// [`SentValue`], owned by a live exchange's worker until its session ends.
pub struct KeptSentValue {
    value: Zeroizing<Vec<u8>>,
    text: String,
}

impl KeptSentValue {
    /// The kept value, to clear with.
    #[must_use]
    pub fn sent(&self) -> SentValue<'_> {
        SentValue {
            value: &self.value,
            text: &self.text,
        }
    }
}

impl fmt::Debug for KeptSentValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeptSentValue")
            .field("text", &self.text)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The text the value of the custody record `custody` becomes in what
    /// came back: its handle text, `[secret sc12]`, or `[secret]` when it
    /// has no handle to read. Value-free.
    #[must_use]
    pub fn secret_clear_text(&self, custody: Option<&EntityId>) -> String {
        let short = custody.and_then(|id| {
            let txn = self.store.env.read_txn().ok()?;
            crate::ports::ShortIdStoreRead::port_short_id_reference(&self.store, &txn, id)
                .ok()
                .flatten()
        });
        short.map_or_else(|| "[secret]".to_owned(), |(short, _)| handle_text(&short))
    }

    /// [`Self::secret_clear_text`] for the record the secret name
    /// `secret_ref` resolves to now: a route's own secret, read before its
    /// send so its reply is cleared inside the door. Value-free.
    #[must_use]
    pub fn secret_clear_text_for_ref(&self, secret_ref: &str) -> String {
        let custody = self.resolve_secret_ref(secret_ref).ok().flatten();
        self.secret_clear_text(custody.as_ref())
    }

    /// `result` and `failure`, from a use whose operation said nothing of
    /// what it sent, cleared of the value of the record `id` read once more
    /// through its door for `effector`, only to find it there; withheld when
    /// it cannot be.
    pub(super) fn clear_use_by_reread(
        &self,
        id: &EntityId,
        effector: &str,
        handle: &str,
        result: &mut Option<Value>,
        failure: &mut Option<String>,
    ) -> bool {
        let text = handle_text(handle);
        let cleared = self.inject_secret_record_at_door(id, effector, &mut |value: &[u8]| {
            if let Some(result) = result.as_mut() {
                clear_value(result, value, &text);
            }
            if let Some(failure) = failure.as_mut() {
                clear_text(failure, value, &text);
            }
            Ok(())
        });
        let Err(error) = cleared else {
            return true;
        };
        *result = None;
        // KS-6: a key that does not open says so, typed, with its way out.
        *failure = Some(match error {
            crate::error::Error::Secret(SecretError::CredentialLeafUnreadable { .. }) => {
                format!("the result was withheld: {error}")
            }
            _ => "the result was withheld: it could not be cleared of the value".into(),
        });
        false
    }

    /// Each copy of the value of the custody record `id` in `fields`, in a
    /// string or a key at any depth, replaced by the record's handle text.
    /// The value is read once more through its door for `effector`, only to
    /// find it there: the reply of a host that cannot say it cleared its
    /// sends inside their doors.
    ///
    /// # Errors
    /// The door's refusal, when the value cannot be read: then `fields` may
    /// still hold it, and the caller withholds them.
    pub(crate) fn clear_secret_record_from(
        &self,
        id: &EntityId,
        effector: &str,
        fields: &mut [&mut Value],
    ) -> Result<()> {
        let text = self.secret_clear_text(Some(id));
        self.inject_secret_record_at_door(id, effector, &mut |value: &[u8]| {
            for field in fields.iter_mut() {
                clear_value(&mut **field, value, &text);
            }
            Ok(())
        })
        .map(drop)
    }
}

/// A handle as a text stands it in for a value: `[secret sc12]`.
pub(super) fn handle_text(handle: &str) -> String {
    format!("[secret {handle}]")
}

/// Each copy of `value` in `json`, in a string or a key at any depth,
/// replaced by `text`.
fn clear_value(json: &mut Value, value: &[u8], text: &str) {
    match json {
        Value::String(string) => clear_text(string, value, text),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| clear_value(item, value, text)),
        Value::Object(fields) => {
            let taken = std::mem::take(fields);
            for (mut key, mut field) in taken {
                clear_text(&mut key, value, text);
                clear_value(&mut field, value, text);
                fields.insert(key, field);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Each copy of `value` in `string`, as held and with its surrounding
/// whitespace trimmed (consumers trim before they present it), replaced by
/// `text`.
pub(super) fn clear_text(string: &mut String, value: &[u8], text: &str) {
    let Ok(value) = std::str::from_utf8(value) else {
        return;
    };
    let trimmed = value.trim();
    for form in [value, trimmed] {
        if !form.is_empty() && string.contains(form) {
            *string = string.replace(form, text);
        }
        if trimmed == value {
            break;
        }
    }
}

/// `bytes` with each copy of `form` replaced by `text`.
fn replace_bytes(bytes: &[u8], form: &[u8], text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(at) = rest.windows(form.len()).position(|window| window == form) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(text);
        rest = &rest[at + form.len()..];
    }
    out.extend_from_slice(rest);
    out
}
