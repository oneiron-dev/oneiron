//! The wiping body path for the custody rows that carry a secret's value in
//! plaintext over the HTTP facade (FIX 11442): `vault.secrets.register` and
//! `vault.secrets.rotate`.
//! `read_middleware_body`, `scope_secret` and `current_secret` are its call surface.
//! The owner's routes (`owner::secrets`) define the wiping reader this follows.
//!
//! A body for either verb is read once, here, into the one buffer the call
//! owns: each frame is wiped as it is copied, the buffer is wiped on every
//! path, and the value is borrowed as a `RawValue`, never unescaped into a
//! `Value`. What runs on carries a redacted body whose `value_base64` is
//! empty: the receipt and invocation readers, the row's input check, its verb
//! hooks and their records. The real encoding rides the request's extensions
//! to the route, which scopes it for the door; the door puts it back into the
//! typed input it decodes from the redacted args. The rows keep no call
//! receipt (`NO_RECORD_ROWS`), and the invocation claim states the arrival's
//! own digest, so a retry naming another value still names another call.

use std::future::Future;

use axum::body::{Body, Bytes, HttpBody as _};
use axum::http::Extensions;
use futures_util::StreamExt as _;
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

/// The verbs whose body carries `value_base64` in plaintext.
fn needs_wipe(verb: &str) -> bool {
    matches!(verb, "vault.secrets.register" | "vault.secrets.rotate")
}

/// The real `value_base64` a wiping read carried, unescaped. Rides the
/// request's extensions from the outer middleware to the route.
#[derive(Clone)]
pub(super) struct FacadeSecret(Zeroizing<String>);

impl FacadeSecret {
    pub(super) fn secret(&self) -> Zeroizing<String> {
        self.0.clone()
    }
}

/// The arrival's own digest, for the invocation claim: a redacted body
/// digests differently, but a retry naming another value is still another
/// call.
#[derive(Clone)]
pub(super) struct FacadeOriginalDigest(String);

impl FacadeOriginalDigest {
    pub(super) fn digest(&self) -> &str {
        &self.0
    }
}

tokio::task_local! {
    static SECRET: Zeroizing<String>;
}

/// Runs `call` with `secret` as the custody door's value.
pub(super) async fn scope_secret<F: Future>(secret: Zeroizing<String>, call: F) -> F::Output {
    SECRET.scope(secret, call).await
}

/// The scoped value, if the route scoped one.
pub(super) fn current_secret() -> Option<Zeroizing<String>> {
    SECRET.try_with(|secret| secret.clone()).ok()
}

/// Reads a middleware body for `verb`: a custody value's through the wiping
/// reader, redacted, with its value and arrival digest on `extensions`; any
/// other verb's as `to_bytes` reads it today. A body already redacted
/// upstream reads as it arrived.
pub(super) async fn read_middleware_body(
    body: Body,
    verb: &str,
    extensions: &mut Extensions,
) -> (Bytes, Option<Value>) {
    // `MAX_REMOTE_REQUEST_BYTES` is the facade's own `FACADE_MAX_BODY_BYTES`.
    if !needs_wipe(verb) || extensions.get::<FacadeSecret>().is_some() {
        let bytes = axum::body::to_bytes(body, MAX_REMOTE_REQUEST_BYTES)
            .await
            .unwrap_or_default();
        let value = serde_json::from_slice(&bytes).ok();
        return (bytes, value);
    }
    let Ok(owned) = OwnedBody::read(body).await else {
        // Past the limit, or unreadable: empty, as `to_bytes` failing reads today.
        return (Bytes::new(), None);
    };
    if let Some((redacted, secret)) = redacted_body(verb, &owned.0) {
        // The claim states the arrival: the redacted input's digest beside
        // the value's hash, so another value still names another call.
        let arrival = format!(
            "{}:{}",
            oneiron::receipt::call_json_digest(&redacted),
            blake3::hash(secret.as_bytes()).to_hex(),
        );
        extensions.insert(FacadeSecret(secret));
        extensions.insert(FacadeOriginalDigest(arrival));
        let bytes = Bytes::from(serde_json::to_vec(&redacted).unwrap_or_default());
        return (bytes, Some(redacted));
    }
    // No `value_base64` string to carry: the body as it arrived, value-free.
    let value = serde_json::from_slice(&owned.0).ok();
    (Bytes::copy_from_slice(&owned.0), value)
}

/// The redacted body and its value, when `body` carries a `value_base64`
/// string for `verb`: the typed `RawValue` read first, then a generic
/// `Value` read whose string is wiped once saved, so a body the row refuses
/// still keeps its value out of what runs on.
fn redacted_body(verb: &str, body: &[u8]) -> Option<(Value, Zeroizing<String>)> {
    if let Some(redacted) = typed_redacted(verb, body) {
        return Some(redacted);
    }
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let secret = Zeroizing::new(value.get("value_base64")?.as_str()?.to_owned());
    if let Some(Value::String(held)) = value.get_mut("value_base64") {
        held.zeroize();
        *held = String::new();
    }
    Some((value, secret))
}

/// The typed redaction: the value borrowed as a `RawValue`, the caller's
/// other fields carried as they arrived, `value_base64` empty. `None` when
/// the body is not the verb's shape, or its value is no string.
fn typed_redacted(verb: &str, body: &[u8]) -> Option<(Value, Zeroizing<String>)> {
    match verb {
        "vault.secrets.register" => {
            let fields: RegisterFields<'_> = serde_json::from_slice(body).ok()?;
            let secret = secret_text(fields.value_base64)?;
            Some((register_redacted(fields)?, secret))
        }
        "vault.secrets.rotate" => {
            let fields: RotateFields<'_> = serde_json::from_slice(body).ok()?;
            let secret = secret_text(fields.value_base64)?;
            Some((rotate_redacted(fields), secret))
        }
        _ => None,
    }
}

/// The `value_base64` string, unescaped into a wiped buffer. Base64 needs no
/// escapes, but the facade keeps what it admitted: a value carrying one
/// unescapes here, into this buffer alone.
fn secret_text(raw: &RawValue) -> Option<Zeroizing<String>> {
    serde_json::from_str::<String>(raw.get())
        .ok()
        .map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateFields<'a> {
    name: String,
    /// Raw, as on the owner's route, so the parser skips the string in
    /// place and never unescapes it into its own scratch buffer.
    #[serde(borrow)]
    value_base64: &'a RawValue,
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    recipients: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFields<'a> {
    name: String,
    class: String,
    rung: u8,
    #[serde(default)]
    device_only: bool,
    #[serde(default)]
    bindings: Vec<BindingFields>,
    #[serde(default)]
    manifest: Option<ManifestFields>,
    /// Raw, as in [`RotateFields`].
    #[serde(borrow)]
    value_base64: &'a RawValue,
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    recipients: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingFields {
    effector: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    tier_ceiling: Option<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFields {
    repo: String,
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
}

/// The rotate body without its value: the caller's fields, `value_base64`
/// empty. A field the caller omitted stays omitted, so the redacted body
/// decodes as the arrival did.
fn rotate_redacted(fields: RotateFields<'_>) -> Value {
    let mut redacted = serde_json::Map::new();
    redacted.insert("name".to_owned(), Value::String(fields.name));
    redacted.insert("value_base64".to_owned(), Value::String(String::new()));
    if let Some(holder) = fields.holder {
        redacted.insert("holder".to_owned(), Value::String(holder));
    }
    if !fields.recipients.is_empty() {
        redacted.insert(
            "recipients".to_owned(),
            Value::Array(fields.recipients.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(redacted)
}

/// The register body without its value, as [`rotate_redacted`].
fn register_redacted(fields: RegisterFields<'_>) -> Option<Value> {
    let mut redacted = serde_json::Map::new();
    redacted.insert("name".to_owned(), Value::String(fields.name));
    redacted.insert("class".to_owned(), Value::String(fields.class));
    redacted.insert("rung".to_owned(), Value::Number(fields.rung.into()));
    if fields.device_only {
        redacted.insert("device_only".to_owned(), Value::Bool(true));
    }
    if !fields.bindings.is_empty() {
        redacted.insert(
            "bindings".to_owned(),
            serde_json::to_value(fields.bindings).ok()?,
        );
    }
    if let Some(manifest) = fields.manifest {
        redacted.insert("manifest".to_owned(), serde_json::to_value(manifest).ok()?);
    }
    redacted.insert("value_base64".to_owned(), Value::String(String::new()));
    if let Some(holder) = fields.holder {
        redacted.insert("holder".to_owned(), Value::String(holder));
    }
    if !fields.recipients.is_empty() {
        redacted.insert(
            "recipients".to_owned(),
            Value::Array(fields.recipients.into_iter().map(Value::String).collect()),
        );
    }
    Some(Value::Object(redacted))
}

/// The body in the one buffer this read owns, wiped when it drops. It is
/// sized before the first byte arrives and never grows: growing would move
/// the bytes and free the old allocation unwiped.
struct OwnedBody(Vec<u8>);

impl OwnedBody {
    async fn read(body: Body) -> Result<Self, ()> {
        let room = match body.size_hint().upper() {
            None => MAX_REMOTE_REQUEST_BYTES,
            Some(declared) => usize::try_from(declared)
                .ok()
                .filter(|declared| *declared <= MAX_REMOTE_REQUEST_BYTES)
                .ok_or(())?,
        };
        let mut owned = Self(Vec::with_capacity(room));
        let mut frames = body.into_data_stream();
        while let Some(frame) = frames.next().await {
            let frame = frame.map_err(|_| ())?;
            let fits = frame.len() <= owned.0.capacity() - owned.0.len();
            if fits {
                owned.0.extend_from_slice(&frame);
            }
            wipe_frame(frame);
            if !fits {
                return Err(());
            }
        }
        Ok(owned)
    }
}

impl Drop for OwnedBody {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Wipes a frame in place once it is copied, when this read holds its only
/// reference. A frame the server still shares with the connection's read
/// buffer, which hyper splits frames from, is transport memory: no handler
/// reaches it, as none reaches the bearer token read with the headers.
fn wipe_frame(frame: Bytes) {
    if let Ok(mut frame) = frame.try_into_mut() {
        frame[..].zeroize();
    }
}
