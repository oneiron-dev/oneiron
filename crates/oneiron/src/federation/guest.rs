//! Guest-share envelope body and signed envelope codec.

use rmpv::Value;

use super::codec::encode_msgpack_value;
use super::grant::{FederationGrantScope, encode_scope};

use crate::entity_id::EntityId;
use crate::error::Result;

/// Current guest-share envelope body schema version.
pub const GUEST_SHARE_ENVELOPE_SCHEMA_VERSION: u64 = 1;

/// Pinned MessagePack key set for guest-share envelope bodies.
pub const GUEST_SHARE_ENVELOPE_BODY_KEYS: [&str; 6] = [
    "schema_version",
    "scope",
    "member_ref",
    "selector",
    "window_key",
    "update",
];

/// Pinned MessagePack key set for signed guest-share envelopes.
pub const GUEST_SHARE_ENVELOPE_KEYS: [&str; 2] = ["body", "signature"];

const KEY_GUEST_SCHEMA_VERSION: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[0];

const KEY_GUEST_SCOPE: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[1];

const KEY_GUEST_MEMBER_REF: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[2];

const KEY_GUEST_SELECTOR: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[3];

const KEY_GUEST_WINDOW_KEY: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[4];

const KEY_GUEST_UPDATE: &str = GUEST_SHARE_ENVELOPE_BODY_KEYS[5];

const KEY_GUEST_BODY: &str = GUEST_SHARE_ENVELOPE_KEYS[0];

const KEY_GUEST_SIGNATURE: &str = GUEST_SHARE_ENVELOPE_KEYS[1];

/// Canonical, pre-sign guest-share envelope body.
///
/// Membership lists, authority rosters, topology summaries, and counts are not
/// representable in this body. Callers must place only selector-filtered,
/// redacted update bytes in `update`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestShareEnvelopeBody {
    /// Shared-vault scope for the guest share.
    pub scope: FederationGrantScope,
    /// Recipient principal for this share.
    pub member_ref: EntityId,
    /// Canonical encoded [`crate::sync::SyncSelector`] bytes.
    pub selector: Vec<u8>,
    /// Window key addressed by `update`.
    pub window_key: String,
    /// Selector-filtered, metadata-stripped Loro update bytes.
    pub update: Vec<u8>,
}

impl GuestShareEnvelopeBody {
    /// Constructs a canonical guest-share envelope body.
    #[must_use]
    pub fn new(
        scope: FederationGrantScope,
        member_ref: EntityId,
        selector: Vec<u8>,
        window_key: impl Into<String>,
        update: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            member_ref,
            selector,
            window_key: window_key.into(),
            update,
        }
    }
}

/// Signed guest-share envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestShareEnvelope {
    /// Body that was signed.
    pub body: GuestShareEnvelopeBody,
    /// Caller-provided signature over `encode_guest_share_envelope_body(body)`.
    pub signature: Vec<u8>,
}

/// Encodes a guest-share envelope body in canonical MessagePack field order.
pub fn encode_guest_share_envelope_body(body: &GuestShareEnvelopeBody) -> Result<Vec<u8>> {
    body.scope.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_GUEST_SCHEMA_VERSION),
            Value::from(GUEST_SHARE_ENVELOPE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_GUEST_SCOPE), encode_scope(body.scope)),
        (
            Value::from(KEY_GUEST_MEMBER_REF),
            Value::from(body.member_ref.to_hex()),
        ),
        (
            Value::from(KEY_GUEST_SELECTOR),
            Value::Binary(body.selector.clone()),
        ),
        (
            Value::from(KEY_GUEST_WINDOW_KEY),
            Value::from(body.window_key.as_str()),
        ),
        (
            Value::from(KEY_GUEST_UPDATE),
            Value::Binary(body.update.clone()),
        ),
    ]);

    encode_msgpack_value(
        &value,
        "guest-share envelope body MessagePack encode failed",
    )
}

/// Signs a guest-share envelope body after canonical stripping has completed.
pub fn sign_guest_share_envelope<S>(
    body: GuestShareEnvelopeBody,
    signer: S,
) -> Result<GuestShareEnvelope>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let body_bytes = encode_guest_share_envelope_body(&body)?;
    let signature = signer(&body_bytes)?;
    Ok(GuestShareEnvelope { body, signature })
}

/// Encodes a signed guest-share envelope in canonical MessagePack field order.
pub fn encode_guest_share_envelope(envelope: &GuestShareEnvelope) -> Result<Vec<u8>> {
    let body = encode_guest_share_envelope_body(&envelope.body)?;
    let value = Value::Map(vec![
        (Value::from(KEY_GUEST_BODY), Value::Binary(body)),
        (
            Value::from(KEY_GUEST_SIGNATURE),
            Value::Binary(envelope.signature.clone()),
        ),
    ]);

    encode_msgpack_value(&value, "guest-share envelope MessagePack encode failed")
}
