//! Deterministic unsubscribe headers and their frozen outbound payload representation.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// RFC 2369 unsubscribe header name.
pub const LIST_UNSUBSCRIBE: &str = "List-Unsubscribe";
/// RFC 8058 one-click header name.
pub const LIST_UNSUBSCRIBE_POST: &str = "List-Unsubscribe-Post";
/// The one RFC 8058 one-click header value.
pub const LIST_UNSUBSCRIBE_POST_ONE_CLICK: &str = "List-Unsubscribe=One-Click";

/// The only channel these headers exist for.
pub const EMAIL_CHANNEL: &str = "email";

/// Field the frozen outbound payload carries hygiene headers under.
///
/// Public because it is wire shape: the frozen bytes are the retry contract, and
/// a connector adapter reading them back needs the same name the writer used.
pub const HYGIENE_HEADERS_PAYLOAD_FIELD: &str = "hygiene_headers";

/// Upper bound for one unsubscribe URI.
const MAX_UNSUBSCRIBE_URI_BYTES: usize = 998;

/// Where an unsubscribe lands, frozen with the send it belongs to.
///
/// The HTTPS one-click target is mandatory and the mailto is optional, which is
/// exactly RFC 8058's shape: one-click needs an HTTPS endpoint, and a mailto
/// alone cannot satisfy it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListUnsubscribeTarget {
    /// Optional RFC 2369 mailto target.
    pub mailto_uri: Option<String>,
    /// Mandatory RFC 8058 one-click HTTPS target.
    pub https_one_click_uri: String,
}

/// Builds the deterministic unsubscribe headers for one frozen target.
///
/// Determinism is the contract, not a nicety: the same frozen intent must
/// produce byte-identical header names, values, and ordering on every retry, or
/// a mailbox provider sees two different unsubscribe surfaces for one message.
/// Two things pin it — a [`BTreeMap`] fixes header ordering, and the URI list
/// order is fixed as HTTPS-then-mailto rather than following the input.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a URI carries the wrong scheme, is empty past
/// its scheme, exceeds `MAX_UNSUBSCRIBE_URI_BYTES`, or contains a character
/// that would break header framing.
pub fn list_unsubscribe_headers(
    target: &ListUnsubscribeTarget,
) -> Result<BTreeMap<String, String>> {
    validate_unsubscribe_uri(&target.https_one_click_uri, "https://")?;
    let mut value = format!("<{}>", target.https_one_click_uri);
    if let Some(mailto_uri) = &target.mailto_uri {
        validate_unsubscribe_uri(mailto_uri, "mailto:")?;
        value.push_str(", <");
        value.push_str(mailto_uri);
        value.push('>');
    }
    Ok(BTreeMap::from([
        (LIST_UNSUBSCRIBE.to_owned(), value),
        (
            LIST_UNSUBSCRIBE_POST.to_owned(),
            LIST_UNSUBSCRIBE_POST_ONE_CLICK.to_owned(),
        ),
    ]))
}

/// Folds the unsubscribe headers into an email payload's header map.
///
/// A small pre-send transformation, deliberately: it is not a transport layer,
/// it never invents a target, and a non-email channel or a send with no frozen
/// target passes through untouched.
///
/// `channel` is expected already normalized; the caller owns normalization
/// because it already holds the connector-class spelling.
///
/// # Errors
///
/// Propagates [`list_unsubscribe_headers`].
pub fn inject_campaign_email_hygiene_headers(
    channel: &str,
    headers: &mut BTreeMap<String, String>,
    unsubscribe: Option<&ListUnsubscribeTarget>,
) -> Result<()> {
    if channel != EMAIL_CHANNEL {
        return Ok(());
    }
    let Some(target) = unsubscribe else {
        return Ok(());
    };
    headers.extend(list_unsubscribe_headers(target)?);
    Ok(())
}

/// Reads hygiene headers back out of a frozen outbound payload.
///
/// Tolerant by construction: most frozen payloads are opaque connector bytes
/// that were never JSON and carry no hygiene headers at all. Only a payload that
/// DOES carry the field and carries it malformed is an error — a send whose
/// unsubscribe header cannot be reproduced from the frozen bytes must not reach
/// the wire under a header the ledger cannot vouch for.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the field is present but is not a flat map of
/// strings.
pub fn frozen_payload_hygiene_headers(payload: &[u8]) -> Result<BTreeMap<String, String>> {
    let Ok(serde_json::Value::Object(fields)) =
        serde_json::from_slice::<serde_json::Value>(payload)
    else {
        return Ok(BTreeMap::new());
    };
    let Some(headers) = fields.get(HYGIENE_HEADERS_PAYLOAD_FIELD) else {
        return Ok(BTreeMap::new());
    };
    let serde_json::Value::Object(headers) = headers else {
        return Err(invalid_payload("outbound hygiene headers must be a map"));
    };
    headers
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| invalid_payload("outbound hygiene header value must be a string"))
        })
        .collect()
}

/// Rejects a URI that carries the wrong scheme, is empty past it, is too long,
/// or would break header framing.
fn validate_unsubscribe_uri(uri: &str, scheme: &str) -> Result<()> {
    if !uri.starts_with(scheme) || uri.len() == scheme.len() {
        return Err(invalid_payload("unsubscribe URI scheme is invalid"));
    }
    if uri.len() > MAX_UNSUBSCRIBE_URI_BYTES {
        return Err(invalid_payload("unsubscribe URI is too long"));
    }
    // `<`, `>`, and `,` frame the RFC 2369 list; whitespace and controls fold
    // the header. Any of them would let a target rewrite the header around it.
    if uri
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '<' | '>' | ','))
    {
        return Err(invalid_payload(
            "unsubscribe URI contains a framing character",
        ));
    }
    Ok(())
}

pub fn invalid_payload(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
