mod shapes;
mod wordlist;

use heed::{RoTxn, RwTxn};

use self::shapes::Door;
use super::BatchOp;
use super::export::ExportSecretsNulledManifest;
use crate::error::{Error, GateError, Result};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

const REASON_DETECTED: &str = "gate.secret_scan.detected";
const REASON_AWS_ACCESS_KEY_ID: &str = "gate.secret_scan.aws_access_key_id";
const REASON_GITHUB_TOKEN: &str = "gate.secret_scan.github_token";
const REASON_GOOGLE_API_KEY: &str = "gate.secret_scan.google_api_key";
const REASON_OPENAI_KEY: &str = "gate.secret_scan.openai_key";
const REASON_PRIVATE_KEY: &str = "gate.secret_scan.private_key";
const REASON_SLACK_TOKEN: &str = "gate.secret_scan.slack_token";
const REASON_STRIPE_KEY: &str = "gate.secret_scan.stripe_key";
const REASON_JSON_TOO_DEEP: &str = "gate.secret_scan.json_depth_over_127";
const REASON_MESSAGEPACK_TOO_DEEP: &str = "gate.secret_scan.messagepack_depth_over_1024";

/// The vault's `secrets` setting: whether the write door scans what a host
/// writes into this vault for credential shapes. On by default; only the
/// vault owner switches it, and every switch writes a receipt
/// ([`Vault::set_secret_scan_mode`](crate::Vault::set_secret_scan_mode)).
/// Serve and export redact credentials in both modes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanMode {
    /// A credential-shaped hit refuses the whole write.
    #[default]
    On,
    /// The write door does not scan; serve and export still redact.
    Off,
}

/// The owner's switch row. Key: ().
const SECRET_SCAN_MODE: SideTable<(), SecretScanMode, Named> =
    SideTable::new(&side_table::OWNER_POLICY_SECRET_SCAN_MODE);

/// The switch as the write door reads it. An absent row reads as on, and so
/// does a row that does not decode: the scan fails closed.
pub(crate) fn secret_scan_mode_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<SecretScanMode> {
    Ok(SECRET_SCAN_MODE
        .get_lenient(store, txn, &())?
        .unwrap_or_default())
}

/// Stores the switch. The owner door that calls this checks the owner and
/// writes the receipt in the same transaction.
pub(crate) fn put_secret_scan_mode_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    mode: SecretScanMode,
) -> Result<()> {
    SECRET_SCAN_MODE.put(store, txn, &(), &mode)
}

/// The batch write door: every entity put, claim candidate, text field and
/// phonetic code a batch stages, unless the owner switched the scan off.
pub(super) fn scan_batch_ops(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<()> {
    if secret_scan_mode_in_txn(store, txn)? == SecretScanMode::Off {
        return Ok(());
    }
    for op in ops {
        match op {
            BatchOp::Put {
                entity_type, data, ..
            } => {
                // A SECRET_CUSTODY Put body is the *safe container* for a
                // secret: its `value_bytes` field is exactly credential-shaped
                // bytes held under the vault DEK plane, name-indexed and
                // binding-doored by `register_secret`. Running the credential
                // detector over those bytes would reject the very registration
                // the custody module is built to hold. Skip the scan for that
                // one type byte only; every other entity type still scans
                // (a custody byte on a non-custody path is rejected later by
                // the apply_ops door regardless).
                if *entity_type == ENTITY_TYPE_SECRET_CUSTODY {
                    continue;
                }
                let _secrets_nulled = scan_payload(data)?;
            }
            BatchOp::ClaimCandidate {
                candidate,
                envelope,
                ..
            } => {
                // A facet id is no secret material; any stamp scans alike.
                let body = (**candidate).clone().into_claim_body(
                    envelope,
                    crate::claim::substrate_facet_id(envelope.actor().entity_ref())?,
                )?;
                let data = crate::claim::encode_claim_body(&body)?;
                let _secrets_nulled = scan_payload(&data)?;
            }
            BatchOp::Text { fields, .. } => {
                for (_, value) in fields {
                    let _secrets_nulled = scan_payload(value.as_bytes())?;
                }
            }
            BatchOp::Phonetic { codes, .. } => {
                for code in codes {
                    let _secrets_nulled = scan_payload(code.as_bytes())?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Scans bytes with the serve/export reading of the shared detector, without
/// exposing values. Snapshot custody, pack screening and every release door
/// use this; none of them follows the owner's ingest switch.
pub(crate) fn scan_file_content(_path: &str, bytes: &[u8]) -> Option<&'static str> {
    let haystack = String::from_utf8_lossy(bytes);
    detect(&haystack, Door::Release).or_else(|| {
        let payload = framed_payload(bytes)?;
        let Some(mut value) = decode_members(payload) else {
            return nested_past_decoder(payload);
        };
        sanitize_messagepack(&mut value, false, Door::Release)
            .then_some("gate.secret_scan.sensitive_env")
    })
}

/// The release reading of a body no decoder took whole: its text, and a
/// nesting past the decoders ([`nested_past_decoder`]), whose members no
/// scan read.
pub(crate) fn scan_undecoded_body(bytes: &[u8]) -> Option<&'static str> {
    scan_file_content("", bytes).or_else(|| nested_past_decoder(bytes))
}

/// The body a known framed carrier wraps behind its magic and ids: an inert
/// refinement receipt's JSON. The raw text scan reads its text, but no
/// whole-body decode reaches its fields, so every door decodes the wrapped
/// body as a body too.
fn framed_payload(data: &[u8]) -> Option<&[u8]> {
    crate::skill_hub::refinement_carrier_payload(data)
}

/// A structured body with every member it holds: JSON read into a MessagePack
/// tree, whose maps keep a repeated key and its value (a JSON map keeps only
/// the last), or a MessagePack value that is the whole body.
pub(crate) fn decode_members(data: &[u8]) -> Option<rmpv::Value> {
    if let Ok(value) = serde_json::from_slice::<rmpv::Value>(data) {
        return Some(value);
    }
    let mut cursor = std::io::Cursor::new(data);
    rmpv::decode::read_value(&mut cursor)
        .ok()
        .filter(|_| cursor.position() == data.len() as u64)
}

/// [`decode_members`] at the write door, which refuses a body nested past
/// its decoder: none of its members was read.
fn read_members(data: &[u8]) -> Result<Option<rmpv::Value>> {
    match decode_members(data) {
        Some(value) => Ok(Some(value)),
        None => nested_past_decoder(data).map_or(Ok(None), |reason| Err(secret_scan_error(reason))),
    }
}

/// JSON or MessagePack nested past what its decoder reads (127 open JSON
/// containers, 1024 MessagePack levels). Its decode fails, so no scan read
/// its members, and no door takes it as clean. Text that is no JSON before
/// that depth is text: only the decoder's own depth stop counts.
pub(crate) fn nested_past_decoder(data: &[u8]) -> Option<&'static str> {
    let first = data.iter().find(|byte| !byte.is_ascii_whitespace());
    // The same depth-bound decode [`decode_members`] runs (a skip-only parse
    // has no depth stop); serde_json names that stop in its message only.
    let json = matches!(first, Some(b'{' | b'['))
        && serde_json::from_slice::<rmpv::Value>(data)
            .is_err_and(|error| error.to_string().starts_with("recursion limit exceeded"));
    if json {
        return Some(REASON_JSON_TOO_DEEP);
    }
    let container = matches!(data.first(), Some(0x80..=0x9f | 0xdc..=0xdf));
    let too_deep = container
        && matches!(
            rmpv::decode::read_value(&mut std::io::Cursor::new(data)),
            Err(rmpv::decode::Error::DepthLimitExceeded)
        );
    too_deep.then_some(REASON_MESSAGEPACK_TOO_DEEP)
}

/// The release doors' text rules over strings a reader keeps apart (one
/// array's items), read one per line: a phrase or key split over the items.
pub(crate) fn release_joined_strings<S: std::borrow::Borrow<str>>(items: &[S]) -> bool {
    joined_strings(items, Door::Release)
}

/// A secret split over an array's strings (a recovery phrase one word per
/// item, a private key one line per item) is read whole, one item per line,
/// before each item is read alone.
fn joined_strings<S: std::borrow::Borrow<str>>(items: &[S], door: Door) -> bool {
    items.len() > 1 && detect(&items.join("\n"), door).is_some()
}

/// [`release_joined_strings`] over a MessagePack array's items.
pub(crate) fn release_joined_messagepack(items: &[rmpv::Value]) -> bool {
    joined_messagepack(items, Door::Release)
}

/// The text items of a MessagePack array read joined. An item is read as text
/// as it is read alone: a string, and binary or extension bytes, which carry
/// words as well as a string does.
fn joined_messagepack(items: &[rmpv::Value], door: Door) -> bool {
    let texts: Vec<_> = items
        .iter()
        .filter_map(|item| match item {
            rmpv::Value::String(text) => Some(String::from_utf8_lossy(text.as_bytes())),
            rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => {
                Some(String::from_utf8_lossy(bytes))
            }
            _ => None,
        })
        .collect();
    joined_strings(&texts, door)
}

/// The write door's text rules over text a stream scanner joined across a
/// chunk edge. Like the batch door, it follows the owner's switch: its caller
/// reads it.
pub(crate) fn scan_write_seam(text: &str) -> Result<()> {
    match detect(text, Door::Write) {
        Some(reason) => Err(secret_scan_error(reason)),
        None => Ok(()),
    }
}

/// The release doors' field rule, for a reader that finds fields the
/// structural scans below do not walk (a binary map key, a repeated JSON key).
pub(crate) fn release_credential_field(name: &str, nil: bool, text: Option<&str>) -> bool {
    credential_field(name, nil, text, Door::Release)
}

/// A credential name holding anything but nil or a placeholder.
fn credential_field(name: &str, nil: bool, text: Option<&str>, door: Door) -> bool {
    shapes::sensitive_key(name)
        && !nil
        && !text.is_some_and(|text| shapes::field_placeholder(text, door))
}

/// Identifiers and records outside the batch door (refs, paths, telemetry
/// keys, session tags, question rows) keep their scan in both modes: they land
/// in keys, indexes and receipts that a later mask cannot reach.
pub(crate) fn scan_metadata_field(value: &str) -> Result<()> {
    let _secrets_nulled = scan_payload(value.as_bytes())?;
    Ok(())
}

/// Both doors' text rules and no structured reading, for text a caller joined
/// from separate strings: the join is no record a field walk could read.
pub(crate) fn scan_joined_text(text: &str) -> Option<&'static str> {
    detect(text, Door::Write).or_else(|| detect(text, Door::Release))
}

/// The batch write door's scan of one payload, for a planner that must say
/// what that door would refuse without staging a write. It does not read the
/// owner's switch; the caller does.
pub(crate) fn scan_write_payload(data: &[u8]) -> Result<()> {
    let _secrets_nulled = scan_payload(data)?;
    Ok(())
}

/// Apply the same raw/structured scan as ordinary non-custody batch puts to
/// source bytes staged outside the entity tables, before their first write.
/// It follows the batch door, so the owner's switch turns it off too.
pub(crate) fn scan_staged_payload(store: &Store, data: &[u8]) -> Result<()> {
    let mode = {
        let txn = store.env.read_txn()?;
        secret_scan_mode_in_txn(store, &txn)?
    };
    if mode == SecretScanMode::Off {
        return Ok(());
    }
    let _secrets_nulled = scan_payload(data)?;
    Ok(())
}

fn scan_payload(data: &[u8]) -> Result<ExportSecretsNulledManifest> {
    let haystack = String::from_utf8_lossy(data);
    let secrets_nulled =
        ExportSecretsNulledManifest::from_redacted(has_redaction_marker(&haystack));
    if let Some(reason) = detect(&haystack, Door::Write) {
        return Err(secret_scan_error(reason));
    }
    // Every member is read, a repeated JSON key and every map key included,
    // and a framed carrier's body as a body too.
    for body in std::iter::once(data).chain(framed_payload(data)) {
        if read_members(body)?
            .is_some_and(|mut value| sanitize_messagepack(&mut value, false, Door::Write))
        {
            return Err(secret_scan_error("gate.secret_scan.sensitive_env"));
        }
    }
    Ok(secrets_nulled)
}

fn secret_scan_error(reason: &'static str) -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![REASON_DETECTED, reason],
    })
}

fn has_redaction_marker(haystack: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    [
        "[redacted]",
        "[secret redacted]",
        "<redacted>",
        "secret_nulled",
        "structurally_secret_nulled",
        "secrets_nulled",
        "structural_placeholders",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn detect(haystack: &str, door: Door) -> Option<&'static str> {
    let private_key = match door {
        Door::Write => shapes::private_key_block(haystack),
        Door::Release => shapes::private_key_header(haystack),
    };
    if private_key {
        return Some(REASON_PRIVATE_KEY);
    }

    if shapes::blocklisted(haystack) {
        return Some("gate.secret_scan.blocklist");
    }
    if shapes::mnemonic(haystack) {
        return Some("gate.secret_scan.mnemonic");
    }
    // Preserve precise provider reason codes before the generic env class.
    let provider = haystack
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        .find_map(classify_token);
    provider.or_else(|| {
        shapes::sensitive_assignment(haystack, door).then_some("gate.secret_scan.sensitive_env")
    })
}

/// Recursively filters both credential field names and credential-shaped values.
/// Returns whether any bytes were removed. `null` is the export representation;
/// the serving representation is the fixed, non-authoritative redaction marker.
pub(crate) fn sanitize_credentials(value: &mut serde_json::Value, null: bool) -> bool {
    sanitize_json(value, null, Door::Release)
}

fn sanitize_json(value: &mut serde_json::Value, null: bool, door: Door) -> bool {
    use serde_json::Value;
    let replacement = || {
        if null {
            Value::Null
        } else {
            Value::String("[redacted]".into())
        }
    };
    match value {
        Value::String(text) if detect(text, door).is_some() => {
            *value = replacement();
            true
        }
        Value::Array(values) => {
            // MessagePack binary values project to JSON byte arrays. They must
            // not become an alternate encoding around recursive redaction.
            let bytes: Option<Vec<u8>> = values
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            let strings: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
            if bytes
                .as_ref()
                .is_some_and(|bytes| detect_bytes(bytes, door))
                || joined_strings(&strings, door)
            {
                *value = replacement();
                return true;
            }
            let changed = values.iter_mut().fold(false, |changed, value| {
                sanitize_json(value, null, door) | changed
            });
            // Read again once items are nulled: the strings left are the ones
            // a second pass reads joined, so the array is its own fixed point.
            let strings: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
            if changed && joined_strings(&strings, door) {
                *value = replacement();
            }
            changed
        }
        Value::Object(fields) => {
            // A JSON key is text a reader shows; one shaped like a credential
            // goes with its member, since a key cannot be nulled.
            let before = fields.len();
            fields.retain(|key, _| detect(key, door).is_none());
            let dropped = fields.len() != before;
            fields.iter_mut().fold(dropped, |changed, (key, value)| {
                let sensitive = credential_field(key, value.is_null(), value.as_str(), door);
                if sensitive {
                    *value = replacement();
                    true
                } else {
                    sanitize_json(value, null, door) | changed
                }
            })
        }
        _ => false,
    }
}

/// Scan MessagePack before any lossy JSON projection. Safe binary and extension
/// values retain their original type on raw transports.
pub(crate) fn sanitize_messagepack_credentials(value: &mut rmpv::Value, null: bool) -> bool {
    sanitize_messagepack(value, null, Door::Release)
}

fn sanitize_messagepack(value: &mut rmpv::Value, null: bool, door: Door) -> bool {
    use rmpv::Value;
    let replacement = || {
        if null {
            Value::Nil
        } else {
            Value::from("[redacted]")
        }
    };
    match value {
        Value::String(text) if detect_bytes(text.as_bytes(), door) => {
            *value = replacement();
            true
        }
        Value::Binary(bytes) | Value::Ext(_, bytes) if detect_bytes(bytes, door) => {
            *value = replacement();
            true
        }
        Value::Array(values) => {
            let bytes: Option<Vec<u8>> = values
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            if bytes
                .as_ref()
                .is_some_and(|bytes| detect_bytes(bytes, door))
                || joined_messagepack(values, door)
            {
                *value = replacement();
                return true;
            }
            let changed = values.iter_mut().fold(false, |changed, value| {
                sanitize_messagepack(value, null, door) | changed
            });
            // Read again once items are nulled, as the JSON walk does.
            if changed && joined_messagepack(values, door) {
                *value = replacement();
            }
            changed
        }
        Value::Map(fields) => {
            // A key shaped like a credential goes with its member, as a JSON
            // object's does: a marker in its place could repeat a real key.
            let before = fields.len();
            fields.retain(|(key, _)| !sanitize_messagepack(&mut key.clone(), null, door));
            let dropped = fields.len() != before;
            fields.iter_mut().fold(dropped, |changed, (key, value)| {
                let sensitive = key
                    .as_str()
                    .is_some_and(|key| credential_field(key, value.is_nil(), value.as_str(), door));
                if sensitive {
                    *value = replacement();
                    true
                } else {
                    sanitize_messagepack(value, null, door) | changed
                }
            })
        }
        _ => false,
    }
}

fn detect_bytes(bytes: &[u8], door: Door) -> bool {
    detect(&String::from_utf8_lossy(bytes), door).is_some()
}

fn classify_token(token: &str) -> Option<&'static str> {
    if is_aws_access_key_id(token) {
        Some(REASON_AWS_ACCESS_KEY_ID)
    } else if is_github_token(token) {
        Some(REASON_GITHUB_TOKEN)
    } else if is_google_api_key(token) {
        Some(REASON_GOOGLE_API_KEY)
    } else if is_openai_key(token) {
        Some(REASON_OPENAI_KEY)
    } else if is_slack_token(token) {
        Some(REASON_SLACK_TOKEN)
    } else if is_stripe_key(token) {
        Some(REASON_STRIPE_KEY)
    } else {
        None
    }
}

fn is_aws_access_key_id(token: &str) -> bool {
    let candidate = token.as_bytes();
    if candidate.len() < 20 || !(candidate.starts_with(b"AKIA") || candidate.starts_with(b"ASIA")) {
        return false;
    }
    candidate[..20]
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_github_token(token: &str) -> bool {
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|prefix| suffix_matches(token, prefix, 36, true, is_ascii_token_body))
        || suffix_matches(token, "github_pat_", 70, false, is_ascii_token_body)
}

fn is_google_api_key(token: &str) -> bool {
    suffix_matches(token, "AIza", 35, true, is_ascii_token_body)
}

fn is_openai_key(token: &str) -> bool {
    suffix_matches(token, "sk-proj-", 32, false, is_ascii_token_body)
        || suffix_matches(token, "sk-", 48, true, is_ascii_token_body)
}

fn is_slack_token(token: &str) -> bool {
    ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"]
        .iter()
        .any(|prefix| suffix_matches(token, prefix, 24, false, is_ascii_token_body))
}

fn is_stripe_key(token: &str) -> bool {
    suffix_matches(token, "sk_live_", 24, false, is_ascii_token_body)
        || suffix_matches(token, "rk_live_", 24, false, is_ascii_token_body)
}

fn suffix_matches(
    token: &str,
    prefix: &str,
    suffix_len: usize,
    exact_len: bool,
    allowed: fn(u8) -> bool,
) -> bool {
    let token = token.as_bytes();
    let prefix = prefix.as_bytes();
    if prefix.is_empty() || token.len() < prefix.len() + suffix_len {
        return false;
    }

    if !token.starts_with(prefix) {
        return false;
    }
    let suffix_start = prefix.len();
    let min_suffix_end = suffix_start + suffix_len;
    let suffix = if exact_len {
        &token[suffix_start..min_suffix_end]
    } else {
        &token[suffix_start..]
    };
    suffix.iter().copied().all(allowed)
}

fn is_ascii_token_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

#[cfg(test)]
mod tests;
