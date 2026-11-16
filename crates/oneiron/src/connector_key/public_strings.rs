//! A connector key's tool strings the owner accepted as public at install
//! (RULING SCREENING-SECRET-OVERRIDE = B; ANSWER SCREENING-SECRET-READERS =
//! A; FIX SCREENING-PER-TOOL-SKIP, PR C2). The owner's "install it anyway"
//! on a tool whose name or schema holds a secret-shaped string marks the
//! tool's row in the key's resolved manifest
//! ([`super::ResolvedConnectorManifest::public_strings`]). The secret lift
//! census reads the key body with those strings taken out, so it does not
//! raise the string again as a leak, while any other secret in the record is
//! read as before.
//!
//! Only a manifest row the owner accepted at its digest is marked: the
//! admission host marks a tool only when the acceptance on the slate still
//! covers it, and a row that changed since no longer matches its mark.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value as Mp;
use serde_json::Value as Json;

use super::decode_connector_key_body;

/// The connector key body `body` as the secret lift census reads it: each
/// string of a tool whose stored strings are public, owner-accepted at
/// install, emptied where it stands (a MessagePack string, or a string or
/// key of a JSON manifest the body carries as bytes). `None` when `body`
/// does not decode as a key record or marks no public tool; the census then
/// reads the body as it is.
pub(crate) fn body_without_owner_public_strings(body: &[u8]) -> Option<Vec<u8>> {
    let record = decode_connector_key_body(body).ok()?;
    let public: BTreeSet<String> = record
        .retained_manifest
        .iter()
        .chain(
            record
                .pending_manifest
                .iter()
                .map(|pending| &pending.manifest),
        )
        .flat_map(super::ResolvedConnectorManifest::public_strings)
        .collect();
    if public.is_empty() {
        return None;
    }
    let mut cursor = Cursor::new(body);
    let mut value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != body.len() as u64 {
        return None;
    }
    empty_public(&mut value, &public);
    let mut out = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut out, &value).ok()?;
    Some(out)
}

/// Empties each string of `value` that `public` holds, and each one inside
/// a JSON document a binary node carries. Map keys of the body itself are
/// its field names and stay.
fn empty_public(value: &mut Mp, public: &BTreeSet<String>) {
    match value {
        Mp::String(text) => {
            if text.as_str().is_some_and(|text| public.contains(text)) {
                *text = String::new().into();
            }
        }
        Mp::Binary(bytes) => {
            if let Ok(mut json) = serde_json::from_slice::<Json>(bytes) {
                empty_public_json(&mut json, public);
                if let Ok(projected) = serde_json::to_vec(&json) {
                    *bytes = projected;
                }
            }
        }
        Mp::Array(items) => {
            for item in items {
                empty_public(item, public);
            }
        }
        Mp::Map(entries) => {
            for (_, item) in entries {
                empty_public(item, public);
            }
        }
        _ => {}
    }
}

/// Empties each string value of `json` that `public` holds, and renames
/// each object key it holds to a name no key of the object uses, so the
/// key's value is still read and no other key's value is replaced.
fn empty_public_json(json: &mut Json, public: &BTreeSet<String>) {
    match json {
        Json::String(text) => {
            if public.contains(text.as_str()) {
                text.clear();
            }
        }
        Json::Array(items) => {
            for item in items {
                empty_public_json(item, public);
            }
        }
        Json::Object(entries) => {
            let taken = std::mem::take(entries);
            let original: BTreeSet<String> = taken.keys().cloned().collect();
            let mut renamed = 0usize;
            for (key, mut item) in taken {
                empty_public_json(&mut item, public);
                let key = if public.contains(key.as_str()) {
                    loop {
                        let candidate = format!("public_{renamed}");
                        renamed += 1;
                        if !original.contains(&candidate) && !entries.contains_key(&candidate) {
                            break candidate;
                        }
                    }
                } else {
                    key
                };
                entries.insert(key, item);
            }
        }
        _ => {}
    }
}
