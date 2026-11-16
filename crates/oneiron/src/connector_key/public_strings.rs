//! A connector key's tool strings the owner accepted as public at install
//! (RULING SCREENING-SECRET-OVERRIDE = B; ANSWERS SCREENING-SECRET-READERS =
//! A and SCREENING-C2-EXPORT-SCOPE = B; FIX SCREENING-PER-TOOL-SKIP, PR
//! C2). The owner's "install it anyway" on a tool whose name or schema
//! holds a secret-shaped string marks the tool's row in the key's resolved
//! manifest ([`super::ResolvedConnectorManifest::public_secret_shape_tools`]).
//! The secret lift census reads the key body with those rows blanked, so it
//! does not raise the accepted string again as a leak, while every other
//! string of the key is read as before.
//!
//! Only a row the owner accepted at its digest is marked: the admission host
//! marks a tool only when the owner's acceptance covers it at the digest
//! listed now, and a row that changed since no longer matches its mark.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value as Mp;
use serde_json::Value as Json;

use super::decode_connector_key_body;

/// The rows and names one key body marks public.
struct Public {
    /// Each public row as its manifest stores it.
    rows: Vec<Json>,
    /// Each public row's tool name.
    names: BTreeSet<String>,
}

/// The connector key body `body` as the secret lift census reads it: each
/// public row of its retained or pending manifest blanked where the body
/// carries it (every string emptied, every key renamed), and each public
/// tool's name emptied wherever it stands as a whole string (the catalog's
/// verbs, a drift's tool sets, the marks themselves). Any other string stays.
/// `None` when `body` does not decode as a key record or marks no public
/// row; the census then reads the body as it is.
pub(crate) fn body_without_owner_public_strings(body: &[u8]) -> Option<Vec<u8>> {
    let record = decode_connector_key_body(body).ok()?;
    let mut public = Public {
        rows: Vec::new(),
        names: BTreeSet::new(),
    };
    for manifest in record.retained_manifest.iter().chain(
        record
            .pending_manifest
            .iter()
            .map(|pending| &pending.manifest),
    ) {
        for row in manifest.public_secret_shape_tools() {
            public.rows.push(serde_json::to_value(row).ok()?);
            public.names.insert(row.name.clone());
        }
    }
    if public.rows.is_empty() {
        return None;
    }
    let mut cursor = Cursor::new(body);
    let mut value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != body.len() as u64 {
        return None;
    }
    take_out(&mut value, &public);
    let mut out = Vec::with_capacity(body.len());
    rmpv::encode::write_value(&mut out, &value).ok()?;
    Some(out)
}

/// Empties each public name in `value`, and takes the public rows and names
/// out of each JSON document a binary node carries. The body's own map keys
/// are its field names and stay.
fn take_out(value: &mut Mp, public: &Public) {
    match value {
        Mp::String(text) => {
            if text
                .as_str()
                .is_some_and(|text| public.names.contains(text))
            {
                *text = String::new().into();
            }
        }
        Mp::Binary(bytes) => {
            if let Ok(mut json) = serde_json::from_slice::<Json>(bytes) {
                take_out_json(&mut json, public);
                if let Ok(projected) = serde_json::to_vec(&json) {
                    *bytes = projected;
                }
            }
        }
        Mp::Array(items) => {
            for item in items {
                take_out(item, public);
            }
        }
        Mp::Map(entries) => {
            for (_, item) in entries {
                take_out(item, public);
            }
        }
        _ => {}
    }
}

/// Blanks each public row in `json`, and empties each public name standing
/// as a string or an object key elsewhere in it.
fn take_out_json(json: &mut Json, public: &Public) {
    if public.rows.iter().any(|row| *row == *json) {
        blank(json);
        return;
    }
    match json {
        Json::String(text) => {
            if public.names.contains(text.as_str()) {
                text.clear();
            }
        }
        Json::Array(items) => {
            for item in items {
                take_out_json(item, public);
            }
        }
        Json::Object(entries) => {
            let taken = std::mem::take(entries);
            let original: BTreeSet<String> = taken.keys().cloned().collect();
            let mut renamed = 0usize;
            for (key, mut item) in taken {
                take_out_json(&mut item, public);
                let key = if public.names.contains(key.as_str()) {
                    unused_key(&original, entries, &mut renamed)
                } else {
                    key
                };
                entries.insert(key, item);
            }
        }
        _ => {}
    }
}

/// Every string of `json` emptied and every object key renamed, at any
/// depth: an accepted row, read as no text at all.
fn blank(json: &mut Json) {
    match json {
        Json::String(text) => text.clear(),
        Json::Array(items) => items.iter_mut().for_each(blank),
        Json::Object(entries) => {
            let taken = std::mem::take(entries);
            for (at, (_, mut item)) in taken.into_iter().enumerate() {
                blank(&mut item);
                entries.insert(format!("k{at}"), item);
            }
        }
        _ => {}
    }
}

/// A key no key of the object uses, before or after the renames.
fn unused_key(
    original: &BTreeSet<String>,
    entries: &serde_json::Map<String, Json>,
    renamed: &mut usize,
) -> String {
    loop {
        let candidate = format!("public_{renamed}");
        *renamed += 1;
        if !original.contains(&candidate) && !entries.contains_key(&candidate) {
            return candidate;
        }
    }
}
