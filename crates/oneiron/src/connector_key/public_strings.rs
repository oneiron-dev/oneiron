//! A connector key's tool strings the owner accepted as public at install
//! (RULING SCREENING-SECRET-OVERRIDE = B; ANSWERS SCREENING-SECRET-READERS =
//! A and SCREENING-C2-EXPORT-SCOPE = B; FIX SCREENING-PER-TOOL-SKIP, PR
//! C2). The owner's "install it anyway" on a tool whose name or schema
//! holds a secret-shaped string marks the tool's row in the key's resolved
//! manifest ([`super::ResolvedConnectorManifest::public_secret_shape_tools`]).
//! The secret lift census reads the key body without those rows, so it does
//! not raise the accepted string again as a leak.
//!
//! Only the fields that hold a tool's identity change: the public rows and
//! their marks leave the retained and the pending manifest, and the public
//! tools' names leave the catalog's verbs and the pending drift's tool sets.
//! Every other byte of the body is read as stored, so a string the owner
//! did not accept keeps the context the census reads it in (review-c2 F1:
//! a public tool named `token` no longer hides another tool's
//! `"token":"..."`).
//!
//! Only a row the owner accepted at its digest is marked: the admission host
//! marks a tool only when the owner's acceptance covers it at the digest
//! listed now, and a row that changed since no longer matches its mark.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value as Mp;
use serde::Serialize;

use super::codec::{CATALOG_ENTRY_KEYS, KEY_CATALOG, KEY_PENDING_MANIFEST, KEY_RETAINED_MANIFEST};
use super::{
    ConnectorManifestDrift, PendingConnectorManifest, ResolvedConnectorManifest,
    decode_connector_key_body,
};

/// The connector key body `body` as the secret lift census reads it: each
/// public row of its retained or pending manifest left out with its mark,
/// and each public tool's name left out of the catalog's verbs and the
/// pending drift's tool sets. Every other field keeps its stored bytes.
/// `None` when `body` does not decode as a key record, marks no public row,
/// or is not in the canonical encoding its record re-encodes to; the census
/// then reads the body as it is.
pub(crate) fn body_without_owner_public_strings(body: &[u8]) -> Option<Vec<u8>> {
    let record = decode_connector_key_body(body).ok()?;
    let retained = record.retained_manifest.as_ref();
    let pending = record.pending_manifest.as_ref();
    let names: BTreeSet<String> = retained
        .into_iter()
        .chain(pending.map(|pending| &pending.manifest))
        .flat_map(ResolvedConnectorManifest::public_secret_shape_tools)
        .map(|row| row.name.clone())
        .collect();
    if names.is_empty() {
        return None;
    }
    let mut cursor = Cursor::new(body);
    let mut value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != body.len() as u64 || encoded(&value)? != body {
        return None;
    }
    let Mp::Map(fields) = &mut value else {
        return None;
    };
    for (key, field) in fields {
        match (key.as_str(), retained, pending) {
            (Some(KEY_RETAINED_MANIFEST), Some(stored), _) => {
                replace_json(field, stored, &stored.without_public_secret_shape_rows())?;
            }
            (Some(KEY_PENDING_MANIFEST), _, Some(stored)) => {
                replace_json(field, stored, &pending_without(stored, &names))?;
            }
            (Some(KEY_CATALOG), _, _) => verbs_without(field, &names),
            _ => {}
        }
    }
    encoded(&value)
}

/// `stored`'s pending candidate without its public rows, and its drift
/// without the public tools' names. Each field is named, so a field added
/// later is read here before the census reads it projected.
fn pending_without(
    stored: &PendingConnectorManifest,
    names: &BTreeSet<String>,
) -> PendingConnectorManifest {
    let kept = |tools: &BTreeSet<String>| -> BTreeSet<String> {
        tools.difference(names).cloned().collect()
    };
    PendingConnectorManifest {
        candidate_id: stored.candidate_id,
        manifest: stored.manifest.without_public_secret_shape_rows(),
        protocol_revision: stored.protocol_revision.clone(),
        drift: ConnectorManifestDrift {
            kinds: stored.drift.kinds.clone(),
            affected_tools: kept(&stored.drift.affected_tools),
            reconsent_tools: kept(&stored.drift.reconsent_tools),
            requires_reregistration: stored.drift.requires_reregistration,
        },
        qualification_report_hash: stored.qualification_report_hash.clone(),
    }
}

/// Puts `projected`'s JSON in `field`, when `field` holds `stored`'s JSON
/// byte for byte; `None` otherwise.
fn replace_json<T: Serialize>(field: &mut Mp, stored: &T, projected: &T) -> Option<()> {
    let Mp::Binary(bytes) = field else {
        return None;
    };
    if *bytes != serde_json::to_vec(stored).ok()? {
        return None;
    }
    *bytes = serde_json::to_vec(projected).ok()?;
    Some(())
}

/// Takes each of `names` out of the catalog entry's verbs in `field`.
fn verbs_without(field: &mut Mp, names: &BTreeSet<String>) {
    let Mp::Map(entries) = field else {
        return;
    };
    for (key, item) in entries {
        if key.as_str() != Some(CATALOG_ENTRY_KEYS[3]) {
            continue;
        }
        if let Mp::Array(verbs) = item {
            verbs.retain(|verb| !verb.as_str().is_some_and(|verb| names.contains(verb)));
        }
    }
}

fn encoded(value: &Mp) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).ok()?;
    Some(out)
}
