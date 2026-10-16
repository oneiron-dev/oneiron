//! Release checks for a payload a caller was served earlier and is sent again
//! (DEC-0005): a payload naming a row a device-local world keeps now never
//! leaves this device a second time, whether the row's world was flagged
//! since or the row moved into a flagged world.

use oneiron::EntityId;
use oneiron::claim::CallerLocality;

/// Whether a retained payload stays on this device for a caller at
/// `locality`: one of the `rows` its producer derived it from, listed when it
/// was produced, is a row a device-local world keeps now. A retained payload
/// leaves again only while every row it was derived from may leave. The scan
/// of `payload` for whole entity ids is a backstop for a row its producer did
/// not list.
pub(crate) fn withholds_retained(
    vault: &oneiron::Vault,
    locality: CallerLocality,
    rows: &[EntityId],
    payload: &[u8],
) -> oneiron::Result<bool> {
    if locality == CallerLocality::OnDevice {
        return Ok(false);
    }
    let mut named = entity_ids_in(payload);
    named.extend_from_slice(rows);
    named.sort_unstable_by_key(|id| *id.as_bytes());
    named.dedup();
    if named.is_empty() {
        return Ok(false);
    }
    let count = named.len();
    Ok(vault.off_device_readable(named)?.len() != count)
}

/// [`withholds_retained`] for the machine `peer` proved on the socket
/// (OF-534 G6): a proved machine's rows are judged by its own world read
/// settings, so a private world it may read reaches it. An unproved peer is
/// an unknown destination and keeps the device's own judgment.
pub(crate) fn withholds_retained_for(
    vault: &oneiron::Vault,
    locality: CallerLocality,
    peer: oneiron::authority::PeerMachine,
    rows: &[EntityId],
    payload: &[u8],
) -> oneiron::Result<bool> {
    if locality == CallerLocality::OnDevice {
        return Ok(false);
    }
    if oneiron::sync::residence::withheld_from_peer(vault, peer)?.is_none() {
        return withholds_retained(vault, locality, rows, payload);
    }
    let mut named = entity_ids_in(payload);
    named.extend_from_slice(rows);
    named.sort_unstable_by_key(|id| *id.as_bytes());
    named.dedup();
    Ok(!oneiron::sync::residence::rows_may_reach(
        vault, peer, &named,
    )?)
}

/// Whether a cached response replayed to a caller at `locality` stays on
/// this device: one of the `rows` its handler listed, or a row its body
/// names, is one a device-local world keeps now. A short ref in the body
/// that names no row keeps it too.
pub(crate) fn replay_withheld(
    vault: &oneiron::Vault,
    locality: CallerLocality,
    body: &[u8],
    rows: &[EntityId],
) -> bool {
    if locality == CallerLocality::OnDevice {
        return false;
    }
    let Some(mut named) = short_refs_in(vault, body) else {
        return true;
    };
    named.extend_from_slice(rows);
    withholds_retained(vault, locality, &named, body).unwrap_or(true)
}

/// The rows a JSON body names by short ref, keys included; `None` when one
/// names no row. Whole ids are left to the payload scan.
fn short_refs_in(vault: &oneiron::Vault, body: &[u8]) -> Option<Vec<EntityId>> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Some(Vec::new());
    };
    short_refs_named(vault, &value)
}

/// The rows `value` names by short ref, keys included; `None` when one names
/// no row.
pub(crate) fn short_refs_named(
    vault: &oneiron::Vault,
    value: &serde_json::Value,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    let mut name = |text: &str| {
        let reference = text
            .split_once('@')
            .map_or(text, |(reference, _)| reference);
        if oneiron::entity_id::parse_short_ref_syntax(reference).is_err() {
            return Some(());
        }
        rows.push(oneiron::memory::resolve_entity_ref(vault, reference).ok()?);
        Some(())
    };
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(text) => name(text)?,
            serde_json::Value::Array(items) => pending.extend(items),
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    name(key)?;
                    pending.push(item);
                }
            }
            _ => {}
        }
    }
    Some(rows)
}

/// The rows `text` names by a short ref among its words, whatever stands
/// around one; `None` when one names no row. Whole ids are left to the
/// payload scan.
pub(crate) fn short_refs_in_text(vault: &oneiron::Vault, text: &str) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for word in text.split(|c: char| !c.is_ascii_alphanumeric() && c != ':') {
        let parts = word.split(':').collect::<Vec<_>>();
        for pair in parts.windows(2) {
            let reference = format!("{}:{}", pair[0], pair[1]);
            if oneiron::entity_id::parse_short_ref_syntax(&reference).is_ok() {
                rows.push(oneiron::memory::resolve_entity_ref(vault, &reference).ok()?);
            }
        }
    }
    Some(rows)
}

/// The rows a changed line names: its lifecycle rows, install receipts and
/// own proposal outcomes, by the id each one is keyed by.
pub(crate) fn changed_line_rows(
    line: &oneiron::context_board::ChangedLine,
) -> impl Iterator<Item = EntityId> + '_ {
    let proposals = line.events.iter().filter_map(|event| match event {
        oneiron::context_board::ChangedEvent::Proposal { id, .. } => Some(id.as_str()),
        oneiron::context_board::ChangedEvent::Connector { .. } => None,
    });
    line.rows
        .iter()
        .map(|(id, _)| id.as_str())
        .chain(
            line.install_rows
                .iter()
                .map(|receipt| receipt.entity.as_str()),
        )
        .chain(proposals)
        .filter_map(|id| {
            let hex = id.rsplit_once(':').map_or(id, |(_, hex)| hex);
            EntityId::from_hex(hex).ok()
        })
}

/// Every whole 32-digit hex token in `bytes`, as the entity id it spells.
fn entity_ids_in(bytes: &[u8]) -> Vec<EntityId> {
    let mut ids = Vec::new();
    for run in bytes.split(|byte| !byte.is_ascii_hexdigit()) {
        if run.len() == 32
            && let Ok(hex) = std::str::from_utf8(run)
            && let Ok(id) = EntityId::from_hex(&hex.to_ascii_lowercase())
        {
            ids.push(id);
        }
    }
    ids
}
