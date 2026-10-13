//! Release checks for a payload a caller was served earlier and is sent again
//! (DEC-0005): a payload naming a row a device-local world keeps now never
//! leaves this device a second time, whether the row's world was flagged
//! since or the row moved into a flagged world.

use oneiron::EntityId;
use oneiron::claim::CallerLocality;

/// Whether `payload` names a row a device-local world keeps from a caller at
/// `locality`: an entity id in it, as a whole 32-digit hex token, that a
/// caller off this device may not read now.
pub(crate) fn names_kept_row(
    vault: &oneiron::Vault,
    locality: CallerLocality,
    payload: &[u8],
) -> oneiron::Result<bool> {
    withholds_retained(vault, locality, &[], payload)
}

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
