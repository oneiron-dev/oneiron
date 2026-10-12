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
    if locality == CallerLocality::OnDevice {
        return Ok(false);
    }
    let named = entity_ids_in(payload);
    if named.is_empty() {
        return Ok(false);
    }
    let count = named.len();
    Ok(vault.off_device_readable(named)?.len() != count)
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
    ids.sort_unstable_by_key(|id| *id.as_bytes());
    ids.dedup();
    ids
}
