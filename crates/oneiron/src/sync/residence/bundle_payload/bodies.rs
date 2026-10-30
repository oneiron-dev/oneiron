//! The by-reference ASSET bodies a sealed bundle section carries (FIX 5532).
//!
//! A window snapshot holds a body that moves by reference as its carrier
//! and reference only. So that a bundle restores what it restored before
//! the file plane, each section carries, after its windows, every such body
//! its windows bind that the publisher holds, whole, as a file part. A body
//! the publisher does not hold is listed by its reference alone, as owed;
//! the section is assembled all the same. A take that materializes lands
//! each carried body against the window snapshot that bound it, where no row
//! stands at its owner here yet; the live body transfer brings any other.

use std::collections::HashMap;

use loro::LoroDoc;

use super::reader::Reader;
use super::{malformed, put_u32};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ASSET_FILE_PLANE;
use crate::sync::WindowManager;
use crate::sync::asset_body::references::{AssetBodyRef, bound_refs};
use crate::sync::asset_body::served_row;
use crate::sync::asset_body::session::{AssetBodyLane, AssetBodyPeer, land_carried_body};
use crate::sync::loro_support::{import_doc, map_get_bytes};
use crate::sync::types::WindowKey;

/// One body a section carries: the window whose snapshot binds it, its
/// reference, and its bytes, `None` when it is owed.
pub(super) struct CarriedBody {
    window: WindowKey,
    body: AssetBodyRef,
    bytes: Option<Vec<u8>>,
}

/// The bodies `windows`, each a window and its snapshot, bind by reference,
/// each with its bytes when this vault holds it. A body this vault cannot
/// read is owed, never a failed assembly.
///
/// # Errors
///
/// A snapshot that does not import.
pub(super) fn carried(vault: &Vault, windows: &[(WindowKey, Vec<u8>)]) -> Result<Vec<CarriedBody>> {
    let mut carried = Vec::new();
    if !ASSET_FILE_PLANE {
        return Ok(carried);
    }
    for (window, snapshot) in windows {
        let doc = LoroDoc::new();
        import_doc(&doc, snapshot)?;
        let entities = doc.get_map("entities");
        for body in bound_refs(&doc) {
            let carrier = map_get_bytes(&entities, &body.key()).unwrap_or_default();
            let bytes = match served_row(vault, &doc, &body.id, carrier) {
                Ok(row) => {
                    row.and_then(|row| row.get(ENTITY_METADATA_HEADER_LEN..).map(<[u8]>::to_vec))
                }
                Err(error) => {
                    let entity = body.id.to_hex();
                    tracing::warn!(%entity, %error, "bundle owes an unreadable asset body");
                    None
                }
            };
            carried.push(CarriedBody {
                window: window.clone(),
                body,
                bytes,
            });
        }
    }
    Ok(carried)
}

/// count (4) ‖ each body: its window key `u16`-length-prefixed, its owner
/// (16), its reference `u32`-length-prefixed ([`AssetBodyRef::encode`]),
/// then 1 and its bytes `u64`-length-prefixed, or 0 when it is owed.
///
/// # Errors
///
/// A field past its length prefix.
pub(super) fn encode(out: &mut Vec<u8>, bodies: &[CarriedBody]) -> Result<()> {
    put_u32(out, bodies.len())?;
    for carried in bodies {
        let name = u16::try_from(carried.window.as_str().len()).map_err(|_| malformed())?;
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(carried.window.as_str().as_bytes());
        out.extend_from_slice(carried.body.id.as_bytes());
        let reference = carried.body.encode()?;
        put_u32(out, reference.len())?;
        out.extend_from_slice(&reference);
        match &carried.bytes {
            Some(bytes) => {
                out.push(1);
                out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                out.extend_from_slice(bytes);
            }
            None => out.push(0),
        }
    }
    Ok(())
}

/// [`encode`] back, each carried body exactly its reference's length.
///
/// # Errors
///
/// A malformed section.
pub(super) fn decode(reader: &mut Reader<'_>) -> Result<Vec<CarriedBody>> {
    let mut bodies = Vec::new();
    for _ in 0..reader.u32()? {
        let name = usize::from(reader.u16()?);
        let window = std::str::from_utf8(reader.take(name)?)
            .ok()
            .and_then(WindowKey::try_new)
            .ok_or_else(malformed)?;
        let owner = EntityId::from_bytes(reader.array::<16>()?).map_err(|_| malformed())?;
        let len = reader.u32()? as usize;
        let body =
            AssetBodyRef::decode(&owner.to_hex(), reader.take(len)?).ok_or_else(malformed)?;
        let bytes = match reader.u8()? {
            0 => None,
            1 => {
                let len = usize::try_from(reader.u64()?).map_err(|_| malformed())?;
                Some(reader.take(len)?.to_vec())
            }
            _ => return Err(malformed()),
        };
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() as u64 != body.len)
        {
            return Err(malformed());
        }
        bodies.push(CarriedBody {
            window,
            body,
            bytes,
        });
    }
    Ok(bodies)
}

/// Lands each body `bodies` carries whole against the snapshot of `windows`
/// that bound it, where no row stands at its owner here: a carried body
/// never lands over a row this machine holds. One that does not land waits
/// for the live body transfer; the take goes on.
pub(super) fn land(
    manager: &WindowManager,
    windows: &[(WindowKey, Vec<u8>)],
    bodies: Vec<CarriedBody>,
) {
    let vault: &Vault = manager.vault();
    let mut docs: HashMap<WindowKey, LoroDoc> = HashMap::new();
    for carried in bodies {
        let Some(bytes) = carried.bytes else {
            continue;
        };
        let landed = (|| -> Result<bool> {
            {
                let txn = vault.store.env.read_txn()?;
                if crate::ports::EntityStoreRead::port_entity_present(
                    &vault.store,
                    &txn,
                    &carried.body.id,
                )? {
                    return Ok(false);
                }
            }
            if !docs.contains_key(&carried.window) {
                let Some((_, snapshot)) = windows.iter().find(|(key, _)| *key == carried.window)
                else {
                    return Ok(false);
                };
                let doc = LoroDoc::new();
                import_doc(&doc, snapshot)?;
                docs.insert(carried.window.clone(), doc);
            }
            let doc = docs.get(&carried.window).cloned();
            let window = |key: &WindowKey| doc.clone().filter(|_| *key == carried.window);
            let windows = || vec![carried.window.clone()];
            let peer = AssetBodyPeer {
                lane: AssetBodyLane::OwnDevice,
                vault,
                materializer: manager.materializer(),
                window: &window,
                windows: &windows,
            };
            land_carried_body(&peer, &carried.window, &carried.body, &bytes)
        })();
        if let Err(error) = landed {
            let entity = carried.body.id.to_hex();
            tracing::warn!(%entity, %error, "bundle asset body left to the live transfer");
        }
    }
}
