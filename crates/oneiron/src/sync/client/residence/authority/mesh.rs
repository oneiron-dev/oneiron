//! The home's host-signed mesh bindings, read each sync round whatever this
//! machine's residence (`residence.authority.mesh`,
//! MESH-AUTHORITY-REPLICATION). No window carries a binding or the MACHINE
//! address it binds, and a joined machine holds no host issuer to sign its
//! own. Each binding a live owner host of this machine's fold signed lands
//! as signed ([`Vault::import_mesh_authority_rows`]), so a node here proves
//! the peers the owner bound on the home.
//!
//! A round reads at most [`MAX_PAGES`] pages, from where the last round
//! stopped, so every binding lands however many the home holds
//! (REVIEW-10536 P1). A binding past one page comes by reference, and this
//! machine reads its signed row a part at a time
//! (`residence.authority.mesh.part`, MESH-AUTHORITY-ROW-PARTS), checks the
//! joined row's length and content hash ([`MeshAuthorityRowJoin`]) and
//! imports it with the page's other rows.

use std::sync::{Mutex, PoisonError};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{MAX_PAGES, ResidenceRpc, refused, residence_budgets, storage};
use crate::authority::{
    MESH_AUTHORITY_PAGE_MAX, MeshAuthorityPart, MeshAuthorityRow, MeshAuthorityRowJoin,
    MeshAuthorityRowRef,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

/// One binding as the home serves it, each part in base64.
#[derive(Deserialize)]
struct MeshAuthorityRowReply {
    machine: String,
    authority: String,
    address: String,
    /// The address was served without its direct addresses, to fit the page.
    #[serde(default)]
    bare: bool,
}

/// A binding the home names by reference, its signed row read in parts: its
/// length, its content hash as `blake3:<hex>` and its address in base64.
#[derive(Deserialize)]
struct MeshAuthorityRowRefReply {
    machine: String,
    total: u64,
    digest: String,
    address: String,
    #[serde(default)]
    bare: bool,
}

/// One part of a signed row the home holds, and the row's whole length.
#[derive(Deserialize)]
struct MeshAuthorityPartReply {
    total: u64,
    part: String,
}

/// The home's answer to one mesh bindings ask: the page's rows, those it
/// names by reference (none from a home older than MESH-AUTHORITY-ROW-PARTS),
/// and the MACHINE the next page starts after while there is one.
#[derive(Deserialize)]
struct MeshAuthorityReply {
    rows: Vec<MeshAuthorityRowReply>,
    #[serde(default)]
    parted: Vec<MeshAuthorityRowRefReply>,
    #[serde(default)]
    next: Option<String>,
}

/// Reads the home's mesh bindings for one round and imports each page. The
/// round starts after the MACHINE `cursor` holds, or at the first binding
/// when it holds none. Each page this machine committed moves `cursor` past
/// it, so a round that stops early, or a reconnect, goes on from there; it
/// holds `None` once the scan reached the home's last binding. Returns how
/// many bindings were written here.
///
/// # Errors
///
/// A member lane; the home is offline, serves no such method (a home older
/// than MESH-AUTHORITY-REPLICATION) or answers what this machine refuses;
/// storage errors. Pages committed before the error stay committed.
pub(crate) async fn catch_up_mesh_authority(
    vault: &Vault,
    config: &SyncClientConfig,
    cursor: &Mutex<Option<EntityId>>,
) -> Result<usize, TransportError> {
    if config.member_lane {
        return Err(refused());
    }
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::home_offline());
    };
    let mut after = *cursor.lock().unwrap_or_else(PoisonError::into_inner);
    let mut written = 0;
    for _ in 0..MAX_PAGES {
        let reply = rpc
            .request(
                "residence.authority.mesh",
                json!({ "after": after.as_ref().map(EntityId::to_hex) }),
            )
            .await?;
        let reply: MeshAuthorityReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let (mut rows, parted, next) = decoded_page(reply, after)?;
        for reference in parted {
            match MeshAuthorityRowJoin::start(reference) {
                Some(join) => rows.push(joined_row(&mut rpc, join).await?),
                None => tracing::warn!(
                    "the home named a mesh binding longer than this machine joins; it stays out"
                ),
            }
        }
        rows.sort_by_key(|row| row.machine);
        let import = vault.import_mesh_authority_rows(rows).map_err(storage)?;
        if !import.refused.is_empty() {
            tracing::warn!(
                refused = import.refused.len(),
                "the home served mesh bindings this machine refused"
            );
        }
        written += import.written.len();
        after = next;
        *cursor.lock().unwrap_or_else(PoisonError::into_inner) = after;
        if after.is_none() {
            break;
        }
    }
    Ok(written)
}

/// The row `join` names, read from the home a part at a time and checked
/// against the length and content hash its page named. A part that does not
/// continue it, or a joined row the page did not name (the home signed it
/// again since), ends the round; the next round reads that page again.
async fn joined_row(
    rpc: &mut ResidenceRpc,
    mut join: MeshAuthorityRowJoin,
) -> Result<MeshAuthorityRow, TransportError> {
    while !join.is_whole() {
        let reply: MeshAuthorityPartReply = serde_json::from_value(
            rpc.request(
                "residence.authority.mesh.part",
                json!({ "machine": join.machine().to_hex(), "offset": join.offset() }),
            )
            .await?,
        )
        .map_err(|_| refused())?;
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if !join.take(MeshAuthorityPart {
            total: reply.total,
            part,
        }) {
            return Err(refused());
        }
    }
    join.finish().ok_or_else(refused)
}

/// A page's rows, those it names by reference and where the next page
/// starts, checked: at most [`MESH_AUTHORITY_PAGE_MAX`] bindings, each list
/// in MACHINE order past `after`, no MACHINE in both, and a next page that
/// starts past them all, so no answer can turn the scan back.
fn decoded_page(
    reply: MeshAuthorityReply,
    after: Option<EntityId>,
) -> Result<
    (
        Vec<MeshAuthorityRow>,
        Vec<MeshAuthorityRowRef>,
        Option<EntityId>,
    ),
    TransportError,
> {
    if reply.rows.len() + reply.parted.len() > MESH_AUTHORITY_PAGE_MAX {
        return Err(refused());
    }
    let decode = |encoded: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| refused())
    };
    // Each MACHINE past `after` and the one before it in its list.
    let ordered = |floor: &mut Option<EntityId>, hex: &str| -> Result<EntityId, TransportError> {
        let machine = EntityId::from_hex(hex).map_err(|_| refused())?;
        if floor.is_some_and(|floor| machine <= floor) {
            return Err(refused());
        }
        *floor = Some(machine);
        Ok(machine)
    };
    let mut rows: Vec<MeshAuthorityRow> = Vec::with_capacity(reply.rows.len());
    let mut floor = after;
    for row in &reply.rows {
        rows.push(MeshAuthorityRow {
            machine: ordered(&mut floor, &row.machine)?,
            authority: decode(&row.authority)?,
            address: decode(&row.address)?,
            bare: row.bare,
        });
    }
    let mut parted: Vec<MeshAuthorityRowRef> = Vec::with_capacity(reply.parted.len());
    let mut floor = after;
    for reference in &reply.parted {
        let machine = ordered(&mut floor, &reference.machine)?;
        if rows.iter().any(|row| row.machine == machine) {
            return Err(refused());
        }
        parted.push(MeshAuthorityRowRef {
            machine,
            total: reference.total,
            digest: MeshAuthorityRowRef::digest_from_text(&reference.digest).ok_or_else(refused)?,
            address: decode(&reference.address)?,
            bare: reference.bare,
        });
    }
    let next = reply
        .next
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| refused())?;
    let last = rows
        .last()
        .map(|row| row.machine)
        .max(parted.last().map(|reference| reference.machine));
    if let Some(next) = next
        && (after.is_some_and(|after| next <= after) || last.is_some_and(|last| next < last))
    {
        return Err(refused());
    }
    Ok((rows, parted, next))
}

#[cfg(test)]
mod tests {
    //! MESH-AUTHORITY-ROW-PARTS: a page names its bindings whole and by
    //! reference, and the machine refuses one that names a MACHINE twice or
    //! turns its scan back.

    use super::*;

    /// Three MACHINE ids, in order.
    fn machines() -> [EntityId; 3] {
        let mut machines = [EntityId::now(), EntityId::now(), EntityId::now()];
        machines.sort();
        machines
    }

    /// A page with `rows` carried whole, `parted` named by reference, and
    /// the next page after `next`.
    fn reply(rows: &[EntityId], parted: &[EntityId], next: Option<EntityId>) -> MeshAuthorityReply {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        serde_json::from_value(json!({
            "rows": rows
                .iter()
                .map(|machine| json!({
                    "machine": machine.to_hex(),
                    "authority": encode(b"row"),
                    "address": encode(b"address"),
                }))
                .collect::<Vec<_>>(),
            "parted": parted
                .iter()
                .map(|machine| json!({
                    "machine": machine.to_hex(),
                    "total": 3,
                    "digest": format!("blake3:{}", "01".repeat(32)),
                    "address": encode(b"address"),
                }))
                .collect::<Vec<_>>(),
            "next": next.as_ref().map(EntityId::to_hex),
        }))
        .unwrap()
    }

    #[test]
    fn a_page_names_its_bindings_whole_and_by_reference() {
        let [a, b, c] = machines();
        let (rows, parted, next) = decoded_page(reply(&[a, c], &[b], Some(c)), None).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.machine).collect::<Vec<_>>(),
            vec![a, c]
        );
        assert_eq!(
            parted,
            vec![MeshAuthorityRowRef {
                machine: b,
                total: 3,
                digest: [1; 32],
                address: b"address".to_vec(),
                bare: false,
            }]
        );
        assert_eq!(next, Some(c));

        let older: MeshAuthorityReply =
            serde_json::from_value(json!({ "rows": [], "next": null })).unwrap();
        let (rows, parted, next) = decoded_page(older, None).unwrap();
        assert!(
            rows.is_empty() && parted.is_empty() && next.is_none(),
            "a home older than MESH-AUTHORITY-ROW-PARTS names none by reference"
        );
    }

    #[test]
    fn a_page_that_names_a_machine_twice_or_turns_the_scan_back_is_refused() {
        let [a, b, c] = machines();
        assert!(
            decoded_page(reply(&[a, b], &[b], None), None).is_err(),
            "one MACHINE whole and by reference"
        );
        assert!(
            decoded_page(reply(&[a], &[c], Some(b)), None).is_err(),
            "a next page that starts before the last reference"
        );
        assert!(
            decoded_page(reply(&[], &[c, b], None), None).is_err(),
            "references out of order"
        );
        assert!(
            decoded_page(reply(&[], &[a], None), Some(a)).is_err(),
            "a reference at or before where the page starts"
        );
        let mut other_hash = reply(&[], &[a], None);
        other_hash.parted[0].digest = format!("sha256:{}", "01".repeat(32));
        assert!(
            decoded_page(other_hash, None).is_err(),
            "a content hash of another name"
        );
    }
}
