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
//! (REVIEW-10536 P1).

use std::sync::{Mutex, PoisonError};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{MAX_PAGES, ResidenceRpc, refused, residence_budgets, storage};
use crate::authority::{MESH_AUTHORITY_PAGE_MAX, MeshAuthorityRow};
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

/// The home's answer to one mesh bindings ask: the page's rows, and the
/// MACHINE the next page starts after while there is one.
#[derive(Deserialize)]
struct MeshAuthorityReply {
    rows: Vec<MeshAuthorityRowReply>,
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
        let (rows, next) = decoded_page(reply, after)?;
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

/// The rows of one page and where the next starts, checked: at most
/// [`MESH_AUTHORITY_PAGE_MAX`] rows, each past `after` and the row before
/// it, and a next page that starts past them all, so no answer can turn
/// the scan back.
fn decoded_page(
    reply: MeshAuthorityReply,
    after: Option<EntityId>,
) -> Result<(Vec<MeshAuthorityRow>, Option<EntityId>), TransportError> {
    if reply.rows.len() > MESH_AUTHORITY_PAGE_MAX {
        return Err(refused());
    }
    let decode = |encoded: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| refused())
    };
    let mut rows: Vec<MeshAuthorityRow> = Vec::with_capacity(reply.rows.len());
    let mut floor = after;
    for row in &reply.rows {
        let machine = EntityId::from_hex(&row.machine).map_err(|_| refused())?;
        if floor.is_some_and(|floor| machine <= floor) {
            return Err(refused());
        }
        floor = Some(machine);
        rows.push(MeshAuthorityRow {
            machine,
            authority: decode(&row.authority)?,
            address: decode(&row.address)?,
            bare: row.bare,
        });
    }
    let next = reply
        .next
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| refused())?;
    if let Some(next) = next
        && (after.is_some_and(|after| next <= after)
            || rows.last().is_some_and(|last| next < last.machine))
    {
        return Err(refused());
    }
    Ok((rows, next))
}
