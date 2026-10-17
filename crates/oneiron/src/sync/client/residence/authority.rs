//! Authority history from the home for a machine that syncs what it opened
//! (OF-469). Its windows carry only the AUTHORITY_LOG rows they hold, so the
//! machine asks the home for every signed entry it lacks, names what it holds,
//! and imports each page through the signed-history door, which checks every
//! signature and parent and refolds here. Nothing the home asserts is trusted
//! beyond the signed bytes. The tail's last page names the entries this
//! machine holds and the home lacks, and the machine appends them, parents
//! first, so what it wrote reaches the home without the window it rides.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use std::collections::BTreeSet;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, authority_entry_hash, decode_authority_log_entry_body};
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::{AUTHORITY_TAIL_PAGE_MAX, held_authority_entries};
use crate::sync::transport::TransportError;

/// The most pages one catch-up takes, or appends, before it stops for this
/// round.
const MAX_PAGES: usize = 1024;

/// The most signed bytes one append page carries: inside the request frame
/// once base64 and the RPC envelope are added.
const APPEND_PAGE_BYTES: usize = 4 << 20;

#[derive(Deserialize)]
struct AuthorityTailReply {
    entries: Vec<String>,
    /// On the last page: the entries this machine named that the home
    /// lacks, as concatenated 32-byte hashes in base64.
    #[serde(default)]
    wanted: String,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

impl SyncClient {
    /// Takes in the signed authority entries the home holds and this machine
    /// lacks, a page at a time, then appends those the home lacks. Returns
    /// how many it imported.
    pub async fn catch_up_authority(&self) -> Result<usize, TransportError> {
        catch_up_authority(&self.vault, &self.config).await
    }
}

/// [`SyncClient::catch_up_authority`] on a vault and a client config alone,
/// for a task off the live sync loop.
pub(crate) async fn catch_up_authority(
    vault: &Vault,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::Storage("home node offline".into()));
    };
    let mut taken = 0;
    let mut wanted = None;
    for _ in 0..MAX_PAGES {
        let held = held_authority_entries(vault).map_err(storage)?;
        let packed: Vec<u8> = held.iter().flatten().copied().collect();
        let reply = rpc
            .request(
                "residence.authority.tail",
                json!({
                    "held": base64::engine::general_purpose::STANDARD.encode(packed),
                    "limit": AUTHORITY_TAIL_PAGE_MAX,
                }),
            )
            .await?;
        let reply: AuthorityTailReply = serde_json::from_value(reply).map_err(|_| refused())?;
        if reply.entries.len() > AUTHORITY_TAIL_PAGE_MAX {
            return Err(refused());
        }
        let entries = reply
            .entries
            .iter()
            .map(|entry| base64::engine::general_purpose::STANDARD.decode(entry))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| refused())?;
        let count = entries.len();
        if count > 0 {
            vault
                .import_signed_authority_history(&entries)
                .map_err(storage)?;
            taken += count;
        }
        if count < AUTHORITY_TAIL_PAGE_MAX {
            wanted = Some(reply.wanted);
            break;
        }
    }
    if let Some(wanted) = wanted {
        let appended = append_authority(vault, &mut rpc, &wanted).await?;
        if appended > 0 {
            tracing::debug!(appended, "authority entries appended to the home");
        }
    }
    Ok(taken)
}

/// Appends to the home the signed entries it named as lacking, parents
/// first, in pages that each import whole there: every parent of an entry is
/// held by the home or sent before it. Returns how many it sent.
async fn append_authority(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    wanted: &str,
) -> Result<usize, TransportError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(wanted)
        .map_err(|_| refused())?;
    if raw.len() % 32 != 0 {
        return Err(refused());
    }
    let wanted: BTreeSet<AuthorityEntryHash> = raw
        .chunks_exact(32)
        .map(|hash| <[u8; 32]>::try_from(hash).map_err(|_| refused()))
        .collect::<Result<_, _>>()?;
    if wanted.is_empty() {
        return Ok(0);
    }
    let mut pages = Vec::new();
    let mut page: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0;
    for entry in vault.export_signed_authority_history().map_err(storage)? {
        let hash = authority_entry_hash(&decode_authority_log_entry_body(&entry).map_err(storage)?)
            .map_err(storage)?;
        if !wanted.contains(&hash) {
            continue;
        }
        if entry.len() > APPEND_PAGE_BYTES {
            return Err(refused());
        }
        if page.len() == AUTHORITY_TAIL_PAGE_MAX || bytes + entry.len() > APPEND_PAGE_BYTES {
            pages.push(std::mem::take(&mut page));
            bytes = 0;
        }
        bytes += entry.len();
        page.push(entry);
    }
    if !page.is_empty() {
        pages.push(page);
    }
    let mut sent = 0;
    for page in pages.into_iter().take(MAX_PAGES) {
        let entries: Vec<String> = page
            .iter()
            .map(|entry| base64::engine::general_purpose::STANDARD.encode(entry))
            .collect();
        rpc.request("residence.authority.append", json!({ "entries": entries }))
            .await?;
        sent += page.len();
    }
    Ok(sent)
}
