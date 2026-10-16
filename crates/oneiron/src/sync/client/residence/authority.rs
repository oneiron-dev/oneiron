//! Authority history from the home for a machine that syncs what it opened
//! (OF-469). Its windows carry only the AUTHORITY_LOG rows they hold, so the
//! machine asks the home for every signed entry it lacks, names what it holds,
//! and imports each page through the signed-history door, which checks every
//! signature and parent and refolds here. Nothing the home asserts is trusted
//! beyond the signed bytes.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::Vault;
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::{AUTHORITY_TAIL_PAGE_MAX, held_authority_entries};
use crate::sync::transport::TransportError;

/// The most pages one catch-up takes before it stops for this round.
const MAX_PAGES: usize = 1024;

#[derive(Deserialize)]
struct AuthorityTailReply {
    entries: Vec<String>,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

impl SyncClient {
    /// Takes in the signed authority entries the home holds and this machine
    /// lacks, a page at a time. Returns how many it imported.
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
        if count == 0 {
            break;
        }
        vault
            .import_signed_authority_history(&entries)
            .map_err(storage)?;
        taken += count;
        if count < AUTHORITY_TAIL_PAGE_MAX {
            break;
        }
    }
    Ok(taken)
}
