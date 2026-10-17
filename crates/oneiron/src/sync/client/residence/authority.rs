//! Authority history from the home for a machine that syncs what it opened
//! (OF-469). Its windows carry only the AUTHORITY_LOG rows they hold, so the
//! machine asks the home for every signed entry it lacks, names what it holds,
//! and imports each page through the signed-history door, which checks every
//! signature and parent and refolds here. Nothing the home asserts is trusted
//! beyond the signed bytes. An entry the door refuses holds back only itself
//! and what stands on it, and the rest of the round asks past it. The tail's
//! last page names the entries this machine holds and the home lacks, and
//! the machine appends them, parents first, so what it wrote reaches the home
//! without the window it rides. A round ends by asking what history this
//! machine's rows still name and it lacks (`Vault::authority_history_request`)
//! and fetching exactly that from the home (`residence.authority.range`), each
//! missing entry with its ancestors, through the repair door: the rows wait in
//! the stage until together they close the history, then land at once. When
//! the fold asks for the whole coverage of the image this machine adopted,
//! that coverage pages by the image itself, with no hash list
//! ([`Vault::authority_history_fetch`]); isolated gaps keep exact hashes.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use std::collections::BTreeSet;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::Vault;
use crate::authority::{
    AUTHORITY_HISTORY_PAGE_MAX, AuthorityEntryHash, AuthorityHistoryFetch, AuthorityHistoryRequest,
    AuthorityHistorySelection, AuthorityRepairOutcome, authority_entry_hash,
    decode_authority_log_entry_body,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::{
    AUTHORITY_TAIL_PAGE_MAX, held_authority_entries, import_authority_page,
};
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

/// One page of a range fetch, naming the selection it serves. The home's
/// vault, checkpoint and unheld claims count for nothing here, so they are
/// not read.
#[derive(Deserialize)]
struct AuthorityRangeReply {
    selection: String,
    rows: Vec<String>,
    #[serde(default)]
    next: Option<String>,
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
    // Entries refused this round: named as held, so the home pages past them.
    let mut skipped = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let mut held = held_authority_entries(vault).map_err(storage)?;
        held.extend(skipped.iter().copied());
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
        let page = import_authority_page(vault, &entries).map_err(storage)?;
        taken += page.written;
        if !page.refused.is_empty() {
            tracing::debug!(refused = page.refused.len(), "authority entries refused");
            skipped.extend(page.refused);
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
    let (repaired, missing) = repair_authority_history(vault, &mut rpc, &skipped).await?;
    taken += repaired;
    if !missing.is_complete() {
        tracing::warn!(
            missing = missing.missing.len(),
            refused = skipped.len(),
            "authority history still names entries this machine lacks"
        );
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

/// Fetches the history this machine's rows name and it lacks, by exact hash,
/// each missing entry with its ancestors down to what this machine holds or
/// staged, parents first, and imports each page through the repair door. It
/// asks again after each page, since a fetched entry may name further
/// ancestors, and stops once nothing is missing, the home serves none of it,
/// or the door refuses a page. `refused` are entries refused this round:
/// named as held, so no page carries them again. Once a round, a request for
/// the whole adopted coverage pages it by the image instead, under one fixed
/// selection and held set, the cursor walking it; its end is no proof of
/// completeness, so the round asks again after it and fetches what remains
/// by exact hash. Returns how many rows landed and what is still missing.
async fn repair_authority_history(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    refused: &BTreeSet<AuthorityEntryHash>,
) -> Result<(usize, AuthorityHistoryRequest), TransportError> {
    let mut refused = refused.clone();
    let mut written = 0;
    let mut cursor = None;
    let mut request = vault
        .authority_history_request(&BTreeSet::new())
        .map_err(storage)?;
    // The covered pass in flight, and whether this round has run one.
    let mut pass: Option<AuthorityHistoryFetch> = None;
    let mut passed = false;
    for _ in 0..MAX_PAGES {
        if request.is_complete() {
            break;
        }
        let fetch = match pass.take() {
            Some(pass) => AuthorityHistoryFetch { cursor, ..pass },
            None => {
                let mut held = held_authority_entries(vault).map_err(storage)?;
                held.extend(vault.authority_staged_history().map_err(storage)?);
                held.extend(refused.iter().copied());
                match vault
                    .authority_history_fetch(&request, held.clone())
                    .map_err(storage)?
                {
                    covered @ AuthorityHistoryFetch {
                        selection: AuthorityHistorySelection::Covered { .. },
                        ..
                    } if !passed => {
                        passed = true;
                        covered
                    }
                    _ => AuthorityHistoryFetch {
                        cursor,
                        ..AuthorityHistoryFetch::closing(&request, held)
                    },
                }
            }
        };
        let covered = matches!(fetch.selection, AuthorityHistorySelection::Covered { .. });
        let Some((rows, next)) = fetch_authority_range(rpc, &fetch).await? else {
            // A home that keeps no such image refuses the covered pass: the
            // round goes on by exact hash.
            if covered {
                cursor = None;
                continue;
            }
            break;
        };
        if rows.is_empty() {
            if covered {
                cursor = None;
                continue;
            }
            break;
        }
        let outcome = match vault.import_signed_authority_repair_page(&rows) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(%error, "authority repair page refused");
                break;
            }
        };
        request = match outcome {
            AuthorityRepairOutcome::Applied {
                written: landed,
                refused: dropped,
            } => {
                written += landed.len();
                refused.extend(dropped);
                vault
                    .authority_history_request(&BTreeSet::new())
                    .map_err(storage)?
            }
            AuthorityRepairOutcome::Staged {
                request,
                refused: dropped,
            } => {
                refused.extend(dropped);
                request
            }
        };
        // Rows this page carried are held or staged now, so a home that
        // finds its cursor among them starts the selection again. A covered
        // pass keeps its selection and held set, so its cursor walks on.
        cursor = next;
        if covered {
            if next.is_some() {
                pass = Some(fetch);
            } else {
                cursor = None;
            }
        }
    }
    Ok((written, request))
}

/// One page of `fetch` from the home: its signed rows, parents first, and the
/// cursor of the next page. `None` when the home refuses the fetch; a page
/// naming another selection than `fetch`'s is refused here.
async fn fetch_authority_range(
    rpc: &mut ResidenceRpc,
    fetch: &AuthorityHistoryFetch,
) -> Result<Option<(Vec<Vec<u8>>, Option<AuthorityEntryHash>)>, TransportError> {
    let packed = |hashes: &BTreeSet<AuthorityEntryHash>| {
        base64::engine::general_purpose::STANDARD
            .encode(hashes.iter().flatten().copied().collect::<Vec<u8>>())
    };
    let one = |hash: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(hash);
    let selection = match &fetch.selection {
        AuthorityHistorySelection::Hashes(hashes) => json!({ "hashes": packed(hashes) }),
        AuthorityHistorySelection::Covered {
            checkpoint,
            archive,
            lower_exclusive,
            upper_inclusive,
        } => json!({ "covered": {
            "checkpoint": one(checkpoint),
            "archive": archive.as_ref().map(one),
            "lower_exclusive": lower_exclusive.as_ref().map(one),
            "upper_inclusive": upper_inclusive.as_ref().map(one),
        }}),
    };
    let reply = match rpc
        .request(
            "residence.authority.range",
            json!({
                "vault_id": fetch.vault_id.map(|id| base64::engine::general_purpose::STANDARD.encode(id)),
                "selection": selection,
                "parent_closure": fetch.parent_closure,
                "held": packed(&fetch.held),
                "cursor": fetch.cursor.map(|cursor| base64::engine::general_purpose::STANDARD.encode(cursor)),
                "limit": fetch.limit,
            }),
        )
        .await
    {
        Ok(reply) => reply,
        Err(TransportError::InvalidPayload(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let reply: AuthorityRangeReply = serde_json::from_value(reply).map_err(|_| refused())?;
    if reply.rows.len() > AUTHORITY_HISTORY_PAGE_MAX
        || base64::engine::general_purpose::STANDARD
            .decode(&reply.selection)
            .ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            != Some(fetch.selection.id())
    {
        return Err(refused());
    }
    let rows = reply
        .rows
        .iter()
        .map(|row| base64::engine::general_purpose::STANDARD.decode(row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refused())?;
    let next = reply
        .next
        .map(|next| {
            base64::engine::general_purpose::STANDARD
                .decode(next)
                .ok()
                .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .ok_or_else(refused)
        })
        .transpose()?;
    Ok(Some((rows, next)))
}
