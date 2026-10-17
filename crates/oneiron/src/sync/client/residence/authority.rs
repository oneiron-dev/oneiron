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
//! the stage until together they close the history, then land at once.
//!
//! A machine whose owner-authorized pairing returned a checkpoint pin adopts
//! that image first, while this vault has adopted none: it reads the image
//! the pin names from the home a part at a time
//! (`residence.authority.checkpoint`), keeps the attestations made with the
//! pin's own key bindings, and hands both to the adoption door, which
//! verifies them against the pin and refuses what this vault cannot take.

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use std::collections::BTreeSet;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::Vault;
use crate::authority::{
    AUTHORITY_CHECKPOINT_V2_MAX_BYTES, AUTHORITY_HISTORY_PAGE_MAX, AuthorityCheckpointAttestation,
    AuthorityCheckpointPin, AuthorityEntryHash, AuthorityHistoryFetch, AuthorityHistoryRequest,
    AuthorityRepairOutcome, authority_entry_hash, decode_authority_log_entry_body,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::{
    AUTHORITY_CHECKPOINT_PART_MAX, AUTHORITY_TAIL_PAGE_MAX, held_authority_entries,
    import_authority_page,
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

/// One page of an exact-hash fetch. The home's vault, checkpoint and unheld
/// claims count for nothing here, so they are not read.
#[derive(Deserialize)]
struct AuthorityRangeReply {
    rows: Vec<String>,
    #[serde(default)]
    next: Option<String>,
}

/// One part of a kept checkpoint image.
#[derive(Deserialize)]
struct AuthorityCheckpointReply {
    total: u64,
    part: String,
    /// On the part at offset zero: the attestations the home keeps for it.
    #[serde(default)]
    attestations: Vec<AuthorityCheckpointAttestation>,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

impl SyncClient {
    /// Takes in the signed authority entries the home holds and this machine
    /// lacks, a page at a time, then appends those the home lacks. A machine
    /// whose pairing pinned a checkpoint adopts its image first, while this
    /// vault has adopted none. Returns how many entries it imported.
    pub async fn catch_up_authority(&self) -> Result<usize, TransportError> {
        catch_up_authority(&self.vault, &self.config).await
    }
}

/// Whether this vault holds an adopted checkpoint, read without verifying
/// it.
fn checkpoint_adopted(vault: &Vault) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .authority_checkpoint_expectation_in_txn(&txn)?
        .adopted_pin_digest
        .is_some())
}

/// Whether `config` names a checkpoint pin this vault has yet to adopt an
/// image under: its first authority catch-up adopts one.
pub(crate) fn pinned_checkpoint_pending(vault: &Vault, config: &SyncClientConfig) -> bool {
    config.authority_checkpoint_pin.is_some()
        && checkpoint_adopted(vault).is_ok_and(|adopted| !adopted)
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
    // A checkpoint that cannot be read this round holds back no tail.
    if let Some(pin) = &config.authority_checkpoint_pin
        && !checkpoint_adopted(vault).map_err(storage)?
        && let Err(error) = adopt_pinned_checkpoint(vault, &mut rpc, pin).await
    {
        tracing::warn!(%error, "pinned authority checkpoint not read");
    }
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

/// Adopts the checkpoint image `pin` names (OF-469): read from the home, its
/// attestations kept to those made with the pin's own key bindings, then
/// verified against the pin and adopted in one write. The adoption door
/// decides what this vault takes: a refusal is logged, and the tail folds
/// as it would have.
async fn adopt_pinned_checkpoint(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    pin: &AuthorityCheckpointPin,
) -> Result<(), TransportError> {
    let Some((image, mut attestations)) = fetch_authority_checkpoint(rpc, &pin.checkpoint).await?
    else {
        tracing::warn!("the home serves no image of the pinned authority checkpoint");
        return Ok(());
    };
    attestations
        .retain(|attestation| pin.binding(&attestation.binding.root) == Some(&attestation.binding));
    match vault.adopt_authority_checkpoint(pin, &image, &attestations) {
        Ok(_) => tracing::info!("pinned authority checkpoint adopted"),
        Err(error) => tracing::warn!(%error, "pinned authority checkpoint refused"),
    }
    Ok(())
}

/// The checkpoint image the home keeps at `checkpoint` and the attestations
/// it keeps for it, read a part at a time. `None` when the home refuses the
/// read or keeps no such image.
async fn fetch_authority_checkpoint(
    rpc: &mut ResidenceRpc,
    checkpoint: &[u8; 32],
) -> Result<Option<(Vec<u8>, Vec<AuthorityCheckpointAttestation>)>, TransportError> {
    let mut image = Vec::new();
    let mut attestations = Vec::new();
    let mut total = None;
    loop {
        let reply = match rpc
            .request(
                "residence.authority.checkpoint",
                json!({
                    "checkpoint": base64::engine::general_purpose::STANDARD.encode(checkpoint),
                    "offset": image.len(),
                }),
            )
            .await
        {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let reply: AuthorityCheckpointReply =
            serde_json::from_value(reply).map_err(|_| refused())?;
        if *total.get_or_insert(reply.total) != reply.total
            || reply.total > AUTHORITY_CHECKPOINT_V2_MAX_BYTES as u64
            || (!image.is_empty() && !reply.attestations.is_empty())
        {
            return Err(refused());
        }
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if part.is_empty()
            || part.len() > AUTHORITY_CHECKPOINT_PART_MAX
            || (image.len() + part.len()) as u64 > reply.total
        {
            return Err(refused());
        }
        if image.is_empty() {
            attestations = reply.attestations;
        }
        image.extend_from_slice(&part);
        if image.len() as u64 == reply.total {
            return Ok(Some((image, attestations)));
        }
    }
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
/// named as held, so no page carries them again. Returns how many rows landed
/// and what is still missing.
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
    for _ in 0..MAX_PAGES {
        if request.is_complete() {
            break;
        }
        let mut held = held_authority_entries(vault).map_err(storage)?;
        held.extend(vault.authority_staged_history().map_err(storage)?);
        held.extend(refused.iter().copied());
        let fetch = AuthorityHistoryFetch {
            cursor,
            ..AuthorityHistoryFetch::closing(&request, held)
        };
        let Some((rows, next)) = fetch_authority_range(rpc, &fetch).await? else {
            break;
        };
        if rows.is_empty() {
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
        // finds its cursor among them starts the selection again.
        cursor = next;
    }
    Ok((written, request))
}

/// One page of `fetch` from the home: its signed rows, parents first, and the
/// cursor of the next page. `None` when the home refuses the fetch.
async fn fetch_authority_range(
    rpc: &mut ResidenceRpc,
    fetch: &AuthorityHistoryFetch,
) -> Result<Option<(Vec<Vec<u8>>, Option<AuthorityEntryHash>)>, TransportError> {
    let packed = |hashes: &BTreeSet<AuthorityEntryHash>| {
        base64::engine::general_purpose::STANDARD
            .encode(hashes.iter().flatten().copied().collect::<Vec<u8>>())
    };
    let reply = match rpc
        .request(
            "residence.authority.range",
            json!({
                "vault_id": fetch.vault_id.map(|id| base64::engine::general_purpose::STANDARD.encode(id)),
                "hashes": packed(&fetch.hashes),
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
    if reply.rows.len() > AUTHORITY_HISTORY_PAGE_MAX {
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
