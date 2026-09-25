//! Peer authority-log admission (FED-03) and roster refolding.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityVaultId,
    authority_entry_hash, decode_authority_log_entry_body, fold_peer_authority_log,
    folded_peer_device_is_consent_root, genesis_vault_id,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Peer authority-log admission (FED-03).
//
// The transport relays canonical AUTHORITY_LOG entry BYTES and nothing else.
// There is no API here that takes a roster, an owner list, or a boolean owner
// assertion: a peer roster is always RECOMPUTED locally by the pure authority
// fold over the bytes we hold. That is the whole trust boundary — a cached
// roster row would be a server-influenceable projection carrying authority
// semantics, so none is kept.
// ---------------------------------------------------------------------------

/// LMDB `sync_state` key prefix for admitted peer authority-log entry bytes.
pub const PEER_AUTHORITY_KEY_PREFIX: &str = "peerauth:";

/// Ceiling on DISTINCT admitted entry hashes per peer vault.
///
/// Distinct HASHES, not admission calls: re-offering a stored entry is
/// idempotent at any size, including at the ceiling.
pub const MAX_PEER_AUTHORITY_ENTRIES_PER_PEER: usize = 4096;

/// Admitted peer AUTHORITY_LOG entry bytes. Key: `{peer_vault_id_hex}:{entry_hash_hex}`
/// (after the `peerauth:` table prefix).
const PEER_AUTHORITY: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::PEER_AUTHORITY_ENTRY);

/// `peerauth:{peer_vault_id_hex}:{entry_hash_hex}`.
#[must_use]
pub fn peer_authority_entry_key(peer_vault_id: &[u8; 32], entry_hash: &[u8; 32]) -> String {
    let mut key = String::from(PEER_AUTHORITY_KEY_PREFIX);
    key.push_str(&peer_authority_row_key(peer_vault_id, entry_hash));
    key
}

/// `{peer_vault_id_hex}:{entry_hash_hex}` — [`PEER_AUTHORITY`]'s key for one entry, the bytes
/// after the shared `peerauth:` table prefix.
fn peer_authority_row_key(peer_vault_id: &AuthorityVaultId, entry_hash: &[u8; 32]) -> String {
    let mut key = peer_authority_row_prefix(peer_vault_id);
    key.push_str(&bytes_to_hex_lower(entry_hash));
    key
}

/// `{peer_vault_id_hex}:` — [`PEER_AUTHORITY`]'s scan prefix for ONE peer.
fn peer_authority_row_prefix(peer_vault_id: &AuthorityVaultId) -> String {
    let mut prefix = String::with_capacity(66);
    prefix.push_str(&bytes_to_hex_lower(peer_vault_id));
    prefix.push(':');
    prefix
}

/// Admits one canonical peer AUTHORITY_LOG entry body under `peer_vault_id`.
///
/// The order is fixed and every step fails closed: validate the canonical body
/// bytes and decode (one act — the decoder re-encodes, compares, and verifies
/// the embedded origin signature before yielding an entry), derive the entry's
/// OWN vault id and require it to equal the claimed peer, hash the canonical
/// bytes, check the per-peer ceiling, store idempotently.
///
/// Admitted bytes live in `sync_state` only. They never enter AUTHORITY_LOG entity
/// storage and never touch the local roster.
pub fn admit_peer_authority_log_entry(
    vault: &Vault,
    peer_vault_id: &AuthorityVaultId,
    bytes: &[u8],
) -> Result<()> {
    let entry = decode_authority_log_entry_body(bytes)?;
    let entry_vault_id = match entry.op {
        // Genesis carries no `vault_id` field — its id IS its content hash.
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        // `validate_shape` (which the decode above ran) already refuses a
        // non-genesis entry without a vault id, so this arm's `None` is
        // structurally unreachable; it resolves to the same refusal rather than
        // to a panic.
        _ => entry.vault_id.ok_or_else(peer_authority_vault_mismatch)?,
    };
    if entry_vault_id != *peer_vault_id {
        return Err(peer_authority_vault_mismatch());
    }
    let key = peer_authority_row_key(peer_vault_id, &authority_entry_hash(&entry)?);
    let prefix = peer_authority_row_prefix(peer_vault_id);
    vault.with_write_txn(|wtxn| {
        if PEER_AUTHORITY.contains(&vault.store, wtxn, &key)? {
            return Ok(());
        }
        let distinct = PEER_AUTHORITY
            .scan_keys(&vault.store, wtxn, prefix.as_bytes())?
            .len();
        if distinct >= MAX_PEER_AUTHORITY_ENTRIES_PER_PEER {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                "peer authority log flood",
            )));
        }
        PEER_AUTHORITY.put(&vault.store, wtxn, &key, &bytes.to_vec())?;
        Ok(())
    })
}

/// Recomputes `peer_vault_id`'s roster from the entries admitted for it.
///
/// The fold must root at the peer we filed the rows under; anything else is a
/// log we cannot attribute, and it is refused rather than reported as a roster.
pub fn peer_authority_roster(
    vault: &Vault,
    peer_vault_id: &AuthorityVaultId,
) -> Result<AuthorityFold> {
    let rtxn = vault.store.env.read_txn()?;
    let fold =
        fold_peer_authority_log(&peer_authority_entries_in_txn(vault, &rtxn, peer_vault_id)?);
    if fold.vault_id != Some(*peer_vault_id) {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "peer authority fold root mismatch",
        )));
    }
    Ok(fold)
}

/// Consent roots of an ADMITTED PEER roster — host key included (host-root).
///
/// Callers: the FED-01 gesture check only. Never feed this back into the local
/// fold; these keys hold no local authority of any kind.
#[must_use]
pub fn peer_consent_roots(fold: &AuthorityFold) -> BTreeSet<AuthorityKey> {
    fold.roster
        .iter()
        .filter(|(_, device)| folded_peer_device_is_consent_root(device))
        .map(|(key, _)| key.clone())
        .collect()
}

/// Every admitted peer's consent-root set, for one local authority fold.
///
/// Discovers the distinct `peerauth:` peers in `sync_state` and refolds each
/// one. A peer whose rows do not fold back to the vault id they were filed
/// under contributes NOTHING — that is the pinned-key-only FED-01 baseline, not
/// a refusal. Which bytes arrive is the relay's choice, and a withheld genesis
/// must never be able to fail the LOCAL fold.
pub(crate) fn admitted_peer_consent_roots_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>> {
    admitted_peer_consent_roots_for_store_in_txn(&vault.store, txn)
}
pub(crate) fn admitted_peer_consent_roots_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>> {
    let mut by_peer: BTreeMap<String, Vec<AuthorityLogEntry>> = BTreeMap::new();
    for (key, raw) in PEER_AUTHORITY.scan(store, txn)? {
        by_peer
            .entry(peer_authority_row_key_group(&key)?)
            .or_default()
            .push(decode_peer_authority_row(&raw)?);
    }
    let mut roots = BTreeMap::new();
    for (prefix, entries) in by_peer {
        let fold = fold_peer_authority_log(&entries);
        if let Some(vault_id) = fold.vault_id
            && peer_authority_row_prefix(&vault_id) == prefix
        {
            roots.insert(vault_id, peer_consent_roots(&fold));
        }
    }
    Ok(roots)
}

fn peer_authority_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer_vault_id: &AuthorityVaultId,
) -> Result<Vec<AuthorityLogEntry>> {
    PEER_AUTHORITY
        .scan_from(
            &vault.store,
            txn,
            peer_authority_row_prefix(peer_vault_id).as_bytes(),
        )?
        .into_iter()
        .map(|(_, raw)| decode_peer_authority_row(&raw))
        .collect()
}

/// Decodes one STORED peer row.
///
/// These bytes already passed admission, so a decode failure here is local
/// storage corruption, not a bad peer body — and it propagates. Skipping the
/// row would silently hand back a roster folded over a subset of what we hold,
/// which is exactly the shape an attacker with write access would want.
fn decode_peer_authority_row(raw: &[u8]) -> Result<AuthorityLogEntry> {
    decode_authority_log_entry_body(raw)
        .map_err(|_| Error::CorruptedIndex("peer authority log row"))
}

/// `{peer}:` — the grouping prefix of one stored row's key (after the table prefix).
///
/// Derived by position rather than by parsing hex: the id itself comes back
/// from the fold, and re-deriving the prefix from THAT is what proves the rows
/// were filed under the vault they actually root at.
fn peer_authority_row_key_group(key: &str) -> Result<String> {
    let end = key
        .find(':')
        .map(|index| index + 1)
        .ok_or(Error::CorruptedIndex("peer authority log row key"))?;
    Ok(key[..end].to_owned())
}

fn peer_authority_vault_mismatch() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        "peer authority log vault id",
    ))
}
