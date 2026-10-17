//! Exact-hash authority history fetch, and the coverage an asker verifies
//! itself (OF-469).
//!
//! An asker names the exact rows it lacks (its [`AuthorityHistoryRequest`]),
//! never a sequence range: sequences are per signer. A holder answers from
//! the signed rows it holds: those hashes and, with parent closure, each
//! ancestor it holds down to the rows the asker holds, parents first, a page
//! at a time, every row in its original signed bytes. What the holder lacks
//! as well it names as unheld, a claim and not evidence: an asker never reads
//! it as erased or as permission. The whole log is kept hot for now, so every
//! row a holder serves is a hot row; no archive stands behind this door yet.
//!
//! The asker trusts none of the page. It checks each row's bytes, signatures
//! and vault itself ([`Vault::verify_authority_history_page`]) and reports
//! each hash by the evidence it holds. A verified scaffold is not replayed
//! semantics: only a row the local fold folded counts as replayed, so a page
//! row counts once it is imported and folded. `checkpoint_attested` waits for
//! hash-signed authority checkpoints (v2) and `erased` for an erasure record,
//! so both stay empty until those exist.

use std::collections::{BTreeMap, BTreeSet};

use super::history_transfer::{DecodedRow, decode_page, history_in_txn};
use super::*;
use crate::Vault;
use crate::error::{Error, Result};

/// The most rows one history page carries.
pub const AUTHORITY_HISTORY_PAGE_MAX: usize = 512;

/// What an asker fetches of a holder's authority history: exact hashes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryFetch {
    /// The vault the asker's history belongs to: a holder of another vault
    /// serves nothing.
    pub vault_id: Option<AuthorityVaultId>,
    /// The rows wanted.
    pub hashes: BTreeSet<AuthorityEntryHash>,
    /// Also each ancestor of theirs the holder holds, down to `held`.
    pub parent_closure: bool,
    /// Rows the asker holds or has staged: the holder sends none of them and
    /// the closure walks no further. Any subset will do; a smaller one costs
    /// only rows the asker already has.
    pub held: BTreeSet<AuthorityEntryHash>,
    /// The last row of the page before. One no longer in the selection (the
    /// asker now names it held) starts the selection again.
    pub cursor: Option<AuthorityEntryHash>,
    /// The most rows wanted, at most [`AUTHORITY_HISTORY_PAGE_MAX`].
    pub limit: usize,
}

impl AuthorityHistoryFetch {
    /// The fetch that closes `request`: its missing rows and their ancestors,
    /// past the rows the asker holds or staged.
    #[must_use]
    pub fn closing(request: &AuthorityHistoryRequest, held: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            vault_id: request.vault_id,
            hashes: request.missing.clone(),
            parent_closure: true,
            held,
            cursor: None,
            limit: AUTHORITY_HISTORY_PAGE_MAX,
        }
    }
}

/// One page a holder serves for an [`AuthorityHistoryFetch`]. The asker
/// trusts none of it ([`Vault::verify_authority_history_page`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryPage {
    /// The holder's vault, as its rows name it.
    pub vault_id: Option<AuthorityVaultId>,
    /// The holder's local checkpoint head.
    pub checkpoint: Option<AuthorityEntryHash>,
    /// Original signed bytes, parents first: each row's parents are held by
    /// the asker, earlier on this page or an earlier one, or unheld.
    pub rows: Vec<Vec<u8>>,
    /// Requested hashes, and ancestors the closure reached, that the holder
    /// does not hold either. A claim only: never erased, never permission.
    pub unheld: BTreeSet<AuthorityEntryHash>,
    /// The cursor for the next page; none on the last.
    pub next: Option<AuthorityEntryHash>,
}

/// The evidence an asker itself holds for each hash: those requested, and
/// every row a page carried. The sets overlap; a hash is in only those its
/// evidence supports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryVerificationCoverage {
    pub requested: BTreeSet<AuthorityEntryHash>,
    /// The local checkpoint head the coverage was judged against.
    pub checkpoint: Option<AuthorityEntryHash>,
    /// Held, staged or on the page in canonical signed bytes whose
    /// signatures verify, naming this vault.
    pub scaffold_verified: BTreeSet<AuthorityEntryHash>,
    /// The local fold replayed its operation and holds it valid.
    pub semantics_replayed: BTreeSet<AuthorityEntryHash>,
    /// Covered by a verified, adopted hash-signed checkpoint image (none
    /// until authority checkpoint v2).
    pub checkpoint_attested: BTreeSet<AuthorityEntryHash>,
    /// Known erased by an erasure record (none until one exists).
    pub erased: BTreeSet<AuthorityEntryHash>,
    /// Requested and not verified: never erased, never permission.
    pub unavailable: BTreeSet<AuthorityEntryHash>,
    /// Verified, but an ancestor is neither held, staged nor on the page, so
    /// no fold judges it yet.
    pub unresolved: BTreeSet<AuthorityEntryHash>,
    /// Stands on a key a handoff the local fold holds retired.
    pub retired: BTreeSet<AuthorityEntryHash>,
    /// Page rows in signed bytes that name another vault: they prove
    /// nothing here.
    pub refused: BTreeSet<AuthorityEntryHash>,
}

/// The vault a row belongs to: a genesis is its own, any other names one.
fn row_vault(hash: &AuthorityEntryHash, entry: &AuthorityLogEntry) -> Option<AuthorityVaultId> {
    if matches!(entry.op, AuthorityOp::Genesis { .. }) {
        Some(*hash)
    } else {
        entry.vault_id
    }
}

/// The vault `rows` belong to: their genesis, else the vault they name.
fn rows_vault<'a>(
    mut rows: impl Iterator<Item = (&'a AuthorityEntryHash, &'a AuthorityLogEntry)> + Clone,
) -> Option<AuthorityVaultId> {
    rows.clone()
        .find_map(|(hash, entry)| matches!(entry.op, AuthorityOp::Genesis { .. }).then_some(*hash))
        .or_else(|| rows.find_map(|(_, entry)| entry.vault_id))
}

/// `selected` so each row follows every selected parent of its, ties by hash.
fn parents_first(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    selected: &BTreeSet<AuthorityEntryHash>,
) -> Result<Vec<AuthorityEntryHash>> {
    let mut waiting: BTreeMap<AuthorityEntryHash, usize> = BTreeMap::new();
    let mut children: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for hash in selected {
        let parents: BTreeSet<AuthorityEntryHash> = history
            .get(hash)
            .map(|(_, entry)| {
                entry
                    .parent_hashes
                    .iter()
                    .filter(|parent| selected.contains(*parent))
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        for parent in &parents {
            children.entry(*parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.insert(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut order = Vec::with_capacity(selected.len());
    while let Some(hash) = ready.pop_first() {
        order.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.insert(*child);
                }
            }
        }
    }
    if order.len() != selected.len() {
        return Err(invalid_authority());
    }
    Ok(order)
}

/// [`Vault::authority_history_page`] on the caller's snapshot.
fn authority_history_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fetch: &AuthorityHistoryFetch,
) -> Result<AuthorityHistoryPage> {
    let history = history_in_txn(vault, txn)?;
    let vault_id = rows_vault(history.iter().map(|(hash, (_, entry))| (hash, entry)));
    if fetch.vault_id.is_some() && vault_id.is_some() && fetch.vault_id != vault_id {
        return Err(invalid_authority());
    }
    let checkpoint = super::checkpoint::checkpoint_head_coverage_in_txn(&vault.store, txn)?
        .map(|(head, _)| head);
    let mut selected = BTreeSet::new();
    let mut unheld = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack: Vec<AuthorityEntryHash> = fetch.hashes.iter().copied().collect();
    while let Some(hash) = stack.pop() {
        if fetch.held.contains(&hash) || !seen.insert(hash) {
            continue;
        }
        match history.get(&hash) {
            Some((_, entry)) => {
                selected.insert(hash);
                if fetch.parent_closure {
                    stack.extend(entry.parent_hashes.iter().copied());
                }
            }
            None => {
                unheld.insert(hash);
            }
        }
    }
    let order = parents_first(&history, &selected)?;
    let start = fetch
        .cursor
        .and_then(|cursor| order.iter().position(|hash| *hash == cursor))
        .map_or(0, |at| at + 1);
    let limit = fetch.limit.clamp(1, AUTHORITY_HISTORY_PAGE_MAX);
    let page: Vec<AuthorityEntryHash> = order.iter().skip(start).take(limit).copied().collect();
    let next = if start + page.len() < order.len() {
        page.last().copied()
    } else {
        None
    };
    let rows = page
        .iter()
        .map(|hash| {
            history
                .get(hash)
                .map(|(bytes, _)| bytes.clone())
                .ok_or(Error::InvariantViolation("authority history page row"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AuthorityHistoryPage {
        vault_id,
        checkpoint,
        rows,
        unheld,
        next,
    })
}

/// Whether `hash` and every ancestor of it are in `rows`, memoized in
/// `closed`. Walked without recursion: a history may be deep.
fn ancestry_closed(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    hash: AuthorityEntryHash,
    closed: &mut BTreeMap<AuthorityEntryHash, bool>,
) -> bool {
    let mut stack = vec![(hash, false)];
    while let Some((at, expanded)) = stack.pop() {
        if closed.contains_key(&at) {
            continue;
        }
        let Some(entry) = rows.get(&at) else {
            closed.insert(at, false);
            continue;
        };
        if expanded {
            let whole = entry
                .parent_hashes
                .iter()
                .all(|parent| closed.get(parent).copied().unwrap_or(false));
            closed.insert(at, whole);
        } else {
            stack.push((at, true));
            stack.extend(
                entry
                    .parent_hashes
                    .iter()
                    .filter(|parent| !closed.contains_key(*parent))
                    .map(|parent| (*parent, false)),
            );
        }
    }
    closed.get(&hash).copied().unwrap_or(false)
}

/// The verification coverage of `requested` and of `page`'s rows, judged
/// against what this vault holds and staged on the caller's snapshot. Every
/// held and staged row decoded, so its bytes are canonical and its
/// signatures verify; so did every page row (`decode_page`). The vault is
/// this vault's own, else `expected`, else the one the first page row names.
fn verification_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    requested: &BTreeSet<AuthorityEntryHash>,
    expected: Option<AuthorityVaultId>,
    page: Vec<DecodedRow>,
) -> Result<AuthorityHistoryVerificationCoverage> {
    let mut rows: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = history_in_txn(vault, txn)?
        .into_iter()
        .map(|(hash, (_, entry))| (hash, entry))
        .collect();
    let mut bound = rows_vault(rows.iter()).or(expected);
    for (hash, _, entry) in super::history_repair::staged_rows_in_txn(&vault.store, txn)? {
        rows.entry(hash).or_insert(entry);
    }
    let mut coverage = AuthorityHistoryVerificationCoverage {
        requested: requested.clone(),
        checkpoint: super::checkpoint::checkpoint_head_coverage_in_txn(&vault.store, txn)?
            .map(|(head, _)| head),
        ..AuthorityHistoryVerificationCoverage::default()
    };
    let mut scope = requested.clone();
    for (hash, _, entry) in page {
        scope.insert(hash);
        let Some(names) = row_vault(&hash, &entry) else {
            coverage.refused.insert(hash);
            continue;
        };
        if *bound.get_or_insert(names) != names {
            coverage.refused.insert(hash);
            continue;
        }
        rows.entry(hash).or_insert(entry);
    }
    for hash in &scope {
        if rows.contains_key(hash) && !coverage.refused.contains(hash) {
            coverage.scaffold_verified.insert(*hash);
        }
    }
    let mut closed = BTreeMap::new();
    for hash in &coverage.scaffold_verified {
        if !ancestry_closed(&rows, *hash, &mut closed) {
            coverage.unresolved.insert(*hash);
        }
    }
    // Replay and retirement are the local fold's evidence: a vault missing
    // history it must hold has no fold, and claims neither.
    match vault.authority_fold_readonly_in_txn(txn) {
        Ok(fold) => {
            for hash in &coverage.scaffold_verified {
                if fold.valid_entries.contains(hash) {
                    coverage.semantics_replayed.insert(*hash);
                    continue;
                }
                let Some(entry) = rows.get(hash) else {
                    continue;
                };
                if fold.stands_on_retired_key(hash, entry, &mut |parent| {
                    Ok(rows.get(parent).cloned())
                })? {
                    coverage.retired.insert(*hash);
                }
            }
        }
        Err(error) if super::readonly_fold::is_history_incomplete(&error) => {}
        Err(error) => return Err(error),
    }
    coverage.unavailable = requested
        .difference(&coverage.scaffold_verified)
        .copied()
        .collect();
    Ok(coverage)
}

impl Vault {
    /// The rows `fetch` names that this vault holds, and with parent closure
    /// each ancestor of theirs it holds down to the rows the asker holds,
    /// parents first and at most `fetch.limit` from its cursor, in their
    /// original signed bytes; what it lacks too is named unheld. Hot rows
    /// only: no archive stands behind it yet. Serves any caller: delivery
    /// admits the asker first (`residence.authority.range` serves a machine
    /// of the owner's alone), and a fetch naming another vault is refused.
    pub fn authority_history_page(
        &self,
        fetch: &AuthorityHistoryFetch,
    ) -> Result<AuthorityHistoryPage> {
        let txn = self.store.env.read_txn()?;
        authority_history_page_in_txn(self, &txn, fetch)
    }

    /// Checks `page`, served for `fetch`, here and imports nothing: each
    /// row's canonical bytes, signatures and vault, its ancestry against the
    /// rows held, staged or beside it, and what the local fold says of it.
    /// A row that does not decode refuses the page. The holder's own claims
    /// (its vault, checkpoint, unheld set) count for nothing. Import the
    /// rows through [`Self::import_signed_authority_repair_page`], then ask
    /// again: a page row counts as replayed once it is folded here.
    pub fn verify_authority_history_page(
        &self,
        fetch: &AuthorityHistoryFetch,
        page: &AuthorityHistoryPage,
    ) -> Result<AuthorityHistoryVerificationCoverage> {
        let decoded = decode_page(&page.rows)?;
        let txn = self.store.env.read_txn()?;
        verification_in_txn(self, &txn, &fetch.hashes, fetch.vault_id, decoded)
    }

    /// [`Self::verify_authority_history_page`] for `requested` against what
    /// this vault holds and staged alone.
    pub fn authority_history_verification(
        &self,
        requested: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<AuthorityHistoryVerificationCoverage> {
        let txn = self.store.env.read_txn()?;
        verification_in_txn(self, &txn, requested, None, Vec::new())
    }
}
