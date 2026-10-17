//! Authority history fetch, by exact hash or by checkpoint coverage, and the
//! coverage an asker verifies itself (OF-469).
//!
//! An asker names what it lacks ([`AuthorityHistorySelection`]): the exact
//! rows (its [`AuthorityHistoryRequest`]), or the rows one checkpoint image
//! covers, all of them, those one of its archive manifests lists, or a slice
//! of either by sorted hash, `(lower_exclusive, upper_inclusive]`. Never a
//! sequence or time range: sequences are per signer. A covered selection
//! names only the exact image, never "latest", and an image or manifest the
//! holder does not keep refuses: it is never an empty, complete answer. A
//! holder answers from the signed rows it holds: the selected rows and, with
//! parent closure, each ancestor it holds down to the rows the asker holds,
//! parents first, a page at a time (at most [`AUTHORITY_HISTORY_PAGE_MAX`]
//! rows and [`AUTHORITY_HISTORY_PAGE_BYTES`] signed bytes), every row in its
//! original signed bytes, the page naming the selection it served. What the
//! holder lacks as well it names as unheld, a claim and not evidence: an
//! asker never reads it as erased or as permission. The whole log is kept
//! hot for now, so every row a holder serves is a hot row; an archive
//! manifest is an inventory of rows the custodian holds, not an offload.
//!
//! The asker trusts none of the page. It checks each row's bytes, signatures
//! and vault itself ([`Vault::verify_authority_history_page`]) and reports
//! each hash by the evidence it holds. For a covered selection it resolves
//! the expected rows from its own kept image at that id, so what it still
//! lacks is what remains of them: never the holder's last page, its unheld
//! claim or a custodian's advertisement. A verified scaffold is not replayed
//! semantics: only a row the local fold folded counts as replayed, so a page
//! row counts once it is imported and folded. A row the adopted checkpoint
//! image covers is attested, and on a vault that adopted one no row counts as
//! replayed: its fold rests on the attested image, covered rows and tail
//! alike. `erased` waits for an erasure record, so it stays empty until one
//! exists.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use serde::Deserialize;

use super::history_transfer::{DecodedRow, decode_page, history_in_txn};
use super::*;
use crate::Vault;
use crate::error::{Error, RecordError, Result};

/// The most rows one history page carries.
pub const AUTHORITY_HISTORY_PAGE_MAX: usize = 512;
/// The most signed row bytes one history page carries (one row always goes):
/// as base64 inside the 32 MiB RPC reply, with room left for the unheld
/// claim and the envelope.
pub const AUTHORITY_HISTORY_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// The context of a selection's id ([`AuthorityHistorySelection::id`]).
pub const AUTHORITY_HISTORY_SELECTION_ID_CONTEXT: &str =
    "oneiron/authority/history-selection/id/v1";

/// Which rows of a holder's authority history a fetch selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityHistorySelection {
    /// Exactly these rows.
    Hashes(BTreeSet<AuthorityEntryHash>),
    /// The rows the kept checkpoint image `checkpoint` covers, or only those
    /// its archive manifest `archive` lists, whose hash lies in
    /// `(lower_exclusive, upper_inclusive]` (an absent bound is open). The
    /// image is immutable, so the selection is too, whatever the holder's
    /// head does meanwhile.
    Covered {
        checkpoint: [u8; 32],
        archive: Option<[u8; 32]>,
        lower_exclusive: Option<AuthorityEntryHash>,
        upper_inclusive: Option<AuthorityEntryHash>,
    },
}

impl Default for AuthorityHistorySelection {
    fn default() -> Self {
        Self::Hashes(BTreeSet::new())
    }
}

impl AuthorityHistorySelection {
    /// The id a page names to say which selection it served:
    /// `BLAKE3-derive_key(AUTHORITY_HISTORY_SELECTION_ID_CONTEXT, …)` over
    /// `0 ‖ count (u64 BE) ‖ each hash` for exact hashes, and over `1 ‖
    /// checkpoint` then, for the archive and each bound, `0` when absent or
    /// `1 ‖ value`, for a covered selection.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(AUTHORITY_HISTORY_SELECTION_ID_CONTEXT);
        match self {
            Self::Hashes(hashes) => {
                hasher.update(&[0]);
                hasher.update(
                    &u64::try_from(hashes.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                for hash in hashes {
                    hasher.update(hash);
                }
            }
            Self::Covered {
                checkpoint,
                archive,
                lower_exclusive,
                upper_inclusive,
            } => {
                hasher.update(&[1]);
                hasher.update(checkpoint);
                for part in [archive, lower_exclusive, upper_inclusive] {
                    match part {
                        Some(value) => {
                            hasher.update(&[1]);
                            hasher.update(value);
                        }
                        None => {
                            hasher.update(&[0]);
                        }
                    }
                }
            }
        }
        *hasher.finalize().as_bytes()
    }
}

/// What an asker fetches of a holder's authority history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryFetch {
    /// The vault the asker's history belongs to: a holder of another vault
    /// serves nothing.
    pub vault_id: Option<AuthorityVaultId>,
    /// The rows wanted.
    pub selection: AuthorityHistorySelection,
    /// Also each ancestor of theirs the holder holds, down to `held`.
    pub parent_closure: bool,
    /// Rows the asker holds or has staged: the holder sends none of them and
    /// the closure walks no further. Any subset will do; a smaller one costs
    /// only rows the asker already has. Keep it fixed across a covered
    /// selection's pages, so the cursor walks one order.
    pub held: BTreeSet<AuthorityEntryHash>,
    /// The last row of the page before. One no longer in the selection (the
    /// asker now names it held) starts the selection again; for a covered
    /// selection, a cursor that is no row of its image refuses.
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
            selection: AuthorityHistorySelection::Hashes(request.missing.clone()),
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
    /// The holder's local checkpoint head: a hint, never the selection.
    pub checkpoint: Option<AuthorityEntryHash>,
    /// The id of the selection the page serves
    /// ([`AuthorityHistorySelection::id`]): an asker refuses a page served
    /// for any other.
    pub selection: [u8; 32],
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
    /// The local fold replayed its operation from the whole history and
    /// holds it valid. Empty on a vault that adopted a checkpoint image: its
    /// fold rests on the image.
    pub semantics_replayed: BTreeSet<AuthorityEntryHash>,
    /// Covered by the verified checkpoint image this vault adopted.
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
    /// The same hashes by archive evidence: original bytes held here,
    /// advertised elsewhere, attested, erased, unavailable. A page row is
    /// not held until it is imported.
    pub archive: AuthorityArchiveCoverage,
}

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// A selection resolved on one snapshot.
struct ResolvedSelection {
    /// The rows it names.
    rows: BTreeSet<AuthorityEntryHash>,
    /// For a covered selection, every row its image covers: the image is
    /// ancestor-closed, so each row its closure reaches, and each cursor of
    /// it, is one.
    image: Option<BTreeSet<AuthorityEntryHash>>,
}

/// What a covered selection reads of a kept image's bytes: its covered rows
/// and each manifest's rows.
#[derive(Deserialize)]
struct SelectableOnly {
    covered: Vec<AuthorityEntryHash>,
    archive_manifests: Vec<ManifestRowsOnly>,
}

#[derive(Deserialize)]
struct ManifestRowsOnly {
    archive: [u8; 32],
    rows: Vec<AuthorityEntryHash>,
}

/// The rows `selection` names on the caller's snapshot: exact hashes as
/// given, or the rows of the kept image at `checkpoint` (this vault's own
/// chain or the image it adopted), or of its manifest `archive`, in bounds.
/// The image is read from its bytes, bound by its id; naming a hash to fetch
/// is not trust. An image this vault does not keep, a manifest it does not
/// list, or bounds that leave nothing (`lower_exclusive >= upper_inclusive`)
/// refuse.
fn authority_history_selection_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    selection: &AuthorityHistorySelection,
) -> Result<ResolvedSelection> {
    let (checkpoint, archive, lower, upper) = match selection {
        AuthorityHistorySelection::Hashes(hashes) => {
            return Ok(ResolvedSelection {
                rows: hashes.clone(),
                image: None,
            });
        }
        AuthorityHistorySelection::Covered {
            checkpoint,
            archive,
            lower_exclusive,
            upper_inclusive,
        } => (checkpoint, archive, lower_exclusive, upper_inclusive),
    };
    if let (Some(lower), Some(upper)) = (lower, upper)
        && lower >= upper
    {
        return Err(refused("a covered history range that selects nothing"));
    }
    let bytes = super::checkpoint::checkpoint_image_bytes_in_txn(&vault.store, txn, checkpoint)?
        .ok_or_else(|| refused("no kept checkpoint image has this id"))?;
    if bytes.len() > AUTHORITY_CHECKPOINT_V2_MAX_BYTES
        || super::checkpoint_image::checkpoint_image_id(&bytes) != *checkpoint
    {
        return Err(refused("checkpoint image id"));
    }
    let image: SelectableOnly = bytes
        .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
        .and_then(|body| rmp_serde::from_slice(body).ok())
        .ok_or_else(|| refused("checkpoint image coverage"))?;
    if image.covered.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(refused("checkpoint image coverage"));
    }
    let covered: BTreeSet<AuthorityEntryHash> = image.covered.into_iter().collect();
    let listed: BTreeSet<AuthorityEntryHash> = match archive {
        None => covered.clone(),
        Some(archive) => {
            let manifest = image
                .archive_manifests
                .into_iter()
                .find(|manifest| manifest.archive == *archive)
                .ok_or_else(|| refused("the checkpoint image lists no such archive"))?;
            if !manifest.rows.iter().all(|hash| covered.contains(hash)) {
                return Err(refused("checkpoint image archive manifests"));
            }
            manifest.rows.into_iter().collect()
        }
    };
    let bounds = (
        lower.map_or(Bound::Unbounded, Bound::Excluded),
        upper.map_or(Bound::Unbounded, Bound::Included),
    );
    Ok(ResolvedSelection {
        rows: listed.range(bounds).copied().collect(),
        image: Some(covered),
    })
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
    let selection = authority_history_selection_in_txn(vault, txn, &fetch.selection)?;
    // A covered selection's cursor is a row of its image: any other is the
    // cursor of another selection, refused rather than read as a restart.
    if let (Some(image), Some(cursor)) = (&selection.image, &fetch.cursor)
        && !image.contains(cursor)
    {
        return Err(refused("a cursor outside the selected checkpoint image"));
    }
    let mut selected = BTreeSet::new();
    let mut unheld = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack: Vec<AuthorityEntryHash> = selection.rows.into_iter().collect();
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
    let mut page = Vec::new();
    let mut rows = Vec::new();
    let mut carried = 0_usize;
    for hash in order.iter().skip(start) {
        let (bytes, _) = history
            .get(hash)
            .ok_or(Error::InvariantViolation("authority history page row"))?;
        if page.len() == limit
            || (!page.is_empty()
                && carried.saturating_add(bytes.len()) > AUTHORITY_HISTORY_PAGE_BYTES)
        {
            break;
        }
        carried = carried.saturating_add(bytes.len());
        page.push(*hash);
        rows.push(bytes.clone());
    }
    let next = if start + page.len() < order.len() {
        page.last().copied()
    } else {
        None
    };
    Ok(AuthorityHistoryPage {
        vault_id,
        checkpoint,
        selection: fetch.selection.id(),
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
/// against what this vault holds and staged on the caller's snapshot, with
/// their archive coverage. Every
/// held and staged row decoded, so its bytes are canonical and its
/// signatures verify; so did every page row (`decode_page`). The vault is
/// this vault's own, else the genesis of the checkpoint pin it adopted, else
/// `expected`, else the one the first page row names.
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
    let adopted = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(&vault.store, txn)?;
    let mut bound = rows_vault(rows.iter())
        .or_else(|| adopted.as_ref().map(|adopted| adopted.pin().genesis))
        .or(expected);
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
    if let Some(adopted) = &adopted {
        coverage.checkpoint_attested = scope
            .iter()
            .filter(|hash| adopted.image().rows.contains_key(*hash))
            .copied()
            .collect();
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
                    if adopted.is_none() {
                        coverage.semantics_replayed.insert(*hash);
                    }
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
    coverage.archive =
        super::history_coverage::archive_coverage_in_txn(vault, txn, adopted.as_ref(), &scope)?;
    Ok(coverage)
}

impl Vault {
    /// The rows `fetch` selects that this vault holds, and with parent
    /// closure each ancestor of theirs it holds down to the rows the asker
    /// holds, parents first and at most `fetch.limit` rows and
    /// [`AUTHORITY_HISTORY_PAGE_BYTES`] from its cursor, in their original
    /// signed bytes; what it lacks too is named unheld. A covered selection
    /// reads this vault's kept image at its id; an unknown image or archive
    /// refuses. Hot rows only: the whole log is kept. Serves any caller:
    /// delivery admits the asker first (`residence.authority.range` serves a
    /// machine of the owner's alone), and a fetch naming another vault is
    /// refused.
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
    /// A row that does not decode, a page served for another selection, or
    /// for a covered selection a row its image does not cover, refuses the
    /// page. The requested rows are the selection resolved here: for a
    /// covered one, from this vault's own kept image at that id, so
    /// `unavailable` is what remains of it, never read from the holder's
    /// `next`, its unheld set or any custodian. The holder's own claims (its
    /// vault, checkpoint, unheld set) count for nothing. Import the rows
    /// through [`Self::import_signed_authority_repair_page`], then ask
    /// again: a page row counts as replayed once it is folded here.
    pub fn verify_authority_history_page(
        &self,
        fetch: &AuthorityHistoryFetch,
        page: &AuthorityHistoryPage,
    ) -> Result<AuthorityHistoryVerificationCoverage> {
        if page.selection != fetch.selection.id() {
            return Err(refused("a history page served for another selection"));
        }
        let decoded = decode_page(&page.rows)?;
        let txn = self.store.env.read_txn()?;
        let selection = authority_history_selection_in_txn(self, &txn, &fetch.selection)?;
        if let Some(image) = &selection.image
            && decoded.iter().any(|(hash, _, _)| !image.contains(hash))
        {
            return Err(refused(
                "a history page row outside the selected checkpoint image",
            ));
        }
        verification_in_txn(self, &txn, &selection.rows, fetch.vault_id, decoded)
    }

    /// The fetch that closes `request` from a holder, past `held` (the rows
    /// this vault holds, staged or names as refused): when `request` names
    /// every row of the adopted image's coverage that `held` lacks (the fold
    /// could not answer past the image), that coverage by the image itself
    /// ([`AuthorityHistorySelection::Covered`], no hash list, no closure:
    /// the coverage is ancestor-closed); else the exact hashes
    /// ([`AuthorityHistoryFetch::closing`]). Page a covered fetch with `held`
    /// fixed and the cursor at each page's `next`.
    pub fn authority_history_fetch(
        &self,
        request: &AuthorityHistoryRequest,
        held: BTreeSet<AuthorityEntryHash>,
    ) -> Result<AuthorityHistoryFetch> {
        let txn = self.store.env.read_txn()?;
        let Some(adopted) =
            super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(&self.store, &txn)?
        else {
            return Ok(AuthorityHistoryFetch::closing(request, held));
        };
        let mut lacking = adopted
            .image()
            .covered
            .iter()
            .filter(|hash| !held.contains(*hash))
            .peekable();
        let whole = lacking.peek().is_some() && lacking.all(|hash| request.missing.contains(hash));
        if !whole {
            return Ok(AuthorityHistoryFetch::closing(request, held));
        }
        Ok(AuthorityHistoryFetch {
            vault_id: request.vault_id.or(Some(adopted.image().vault_id)),
            selection: AuthorityHistorySelection::Covered {
                checkpoint: adopted.id(),
                archive: None,
                lower_exclusive: None,
                upper_inclusive: None,
            },
            parent_closure: false,
            held,
            cursor: None,
            limit: AUTHORITY_HISTORY_PAGE_MAX,
        })
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
