//! `vault.snapshot.open` and `vault.snapshot.page`: bounded pages of one
//! caller's rows, each with its source version (primitive A, slice 6.4b;
//! ENGINE CALL S64: a version pin, not a held transaction).
//!
//! A handle holds no storage snapshot. It fixes the caller, the kinds and
//! read filter it pages, the vault's learned frontier when it opened, and
//! its end, with the vault's markers of change at the open: its latest
//! learned time, its change-log head and its document-mutation head. Each page
//! reads current rows under the caller's live read: a page is current as of
//! its own call, not as of the open. A row that may have been born or changed
//! since the open is served marked `changed_since_open`, and a commit that
//! cites a version refuses when the version has moved.

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, served_turn_text_in_txn, source_version_in_txn};
use crate::EntityId;
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::memory::{
    EntityView, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideTable};

/// The open handles. Key: (actor, handle).
const HANDLES: SideTable<(EntityId, EntityId), SnapshotHandleRow, Named> =
    SideTable::new(&side_table::SNAPSHOT_READ_HANDLE);

/// The most kinds one handle pages.
pub const SNAPSHOT_MAX_KINDS: usize = 16;

/// One kind of row a snapshot pages, by the vault's type index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// CLAIM rows.
    Claim,
    /// TURN rows, each served with its projected text.
    Turn,
    /// MESSAGE rows.
    Message,
    /// NOTE rows.
    Note,
    /// The rows of one other entity type code.
    Entity {
        /// The entity type code.
        entity_type: u8,
    },
}

impl SnapshotKind {
    fn entity_type(self) -> u8 {
        match self {
            Self::Claim => ENTITY_TYPE_CLAIM,
            Self::Turn => ENTITY_TYPE_TURN,
            Self::Message => ENTITY_TYPE_MESSAGE,
            Self::Note => ENTITY_TYPE_NOTE,
            Self::Entity { entity_type } => entity_type,
        }
    }
}

/// One `vault.snapshot.open` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotOpenRequest {
    /// The kinds the handle pages, in this order.
    pub kinds: Vec<SnapshotKind>,
    /// A read filter that narrows every page (it never widens the caller's
    /// read).
    #[serde(default)]
    pub filter: Option<crate::memory::ReadFilterInput>,
    /// The handle's lifetime in seconds: the owner's default when absent,
    /// and never above the owner's most lifetime or past the caller's
    /// credential's end.
    #[serde(default)]
    pub lifetime_secs: Option<u64>,
}

/// One open snapshot handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotHandle {
    /// The handle, for `vault.snapshot.page`.
    pub handle: EntityId,
    /// When it opened, on the vault's clock.
    pub opened_at: u64,
    /// When it ends, on the vault's clock.
    pub expires_at: u64,
    /// The kinds it pages, in order.
    pub kinds: Vec<SnapshotKind>,
}

/// One `vault.snapshot.page` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPageRequest {
    /// The handle `vault.snapshot.open` returned to this caller.
    pub handle: EntityId,
    /// The `next` of the page before; absent for the first page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// The most rows this page serves, at most the owner's rows per page.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One page of a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotPage {
    /// The rows that read for the caller at this call, in kind and id order.
    pub rows: Vec<SnapshotRow>,
    /// Rows that read for the caller but are larger than the owner's bytes
    /// per page: none is served, each is named here with its size, and the
    /// cursor moves past it.
    pub oversized: Vec<SnapshotOversizedRow>,
    /// The cursor of the next page; `None` when every kind is paged.
    pub next: Option<String>,
    /// The rows this handle has served over all its pages.
    pub served: u64,
}

/// A row a page does not serve because it is larger than the owner's bytes
/// per page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotOversizedRow {
    /// The row.
    pub entity: EntityId,
    /// Its size as a page row would encode it, in bytes.
    pub bytes: u64,
}

/// One row of a snapshot page.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotRow {
    /// The row's typed view, as `vault.get` serves it.
    pub view: EntityView,
    /// The row's version, for a later commit's recheck.
    pub version: SourceVersion,
    /// The row may have been born or changed after the handle opened: its
    /// learned time is past the open's, the change log names it (or a MESSAGE
    /// row a TURN's words come from) since the open, or it (or such a MESSAGE
    /// row) keeps its text in a document and some document changed since.
    /// `false` only when none of these holds.
    pub changed_since_open: bool,
    /// A TURN's projected text: its own words, or its visible final MESSAGE
    /// rows joined with `"\n"`, each lifted key read as its handle for every
    /// reader but the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// One open handle as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotHandleRow {
    kinds: Vec<SnapshotKind>,
    filter: Option<crate::memory::ReadFilterInput>,
    opened_at: u64,
    expires_at: u64,
    /// The vault's latest learned time at the open: a row learned later was
    /// born or changed since.
    learned_frontier: u64,
    /// The change log's newest entry at the open: an entry after it names a
    /// row written since.
    #[serde(default)]
    changelog_head: Option<[u8; 16]>,
    /// The vault's document-mutation head at the open: a different head
    /// means some document changed since.
    #[serde(default)]
    document_head: Option<[u8; 16]>,
    rows_served: u64,
}

/// The change-log entries one page reads to judge `changed_since_open`. Past
/// it, every row counts as changed.
const CHANGES_SCAN_MAX: usize = 50_000;

/// What changed in the vault since a handle opened, as one page judges it.
struct ChangesSinceOpen {
    learned_frontier: u64,
    /// The rows the change log names since the open; `None` when there were
    /// more entries than [`CHANGES_SCAN_MAX`].
    entities: Option<std::collections::HashSet<EntityId>>,
    documents_moved: bool,
}

impl ChangesSinceOpen {
    fn read_in(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        handle: &SnapshotHandleRow,
    ) -> crate::Result<Self> {
        use crate::ports::ChangeLogStoreRead;
        let mut entities = std::collections::HashSet::new();
        let mut complete = true;
        for (count, entry) in vault
            .port_changelog_after(txn, handle.changelog_head)?
            .enumerate()
        {
            if count >= CHANGES_SCAN_MAX {
                complete = false;
                break;
            }
            entities.insert(entry?.1.entity);
        }
        let documents_moved =
            crate::vault::entity_revision::document_mutation_head_in_txn(&vault.store, txn)?
                != handle.document_head;
        Ok(Self {
            learned_frontier: handle.learned_frontier,
            entities: complete.then_some(entities),
            documents_moved,
        })
    }

    /// Whether row `id` may have been born or changed since the open.
    fn changed(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        version: &SourceVersion,
    ) -> crate::Result<bool> {
        if version.learned_at > self.learned_frontier {
            return Ok(true);
        }
        let Some(entities) = &self.entities else {
            return Ok(true);
        };
        let touched = |id: &EntityId| -> crate::Result<bool> {
            Ok(entities.contains(id)
                || (self.documents_moved
                    && crate::entity_doc::has_record_head(&vault.store, txn, id)?))
        };
        if touched(&version.entity)? {
            return Ok(true);
        }
        if version.entity_type == ENTITY_TYPE_TURN {
            // Every MESSAGE row bound to the TURN, a deleted one too: a
            // removal changes the words as an edit does.
            for message in vault.filtered_edge_peers(
                txn,
                crate::ports::EdgeDirection::In,
                &version.entity,
                crate::edge::EdgeKind::PartOf,
                Some(ENTITY_TYPE_MESSAGE),
            )? {
                if touched(&message)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// The request's shape checks, run before the caller is resolved.
///
/// # Errors
///
/// No kind, more than [`SNAPSHOT_MAX_KINDS`], a kind named twice, or a zero
/// lifetime.
pub fn validate_snapshot_open(input: &SnapshotOpenRequest) -> MemoryResult<()> {
    if input.kinds.is_empty() || input.kinds.len() > SNAPSHOT_MAX_KINDS {
        return Err(MemoryError::bad_request(format!(
            "a snapshot pages 1 to {SNAPSHOT_MAX_KINDS} kinds"
        )));
    }
    let mut types: Vec<u8> = input.kinds.iter().map(|kind| kind.entity_type()).collect();
    types.sort_unstable();
    types.dedup();
    if types.len() != input.kinds.len() {
        return Err(MemoryError::bad_request("a snapshot names each kind once"));
    }
    if input.lifetime_secs == Some(0) {
        return Err(MemoryError::bad_request(
            "a snapshot lifetime is above zero",
        ));
    }
    Ok(())
}

/// Opens one snapshot handle for the caller.
///
/// # Errors
///
/// A request that fails [`validate_snapshot_open`]; a caller with no read
/// lane; a caller that holds the owner's most open handles already; a
/// credential already past its end; and storage errors.
pub fn snapshot_open(
    memory: &Memory<'_>,
    input: &SnapshotOpenRequest,
) -> MemoryResult<SnapshotHandle> {
    validate_snapshot_open(input)?;
    // The caller must hold a read lane at all; each page opens its own.
    memory.read_lane(ClaimReadStatus::Recorded)?;
    let vault = memory.vault();
    let bounds = vault.snapshot_read_settings()?;
    let now = vault.store.authorization_now()?;
    let lifetime = input
        .lifetime_secs
        .unwrap_or(bounds.default_lifetime_secs)
        .min(bounds.max_lifetime_secs);
    let mut expires_at = now.saturating_add(lifetime);
    // Fixed, not a setting: a handle never outlives the credential it reads by.
    if let Some(credential_end) = memory.read_proof_expires_at() {
        expires_at = expires_at.min(credential_end);
    }
    if expires_at <= now {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the caller's credential has ended",
            &[],
        ));
    }
    let actor = memory.actor();
    let handle = EntityId::now();
    let (changelog_head, document_head) = {
        use crate::ports::ChangeLogStoreRead;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        (
            vault.port_changelog_head(&txn)?.map(|(id, _)| id),
            crate::vault::entity_revision::document_mutation_head_in_txn(&vault.store, &txn)?,
        )
    };
    let row = SnapshotHandleRow {
        kinds: input.kinds.clone(),
        filter: input.filter.clone(),
        opened_at: now,
        expires_at,
        learned_frontier: vault.latest_learned_at()?.unwrap_or(0),
        changelog_head,
        document_head,
        rows_served: 0,
    };
    let opened = vault.with_write_txn_grouped(|txn| {
        let mut open = 0u32;
        let mut ended = Vec::new();
        for entry in HANDLES.iter_from(&vault.store, &*txn, actor.as_bytes())? {
            let ((_, id), held) = entry?;
            if held.expires_at <= now {
                ended.push(id);
            } else {
                open = open.saturating_add(1);
            }
        }
        for id in ended {
            HANDLES.delete(&vault.store, txn, &(actor, id))?;
        }
        if open >= bounds.open_per_actor {
            return Ok(false);
        }
        HANDLES.put(&vault.store, txn, &(actor, handle), &row)?;
        Ok(true)
    })?;
    if !opened {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "the caller holds {} open snapshots, the owner's most",
                bounds.open_per_actor
            ),
            &["Let a snapshot end, or page within an open one."],
        ));
    }
    Ok(SnapshotHandle {
        handle,
        opened_at: now,
        expires_at,
        kinds: input.kinds.clone(),
    })
}

/// Serves the next page of one of the caller's open handles.
///
/// Each row is listed by its kind's type index after the cursor, admitted by
/// the caller's live read with the handle's filter (the predicates
/// `vault.get` applies), and served with its version. A row the caller does
/// not read, and a TURN with a MESSAGE row it may not read, is passed over
/// unsaid. A page stops at the owner's rows and bytes per page; a row larger
/// than the bytes per page is named in `oversized`, never served. A handle
/// stops at its rows per handle, counted in the same write that accepts the
/// page.
///
/// # Errors
///
/// A handle this caller did not open, that has ended, or that ended while the
/// page was read; a handle that served its rows, or whose rows a page read at
/// the same time used; a malformed cursor; the caller's read lane; and storage
/// errors.
pub fn snapshot_page(
    memory: &Memory<'_>,
    input: &SnapshotPageRequest,
) -> MemoryResult<ScopedReadResult<SnapshotPage>> {
    let vault = memory.vault();
    let bounds = vault.snapshot_read_settings()?;
    let key = (memory.actor(), input.handle);
    let now = vault.store.authorization_now()?;
    let handle = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        HANDLES.get(&vault.store, &txn, &key)?
    }
    .ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no open snapshot with this handle for this caller",
            &["Open one with vault.snapshot.open."],
        )
    })?;
    if handle.expires_at <= now {
        vault.with_write_txn_grouped(|txn| HANDLES.delete(&vault.store, txn, &key).map(|_| ()))?;
        return Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "the snapshot has ended",
            &["Open a new one with vault.snapshot.open."],
        ));
    }
    let left = bounds.handle_rows.saturating_sub(handle.rows_served);
    if left == 0 {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the snapshot has served the owner's rows per snapshot",
            &["Open a new one with vault.snapshot.open."],
        ));
    }
    let asked = input
        .limit
        .map_or(bounds.page_rows, |limit| limit.min(bounds.page_rows))
        .max(1);
    let limit = usize::try_from(u64::from(asked).min(left)).unwrap_or(usize::MAX);
    let (mut kind_at, mut after) = parse_cursor(input.cursor.as_deref(), handle.kinds.len())?;
    let reader = memory.with_read_filter(handle.filter.as_ref());
    let lane = reader.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = lane.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let changes = ChangesSinceOpen::read_in(vault, &txn, &handle)?;
    let mut rows = Vec::new();
    let mut oversized = Vec::new();
    let mut bytes = 0u64;
    let mut receipt: Option<crate::claim::ScopedReadReceipt> = None;
    let mut next = None;
    'kinds: while kind_at < handle.kinds.len() {
        let want = limit.saturating_sub(rows.len() + oversized.len()).max(1);
        let entity_type = handle.kinds[kind_at].entity_type();
        let ids = vault.entities_by_type_page_in_txn(&txn, entity_type, after.as_ref(), want)?;
        let exhausted = ids.len() < want;
        let views = reader.read_views_in_txn(&lane, &txn, &ids)?;
        receipt = Some(match receipt.take() {
            None => views.receipt,
            Some(mut kept) => {
                kept.restrict_with(&views.receipt);
                kept
            }
        });
        for (id, view) in ids.iter().zip(views.value) {
            let served = match view {
                Some(view) => match source_version_in_txn(&lane, &txn, id)? {
                    Some((version, text)) => {
                        let text = match &text {
                            Some(turn) => {
                                served_turn_text_in_txn(&reader, &lane, &txn, id, turn)?.0
                            }
                            None => None,
                        };
                        Some(SnapshotRow {
                            changed_since_open: changes.changed(vault, &txn, &version)?,
                            text,
                            view,
                            version,
                        })
                    }
                    None => None,
                },
                None => None,
            };
            if let Some(row) = served {
                let size = serde_json::to_vec(&row).map_or(u64::MAX, |encoded| {
                    u64::try_from(encoded.len()).unwrap_or(u64::MAX)
                });
                if size > bounds.page_bytes {
                    // No page can hold it: named, not served, and passed.
                    oversized.push(SnapshotOversizedRow {
                        entity: *id,
                        bytes: size,
                    });
                } else if bytes.saturating_add(size) > bounds.page_bytes {
                    next = Some(cursor(kind_at, after));
                    break 'kinds;
                } else {
                    bytes = bytes.saturating_add(size);
                    rows.push(row);
                }
            }
            after = Some(*id);
            if rows.len() + oversized.len() >= limit {
                next = Some(cursor(kind_at, after));
                break 'kinds;
            }
        }
        if exhausted {
            kind_at += 1;
            after = None;
        }
    }
    let receipt = match receipt {
        Some(receipt) => receipt,
        None => reader.read_views_in_txn(&lane, &txn, &[])?.receipt,
    };
    drop(txn);
    let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    // The rows are counted against the handle in one write, judged again
    // there: a page read at the same time may have used them (review of
    // #6964), and the handle may have ended or been erased meanwhile.
    let accounted = vault.with_write_txn_grouped(|txn| {
        let Some(mut held) = HANDLES.get(&vault.store, &*txn, &key)? else {
            return Ok(Accounted::Gone);
        };
        if held.rows_served.saturating_add(count) > bounds.handle_rows {
            return Ok(Accounted::Spent);
        }
        held.rows_served = held.rows_served.saturating_add(count);
        HANDLES.put(&vault.store, txn, &key, &held)?;
        Ok(Accounted::Served(held.rows_served))
    })?;
    let served = match accounted {
        Accounted::Served(served) => served,
        Accounted::Gone => {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "the snapshot ended while this page was read",
                &["Open a new one with vault.snapshot.open."],
            ));
        }
        Accounted::Spent => {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a page read at the same time used the snapshot's rows per snapshot",
                &["Open a new one with vault.snapshot.open."],
            ));
        }
    };
    Ok(ScopedReadResult {
        value: SnapshotPage {
            rows,
            oversized,
            next,
            served,
        },
        receipt,
    })
}

/// How a page's rows were counted against its handle.
enum Accounted {
    /// Counted: the rows the handle has served now.
    Served(u64),
    /// The handle ended or was erased while the page was read.
    Gone,
    /// A page read at the same time used the rows this one needs.
    Spent,
}

/// Deletes every snapshot handle `actor` holds: the scrub an actor's erase
/// runs over [`side_table::SNAPSHOT_READ_HANDLE`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_snapshot_handles_of_actor_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    let mut held = Vec::new();
    for entry in HANDLES.iter_from(&vault.store, &*txn, actor.as_bytes())? {
        held.push(entry?.0);
    }
    for key in held {
        HANDLES.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

fn cursor(kind_at: usize, after: Option<EntityId>) -> String {
    match after {
        Some(id) => format!("{kind_at}:{}", id.to_hex()),
        None => format!("{kind_at}:"),
    }
}

fn parse_cursor(cursor: Option<&str>, kinds: usize) -> MemoryResult<(usize, Option<EntityId>)> {
    let Some(cursor) = cursor else {
        return Ok((0, None));
    };
    let bad = || MemoryError::bad_request("the cursor is not this snapshot's");
    let (kind_at, after) = cursor.split_once(':').ok_or_else(bad)?;
    let kind_at: usize = kind_at.parse().map_err(|_| bad())?;
    if kind_at > kinds {
        return Err(bad());
    }
    let after = match after {
        "" => None,
        hex => Some(EntityId::from_hex(hex).map_err(|_| bad())?),
    };
    Ok((kind_at, after))
}
