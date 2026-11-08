//! Carriers no door rewrites. Their stored bytes are what an operation
//! wrote, or what a receipt, an op log or a snapshot's hash binds: a code
//! file's frontiers and ingress, a deck's fork log, a typed body's history,
//! a codebase or repo snapshot, an LFS object, a run's output, and the
//! stored history of each document. A carrier with a door of its own goes
//! through it: a retained one is marked (`retained`), an authored one masked
//! (`authored`). A hit in any other files a proposal, and the row keeps its
//! bytes.

use std::borrow::Cow;

use heed::{RoTxn, RwTxn};

use super::super::write_payload_hit;
use super::accounting::Source;
use super::{Done, LiftCause, Page, hex, table_page};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::lfs::LfsOid;
use crate::side_table::{self as t, HexId, SideDb, SideKey, SideTableDecl};

/// The carriers, in walk order. A cursor's first byte is a carrier's place
/// here.
static CARRIERS: &[&SideTableDecl] = &[
    &t::CODE_DOCUMENT_FRONTIER,
    &t::CODE_DOCUMENT_HEAD,
    &t::CODE_DOCUMENT_INGRESS,
    &t::CODE_RUN_RAW_OUTPUT,
    &t::CODEBASE_SNAPSHOT,
    &t::MESSAGE_STREAM_ACTIVE,
    &t::OFFICE_BODY_FORK,
    &t::ORIGIN_LFS_OBJECT,
    &t::OWNER_POLICY_CHANGE_PROPOSAL,
    &t::OWNER_POLICY_CHANGE_RECEIPT,
    &t::REPO_MUTATION_OPLOG,
    &t::REPO_MUTATION_PROPOSAL,
    &t::REPO_MUTATION_SNAPSHOT,
    &t::SKILL_OPTIMIZE_EVAL_CASE,
    &t::TYPED_BODY_DOC,
    &t::TYPED_BODY_FORK_DOC,
    &t::DOCUMENT_SNAPSHOT,
    &t::DOCUMENT_UPDATE,
    &t::NOTE_PROPOSAL_DOC,
];

/// The carrier rows after `after` (a carrier's place, then a whole key;
/// empty at the start), up to `limit`.
pub(super) fn census(vault: &Vault, txn: &RoTxn<'_>, after: &[u8], limit: usize) -> Result<Page> {
    let (from, key_after) = match after.split_first() {
        Some((&at, rest)) => (usize::from(at), rest),
        None => (0, &[][..]),
    };
    let mut page = Page {
        read: 0,
        known_reads: Vec::new(),
        hits: Vec::new(),
        next: None,
    };
    let mut left = limit;
    for (at, decl) in CARRIERS.iter().enumerate().skip(from) {
        let after = if at == from { key_after } else { &[][..] };
        let (rows, ended) = match decl.db {
            SideDb::VaultMeta => table_page(vault, txn, decl.prefix, after, left)?,
            SideDb::SyncState => sync_page(vault, txn, decl, after, left)?,
        };
        let place = u8::try_from(at)
            .map_err(|_| Error::InvariantViolation("the lift sweep's carriers outgrew a byte"))?;
        for (key, value) in &rows {
            page.read += 1;
            let source = source_of_in_txn(vault, txn, decl, key)?;
            if !source.entities().is_empty() {
                page.known_reads.push(source);
            }
            // A repo-mutation row reads by its own door (FIX 2890).
            let found = match super::retained::hit(vault, txn, decl, key, value)? {
                Some(found) => found,
                None => match super::repo_rows::hit(vault, txn, decl, key, value)? {
                    Some(found) => found,
                    None => match write_payload_hit(value) {
                        None => super::loro_blocks::hit(vault, txn, decl, key, value)?,
                        raw => raw,
                    },
                },
            };
            if found.is_some() {
                page.hits.push(cursor(place, key));
            }
        }
        left = left.saturating_sub(rows.len());
        if (!ended || left == 0)
            && let Some((key, _)) = rows.last()
        {
            page.next = Some(cursor(place, key));
            return Ok(page);
        }
    }
    Ok(page)
}

/// Reads carrier row `key` again; a hit it still holds files a proposal.
pub(super) fn lift(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    let Some((decl, row_key)) = carrier_of(key) else {
        return Ok(Done::Clean);
    };
    if let Some(done) = super::retained::lift(vault, txn, decl, row_key)? {
        return Ok(done);
    }
    // A repo-mutation row marks by its own door (FIX 2890).
    if let Some(done) = super::repo_rows::lift(vault, txn, decl, row_key)? {
        return Ok(done);
    }
    let row = match decl.db {
        SideDb::VaultMeta => vault
            .store
            .vault_meta
            .get(txn, row_key)?
            .map(Cow::into_owned),
        SideDb::SyncState => match std::str::from_utf8(row_key) {
            Ok(row_key) => vault
                .store
                .sync_state
                .get(txn, row_key)?
                .map(Cow::into_owned),
            Err(_) => None,
        },
    };
    if let Some(done) = super::authored::lift(vault, txn, decl, row_key, row.as_deref())? {
        return Ok(done);
    }
    Ok(match row.as_deref().and_then(write_payload_hit) {
        Some(reason) => Done::Propose(LiftCause::NoDoor, reason),
        None => Done::Clean,
    })
}

/// `carrier:<table>:<key after its prefix, hex>`.
pub(super) fn path(key: &[u8]) -> String {
    match carrier_of(key) {
        Some((decl, row_key)) => format!(
            "carrier:{}:{}",
            decl.name,
            hex(row_key.get(decl.prefix.len()..).unwrap_or_default())
        ),
        None => format!("carrier::{}", hex(key)),
    }
}

/// Typed-body documents and codebase snapshots are keyed by their actual
/// source entity; a typed-body fork pairs that entity with its fork id.
/// A note proposal pairs its owning NOTE with its fork head; its source is
/// the first. An office-body fork pairs its artifact with its fork id; its
/// source is the first. A repo-mutation proposal's key is its own admitted
/// journal claim. An LFS object's source is its live native manifest ASSET
/// binding in this transaction. A MESSAGE continuation names its live
/// MESSAGE. Eval cases' native receipts, including same-seat, same-family
/// ancestors' receipts, establish known dependencies from frozen read sets.
/// Labels remain untraced.
/// Other formats remain unknown.
pub(super) fn source_in_txn(vault: &Vault, txn: &RoTxn<'_>, key: &[u8]) -> Result<Source> {
    let Some((decl, row_key)) = carrier_of(key) else {
        return Ok(Source::Unmapped);
    };
    source_of_in_txn(vault, txn, decl, row_key)
}

fn source_of_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    decl: &SideTableDecl,
    row_key: &[u8],
) -> Result<Source> {
    if std::ptr::eq(decl, &t::SKILL_OPTIMIZE_EVAL_CASE) {
        let Some(case) = row_key
            .strip_prefix(decl.prefix)
            .and_then(<EntityId as SideKey>::decode_key)
        else {
            return Ok(Source::Unmapped);
        };
        return Ok(Source::of_set(
            vault.eval_case_receipt_sources_in_txn(txn, &case)?,
        ));
    }
    if std::ptr::eq(decl, &t::ORIGIN_LFS_OBJECT) {
        let Some(oid) = row_key
            .strip_prefix(decl.prefix)
            .and_then(LfsOid::decode_key)
        else {
            return Ok(Source::Unmapped);
        };
        return Ok(vault
            .lfs_object_source_in_txn(txn, oid)?
            .map_or(Source::Unmapped, Source::Entity));
    }
    if std::ptr::eq(decl, &t::MESSAGE_STREAM_ACTIVE) {
        let Some(message) = row_key
            .strip_prefix(decl.prefix)
            .and_then(<EntityId as SideKey>::decode_key)
        else {
            return Ok(Source::Unmapped);
        };
        return Ok(vault
            .message_stream_continuation_source_in_txn(txn, &message)?
            .map_or(Source::Unmapped, Source::Entity));
    }
    Ok(source_of(decl, row_key).map_or(Source::Unmapped, Source::Entity))
}

fn source_of(decl: &SideTableDecl, row_key: &[u8]) -> Option<crate::entity_id::EntityId> {
    if std::ptr::eq(decl, &t::TYPED_BODY_FORK_DOC) || std::ptr::eq(decl, &t::OFFICE_BODY_FORK) {
        let (entity, _): (EntityId, EntityId) =
            SideKey::decode_key(row_key.strip_prefix(decl.prefix)?)?;
        return Some(entity);
    }
    if std::ptr::eq(decl, &t::NOTE_PROPOSAL_DOC) {
        return note_proposal_source(row_key.strip_prefix(decl.prefix)?);
    }
    if !std::ptr::eq(decl, &t::TYPED_BODY_DOC)
        && !std::ptr::eq(decl, &t::CODEBASE_SNAPSHOT)
        && !std::ptr::eq(decl, &t::REPO_MUTATION_PROPOSAL)
    {
        return None;
    }
    super::records::record_id(row_key.strip_prefix(decl.prefix)?)
}

/// The owning NOTE a note-proposal row's key leads with: `hex32(note) ":"`
/// `hex32(head)`. Both halves must decode; only the first is the source.
pub(super) fn note_proposal_source(key: &[u8]) -> Option<EntityId> {
    let (note, rest) = key.split_at_checked(32)?;
    let head = rest.strip_prefix(b":")?;
    let note = HexId::decode_key(note)?;
    HexId::decode_key(head)?;
    Some(note.0)
}

fn cursor(place: u8, key: &[u8]) -> Vec<u8> {
    [&[place][..], key].concat()
}

/// The census cursor of `decl`'s row `row` (its key after the table's
/// prefix): `None` for a table that is no carrier.
pub(super) fn cursor_of(decl: &SideTableDecl, row: &[u8]) -> Option<Vec<u8>> {
    let place = CARRIERS.iter().position(|held| std::ptr::eq(*held, decl))?;
    Some(cursor(
        u8::try_from(place).ok()?,
        &[decl.prefix, row].concat(),
    ))
}

fn carrier_of(key: &[u8]) -> Option<(&'static SideTableDecl, &[u8])> {
    let (&place, row_key) = key.split_first()?;
    let decl = CARRIERS.get(usize::from(place))?;
    row_key.starts_with(decl.prefix).then_some((*decl, row_key))
}

/// The first rows of a `sync_state` carrier after `after`, up to `limit`;
/// with whether it ends there.
fn sync_page<'txn>(
    vault: &Vault,
    txn: &'txn RoTxn<'_>,
    decl: &SideTableDecl,
    after: &[u8],
    limit: usize,
) -> Result<(Vec<(Vec<u8>, Cow<'txn, [u8]>)>, bool)> {
    let prefix = std::str::from_utf8(decl.prefix)
        .map_err(|_| Error::InvariantViolation("a sync_state prefix is not text"))?;
    let mut rows = Vec::new();
    for row in vault.store.sync_state.prefix_iter(txn, prefix)? {
        let (key, value) = row?;
        if key.as_bytes() <= after {
            continue;
        }
        rows.push((key.as_bytes().to_vec(), value));
        if rows.len() == limit {
            return Ok((rows, false));
        }
    }
    Ok((rows, true))
}

/// Carrier row `key` (a census cursor) as it is stored, with its table;
/// `None` once it is gone.
pub(super) fn stored(
    vault: &Vault,
    txn: &RoTxn<'_>,
    key: &[u8],
) -> Result<Option<(&'static SideTableDecl, Vec<u8>)>> {
    let Some((decl, row_key)) = carrier_of(key) else {
        return Ok(None);
    };
    let row = match decl.db {
        SideDb::VaultMeta => vault
            .store
            .vault_meta
            .get(txn, row_key)?
            .map(Cow::into_owned),
        SideDb::SyncState => match std::str::from_utf8(row_key) {
            Ok(row_key) => vault
                .store
                .sync_state
                .get(txn, row_key)?
                .map(Cow::into_owned),
            Err(_) => None,
        },
    };
    Ok(row.map(|row| (decl, row)))
}
