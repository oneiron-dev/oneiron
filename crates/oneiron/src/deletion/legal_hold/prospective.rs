//! A HOST order's or an owner's hold's explicit prospective capture of new
//! on-record messages (LEGAL-HOLD-USE = B as a clone, owner 2026-11-05; FIX
//! 13866, 13867; Ruling L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038
//! :320-321).
//!
//! Default off: only a `CaptureScope::ProspectiveMessages` request stands one.
//! While it stands and before its `ends_at`, every new base MESSAGE row is
//! sealed to the order's public key inside the writer that stores it and kept
//! in the order's outbox; at the end of that batch, in the same writer, so
//! are the outgoing edge rows the batch wrote for it (its turn, conversation,
//! author, parent and reply links). The clone owns that ciphertext from the moment the
//! message lands, so the user's own erase, scrub or compaction of the message
//! is never gated. A host order's connection drains the outbox in batches,
//! each acknowledged on its own; an owner's hold flushes its outbox into its
//! hold store in the same writer. Release or expiry destroys the standing
//! and its outbox, except an owner's term keeps its unflushed entries until
//! they flush. A seal that fails keeps the user's write and records the
//! message as missed, never as captured.

use std::cell::RefCell;
use std::io::{self, Read};

use heed::{RoTxn, RwTxn};
use oneiron_crypto::legal_clone::{
    self, CaptureBinding, ContentBinding, ContentSource, SourceComponent,
};
use oneiron_crypto::{HybridPublicKey, MAX_PLAINTEXT_LEN};
use oneiron_vault_contract::host_legal::{
    CaptureDescriptor, CaptureRequest, CaptureScope, CaptureSource, FrameHeader, FrameKind,
    MessageSelector,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// One order generation: order id and generation.
pub(crate) type OrderKey = ([u8; 16], u64);
type OutboxKey = ([u8; 16], u64, u64);

const STANDINGS: SideTable<OrderKey, Standing, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE);
const OUTBOX: SideTable<OutboxKey, OutboxEntry, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE_OUTBOX);
const RELEASED: SideTable<OrderKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_PROSPECTIVE_RELEASED);

/// How many outbox entries one batch carries at most: a transport chunk, not
/// a limit on what is sealed (CALLS OPUS-LEGALHOLD-13866-batch-entries).
pub(crate) const PROSPECTIVE_BATCH_ENTRIES: usize = 256;

/// A standing prospective order: its exact admitted capture binding, term,
/// public recipient and the next outbox ordinal. Content-free but for the
/// public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Standing {
    covered: CoveredMessages,
    capture: [u8; 16],
    source_vault: [u8; 32],
    request_digest: [u8; 32],
    ends_at: u64,
    recipient: Vec<u8>,
    next_ordinal: u64,
    /// The first outbox ordinal whose message's edge rows are not sealed
    /// yet: the entries of the batch now being written.
    edges_from: u64,
    /// The hold dir path, for an owner's future-messages standing (Ruling
    /// L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038 :320-321); none for a
    /// host order, whose connection drains its outbox.
    #[serde(default)]
    owner_hold_dir: Option<String>,
    /// An owner's standing only: the components sealed into its pending
    /// file so far, which is the member the next one takes. A flushed file's
    /// members run from zero without a gap, as a place capture's do; a
    /// missed entry takes none.
    #[serde(default)]
    file_members: u64,
}

/// The order's own selector, kept with its standing and applied to each new
/// message at its landing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CoveredMessages {
    /// Every new base on-record MESSAGE row of this vault.
    Vault,
}

impl CoveredMessages {
    /// Whether this selector covers the new MESSAGE row `id`.
    fn covers(self, _id: &EntityId) -> bool {
        match self {
            Self::Vault => true,
        }
    }

    /// The request's selector this was stood from.
    #[cfg(unix)]
    fn selector(self) -> MessageSelector {
        match self {
            Self::Vault => MessageSelector::Vault,
        }
    }
}

impl Standing {
    fn binding(&self, (order, generation): OrderKey) -> CaptureBinding {
        CaptureBinding {
            order,
            source_vault: self.source_vault,
            generation,
            capture: self.capture,
            request_digest: self.request_digest,
        }
    }

    /// The member the next sealed component takes: an owner's pending file
    /// counts from zero, so each flushed file opens the way a place capture
    /// does; a host order keeps its global ordinals on the wire.
    fn next_member(&self) -> u64 {
        if self.owner_hold_dir.is_some() {
            self.file_members
        } else {
            self.next_ordinal
        }
    }

    /// Counts `entry` into an owner's pending file when it is sealed; a
    /// missed entry, or any host order's, counts nothing.
    fn count_member(&mut self, entry: &OutboxEntry) -> Result<()> {
        if self.owner_hold_dir.is_some() && !matches!(entry, OutboxEntry::Missed { .. }) {
            self.file_members = self
                .file_members
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("legal prospective file member"))?;
        }
        Ok(())
    }
}

/// One outbox entry: a message row sealed when it landed, one outgoing edge
/// row of it sealed at the end of its birth batch, or the truthful record
/// that a message landed and its rows could not all be sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum OutboxEntry {
    SealedRow {
        message: [u8; 16],
        /// The revision its components carry: the BLAKE3 of the row.
        revision: [u8; 32],
        sealed: SealedComponent,
    },
    SealedEdge {
        message: [u8; 16],
        sealed: SealedComponent,
    },
    Missed {
        message: [u8; 16],
    },
}

/// One component's exact Descriptor and Content frames, ciphertext only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedComponent {
    pub(crate) frames: Vec<u8>,
    /// BLAKE3 of the exact encoded descriptor sealed in `frames`.
    pub(crate) descriptor_digest: [u8; 32],
    pub(crate) plaintext_len: u64,
}

fn order_prefix((order, generation): OrderKey) -> Vec<u8> {
    let mut prefix = order.to_vec();
    prefix.extend_from_slice(&generation.to_be_bytes());
    prefix
}

/// Whether any prospective order stands in `txn`: the one read a new base
/// MESSAGE put pays while none does.
pub(crate) fn prospective_standing_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(STANDINGS.iter_raw_from(store, txn, &[])?.next().is_some())
}

/// Seals the new base MESSAGE row `id`, exactly as this writer just staged
/// it, to every prospective order standing at the writer's recorded time,
/// and keeps it in that order's outbox. A seal that fails keeps the user's
/// write: the entry records the message as missed. Only a storage error
/// fails, as any put's would.
pub(crate) fn seal_prospective_message_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let row = match store.entities().get(wtxn, id.as_bytes())? {
        Some(row) => Zeroizing::new(row.to_vec()),
        None => return Ok(()),
    };
    let now = store.clock.now_recorded_at();
    let message = *id.as_bytes();
    let revision = *blake3::hash(&row).as_bytes();
    let mut sealed_any = false;
    for (key, mut standing) in STANDINGS.scan(store, wtxn)? {
        if now >= standing.ends_at || !standing.covered.covers(id) {
            continue;
        }
        let entry = match seal_component(
            &standing,
            key,
            standing.next_member(),
            SourceComponent::MessageRow,
            &message,
            "entities",
            &message,
            revision,
            &row,
        ) {
            Ok(sealed) => OutboxEntry::SealedRow {
                message,
                revision,
                sealed,
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "a new message could not be sealed to its prospective legal order; recorded as missed"
                );
                OutboxEntry::Missed { message }
            }
        };
        append_in_txn(store, wtxn, key, &mut standing, &entry)?;
        STANDINGS.put(store, wtxn, &key, &standing)?;
        sealed_any = true;
    }
    if sealed_any {
        note_prior_edges_in_txn(store, wtxn, message)?;
        store.host_legal_prospective.bump();
    }
    Ok(())
}

/// Notes the outgoing edge rows the new message `message` already has as it
/// lands: rows an earlier write stored under its id, which its birth batch
/// did not write (FIX 13866). The batch's edge seal leaves them out.
fn note_prior_edges_in_txn(store: &Store, txn: &RoTxn<'_>, message: [u8; 16]) -> Result<()> {
    let prior: Vec<(Vec<u8>, [u8; 32])> = edge_rows_in_txn(store, txn, &message)?
        .into_iter()
        .map(|(key, value)| (key, *blake3::hash(&value).as_bytes()))
        .collect();
    let at = std::ptr::from_ref(store).addr();
    PRIOR_EDGES.with(|notes| {
        let mut notes = notes.borrow_mut();
        notes.retain(|(store, id, _)| !(*store == at && *id == message));
        notes.push((at, message, prior));
    });
    Ok(())
}

/// The prior edge rows noted for `message`; `None` when none were noted on
/// this thread. Every standing order reads the same note; the outermost
/// batch clears its notes as it ends ([`clear_prior_edges`]).
fn prior_edges(store: &Store, message: &[u8; 16]) -> Option<Vec<(Vec<u8>, [u8; 32])>> {
    let at = std::ptr::from_ref(store).addr();
    PRIOR_EDGES.with(|notes| {
        notes
            .borrow()
            .iter()
            .find(|(store, id, _)| *store == at && id == message)
            .map(|(_, _, prior)| prior.clone())
    })
}

/// Clears every prior-edge note of `store` on this thread.
fn clear_prior_edges(store: &Store) {
    let at = std::ptr::from_ref(store).addr();
    PRIOR_EDGES.with(|notes| notes.borrow_mut().retain(|(store, _, _)| *store != at));
}

/// Appends `entry` at `standing`'s next ordinal, and counts it into an
/// owner's pending file when it is sealed. The caller stores the standing.
fn append_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    standing: &mut Standing,
    entry: &OutboxEntry,
) -> Result<()> {
    let ordinal = standing.next_ordinal;
    OUTBOX.put(store, wtxn, &(key.0, key.1, ordinal), entry)?;
    standing.next_ordinal = ordinal
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("legal prospective ordinal"))?;
    standing.count_member(entry)
}

thread_local! {
    /// The base batches open on this thread, innermost last, by their
    /// store's address. A nested apply of the same store, in the same
    /// writer, is part of its outer batch.
    static OPEN_BATCHES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    /// For each new message sealed on this thread, by its store's address:
    /// the outgoing edge rows (key and BLAKE3 of the value) it already had
    /// when it landed (FIX 13866).
    static PRIOR_EDGES: RefCell<Vec<(usize, [u8; 16], Vec<(Vec<u8>, [u8; 32])>)>> =
        const { RefCell::new(Vec::new()) };
}

/// One base batch's op loop, open on this thread until dropped. Only the
/// outermost batch of a store seals its new messages' edge rows, once every
/// op of it applied: a nested apply (a project's revision companions) leaves
/// them pending for its outer batch.
pub(crate) struct ProspectiveBatch<'s> {
    store: &'s Store,
    outermost: bool,
}

impl<'s> ProspectiveBatch<'s> {
    /// Opens the batch of `store` on this thread.
    pub(crate) fn open(store: &'s Store) -> Self {
        let key = std::ptr::from_ref(store).addr();
        let outermost = OPEN_BATCHES.with(|open| {
            let mut open = open.borrow_mut();
            let outermost = !open.contains(&key);
            open.push(key);
            outermost
        });
        Self { store, outermost }
    }

    /// After every op of the batch applied, in its writer: the outermost
    /// batch seals its new messages' edge rows and flushes every owner's
    /// pending outbox into its hold store; a nested one does nothing.
    pub(crate) fn seal_edges_in_txn(&self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        if !self.outermost {
            return Ok(());
        }
        seal_prospective_edges_in_txn(self.store, wtxn)
    }
}

impl Drop for ProspectiveBatch<'_> {
    fn drop(&mut self) {
        let key = std::ptr::from_ref(self.store).addr();
        if self.outermost {
            // A batch that ended before its seal leaves no note behind.
            clear_prior_edges(self.store);
        }
        OPEN_BATCHES.with(|open| {
            let mut open = open.borrow_mut();
            if let Some(at) = open.iter().rposition(|of| *of == key) {
                open.remove(at);
            }
        });
    }
}

/// Seals the outgoing edge rows each message this batch sealed into a
/// standing order's outbox got from this batch, as the batch left them, in
/// the writer that wrote them: called once at the end of every outermost
/// base batch. Each row is its own entry after the message's, under the
/// revision its row carried. A row the message already had when it landed,
/// unchanged since, is not the batch's: it is not sealed, and since the
/// batch may have written the same bytes again, the message is recorded as
/// missed (FIX 13866). So is a message whose prior rows were not noted on
/// this thread, when it has any edge row. A message whose row the same batch
/// replaced or removed after it was sealed has no edges sealed as its own:
/// it is recorded as missed. Edges a later batch adds are later edits, not
/// captured. A seal that fails keeps the user's batch: the message is
/// recorded as missed. Only a storage error fails.
fn seal_prospective_edges_in_txn(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    if !prospective_standing_in_txn(store, wtxn)? {
        return Ok(());
    }
    let mut sealed_any = false;
    for (key, mut standing) in STANDINGS.scan(store, wtxn)? {
        if standing.edges_from == standing.next_ordinal {
            continue;
        }
        let mut born = Vec::new();
        for ordinal in standing.edges_from..standing.next_ordinal {
            if let Some(OutboxEntry::SealedRow {
                message, revision, ..
            }) = OUTBOX.get(store, wtxn, &(key.0, key.1, ordinal))?
            {
                born.push((message, revision));
            }
        }
        for (message, revision) in born {
            let prior = prior_edges(store, &message);
            let current = store.entities().get(wtxn, &message[..])?;
            if current.is_none_or(|row| *blake3::hash(&row).as_bytes() != revision) {
                append_in_txn(
                    store,
                    wtxn,
                    key,
                    &mut standing,
                    &OutboxEntry::Missed { message },
                )?;
                sealed_any = true;
                continue;
            }
            let rows = edge_rows_in_txn(store, wtxn, &message)?;
            let mut unowned = prior.is_none() && !rows.is_empty();
            let mut missed = false;
            for (edge_key, value) in rows {
                let had = prior.as_ref().is_some_and(|prior| {
                    prior.iter().any(|(key, hash)| {
                        *key == edge_key && *hash == *blake3::hash(&value).as_bytes()
                    })
                });
                if had || prior.is_none() {
                    unowned = true;
                    continue;
                }
                let sealed = seal_component(
                    &standing,
                    key,
                    standing.next_member(),
                    SourceComponent::MessageEdge,
                    &message,
                    "edges_out",
                    &edge_key,
                    revision,
                    &value,
                );
                let entry = match sealed {
                    Ok(sealed) => OutboxEntry::SealedEdge { message, sealed },
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "a new message's edge could not be sealed to its prospective legal order; recorded as missed"
                        );
                        OutboxEntry::Missed { message }
                    }
                };
                missed = matches!(entry, OutboxEntry::Missed { .. });
                append_in_txn(store, wtxn, key, &mut standing, &entry)?;
                sealed_any = true;
                if missed {
                    break;
                }
            }
            if unowned && !missed {
                append_in_txn(
                    store,
                    wtxn,
                    key,
                    &mut standing,
                    &OutboxEntry::Missed { message },
                )?;
                sealed_any = true;
            }
        }
        standing.edges_from = standing.next_ordinal;
        STANDINGS.put(store, wtxn, &key, &standing)?;
    }
    // An owner's pending outbox reaches its hold store in the same writer,
    // so the copy outlives a later vault erase.
    #[cfg(unix)]
    flush_owner_standings_in_txn(store, wtxn)?;
    // Every standing order read the batch's notes; none outlives the batch.
    clear_prior_edges(store);
    if sealed_any {
        store.host_legal_prospective.bump();
    }
    Ok(())
}

/// The exact stored outgoing edge rows of `message`, key and value.
fn edge_rows_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    message: &[u8; 16],
) -> Result<Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>> {
    let mut rows = Vec::new();
    let range = (
        std::ops::Bound::Included(&message[..]),
        std::ops::Bound::<&[u8]>::Unbounded,
    );
    for row in store.edges_out().range(txn, &range)? {
        let (key, value) = row?;
        if !key.starts_with(&message[..]) {
            break;
        }
        rows.push((key.to_vec(), Zeroizing::new(value.to_vec())));
    }
    Ok(rows)
}

/// One stored row of `message` sealed under `standing`'s binding at
/// `ordinal`, whole, its fingerprint the BLAKE3 of `value`.
#[allow(clippy::too_many_arguments)]
fn seal_component(
    standing: &Standing,
    key: OrderKey,
    ordinal: u64,
    component: SourceComponent,
    message: &[u8; 16],
    family: &str,
    source_key: &[u8],
    revision: [u8; 32],
    value: &[u8],
) -> Result<SealedComponent> {
    let public = HybridPublicKey::from_bytes(&standing.recipient)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "legal prospective recipient"))?;
    let mut frames = Vec::new();
    let encoded = seal_frames(
        &public,
        &standing.binding(key),
        ordinal,
        component,
        CaptureSource::Message(*message),
        family,
        source_key,
        revision,
        value.len() as u64,
        *blake3::hash(value).as_bytes(),
        &mut &value[..],
        &|| Ok(()),
        &mut |kind, member, part, payload| {
            push_frame(&mut frames, kind, member, part, payload);
            Ok(())
        },
    )?;
    Ok(SealedComponent {
        frames,
        descriptor_digest: *blake3::hash(&encoded).as_bytes(),
        plaintext_len: value.len() as u64,
    })
}

fn push_frame(out: &mut Vec<u8>, kind: FrameKind, member: u64, part: u64, payload: &[u8]) {
    out.extend_from_slice(
        &FrameHeader {
            kind,
            member,
            part,
            len: payload.len() as u64,
        }
        .bytes(),
    );
    out.extend_from_slice(payload);
}

/// Stands the prospective order of `request`, or finds it standing for a
/// reconnect of the same capture. A released generation never stands again.
/// `owner_hold_dir` is the hold dir path for an owner's future-messages
/// standing, none for a host order.
pub(crate) fn stand_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    request: &CaptureRequest,
    request_digest: [u8; 32],
    owner_hold_dir: Option<String>,
) -> Result<()> {
    let key = (request.order, request.generation);
    let CaptureScope::ProspectiveMessages(selector) = &request.scope else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legal capture scope is not prospective",
        )
        .into());
    };
    let covered = match selector {
        MessageSelector::Vault => CoveredMessages::Vault,
    };
    if RELEASED.get_bytes(store, wtxn, &key)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legal prospective order generation released",
        )
        .into());
    }
    match STANDINGS.get(store, wtxn, &key)? {
        Some(standing) => {
            if standing.capture != request.capture
                || standing.request_digest != request_digest
                || standing.covered != covered
                || standing.owner_hold_dir != owner_hold_dir
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "legal prospective standing differs",
                )
                .into());
            }
            Ok(())
        }
        None => STANDINGS.put(
            store,
            wtxn,
            &key,
            &Standing {
                covered,
                capture: request.capture,
                source_vault: request.source_vault,
                request_digest,
                ends_at: request.ends_at,
                recipient: request.recipient.clone(),
                next_ordinal: 0,
                edges_from: 0,
                owner_hold_dir,
                file_members: 0,
            },
        ),
    }
}

/// The standing's next ordinal and the next outbox entries of `key` in
/// ordinal order, at most one batch; `None` once the order generation no
/// longer stands (released or ended).
pub(crate) fn outbox_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    key: OrderKey,
) -> Result<Option<(u64, Vec<(u64, OutboxEntry)>)>> {
    let Some(standing) = STANDINGS.get(store, txn, &key)? else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    for row in OUTBOX.iter_from(store, txn, &order_prefix(key))? {
        let ((order, generation, ordinal), entry) = row?;
        if (order, generation) != key {
            break;
        }
        entries.push((ordinal, entry));
        if entries.len() == PROSPECTIVE_BATCH_ENTRIES {
            break;
        }
    }
    Ok(Some((standing.next_ordinal, entries)))
}

/// Deletes the acknowledged entries `first..first + count` of `key`, only if
/// the same capture still stands. Returns whether it did.
pub(crate) fn acknowledge_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    capture: [u8; 16],
    first: u64,
    count: u64,
) -> Result<bool> {
    match STANDINGS.get(store, wtxn, &key)? {
        Some(standing) if standing.capture == capture => {}
        _ => return Ok(false),
    }
    let end = first
        .checked_add(count)
        .ok_or(Error::ArithmeticOverflow("legal prospective batch"))?;
    for ordinal in first..end {
        OUTBOX.delete(store, wtxn, &(key.0, key.1, ordinal))?;
    }
    Ok(true)
}

/// Ends order generation `key`: deletes its standing and every outbox entry
/// (in-transit clone ciphertext), and on `released` records the generation
/// so it never stands again.
pub(crate) fn end_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    released: bool,
) -> Result<()> {
    if released {
        RELEASED.put(store, wtxn, &key, &Vec::new())?;
    }
    STANDINGS.delete(store, wtxn, &key)?;
    let mut ordinals = Vec::new();
    for row in OUTBOX.iter_from(store, wtxn, &order_prefix(key))? {
        let ((order, generation, ordinal), _) = row?;
        if (order, generation) != key {
            break;
        }
        ordinals.push(ordinal);
    }
    for ordinal in ordinals {
        OUTBOX.delete(store, wtxn, &(key.0, key.1, ordinal))?;
    }
    Ok(())
}

/// Flushes every owner's future-messages standing with a pending outbox
/// into its hold store (Ruling L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038
/// :320-321): one file per pending range, named for its request's capture,
/// then acknowledged and rotated for the next file. A file or collector
/// failure keeps the entries for the next flush; only a storage error
/// fails.
///
/// # Errors
/// A storage error.
#[cfg(unix)]
pub(crate) fn flush_owner_standings_in_txn(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let owners: Vec<(OrderKey, Standing)> = STANDINGS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, standing)| standing.owner_hold_dir.is_some())
        .collect();
    for (key, standing) in owners {
        flush_one_owner_in_txn(store, wtxn, key, standing)?;
    }
    Ok(())
}

/// One owner's pending outbox into its hold store: the file first, then
/// the hold row, the acknowledgement and the next file's binding, all in
/// the caller's writer. A file or collector failure warns and keeps the
/// entries; a storage failure fails, as any write's would.
#[cfg(unix)]
fn flush_one_owner_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: OrderKey,
    mut standing: Standing,
) -> Result<()> {
    let Some(dir) = standing.owner_hold_dir.clone() else {
        return Ok(());
    };
    let mut batch = Vec::new();
    for row in OUTBOX.iter_from(store, wtxn, &order_prefix(key))? {
        let ((order, generation, ordinal), entry) = row?;
        if (order, generation) != key {
            break;
        }
        batch.push((ordinal, entry));
    }
    if batch.is_empty() {
        return Ok(());
    }
    let first = batch[0].0;
    let hold_id = match hold_id_for(key) {
        Ok(hold_id) => hold_id,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "an owner's future-messages outbox could not be flushed; kept for the next flush"
            );
            return Ok(());
        }
    };
    let Some(mut hold) = crate::store::legal_hold::hold_in_txn(store, wtxn, &hold_id)? else {
        // Nowhere to flush, ever: the standing ends with its outbox.
        tracing::warn!("an owner's future-messages hold is gone; its standing ends");
        return end_in_txn(store, wtxn, key, true);
    };
    let flushed = (|| -> Result<([u8; 32], [u8; 16], [u8; 32], EntityId)> {
        let public = HybridPublicKey::from_bytes(&standing.recipient).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "legal prospective recipient")
        })?;
        let capture_id = EntityId::from_bytes(standing.capture)?;
        let file_hex = crate::entity_id::bytes_to_hex_lower(&standing.capture);
        let dir_path = std::path::Path::new(&dir);
        // Files a failed writer left: the standing still names their
        // capture, so no committed row names them, and the one writer
        // excludes any other flush.
        let _ = std::fs::remove_file(dir_path.join(format!("{file_hex}.clone")));
        let _ = std::fs::remove_file(dir_path.join(format!("{file_hex}.clone.partial")));
        let request_for = |capture: [u8; 16]| CaptureRequest {
            order: key.0,
            capture,
            source_vault: standing.source_vault,
            generation: key.1,
            ends_at: standing.ends_at,
            scope: CaptureScope::ProspectiveMessages(standing.covered.selector()),
            recipient: standing.recipient.clone(),
        };
        let request = request_for(standing.capture);
        // Every entry was sealed under the stood request's digest.
        if request.digest()? != standing.request_digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legal prospective request binding",
            )
            .into());
        }
        let new_capture_id = store.clock.entity_id()?;
        let new_digest = request_for(*new_capture_id.as_bytes()).digest()?;
        let fingerprint = super::clone::legal_hold_store::write_owner_prospective_file(
            dir_path, &file_hex, &public, &request, &batch, first,
        )?;
        Ok((
            fingerprint,
            *new_capture_id.as_bytes(),
            new_digest,
            capture_id,
        ))
    })();
    let (fingerprint, new_capture, new_digest, capture_id) = match flushed {
        Ok(flushed) => flushed,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "an owner's future-messages outbox could not be flushed; kept for the next flush"
            );
            return Ok(());
        }
    };
    hold.clone_captures.push(crate::deletion::HoldCloneCapture {
        capture: capture_id,
        fingerprint,
    });
    crate::store::legal_hold::put_hold_in_txn(store, wtxn, &hold)?;
    let acknowledged = acknowledge_in_txn(
        store,
        wtxn,
        key,
        standing.capture,
        first,
        batch.len() as u64,
    )?;
    if !acknowledged {
        return Err(Error::InvariantViolation(
            "legal prospective acknowledgement",
        ));
    }
    standing.capture = new_capture;
    standing.request_digest = new_digest;
    standing.file_members = 0;
    STANDINGS.put(store, wtxn, &key, &standing)?;
    Ok(())
}

/// The hold id of an owner's standing key.
#[cfg(unix)]
fn hold_id_for(key: OrderKey) -> Result<EntityId> {
    EntityId::from_bytes(key.0)
}

/// Ends every prospective order whose term passed at `now`, with its outbox:
/// the maintenance pass's half of expiry, for an order with no live
/// connection. Births after `ends_at` are never sealed either way. An
/// owner's standing with unflushed entries stays until its outbox empties
/// (Ruling L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038 :320-321); a host
/// order ends with its outbox as before.
pub(crate) fn end_lapsed_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, now: u64) -> Result<u64> {
    let candidates: Vec<(OrderKey, Standing)> = STANDINGS
        .scan(store, wtxn)?
        .into_iter()
        .filter(|(_, standing)| now >= standing.ends_at)
        .collect();
    let mut ended = 0_u64;
    for (key, standing) in candidates {
        if standing.owner_hold_dir.is_some() {
            #[cfg(unix)]
            {
                let empty = match outbox_in_txn(store, wtxn, key)? {
                    None => true,
                    Some((_, batch)) => batch.is_empty(),
                };
                if !empty {
                    continue;
                }
            }
        }
        end_in_txn(store, wtxn, key, false)?;
        ended = ended.saturating_add(1);
    }
    if ended != 0 {
        store.host_legal_prospective.bump();
    }
    Ok(ended)
}

/// One component sealed under `binding` at `member`: its exact Descriptor
/// frame then its Content frames, handed to `emit` in stream order. Shared by
/// the streaming collector and the prospective outbox, so both seal one
/// format. Returns the exact encoded descriptor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_frames(
    public: &HybridPublicKey,
    binding: &CaptureBinding,
    member: u64,
    component: SourceComponent,
    source: CaptureSource,
    family: &str,
    key: &[u8],
    revision: [u8; 32],
    plaintext_len: u64,
    fingerprint: [u8; 32],
    input: &mut dyn Read,
    check: &dyn Fn() -> Result<()>,
    emit: &mut dyn FnMut(FrameKind, u64, u64, &[u8]) -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    check()?;
    let source_key_digest = source_key_digest(family, key);
    let chunk_count = plaintext_len.div_ceil(MAX_PLAINTEXT_LEN as u64).max(1);
    let content_source = match &source {
        CaptureSource::GateDecision(decision) => ContentSource::GateDecision(*decision),
        CaptureSource::LiveSession(target) => ContentSource::LiveSession {
            session_ref_digest: legal_clone::live_session_ref_digest(&target.session_ref),
            instance: target.instance,
        },
        CaptureSource::Message(message) => ContentSource::Message(*message),
    };
    let descriptor = CaptureDescriptor {
        component: component as u8,
        source,
        source_key: key.to_vec(),
        source_key_digest,
        revision,
        plaintext_fingerprint: fingerprint,
        plaintext_len,
        chunk_count,
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&descriptor).map_err(io::Error::other)?);
    let sealed =
        legal_clone::seal_descriptor(public, binding, member, &encoded, &mut getrandom::SysRng)
            .map_err(crypto_error)?;
    emit(FrameKind::Descriptor, member, 0, &sealed.to_bytes())?;
    let mut actual = blake3::Hasher::new();
    let mut remaining = plaintext_len;
    for chunk_index in 0..chunk_count {
        check()?;
        let len = remaining.min(MAX_PLAINTEXT_LEN as u64) as usize;
        let mut bytes = Zeroizing::new(vec![0; len]);
        input.read_exact(&mut bytes)?;
        actual.update(&bytes);
        let content = ContentBinding {
            capture: *binding,
            member_ordinal: member,
            component,
            source: content_source,
            source_key_digest,
            revision,
            plaintext_fingerprint: fingerprint,
            chunk_index,
            chunk_count,
        };
        let sealed = legal_clone::seal_content(public, &content, &bytes, &mut getrandom::SysRng)
            .map_err(crypto_error)?;
        emit(FrameKind::Content, member, chunk_index, &sealed.to_bytes())?;
        remaining -= len as u64;
    }
    let mut extra = [0];
    if input.read(&mut extra)? != 0 || actual.finalize().as_bytes() != &fingerprint {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "legal source content changed").into(),
        );
    }
    check()?;
    Ok(encoded)
}

/// The digest of a component's exact source key under its native family.
pub(crate) fn source_key_digest(family: &str, key: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.legal-clone.source-key.v1");
    hash.update(&(family.len() as u64).to_be_bytes());
    hash.update(family.as_bytes());
    hash.update(&(key.len() as u64).to_be_bytes());
    hash.update(key);
    *hash.finalize().as_bytes()
}

pub(crate) fn crypto_error(_error: oneiron_crypto::Error) -> io::Error {
    io::Error::other("legal clone encryption")
}
