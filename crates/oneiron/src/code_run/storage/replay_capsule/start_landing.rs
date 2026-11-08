//! FIX 11415: the length each row a restore's republish of a step start
//! writes lands at, counted before any body is read, so the restore claims
//! it with the image's other rows before anything is opened.
//!
//! The republish (`republish_step_start_in_rows`) puts each piece whose row
//! lacks its bytes back inline with its descriptor and holder row, puts the
//! manifest under the same occurrence, and names both in the capsule. The
//! settle then marks inline the instance row of each body it touched. This
//! count builds the same rows through the same helpers, from the recomposed
//! start's length and how each carried ask stands, never from a body's
//! bytes. A digest it does not know yet takes the width its codec gives
//! it: fixed in a hex handle or a raw key, and in MessagePack the widest
//! any digest takes, each byte 0x80 or above. So each row counts at or
//! above what lands. The final row admission (`landing_rows`) still claims
//! the exact rows.
//!
//! FIX 4192 review fix: a census carries every content piece of a carried
//! start without its bytes, so the republish lands each of them again, not
//! one piece per carried ask. Their rows are known before any body is read
//! ([`StrippedPieces`]), and each counts once, with the first live start
//! whose run and actor hold it. Their bytes count with each start that
//! lands them, within that start's recomposed length.
//!
//! The final row admission alone claims what depends on bytes this count
//! does not read: a secret mark that the scan of a new piece's bytes adds,
//! and the pieces of a start kept as one piece whose recomposed form cuts
//! into many.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::ExecutorStepStart;
use super::super::records::{RAW_OUTPUTS, code_run_body_row_key};
use super::CAPSULES;
use super::pieces::PieceScope;
use super::spawn_erase::republished_start_body;
use super::start_parts::{
    BODY_DIGEST_ROWS, NamingRows, Rows, capsule_scope, naming_rows, place, republished_step_start,
};
use super::start_pieces::{WIDEST_DIGEST, ref_change_growth, widest_node_len};
use crate::compaction::output::OutputRef;
use crate::side_table::SideKey;
use crate::store::BODY_KEYS;
use crate::{EntityId, Error, Result};

/// FIX 11415: the content pieces a census carried without their bytes (FIX
/// 4192 review fix), as an image's raw rows show them before any body is
/// read, each by the run whose holder row names it and the occurrence it
/// holds it under. A piece counts with the first live start whose run and
/// actor hold it at a start piece path: whichever start lands it, its row
/// lands once.
pub(crate) struct StrippedPieces {
    held: BTreeMap<EntityId, Vec<([u8; 32], EntityId)>>,
    scopes: BTreeSet<(EntityId, EntityId)>,
    counted: BTreeSet<[u8; 32]>,
}

impl StrippedPieces {
    /// The pieces `digests` names, each by the holder rows among `rows` that
    /// name it. A holder row that does not decode names none.
    pub(crate) fn of(rows: &Rows, digests: &BTreeSet<[u8; 32]>) -> Self {
        let prefix = BODY_DIGEST_ROWS.decl().prefix;
        let mut held: BTreeMap<EntityId, Vec<([u8; 32], EntityId)>> = BTreeMap::new();
        for digest in digests {
            let mut holders = prefix.to_vec();
            holders.extend_from_slice(digest);
            let (Ok(from) | Err(from)) = place(rows, &holders);
            for (key, value) in rows[from..]
                .iter()
                .take_while(|(key, _)| key.starts_with(&holders))
            {
                let holder = key
                    .strip_prefix(prefix)
                    .and_then(<([u8; 32], EntityId) as SideKey>::decode_key);
                if let (Some((_, occurrence)), Ok(run)) =
                    (holder, BODY_DIGEST_ROWS.decode_value(value))
                {
                    held.entry(run).or_default().push((*digest, occurrence));
                }
            }
        }
        Self {
            held,
            scopes: BTreeSet::new(),
            counted: BTreeSet::new(),
        }
    }

    /// The pieces `scope`'s run holds at its actor's start piece paths that
    /// no start counted yet; none once a start of `scope` took them.
    ///
    /// # Errors
    ///
    /// An occurrence that does not derive.
    fn take(&mut self, scope: PieceScope) -> Result<Vec<[u8; 32]>> {
        let mut taken = Vec::new();
        if !self.scopes.insert((scope.run, scope.actor)) {
            return Ok(taken);
        }
        let Some(held) = self.held.get_mut(&scope.run) else {
            return Ok(taken);
        };
        let mut others = Vec::with_capacity(held.len());
        for (digest, occurrence) in held.drain(..) {
            let path = scope.start_path(&digest);
            if ResultOccurrence::owned(scope.run, &path)?.id() != occurrence {
                others.push((digest, occurrence));
            } else if self.counted.insert(digest) {
                taken.push(digest);
            }
        }
        *held = others;
        Ok(taken)
    }

    /// FIX 4192 review fix: the pieces among `digests` that a run holds at
    /// a start piece path of the run and actor of a capsule among `landed`,
    /// the capsule rows a restore landed again or dropped. A census carried
    /// each without its bytes. A restore rests every one of them, so the
    /// settle prunes a piece no live start lands again, even one whose old
    /// manifest and nodes retired before the restore could walk them. A run
    /// and actor that a capsule among `kept`, one the restore left as it is,
    /// also names keeps its pieces. A capsule row that does not read names
    /// none.
    ///
    /// # Errors
    ///
    /// An occurrence that does not derive.
    pub(crate) fn at_start_paths_in_rows(
        rows: &Rows,
        digests: &BTreeSet<[u8; 32]>,
        landed: &[Vec<u8>],
        kept: &[Vec<u8>],
    ) -> Result<BTreeSet<[u8; 32]>> {
        let scope_of = |row: &Vec<u8>| {
            place(rows, row)
                .ok()
                .and_then(|at| CAPSULES.decode_value(&rows[at].1).ok())
                .as_ref()
                .and_then(capsule_scope)
                .map(|scope| (scope.run, scope.actor))
        };
        let kept: BTreeSet<(EntityId, EntityId)> = kept.iter().filter_map(scope_of).collect();
        let mut pieces = Self::of(rows, digests);
        let mut at = BTreeSet::new();
        for (run, actor) in landed.iter().filter_map(scope_of) {
            if !kept.contains(&(run, actor)) {
                at.extend(pieces.take(PieceScope { run, actor })?);
            }
        }
        Ok(at)
    }
}

/// FIX 11415: the length each row lands at once the republish of the step
/// start the capsule row `row` names runs among an image's raw `vault_meta`
/// rows, counted before any body is read. `len` is the recomposed start's
/// length. `asks` names each carried ask by its call's place among the
/// start's calls, and whether its instance is live, as the restore finds
/// it. `stripped` are the content pieces a census carried without their
/// bytes (FIX 4192 review fix), each counted once. Each row the image holds
/// that the republish or the settle rewrites comes at its new length. The
/// capsule's row comes at its new length, and carries beside it every row
/// the republish inserts and what the piece rows it cannot name grow by.
/// Empty for a capsule that names no start or no actor.
///
/// # Errors
///
/// A capsule row the image does not hold, a row that does not decode or
/// encode, and an occurrence that does not derive.
pub(crate) fn republish_step_start_lengths_in_rows(
    rows: &Rows,
    row: &[u8],
    len: u64,
    asks: &[(u32, bool)],
    stripped: &mut StrippedPieces,
) -> Result<Vec<(Vec<u8>, u64)>> {
    let at = place(rows, row)
        .map_err(|_| Error::CorruptedIndex("a carried step start's capsule row"))?;
    let mut capsule = CAPSULES.decode_value(&rows[at].1)?;
    let Some(scope) = capsule_scope(&capsule) else {
        return Ok(Vec::new());
    };
    let Some(start) = capsule.start.take() else {
        return Ok(Vec::new());
    };
    // The first call whose ask retired: from it on, the start's calls
    // change. With every ask live the start recomposes to its own bytes.
    let retired = asks
        .iter()
        .filter(|(_, live)| !live)
        .map(|(call, _)| *call)
        .min();
    let growth = ref_change_growth()?;
    let manifest = retired.map(|_| start.body.byte_len.saturating_add(growth));
    let mut lengths = Vec::new();
    // FIX 4192 review fix: the settle marks inline the instance row of
    // each content piece the republish rests or lands.
    let taken = stripped.take(scope)?;
    for digest in &taken {
        if let Some(marked) = marked_inline(rows, digest)? {
            lengths.push(marked);
        }
    }
    let pieces = pieces_len(scope, &start, len, asks, retired, taken.len() as u64)?;
    let inserted = manifest_lengths(rows, scope.run, &start, manifest, &mut lengths)?;
    let beside = pieces.saturating_add(inserted);
    let (body, digest) = match manifest {
        Some(byte_len) => (
            OutputRef {
                hash: WIDEST_DIGEST,
                byte_len,
            },
            WIDEST_DIGEST,
        ),
        None => (start.body, start.digest),
    };
    capsule.start = Some(republished_step_start(start, body, digest));
    let capsule_len = CAPSULES.encode_value(&capsule)?.len() as u64;
    lengths.push((row.to_vec(), capsule_len.saturating_add(beside)));
    Ok(lengths)
}

/// The bytes the pieces the republish puts back take, each counted as rows
/// it inserts, as none can be named before a body is read. FIX 4192 review
/// fix: they are the `stripped` content pieces this start counts, each a
/// piece a census carried without its bytes, and, when an ask retired, each
/// retired ask's call element in its erased form and one node for each
/// call from the first retired one (`retired`) to the last, as the calls'
/// chain changes there. The content pieces' bytes come to at most the
/// recomposed start's `len`, and each node to the widest node. Each piece
/// takes an inline body row, a descriptor and a holder row.
fn pieces_len(
    scope: PieceScope,
    start: &ExecutorStepStart,
    len: u64,
    asks: &[(u32, bool)],
    retired: Option<u32>,
    stripped: u64,
) -> Result<u64> {
    let calls = asks
        .iter()
        .map(|(call, _)| u64::from(*call).saturating_add(1))
        .fold(start.bridge_start, u64::max);
    let nodes = retired.map_or(0, |first| calls.saturating_sub(u64::from(first)));
    let erased = asks.iter().filter(|(_, live)| !live).count() as u64;
    let node = widest_node_len()?;
    let widest = len.max(node);
    Ok(len
        .saturating_add(nodes.saturating_mul(node))
        .saturating_add(
            stripped
                .saturating_add(erased)
                .saturating_add(nodes)
                .saturating_mul(piece_rows_len(scope, widest)?),
        ))
}

/// The manifest's rows as the republish and the settle leave them;
/// `manifest` is `None` when every ask is live. Then the start recomposes
/// to its own bytes and the manifest is the one the capsule names: its body
/// row, descriptor and holder row come at the lengths the republish puts
/// them at. When an ask retired, a new manifest of at most `manifest` bytes
/// goes under the same occurrence. Its body row is inserted, its descriptor
/// comes at its new length, and its holder row and marks take the old
/// ones' places at the same width. The old manifest's row lands as it
/// traveled until the settle takes it. Either way the instance row of the
/// manifest the capsule names comes marked inline. Each row the image holds
/// is pushed to `lengths`; returns the bytes of the rows it inserts.
fn manifest_lengths(
    rows: &Rows,
    run: EntityId,
    start: &ExecutorStepStart,
    manifest: Option<u64>,
    lengths: &mut Vec<(Vec<u8>, u64)>,
) -> Result<u64> {
    let stored = republished_start_body(&[]);
    let old = naming_rows(run, &output_at(start.path.clone(), start.body), &stored)?;
    let inserted = match manifest {
        None => {
            let value = inline_row_len(start.body.byte_len)?;
            let key = code_run_body_row_key(&start.body.hash);
            let body = land_row(rows, key, value, lengths);
            let NamingRows { descriptor, holder } = old;
            let descriptor_len = descriptor.1.len() as u64;
            let holder_len = holder.1.len() as u64;
            body.saturating_add(land_row(rows, descriptor.0, descriptor_len, lengths))
                .saturating_add(land_row(rows, holder.0, holder_len, lengths))
        }
        Some(len) => {
            let body_ref = OutputRef {
                hash: WIDEST_DIGEST,
                byte_len: len,
            };
            let new = naming_rows(run, &output_at(start.path.clone(), body_ref), &stored)?;
            let body = (code_run_body_row_key(&body_ref.hash).len() as u64)
                .saturating_add(inline_row_len(len)?);
            let descriptor_len = new.descriptor.1.len() as u64;
            let descriptor = land_row(rows, new.descriptor.0, descriptor_len, lengths);
            let holder = if place(rows, &old.holder.0).is_ok() {
                0
            } else {
                row_len(&new.holder)
            };
            body.saturating_add(descriptor).saturating_add(holder)
        }
    };
    if let Some(marked) = marked_inline(rows, &start.body.hash)? {
        lengths.push(marked);
    }
    Ok(inserted)
}

/// The rows of one start piece of at most `len` bytes that `scope`'s run
/// holds, as the republish inserts them, less its bytes: its body row's key
/// and inline header, its descriptor and its holder row.
fn piece_rows_len(scope: PieceScope, len: u64) -> Result<u64> {
    let piece = OutputRef {
        hash: WIDEST_DIGEST,
        byte_len: len,
    };
    let output = output_at(scope.start_path(&piece.hash), piece);
    let stored = republished_start_body(&[]);
    let NamingRows { descriptor, holder } = naming_rows(scope.run, &output, &stored)?;
    Ok((code_run_body_row_key(&piece.hash).len() as u64)
        .saturating_add(inline_row_len(0)?)
        .saturating_add(row_len(&descriptor))
        .saturating_add(row_len(&holder)))
}

/// The output the republish measures the body `body` as at `path`: the
/// digest, length and path its rows hold.
fn output_at(path: String, body: OutputRef) -> CodeRunRawOutput {
    CodeRunRawOutput {
        path,
        ..CodeRunRawOutput::of_ref(body)
    }
}

/// The bytes the republish's inline body row of `len` bytes takes: its
/// codec's header, then the bytes.
fn inline_row_len(len: u64) -> Result<u64> {
    let header = RAW_OUTPUTS.encode_value(&republished_start_body(&[]))?;
    Ok((header.len() as u64).saturating_add(len))
}

/// The instance row of `digest` as the settle leaves it, marked inline, at
/// its new length; `None` when the image holds none, or holds it marked
/// inline already.
fn marked_inline(rows: &Rows, digest: &[u8; 32]) -> Result<Option<(Vec<u8>, u64)>> {
    let key = BODY_KEYS.key_bytes(digest);
    let Ok(at) = place(rows, &key) else {
        return Ok(None);
    };
    let mut instance = BODY_KEYS.decode_value(&rows[at].1)?;
    if instance.inline {
        return Ok(None);
    }
    instance.inline = true;
    Ok(Some((key, BODY_KEYS.encode_value(&instance)?.len() as u64)))
}

/// Pushes the row `key` to `lengths` at `value` bytes when the image holds
/// it, and returns 0; otherwise returns the bytes it takes inserted.
fn land_row(rows: &Rows, key: Vec<u8>, value: u64, lengths: &mut Vec<(Vec<u8>, u64)>) -> u64 {
    if place(rows, &key).is_ok() {
        lengths.push((key, value));
        return 0;
    }
    (key.len() as u64).saturating_add(value)
}

/// The bytes a row takes: its key and its value.
fn row_len((key, value): &(Vec<u8>, Vec<u8>)) -> u64 {
    (key.len() as u64).saturating_add(value.len() as u64)
}
