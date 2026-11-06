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
//! The final row admission alone claims what depends on bytes this count
//! does not read: a secret mark that the scan of a new piece's bytes adds,
//! and the pieces of a start kept as one piece whose recomposed form cuts
//! into many. A piece that two starts share lands once and counts with each
//! start.

use super::super::super::replay::CodeRunRawOutput;
use super::super::super::replay_capsule::ExecutorStepStart;
use super::super::records::{RAW_OUTPUTS, code_run_body_row_key};
use super::CAPSULES;
use super::pieces::PieceScope;
use super::spawn_erase::republished_start_body;
use super::start_parts::{
    NamingRows, Rows, capsule_scope, naming_rows, place, republished_step_start,
};
use super::start_pieces::{WIDEST_DIGEST, ref_change_growth, widest_node_len};
use crate::compaction::output::OutputRef;
use crate::store::{BODY_KEYS, BodyKeyRow};
use crate::{EntityId, Error, Result};

/// FIX 11415: the length each row lands at once the republish of the step
/// start the capsule row `row` names runs among an image's raw `vault_meta`
/// rows, counted before any body is read. `len` is the recomposed start's
/// length. `asks` names each carried ask by its call's place among the
/// start's calls, and whether its instance is live, as the restore finds
/// it. Each row the image holds that the republish or the settle rewrites
/// comes at its new length. The capsule's row comes at its new length, and
/// carries beside it every row the republish inserts and what the piece
/// rows it cannot name grow by. Empty for a capsule that names no start or
/// no actor.
///
/// # Errors
///
/// A capsule row the image does not hold, and a row that does not decode
/// or encode.
pub(crate) fn republish_step_start_lengths_in_rows(
    rows: &Rows,
    row: &[u8],
    len: u64,
    asks: &[(u32, bool)],
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
    let pieces = pieces_len(scope, &start, len, asks, retired)?;
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
/// it inserts, as none can be named before a body is read. There is one
/// piece per carried ask: its call's element, holding its ask or in its
/// erased form, or the start's one piece when it is kept whole. When an
/// ask retired there is also one node for each call from the first retired
/// one (`retired`) to the last, as the calls' chain changes there. Their
/// bytes come to at most the recomposed start's `len`, and the widest node
/// each. Each piece takes an inline body row, a descriptor and a holder
/// row. The settle marks inline the instance row of each ask's old piece.
fn pieces_len(
    scope: PieceScope,
    start: &ExecutorStepStart,
    len: u64,
    asks: &[(u32, bool)],
    retired: Option<u32>,
) -> Result<u64> {
    if asks.is_empty() {
        return Ok(0);
    }
    let calls = asks
        .iter()
        .map(|(call, _)| u64::from(*call).saturating_add(1))
        .fold(start.bridge_start, u64::max);
    let nodes = retired.map_or(0, |first| calls.saturating_sub(u64::from(first)));
    let node = widest_node_len()?;
    let widest = len.max(node);
    let elements = asks.len() as u64;
    Ok(len
        .saturating_add(nodes.saturating_mul(node))
        .saturating_add(
            elements
                .saturating_add(nodes)
                .saturating_mul(piece_rows_len(scope, widest)?),
        )
        .saturating_add(elements.saturating_mul(inline_mark_len(widest)?)))
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

/// What the instance row of a body of `len` bytes grows by when the settle
/// marks it inline.
fn inline_mark_len(len: u64) -> Result<u64> {
    let file = BODY_KEYS.encode_value(&BodyKeyRow::vault([0; 16], len, false))?;
    let inline = BODY_KEYS.encode_value(&BodyKeyRow::vault([0; 16], len, true))?;
    Ok(inline.len().saturating_sub(file.len()) as u64)
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
