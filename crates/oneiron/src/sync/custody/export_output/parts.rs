//! An export secret supplement's sealed copy past one row on the window plane
//! (FIX 12063; L03 04:0x). The kept copy is cut as any window carrier is
//! (`carrier_parts::split_parts`), and each run rides as a row of its own,
//! keyed `export_output:`, the request's entry hash, a dot and the run's
//! index in eight hex digits. Each row's head names the request, the second
//! the copy was sealed at, the run's index and the part count, so a window
//! files and admits each row alone, by the rules a copy in one row meets.
//!
//! - Bounded: a part count is at least two and at most
//!   [`MAX_EXPORT_OUTPUT_PARTS`], an index is below it, and a run is at most
//!   one carrier part, every run but the last a full one, so a part row is
//!   within one row's bound and a receiver holds at most
//!   [`MAX_EXPORT_OUTPUT_PART_BYTES`] of runs for one request. It reads at
//!   most the count's rows and stops at the first one missing.
//! - Agreed: every part must name the request, the sealing second and the
//!   count the first part names, at its own place. Any disagreement drops
//!   the whole set, logged by its key alone.
//! - Joined once: the runs are joined by `carrier_parts::join_parts`, which
//!   checks the cut and the host's memory before it copies a byte, and the
//!   joined copy is kept only once it stands, as a copy in one row is.
//! - No orphans: part rows leave the window when their request's rows do,
//!   or when the copy they join is due to leave; a set that never completes
//!   leaves with its request or its base window.

use std::collections::{BTreeMap, BTreeSet};

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::super::{CUSTODY_MAP, commit_custody, holds_custody_map, refused};
use super::EXPORT_OUTPUT_ROW_PREFIX;
use crate::authority::AuthorityFold;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::secret_custody::holder_export::KeptExportOutput;
use crate::sync::carrier_parts::{PART_BYTES, Parts, join_parts, part_key, split_parts};
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;

/// The label every part of a relayed copy starts with.
const PART_LABEL: &[u8] = b"oneiron/export-secret-output-part/v1\0";

/// The most bytes of a copy that ride in parts, and so the most a receiver
/// holds of one request's runs: 64 MiB. No seal bounds a copy's size (FIX
/// 5445), so this is the relay's own bound; a longer copy stays with the
/// installs that keep it and is read from them.
const MAX_EXPORT_OUTPUT_PART_BYTES: usize = 64 << 20;

/// The most parts one copy rides in: [`MAX_EXPORT_OUTPUT_PART_BYTES`] of
/// carrier parts.
const MAX_EXPORT_OUTPUT_PARTS: u32 = (MAX_EXPORT_OUTPUT_PART_BYTES / PART_BYTES) as u32;

/// The root of the scratch document a copy's runs are joined in.
const SCRATCH_MAP: &str = "export_output_parts";

/// One part of a relayed copy: run `index` of `count`, beside the request
/// and the second the copy was sealed at.
struct OutputPart {
    sealed_at: u64,
    request: [u8; 32],
    index: u32,
    count: u32,
    run: Vec<u8>,
}

impl OutputPart {
    /// Decodes a part strictly; `None` without its label, for a short head,
    /// a zero request, a count outside two to [`MAX_EXPORT_OUTPUT_PARTS`],
    /// an index not below it, or a run that is empty, past one carrier part,
    /// or short of one before the last part.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(PART_LABEL)?;
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (index, rest) = rest.split_first_chunk::<4>()?;
        let (count, run) = rest.split_first_chunk::<4>()?;
        let index = u32::from_be_bytes(*index);
        let count = u32::from_be_bytes(*count);
        let last = index.checked_add(1)? == count;
        if *request == [0; 32]
            || !(2..=MAX_EXPORT_OUTPUT_PARTS).contains(&count)
            || index >= count
            || run.is_empty()
            || run.len() > PART_BYTES
            || (!last && run.len() != PART_BYTES)
        {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            index,
            count,
            run: run.to_vec(),
        })
    }
}

/// The label, the sealing second, the request, the index and the part
/// count, then the run.
fn encode_part(output: &KeptExportOutput, index: u32, count: u32, run: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PART_LABEL.len() + 8 + 32 + 4 + 4 + run.len());
    out.extend_from_slice(PART_LABEL);
    out.extend_from_slice(&output.sealed_at.to_be_bytes());
    out.extend_from_slice(&output.request);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(run);
    out
}

/// A part's map key after the prefix.
fn part_suffix(request: &[u8; 32], index: u32) -> String {
    format!("{}.{index:08x}", bytes_to_hex_lower(request))
}

fn part_row(request: &[u8; 32], index: u32) -> String {
    format!("{EXPORT_OUTPUT_ROW_PREFIX}{}", part_suffix(request, index))
}

/// Whether `value` is a part filed under `row_key`, the map key after its
/// prefix.
pub(super) fn filed(row_key: &str, value: &[u8]) -> bool {
    OutputPart::decode(value).is_some_and(|part| part_suffix(&part.request, part.index) == row_key)
}

/// Admits one part under `row_key`, the map key after its prefix: one that
/// decodes, filed under its own request and place, in its sealing month's
/// base window. `None` for bytes that are no part.
pub(super) fn admit_part(
    key: Option<&WindowKey>,
    row_key: &str,
    bytes: &[u8],
) -> Option<Result<()>> {
    if !bytes.starts_with(PART_LABEL) {
        return None;
    }
    let Some(part) = OutputPart::decode(bytes) else {
        return Some(Err(refused("malformed export secret supplement part")));
    };
    if part_suffix(&part.request, part.index) != row_key {
        return Some(Err(refused(
            "export secret supplement part filed under another request or place",
        )));
    }
    if key.is_some_and(|key| *key != WindowKey::from_timestamp(part.sealed_at)) {
        return Some(Err(refused(
            "export secret supplement part outside its sealing month's base window",
        )));
    }
    Some(Ok(()))
}

/// Writes `frame`, the kept copy `output`'s bytes past one row, into `doc`'s
/// custody map as its parts, each row that differs committed on its own.
/// A copy past [`MAX_EXPORT_OUTPUT_PARTS`] stays with its keepers. Returns
/// whether it wrote any.
///
/// # Errors
/// Storage errors writing a row.
pub(super) fn mirror_parts(doc: &LoroDoc, output: &KeptExportOutput, frame: &[u8]) -> Result<bool> {
    let (parts, pieces) = split_parts(frame)?;
    let Some(count) = u32::try_from(parts.parts.len())
        .ok()
        .filter(|count| (2..=MAX_EXPORT_OUTPUT_PARTS).contains(count))
    else {
        tracing::debug!(
            bytes = frame.len(),
            "an export secret supplement past its part bound stays with its keepers"
        );
        return Ok(false);
    };
    let map = doc.get_map(CUSTODY_MAP);
    let mut wrote = false;
    for (index, (_, run)) in (0..count).zip(pieces) {
        let row = part_row(&output.request, index);
        let bytes = encode_part(output, index, count, run);
        if map_get_bytes(&map, &row).as_deref() != Some(bytes.as_slice()) {
            // Each row commits on its own: no one update outgrows a frame.
            map_insert_bytes(&map, &row, &bytes)?;
            commit_custody(doc);
            wrote = true;
        }
    }
    Ok(wrote)
}

/// What a copy's parts join to.
enum Joined {
    /// Every part is there and agrees: the copy.
    Copy(KeptExportOutput),
    /// A part is not there yet, or the host has no memory to join them.
    Waiting,
    /// A part disagrees with the first, or the runs join to no copy for
    /// the request: the whole set is dropped.
    Disagrees,
}

/// The copy for `request` joined from the parts `map` holds: each read in
/// order, each naming the request, the sealing second and the count the
/// first names, at its own place; the runs joined by
/// `carrier_parts::join_parts`; the joined bytes a copy for that request,
/// sealed at that second.
fn join(map: &LoroMap, request: &[u8; 32]) -> Joined {
    let Some(first) = map_get_bytes(map, &part_row(request, 0)) else {
        return Joined::Waiting;
    };
    let Some(first) =
        OutputPart::decode(&first).filter(|first| first.request == *request && first.index == 0)
    else {
        return Joined::Disagrees;
    };
    let scratch = LoroDoc::new();
    let runs = scratch.get_map(SCRATCH_MAP);
    let mut digests = Vec::new();
    let mut len = 0_u64;
    for index in 0..first.count {
        let fetched;
        let run = if index == 0 {
            first.run.as_slice()
        } else {
            let Some(bytes) = map_get_bytes(map, &part_row(request, index)) else {
                return Joined::Waiting;
            };
            fetched = match OutputPart::decode(&bytes) {
                Some(part)
                    if part.request == *request
                        && part.index == index
                        && part.count == first.count
                        && part.sealed_at == first.sealed_at =>
                {
                    part
                }
                _ => return Joined::Disagrees,
            };
            fetched.run.as_slice()
        };
        let digest = *blake3::hash(run).as_bytes();
        if map_insert_bytes(&runs, &part_key(&digest), run).is_err() {
            return Joined::Waiting;
        }
        digests.push(digest);
        len += run.len() as u64;
    }
    let Some(frame) = join_parts(
        &runs,
        &Parts {
            len,
            parts: digests,
        },
    ) else {
        return Joined::Waiting;
    };
    match KeptExportOutput::decode(&frame) {
        Some(kept) if kept.request == *request && kept.sealed_at == first.sealed_at => {
            Joined::Copy(kept)
        }
        _ => Joined::Disagrees,
    }
}

/// Every request a part row of `map` names, filed under its own key, with
/// the keys of its rows.
fn part_sets(map: &LoroMap) -> BTreeMap<[u8; 32], Vec<String>> {
    let mut sets: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
    map.for_each(|map_key, value| {
        if let Some(row_key) = map_key.strip_prefix(EXPORT_OUTPUT_ROW_PREFIX)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && let Some(part) = OutputPart::decode(&bytes)
            && part_suffix(&part.request, part.index) == row_key
        {
            sets.entry(part.request)
                .or_default()
                .push(map_key.to_owned());
        }
    });
    sets
}

/// The key of each part row of `map` due to leave its window, with
/// `fenced` this vault's erase fences on `fold`: every row of a request
/// whose rows are done, of a set that disagrees, or of a copy that joins
/// and is due to leave. A set still waiting on a part stays.
pub(super) fn done_part_rows(
    map: &LoroMap,
    fold: &AuthorityFold,
    fenced: impl Fn(&EntityId) -> bool + Copy,
) -> Vec<String> {
    let mut done = Vec::new();
    for (request, rows) in part_sets(map) {
        let gone = KeptExportOutput::request_rows_done(fold, &request, fenced)
            || match join(map, &request) {
                Joined::Copy(output) => output.row_done(fold, fenced),
                Joined::Waiting => false,
                Joined::Disagrees => {
                    tracing::debug!(
                        key = %part_row(&request, 0),
                        "export secret supplement parts disagree; the set leaves its window"
                    );
                    true
                }
            };
        if gone {
            done.extend(rows);
        }
    }
    done
}

/// Each copy one of `rows`, a window's rows, is a part of, filed under its
/// own key, joined from `doc` once every part is there. A set that
/// disagrees is logged by its key and none of it is kept.
pub(super) fn joined_copies(doc: &LoroDoc, rows: &[(String, Vec<u8>)]) -> Vec<KeptExportOutput> {
    let requests: BTreeSet<[u8; 32]> = rows
        .iter()
        .filter_map(|(map_key, bytes)| {
            OutputPart::decode(bytes)
                .filter(|part| *map_key == part_row(&part.request, part.index))
                .map(|part| part.request)
        })
        .collect();
    if requests.is_empty() || !holds_custody_map(doc) {
        return Vec::new();
    }
    let map = doc.get_map(CUSTODY_MAP);
    requests
        .into_iter()
        .filter_map(|request| match join(&map, &request) {
            Joined::Copy(output) => Some(output),
            Joined::Waiting => None,
            Joined::Disagrees => {
                tracing::warn!(
                    key = %part_row(&request, 0),
                    "export secret supplement parts disagree; none kept"
                );
                None
            }
        })
        .collect()
}
