//! An export secret supplement's sealed copy past one row on the window plane
//! (FIX 12063; L03 04:0x). The kept copy is cut as any window carrier is
//! (`carrier_parts::split_parts`), and each run rides as a row of its own,
//! keyed `export_output:`, the request's entry hash, a dot and the run's
//! index in eight hex digits. Each row's head names the request, the second
//! the copy was sealed at, the run's index and the part count, carries the
//! request's signed result as the copy's witness (FIX 12312) and the
//! holder's signature of the part (FIX 12373), so a window files, admits
//! and proves each row alone, by the rules a copy in one row meets. The runs
//! cut the copy's frame with no witness and no signatures.
//!
//! - Bounded: a part count is at least two and at most
//!   [`MAX_EXPORT_OUTPUT_PARTS`], the `u32` count's codec bound, an index is
//!   below it, and a run is at most one carrier part, every run but the last
//!   a full one, so the row bounds the part, never the copy (FIX 5445,
//!   12295). The join is memory-gated and waits past the host's room. It
//!   reads at most the count's rows and stops at the first one missing.
//! - Proven part by part (FIX 12373): a part proves itself alone, without
//!   part zero or any sibling ([`part_proven`]): the signed result its
//!   witness carries stands as this vault judges it (the witness matching
//!   the result it folds once it folds one), the copy that result names is
//!   cut into the part's count (FIX 12294, 12312), and the part's signature
//!   verifies, by that result's own signer, over the vault, the request,
//!   that result's entry, the copy's digest and length, the sealing second,
//!   the count, the part's index and its run
//!   (`holder_export`'s `part_signature`). A part that does not prove
//!   itself, an unsigned one written before parts were signed among them,
//!   is admitted, never joined, and leaves at the next prune by itself;
//!   refusing it would refuse the whole update of a peer that has not
//!   folded the result yet. The proven parts of a set still short of some
//!   keep waiting for the rest.
//! - Agreed: every part must name the request, the sealing second, the
//!   count and the witness the first part names, at its own place. Proven
//!   parts that disagree drop the whole set, logged by its key alone.
//! - Joined once: the runs are joined by `carrier_parts::join_parts`, which
//!   checks the cut and the host's memory before it copies a byte, and the
//!   joined copy is kept only once it stands, as a copy in one row is.
//! - No orphans: part rows leave the window when their request's rows do,
//!   when the copy they join is due to leave, or one by one when they do not
//!   prove themselves; a set of proven parts that never completes leaves
//!   with its request or its base window.

use std::collections::{BTreeMap, BTreeSet};

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::super::{CUSTODY_MAP, admission_read_fault, commit_custody, holds_custody_map, refused};
use super::EXPORT_OUTPUT_ROW_PREFIX;
use crate::Vault;
use crate::authority::{AuthorityFold, SealedWorkOutput};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::secret_custody::holder_export::{
    KeptExportOutput, OutputPartBinding, WitnessedResult, kept_export_output_sealed_at_in_txn,
    witnessed_result,
};
use crate::sync::carrier_parts::{
    PART_BYTES, Parts, assembly_fits, join_parts, part_key, split_parts,
};
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;

/// The label every part of a relayed copy starts with: its head carries its
/// holder's signature (FIX 12373).
const PART_LABEL: &[u8] = b"oneiron/export-secret-output-part/v2\0";

/// The label of a part written before parts were signed: it decodes with no
/// signature, never proves, and leaves at the next prune (FIX 12373).
const UNSIGNED_PART_LABEL: &[u8] = b"oneiron/export-secret-output-part/v1\0";

/// The most parts one copy rides in: the `u32` part count's codec bound. The
/// row bounds the part, never the copy (FIX 5445, 12295): no seal bounds a
/// copy's size, so any copy rides in as many numbered parts as it needs.
const MAX_EXPORT_OUTPUT_PARTS: u32 = u32::MAX;

/// The root of the scratch document a copy's runs are joined in.
const SCRATCH_MAP: &str = "export_output_parts";

/// One part of a relayed copy: run `index` of `count`, beside the request,
/// the second the copy was sealed at, the copy's witness and the holder's
/// signature of the part.
struct OutputPart {
    sealed_at: u64,
    request: [u8; 32],
    index: u32,
    count: u32,
    /// The holder's signature of this part, by the key that signed the
    /// witness (FIX 12373); `None` on a part written before parts were
    /// signed.
    signature: Option<[u8; 64]>,
    /// The request's signed result, canonical (FIX 12312).
    witness: Vec<u8>,
    run: Vec<u8>,
}

/// Whether `bytes` start as a part does, signed or not.
fn part_labelled(bytes: &[u8]) -> bool {
    bytes.starts_with(PART_LABEL) || bytes.starts_with(UNSIGNED_PART_LABEL)
}

impl OutputPart {
    /// Decodes a part strictly; `None` without either label, for a short
    /// head, a zero request, a count outside two to
    /// [`MAX_EXPORT_OUTPUT_PARTS`], the `u32` codec bound, an index not below
    /// it, or a run that is empty, past one carrier part, or short of one
    /// before the last part. A part under [`UNSIGNED_PART_LABEL`] decodes
    /// with no signature. A witness past its bound, or a signature that does
    /// not verify, decodes and is judged unproven ([`part_proven`]), never a
    /// refused update (L03 06:5x).
    fn decode(bytes: &[u8]) -> Option<Self> {
        let (signed, rest) = match bytes.strip_prefix(PART_LABEL) {
            Some(rest) => (true, rest),
            None => (false, bytes.strip_prefix(UNSIGNED_PART_LABEL)?),
        };
        let (sealed_at, rest) = rest.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (index, rest) = rest.split_first_chunk::<4>()?;
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let (signature, rest) = if signed {
            let (signature, rest) = rest.split_first_chunk::<64>()?;
            (Some(*signature), rest)
        } else {
            (None, rest)
        };
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let witness_len = usize::try_from(u32::from_be_bytes(*witness_len)).ok()?;
        let (witness, run) = rest.split_at_checked(witness_len)?;
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
            signature,
            witness: witness.to_vec(),
            run: run.to_vec(),
        })
    }
}

/// How many parts [`mirror_parts`] cuts the copy `output` names into, from
/// its sealed length alone (FIX 12294): none for a copy that rides whole
/// (`KeptExportOutput::rides_in_parts`). The result names no run's bytes,
/// so the joined copy is still judged whole where it is kept.
fn part_count_of(output: &SealedWorkOutput) -> Option<u64> {
    let frame = KeptExportOutput::frame_len(output.bytes)?;
    Some(if KeptExportOutput::rides_in_parts(output.bytes) {
        frame.div_ceil(PART_BYTES as u64)
    } else {
        0
    })
}

/// Whether `part` proves itself under `result`, what its witness proves
/// ([`witnessed_result`]): the copy that result names is cut into the
/// part's count (FIX 12294, 12312), and its signature verifies, by that
/// result's own signer, over the vault, the request, that result's entry,
/// the copy's digest and length, the sealing second, the count, its index
/// and its run (FIX 12373). An unsigned part never proves.
fn proven_by(result: &WitnessedResult, part: &OutputPart) -> bool {
    let Some(signature) = &part.signature else {
        return false;
    };
    part_count_of(&result.output) == Some(u64::from(part.count))
        && OutputPartBinding {
            vault_id: result.vault_id,
            request: part.request,
            result: result.entry,
            output: result.output,
            sealed_at: part.sealed_at,
        }
        .verifies(&result.signer, part.count, part.index, &part.run, signature)
}

/// Whether `part` proves itself on `fold`, alone, without part zero or any
/// sibling (FIX 12373): the signed result its witness carries stands as
/// `fold` judges it ([`witnessed_result`], which a result `fold` folds must
/// match), and the part proves under it ([`proven_by`]). The one per-part
/// judgment admission, the prune and the join share.
fn part_proven(fold: &AuthorityFold, part: &OutputPart) -> bool {
    witnessed_result(fold, &part.request, &part.witness)
        .is_some_and(|result| proven_by(&result, part))
}

/// The label, the sealing second, the request, the index, the part count,
/// the holder's signature of the part, the witness's length (a big-endian
/// `u32`) and the witness, then the run.
fn encode_part(
    output: &KeptExportOutput,
    index: u32,
    count: u32,
    signature: &[u8; 64],
    run: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PART_LABEL.len() + 8 + 32 + 4 + 4 + 64 + 4 + output.witness.len() + run.len(),
    );
    out.extend_from_slice(PART_LABEL);
    out.extend_from_slice(&output.sealed_at.to_be_bytes());
    out.extend_from_slice(&output.request);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(signature);
    // A witness is within its bound, far inside a `u32`.
    out.extend_from_slice(&(output.witness.len() as u32).to_be_bytes());
    out.extend_from_slice(&output.witness);
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

/// Whether an export-part row's payload may be collected for reapply: a
/// part's head count bounds its whole set's peak before any payload is
/// copied (review P1 on #4467). Non-part bytes collect as today. A gated-out
/// set stays in its window for a later tick; `join`'s own gate stays the
/// backstop.
pub(crate) fn part_row_collection_admitted(bytes: &[u8]) -> bool {
    let Some(part) = OutputPart::decode(bytes) else {
        return true;
    };
    let Some(peak_upper) = u64::from(part.count)
        .checked_mul(PART_BYTES as u64)
        .and_then(|frame| frame.checked_mul(3))
    else {
        return false;
    };
    assembly_fits(peak_upper)
}

/// Admits one part under `row_key`, the map key after its prefix: one that
/// decodes, filed under its own request and place, in its sealing month's
/// base window. When it does not prove itself ([`part_proven`]: by the
/// signed result its witness carries, the witness matching the result
/// `vault` folds once it folds one, the part count the copy that result
/// names is cut into, and its holder's signature of its run; an unsigned
/// part never proves) or the second the copy this install keeps was sealed
/// at is another, the part is admitted and logged, never joined, and leaves
/// at the next prune by itself ([`done_part_rows`], FIX 12294, 12312,
/// 12373). Whether the parts join to the copy the result names is judged
/// where the copy is kept.
/// `None` for bytes that are no part.
pub(super) fn admit_part(
    vault: &Vault,
    key: Option<&WindowKey>,
    row_key: &str,
    bytes: &[u8],
) -> Option<Result<()>> {
    part_labelled(bytes).then(|| admit_part_head(vault, key, row_key, bytes))
}

/// [`admit_part`] for bytes that start with the part label.
fn admit_part_head(
    vault: &Vault,
    key: Option<&WindowKey>,
    row_key: &str,
    bytes: &[u8],
) -> Result<()> {
    let part = OutputPart::decode(bytes)
        .ok_or_else(|| refused("malformed export secret supplement part"))?;
    if part_suffix(&part.request, part.index) != row_key {
        return Err(refused(
            "export secret supplement part filed under another request or place",
        ));
    }
    if key.is_some_and(|key| *key != WindowKey::from_timestamp(part.sealed_at)) {
        return Err(refused(
            "export secret supplement part outside its sealing month's base window",
        ));
    }
    // Reading this vault's own authority is the store's work: its fault is
    // this machine's, never the peer's refused update (FIX 5925).
    let rtxn = vault.store.env.read_txn().map_err(admission_read_fault)?;
    let fold = vault
        .authority_view_readonly_in_txn(&rtxn)
        .map_err(admission_read_fault)?;
    let kept_at = kept_export_output_sealed_at_in_txn(vault, &rtxn, &part.request)
        .map_err(admission_read_fault)?;
    if !part_proven(&fold, &part) || kept_at.is_some_and(|sealed_at| sealed_at != part.sealed_at) {
        // Admitted and never joined, as a one-part copy the result does not
        // name is admitted and never kept: the join waits past it, and the
        // prune drops it alone (`done_part_rows`). The row's key alone:
        // never a byte of the run.
        tracing::debug!(
            request = row_key,
            "an export secret supplement part that does not prove itself by its request's signed result; it leaves at the next prune"
        );
    }
    Ok(())
}

/// Writes `frame`, the kept copy `output`'s frame with no witness
/// (`KeptExportOutput::copy_frame`), into `doc`'s custody map as its parts,
/// each carrying `output`'s witness and its holder's signature as `output`
/// keeps it, never signed here (FIX 12373), each row that differs committed
/// on its own.
/// A copy past [`MAX_EXPORT_OUTPUT_PARTS`], the `u32` codec bound, and one
/// kept without a signature for each of its parts, stay with their keepers:
/// no part rides that cannot prove itself. Returns whether it wrote any.
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
    if output.part_signatures.len() != parts.parts.len() {
        tracing::debug!(
            key = %part_row(&output.request, 0),
            "an export secret supplement kept without its holder's part signatures stays with its keepers"
        );
        return Ok(false);
    }
    let map = doc.get_map(CUSTODY_MAP);
    let mut wrote = false;
    for ((index, (_, run)), signature) in (0..count).zip(pieces).zip(&output.part_signatures) {
        let row = part_row(&output.request, index);
        let bytes = encode_part(output, index, count, signature, run);
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
    /// Every part is there, proves itself and agrees: the copy.
    Copy(KeptExportOutput),
    /// A part is not there yet, does not prove itself (it leaves at the next
    /// prune alone, FIX 12373), or the host has no memory to join them.
    Waiting,
    /// A proven part disagrees with the first, or the runs join to no copy
    /// for the request: the whole set is dropped.
    Disagrees,
}

/// The copy for `request` joined from the parts `map` holds, each proven on
/// `fold` (FIX 12373): each read in order, each naming the request, the
/// sealing second, the count and the witness the first names, at its own
/// place, and proving itself under the result that witness carries
/// ([`proven_by`]); the runs joined by `carrier_parts::join_parts`; the
/// joined bytes a copy for that request, sealed at that second, with no
/// witness and no part signatures of its own; the copy then carries the
/// parts' witness and signatures, so its keeper relays it onward as it
/// came. A part that does not prove itself is waited past as a missing one
/// is, never trusted: the prune drops it alone, and a proven part in its
/// place joins. Only a proven part that disagrees drops the set.
fn join(map: &LoroMap, fold: &AuthorityFold, request: &[u8; 32]) -> Joined {
    let Some(first) = map_get_bytes(map, &part_row(request, 0)) else {
        return Joined::Waiting;
    };
    let Some(first) =
        OutputPart::decode(&first).filter(|first| first.request == *request && first.index == 0)
    else {
        return Joined::Disagrees;
    };
    let Some(result) =
        witnessed_result(fold, request, &first.witness).filter(|result| proven_by(result, &first))
    else {
        return Joined::Waiting;
    };
    // The frame holds at most one carrier part per count, so this upper
    // bound only ever waits, never over-admits (FIX 12295). Budget the peak
    // live bytes, not just the frame: the staged scratch runs, the frame
    // join_parts allocates, and the sealed payload KeptExportOutput::decode
    // clones are all live together (review P1 on #4467). Unprovable size
    // waits, fail-closed.
    let Some(peak_upper) = u64::from(first.count)
        .checked_mul(PART_BYTES as u64)
        .and_then(|frame| frame.checked_mul(3))
    else {
        return Joined::Waiting;
    };
    if !assembly_fits(peak_upper) {
        return Joined::Waiting;
    }
    let scratch = LoroDoc::new();
    let runs = scratch.get_map(SCRATCH_MAP);
    let mut digests = Vec::new();
    let mut signatures = Vec::new();
    let mut len = 0_u64;
    for index in 0..first.count {
        let fetched;
        let part = if index == 0 {
            &first
        } else {
            let Some(bytes) = map_get_bytes(map, &part_row(request, index)) else {
                return Joined::Waiting;
            };
            let Some(part) = OutputPart::decode(&bytes)
                .filter(|part| part.request == *request && part.index == index)
            else {
                return Joined::Disagrees;
            };
            let agrees = part.count == first.count
                && part.sealed_at == first.sealed_at
                && part.witness == first.witness;
            if !(agrees && proven_by(&result, &part)) {
                // Only a part that proves itself can disagree; any other is
                // waited past and leaves at the prune alone (FIX 12373).
                return if !agrees && part_proven(fold, &part) {
                    Joined::Disagrees
                } else {
                    Joined::Waiting
                };
            }
            fetched = part;
            &fetched
        };
        let Some(signature) = part.signature else {
            return Joined::Waiting;
        };
        let digest = *blake3::hash(&part.run).as_bytes();
        if map_insert_bytes(&runs, &part_key(&digest), &part.run).is_err() {
            return Joined::Waiting;
        }
        digests.push(digest);
        signatures.push(signature);
        len += part.run.len() as u64;
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
        Some(mut kept)
            if kept.request == *request
                && kept.sealed_at == first.sealed_at
                && kept.witness.is_empty()
                && kept.part_signatures.is_empty() =>
        {
            kept.witness = first.witness;
            kept.part_signatures = signatures;
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
/// whose rows are done; each row that does not prove itself, alone, without
/// part zero or a full set ([`part_proven`], FIX 12373); and every row of a
/// set whose proven parts disagree on the count or the witness (FIX 12294,
/// 12312), or that joins to no copy, or to one due to leave. The proven
/// parts of a set still waiting on a part stay.
pub(super) fn done_part_rows(
    map: &LoroMap,
    fold: &AuthorityFold,
    fenced: impl Fn(&EntityId) -> bool + Copy,
) -> Vec<String> {
    let mut done = Vec::new();
    for (request, rows) in part_sets(map) {
        if KeptExportOutput::request_rows_done(fold, &request, fenced)
            || fold.export_supplement_imported(&request)
        {
            done.extend(rows);
            continue;
        }
        let mut proven = Vec::new();
        let mut head: Option<(u32, Vec<u8>)> = None;
        let mut disagree = false;
        for row in rows {
            let part = map_get_bytes(map, &row)
                .and_then(|bytes| OutputPart::decode(&bytes))
                .filter(|part| part_proven(fold, part));
            let Some(part) = part else {
                // The row's key alone: never a byte of the run.
                tracing::debug!(
                    key = %row,
                    "an export secret supplement part that does not prove itself leaves its window"
                );
                done.push(row);
                continue;
            };
            disagree |= head
                .as_ref()
                .is_some_and(|(count, witness)| part.count != *count || part.witness != *witness);
            if head.is_none() {
                head = Some((part.count, part.witness));
            }
            proven.push(row);
        }
        if proven.is_empty() {
            continue;
        }
        let joined = if disagree {
            Joined::Disagrees
        } else {
            join(map, fold, &request)
        };
        let gone = match joined {
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
            done.extend(proven);
        }
    }
    done
}

/// Each copy one of `rows`, a window's rows, is a part of, filed under its
/// own key, joined from `doc` once every part is there and proves itself on
/// `fold` (FIX 12373). A set that disagrees is logged by its key and none
/// of it is kept.
pub(super) fn joined_copies(
    doc: &LoroDoc,
    fold: &AuthorityFold,
    rows: &[(String, Vec<u8>)],
) -> Vec<KeptExportOutput> {
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
        .filter_map(|request| match join(&map, fold, &request) {
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
