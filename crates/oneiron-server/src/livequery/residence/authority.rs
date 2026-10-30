//! The authority log over residence: its tail, range, checkpoint and append,
//! and an entry past one frame in parts either way (FIX 8246).
//! `authority_tail`, `authority_range`, `authority_checkpoint`, `authority_append`,
//! `authority_entry` and `authority_append_part` serve `run`.
//! The residence root defines the authority request DTOs; `oneiron::sync::residence` the folds.

use super::*;

/// The signed authority entries the proved machine lacks, parents first
/// (OF-469). Only a machine of the owner's is served; any other looks missing.
/// The last page, one short of the limit, also names the entries the machine
/// holds and this home lacks (`wanted`), for it to append.
pub(super) fn authority_tail(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityTailRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(input.held)
        .map_err(|_| AppError::invalid_params())?;
    if raw.len() % 32 != 0 {
        return Err(AppError::invalid_params());
    }
    let held: std::collections::BTreeSet<oneiron::authority::AuthorityEntryHash> = raw
        .chunks_exact(32)
        .map(|hash| <[u8; 32]>::try_from(hash).map_err(|_| AppError::invalid_params()))
        .collect::<Result<_, _>>()?;
    let limit = input
        .limit
        .clamp(1, oneiron::sync::residence::AUTHORITY_TAIL_PAGE_MAX);
    let entries = authority_tail_for(&server.vault, peer, &held, limit)
        .map_err(|_| AppError::not_found("authority history", None))?;
    let wanted: Vec<u8> = if entries.len() < limit {
        authority_wanted(&server.vault, &held)
            .map_err(|_| AppError::internal_server_error("authority history unavailable"))?
            .iter()
            .flatten()
            .copied()
            .collect()
    } else {
        Vec::new()
    };
    let (entries, parted) = parted_page(entries)?;
    Ok((
        json!({
            "entries": entries,
            "parted": parted,
            "wanted": base64::engine::general_purpose::STANDARD.encode(wanted),
        }),
        Some(Vec::new()),
    ))
}

/// One page of entries as it goes (FIX 8246): those that ride inline, in
/// base64, and each named by reference, its place, hash and length, for the
/// machine to fetch in parts (`authority_entry`).
fn parted_page(entries: Vec<Vec<u8>>) -> Result<(Vec<String>, Vec<Value>), AppError> {
    let page = split_authority_page(entries)
        .map_err(|_| AppError::internal_server_error("authority history unavailable"))?;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let inline = page.inline.iter().map(|entry| encode(entry)).collect();
    let parted = page
        .parted
        .iter()
        .map(|named| {
            json!({ "place": named.place, "hash": encode(&named.hash), "total": named.total })
        })
        .collect();
    Ok((inline, parted))
}

/// Concatenated 32-byte hashes in base64, as the authority RPCs pack them.
pub(super) fn packed_hashes(
    packed: &str,
) -> Result<std::collections::BTreeSet<oneiron::authority::AuthorityEntryHash>, AppError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(packed)
        .map_err(|_| AppError::invalid_params())?;
    if raw.len() % 32 != 0 {
        return Err(AppError::invalid_params());
    }
    raw.chunks_exact(32)
        .map(|hash| <[u8; 32]>::try_from(hash).map_err(|_| AppError::invalid_params()))
        .collect()
}

/// One 32-byte hash in base64.
pub(super) fn one_hash(encoded: &str) -> Result<[u8; 32], AppError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AppError::invalid_params())?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| AppError::invalid_params())
}

/// The authority entries the proved machine selects (exact hashes, or the
/// rows one kept checkpoint image covers) and, with parent closure, their
/// ancestors down to what it holds, parents first, from this home's hot log
/// (OF-469). Only a machine of the owner's is served; any other looks
/// missing, as does an image or archive this home does not keep. Nothing in
/// the reply is trusted there: the machine verifies every entry itself,
/// checks `selection` names what it asked, and reads `unheld` as this
/// home's claim only.
pub(super) fn authority_range(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityRangeRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let selection = match input.selection {
        AuthorityRangeSelection::Hashes(packed) => {
            oneiron::authority::AuthorityHistorySelection::Hashes(packed_hashes(&packed)?)
        }
        AuthorityRangeSelection::Covered(covered) => {
            oneiron::authority::AuthorityHistorySelection::Covered {
                checkpoint: one_hash(&covered.checkpoint)?,
                archive: covered.archive.as_deref().map(one_hash).transpose()?,
                lower_exclusive: covered
                    .lower_exclusive
                    .as_deref()
                    .map(one_hash)
                    .transpose()?,
                upper_inclusive: covered
                    .upper_inclusive
                    .as_deref()
                    .map(one_hash)
                    .transpose()?,
            }
        }
    };
    let fetch = oneiron::authority::AuthorityHistoryFetch {
        vault_id: input.vault_id.as_deref().map(one_hash).transpose()?,
        selection,
        parent_closure: input.parent_closure,
        held: packed_hashes(&input.held)?,
        cursor: input.cursor.as_deref().map(one_hash).transpose()?,
        limit: input
            .limit
            .clamp(1, oneiron::authority::AUTHORITY_HISTORY_PAGE_MAX),
    };
    let mut page = authority_range_for(&server.vault, peer, &fetch)
        .map_err(|_| AppError::not_found("authority history", None))?;
    let (rows, parted) = parted_page(std::mem::take(&mut page.rows))?;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let unheld: Vec<u8> = page.unheld.iter().flatten().copied().collect();
    Ok((
        json!({
            "vault_id": page.vault_id.map(|id| encode(&id)),
            "checkpoint": page.checkpoint.map(|head| encode(&head)),
            "selection": encode(&page.selection),
            "rows": rows,
            "parted": parted,
            "unheld": encode(&unheld),
            "next": page.next.map(|next| encode(&next)),
        }),
        Some(Vec::new()),
    ))
}

/// One part of the checkpoint image this home keeps at the id asked for,
/// with its whole length and, on the part at offset zero, the attestations
/// kept for it (OF-469). Only a machine of the owner's is served; any other,
/// an image not kept here and an offset past its end look missing. Nothing
/// here is trusted there: the machine adopts the image only once it verifies
/// against the pin its pairing returned.
pub(super) fn authority_checkpoint(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityCheckpointRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = one_hash(&input.checkpoint)?;
    let part = authority_checkpoint_part_for(&server.vault, peer, &id, input.offset)
        .map_err(|_| AppError::not_found("authority checkpoint", None))?
        .ok_or_else(|| AppError::not_found("authority checkpoint", None))?;
    let attestations = serde_json::to_value(&part.attestations)
        .map_err(|_| AppError::internal_server_error("authority checkpoint unavailable"))?;
    Ok((
        json!({
            "total": part.total,
            "part": base64::engine::general_purpose::STANDARD.encode(&part.part),
            "attestations": attestations,
        }),
        Some(Vec::new()),
    ))
}

/// Imports the signed authority entries the proved machine appends, through
/// the signed-history door (OF-469), every one of them in work slices: an
/// append is never refused for its length (FIX 8887). Only a machine of the
/// owner's is heard; any other looks missing. Answers how many rows the
/// import wrote, and each entry's outcome as packed hashes: the entries that
/// stand here now and those the door refused.
pub(super) fn authority_append(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityAppendRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let entries = input
        .entries
        .iter()
        .map(|entry| base64::engine::general_purpose::STANDARD.decode(entry))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::invalid_params())?;
    let progress = authority_append_progress_for(&server.vault, peer, &entries)
        .map_err(|_| AppError::bad_request("authority entries refused", Some("entries")))?
        .ok_or_else(|| AppError::not_found("authority history", None))?;
    Ok(append_answer(&progress))
}

/// An append's outcome: how many rows the import wrote, and the entries that
/// stand here now and those the door refused, as packed hashes.
fn append_answer(progress: &AuthorityAppendProgress) -> Answer {
    let packed = |hashes: &std::collections::BTreeSet<oneiron::authority::AuthorityEntryHash>| {
        base64::engine::general_purpose::STANDARD
            .encode(hashes.iter().flatten().copied().collect::<Vec<u8>>())
    };
    (
        json!({
            "written": progress.written,
            "accepted": packed(&progress.accepted),
            "refused": packed(&progress.refused),
        }),
        Some(Vec::new()),
    )
}

/// One part of a held authority entry a page named by reference, with its
/// whole length (FIX 8246). Only a machine of the owner's is served; any
/// other, an entry not held here or withheld from it, and an offset past its
/// end look missing. The machine checks the joined entry against its hash.
pub(super) fn authority_entry(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: AuthorityEntryRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let hash = one_hash(&input.hash)?;
    let part = authority_entry_part_for(&server.vault, peer, &hash, input.offset)
        .map_err(|_| AppError::not_found("authority entry", None))?
        .ok_or_else(|| AppError::not_found("authority entry", None))?;
    Ok((
        json!({
            "total": part.total,
            "part": base64::engine::general_purpose::STANDARD.encode(&part.part),
        }),
        Some(Vec::new()),
    ))
}

/// One part of an authority entry the proved machine appends past one
/// request frame (FIX 8246), held for this socket until it is whole, then
/// imported as `authority_append` imports it. Answers how far the entry is
/// staged while parts are to come, then the append's outcome. Only a machine
/// of the owner's is heard; any other looks missing.
pub(super) fn authority_append_part(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
    stage: &mut Option<AuthorityAppendStage>,
) -> Result<Answer, AppError> {
    let input: AuthorityAppendPartRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let hash = one_hash(&input.hash)?;
    let part = base64::engine::general_purpose::STANDARD
        .decode(input.part)
        .map_err(|_| AppError::invalid_params())?;
    let outcome = authority_append_part_for(
        &server.vault,
        peer,
        stage,
        hash,
        input.total,
        input.offset,
        &part,
    )
    .map_err(|_| AppError::bad_request("authority entry part refused", Some("part")))?
    .ok_or_else(|| AppError::not_found("authority history", None))?;
    Ok(match outcome {
        AuthorityAppendPart::Held => (
            json!({ "staged": input.offset + part.len() as u64 }),
            Some(Vec::new()),
        ),
        AuthorityAppendPart::Whole(progress) => append_answer(&progress),
    })
}
