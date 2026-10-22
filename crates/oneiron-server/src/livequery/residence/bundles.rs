//! Sealed residence bundles: their put, list, get, turn and pad replacement.
//! `bundle_put`, `bundle_list`, `bundle_get` and `bundle_pads_replace` are its call surface.
//! The residence root defines the bundle request DTOs; `oneiron::sync::residence` the records.

use super::*;

pub(super) fn bundle_generation(
    hex: &str,
) -> Result<oneiron::world_keys::SealedBundleGeneration, AppError> {
    sealed_generation_from_hex(hex).ok_or_else(AppError::invalid_params)
}

pub(super) fn bundle_object(name: &str) -> Result<SealedBundleObject, AppError> {
    SealedBundleObject::from_name(name).ok_or_else(AppError::invalid_params)
}

/// The bundle publication request a list or a get names, in hex.
pub(super) fn bundle_request(hex: Option<&str>) -> Result<Option<[u8; 32]>, AppError> {
    hex.map(|hex| sealed_digest_from_hex(hex).ok_or_else(AppError::invalid_params))
        .transpose()
}

pub(super) fn bundle_entry(entry: &SealedBundleEntry) -> Value {
    json!({
        "generation": sealed_generation_hex(&entry.generation),
        "commitOrder": entry.commit_order,
        "bundleLength": entry.bundle_len,
        "bundleDigest": sealed_digest_hex(&entry.bundle_digest),
        "padsLength": entry.pads_len,
        "padsDigest": sealed_digest_hex(&entry.pads_digest),
    })
}

/// Asks for the publisher turn of the vault's sealed bundle for a machine of
/// the owner's whose proof stands here, or gives its place up (FIX 3351):
/// only the holder stages a bundle and commits. A refused machine looks
/// missing.
pub(super) fn bundle_turn(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: BundleTurnRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let turn = ask_sealed_bundle_turn(&server.vault, peer, input.leave)
        .map_err(|_| AppError::not_found("sealed bundle", None))?;
    Ok((json!({"turn": turn}), Some(Vec::new())))
}

/// Stages one part of an upload of the vault's sealed bundle or its pad object
/// (FIX 922), from a machine of the owner's whose proof stands here. A stage
/// whose rest would cross the disk's free-space floor is refused before its
/// bytes are kept; the room it claims stays claimed across its parts, through
/// the commit or replace that writes its stored copy (FIX 3354). A refused
/// machine or part looks missing.
pub(super) fn bundle_put(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: BundlePutRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let stage = SealedBundleStage {
        generation: bundle_generation(&input.generation)?,
        object: bundle_object(&input.object)?,
        total: input.total,
        digest: sealed_digest_from_hex(&input.digest).ok_or_else(AppError::invalid_params)?,
    };
    let part = base64::engine::general_purpose::STANDARD
        .decode(input.part)
        .map_err(|_| AppError::invalid_params())?;
    // A peer that proved no machine is refused by the stage itself.
    let claim = match peer {
        PeerMachine::Proven { machine, .. } => Some(
            server
                .transfers
                .hold_sealed_stage(machine, stage.object, input.total, input.offset)
                .ok_or_else(|| {
                    AppError::new(
                        "DISK_FLOOR",
                        "the home's disk keeps its free-space floor",
                        ["Retry once the home has room."],
                    )
                })?,
        ),
        PeerMachine::Unknown => None,
    };
    let staged = stage_sealed_bundle_part(&server.vault, peer, &stage, input.offset, &part);
    drop(claim);
    server.transfers.reconcile_sealed_stages(&server.vault);
    let staged = staged.map_err(|_| AppError::not_found("sealed bundle", None))?;
    Ok((json!({"staged": staged}), Some(Vec::new())))
}

/// The generations the home keeps, newest first, for a machine of the
/// owner's, or the one his named request asked to publish here (FIX 922). It
/// names no world. A stage idled out since gives its room on the disk back
/// (FIX 3354).
pub(super) fn bundle_list(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let BundleListRequest { request } =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let request = bundle_request(request.as_deref())?;
    server.transfers.reconcile_sealed_stages(&server.vault);
    let index = sealed_bundle_index(&server.vault, peer, request)
        .map_err(|_| AppError::not_found("sealed bundle", None))?;
    let generations: Vec<Value> = index.entries.iter().map(bundle_entry).collect();
    Ok((
        json!({
            "generations": generations,
            "retainedRevision": sealed_digest_hex(&index.retained_revision),
        }),
        Some(Vec::new()),
    ))
}

/// One slice of a kept generation's bundle or pad object from `offset`, with
/// its whole length and digest, for a machine of the owner's (FIX 922). The
/// home serves the whole vault's object and never learns which worlds the
/// machine reads.
pub(super) fn bundle_get(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: BundleGetRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let generation = input
        .generation
        .as_deref()
        .map(bundle_generation)
        .transpose()?;
    let object = bundle_object(&input.object)?;
    let request = bundle_request(input.request.as_deref())?;
    let (entry, read) = sealed_bundle_part(
        &server.vault,
        peer,
        generation,
        object,
        input.offset,
        request,
    )
    .map_err(|_| AppError::not_found("sealed bundle", None))?
    .ok_or_else(|| AppError::not_found("sealed bundle", None))?;
    let part = match read {
        BundlePartRead::Part(part) => part,
        BundlePartRead::End => return Err(AppError::not_found("sealed bundle", None)),
        BundlePartRead::PadObjectUnavailable(unavailable) => {
            return Ok((
                pad_objects::unavailable(&entry, &unavailable),
                Some(Vec::new()),
            ));
        }
    };
    let (total, digest) = entry.object(object);
    Ok((
        json!({
            "generation": sealed_generation_hex(&entry.generation),
            "object": object.name(),
            "total": total,
            "digest": sealed_digest_hex(&digest),
            "offset": input.offset,
            "last": input.offset.saturating_add(part.len() as u64) == total,
            "part": base64::engine::general_purpose::STANDARD.encode(part),
        }),
        Some(Vec::new()),
    ))
}

/// Replaces a kept generation's pad object with erase's rewrite the machine
/// staged whole (FIX 922): same generation, same length. The old object is
/// deleted. A refused machine, a moved object or a bad stage looks missing.
pub(super) fn bundle_pads_replace(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let input: BundlePadsReplaceRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let generation = bundle_generation(&input.generation)?;
    let replaces = sealed_digest_from_hex(&input.replaces).ok_or_else(AppError::invalid_params)?;
    let entry = replace_sealed_bundle_pads(&server.vault, peer, generation, &replaces);
    server.transfers.reconcile_sealed_stages(&server.vault);
    let entry = entry.map_err(|_| AppError::not_found("sealed bundle", None))?;
    Ok((bundle_entry(&entry), Some(Vec::new())))
}
