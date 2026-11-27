//! The replay identity hashes of a run: the config hash its config marker
//! stores as hex, and each REPL step's checkpoint hash. Both keep their
//! bytes through the K door (purposes::engine_executor::{CONFIG,
//! STEP_CHECKPOINT}, PLAN-UC-04 3.4b). Moved out of `record.rs` (ratchet
//! giant_files).

use super::super::types::{EngineExecutorConfig, EngineExecutorResult};
use super::{StepEnd, StepResultDigests};
use crate::ModelLocality;
use crate::code_run::{CodeRunBridgeCall, ExecutorStorage, encode_code_run_replay_value};
use crate::entity_id::bytes_to_hex_lower;
use crate::session_overlay::RouteTarget;
use oneiron_contracts::fingerprint::{ContentHash, LegacyDigest, purposes};

/// The checkpoint hash's first field: its purpose's tag (K, PLAN-UC-04 3.4b).
const CHECKPOINT_DOMAIN: &[u8] = purposes::engine_executor::STEP_CHECKPOINT.tag().as_bytes();

/// Marks a step that ran as the JavaScript Oxc printed for its TypeScript
/// program (FIX 8276); a JavaScript step hashes no such part.
const PREPARED_SOURCE_DOMAIN: &[u8] = b"oneiron:engine-executor-repl-step:prepared-source:v1";

/// The config hash's first field: its purpose's tag (K, PLAN-UC-04 3.4b).
const CONFIG_HASH_DOMAIN: &[u8] = purposes::engine_executor::CONFIG.tag().as_bytes();

/// Storage-binding tags folded into the config marker (ONE-1729).
const CONFIG_BINDING_CANONICAL_TAG: &[u8] = b"storage:canonical";

const CONFIG_BINDING_SESSION_TAG: &[u8] = b"storage:off-record-session";

const CONFIG_ROUTE_OVERLAY_TAG: &[u8] = b"route:overlay";

const CONFIG_ROUTE_BASE_TAG: &[u8] = b"route:base";

/// Tags the digest of the approved continuation a child run was forked
/// under (FIX 3694); a run with none hashes nothing more.
const CONFIG_CONTINUATION_TAG: &[u8] = b"continuation";

/// Tags the content hash of a caller-source run's exact code (FIX EXECUTE-CALLER-CODE); a task
/// run hashes nothing more.
const CONFIG_CALLER_SOURCE_TAG: &[u8] = b"caller_source.v1";

pub(super) fn executor_config_hash_hex(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> String {
    bytes_to_hex_lower(&executor_config_hash(storage, config, continuation))
}

/// Binds replay identity to storage, privacy-route target, and the executor
/// config. The resolved prompt bytes are bound BESIDE this hash, in the config
/// marker's own `prompt_fingerprint` field, so drift can gate provider work
/// without gating a terminal record's materialization.
///
/// Wherever the bound storage can see an existing replay record — the session
/// view is overlay ∪ base, the canonical view is base — a run under a
/// different binding refuses before it writes an output or replay row. Target
/// binding also refuses a same-id resume across an off-record/on-record flip:
/// the old record can point at overlay-only raw outputs and must never be
/// copied to base. The overlay's RAM-local mode generation is not identity; it
/// can reset after a process restart.
///
/// A record that lived only in an overlay evaporates at close, so a later run
/// under any binding starts fresh. That is BY DESIGN: evaporation is the
/// absence of history, not a resumable identity.
///
/// A child run forked from a failed one (FIX 3694) also binds its
/// continuation's digest, after every other input: the same run under
/// another approved note, or under none, is another identity.
fn executor_config_hash(
    storage: &ExecutorStorage<'_>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    executor_config_hash_for_binding(
        storage.session_ref(),
        storage.session_route_target(),
        config,
        continuation,
    )
}

/// [`executor_config_hash`] over what it reads of the storage: the session
/// ref of a session binding and the route target. The config marker stores
/// its hex, so it keeps its bytes (K, PLAN-UC-04 3.4b): each field a u64
/// big-endian length and its bytes, but the frozen time, its 8 big-endian
/// bytes with no length (`hash_u64`).
pub(in crate::engine_executor) fn executor_config_hash_for_binding(
    session_ref: Option<&str>,
    route_target: Option<RouteTarget>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = LegacyDigest::new(purposes::engine_executor::CONFIG);
    hash_bytes(&mut hasher, CONFIG_HASH_DOMAIN);
    match session_ref {
        None => hash_bytes(&mut hasher, CONFIG_BINDING_CANONICAL_TAG),
        Some(session_ref) => {
            hash_bytes(&mut hasher, CONFIG_BINDING_SESSION_TAG);
            hash_str(&mut hasher, session_ref);
        }
    }
    if let Some(target) = route_target {
        hash_bytes(
            &mut hasher,
            match target {
                RouteTarget::Overlay => CONFIG_ROUTE_OVERLAY_TAG,
                RouteTarget::Base => CONFIG_ROUTE_BASE_TAG,
                RouteTarget::Discard => b"discard",
            },
        );
    }
    hash_str(&mut hasher, &config.run_id.to_hex());
    hash_str(&mut hasher, &config.task);
    hash_str(&mut hasher, config.model.as_str());
    hash_str(&mut hasher, model_locality_str(config.model_locality));
    if let Some(effort) = config.seat_effort {
        hash_str(&mut hasher, &format!("seat_effort:{effort:?}"));
    }
    hash_str(&mut hasher, config.global_tier.as_str());
    hash_u64(&mut hasher, config.determinism.frozen_unix_ms);
    hash_bytes(&mut hasher, &config.determinism.rng_seed);
    if let Some(digest) = continuation {
        hash_bytes(&mut hasher, CONFIG_CONTINUATION_TAG);
        hash_bytes(&mut hasher, digest);
    }
    // FIX EXECUTE-CALLER-CODE: a caller-source run binds the content hash of its exact code,
    // after every other input. A task run (no digest) hashes exactly as before: no tag, no
    // bytes.
    if let Some(digest) = &config.caller_source_digest {
        hash_bytes(&mut hasher, CONFIG_CALLER_SOURCE_TAG);
        hash_bytes(&mut hasher, digest.as_bytes());
    }
    hasher.finish()
}

/// Seam for `test_doors::fingerprint_keep_executor_cohort_credit` (PLAN-UC-04 3.4b).
#[cfg(oneiron_test_support)]
pub(crate) fn executor_config_hash_for_test(
    session_ref: Option<&str>,
    route_target: Option<RouteTarget>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    executor_config_hash_for_binding(session_ref, route_target, config, continuation)
}

fn model_locality_str(locality: ModelLocality) -> &'static str {
    match locality {
        ModelLocality::OnDevice => "on_device",
        ModelLocality::OwnServer => "own_server",
        ModelLocality::ThirdParty => "third_party",
    }
}

/// [`prepared_step_state_hash`] for a JavaScript step, which hashes no
/// preparation, and of a step that ends at bridge position zero with no
/// replay context; every caller outside the tests passes its own.
#[cfg(test)]
pub(in crate::engine_executor) fn step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    result: &StepResultDigests,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
) -> EngineExecutorResult<[u8; 32]> {
    prepared_step_state_hash(
        previous,
        seq,
        request_hash,
        script,
        None,
        result,
        implicit_speak,
        bridge_calls,
        StepEnd {
            bridge_end: 0,
            context: [0; 32],
        },
    )
}

/// The checkpoint hash of one step, for a step whose program may have run as
/// the JavaScript Oxc printed for it (FIX 8276). `prepared` is that
/// preparation's identity (the executed JavaScript, its map and the Oxc
/// pin), hashed beside the original program; a JavaScript step has none.
/// `end` is where the step's calls end and the digest of its replay context
/// (FIX 6354, FIX 6351), so a context with other responses never stands for
/// the same step.
#[expect(
    clippy::too_many_arguments,
    reason = "the checkpoint hashes every part of the step's state"
)]
pub(in crate::engine_executor) fn prepared_step_state_hash(
    previous: [u8; 32],
    seq: u64,
    request_hash: &[u8; 32],
    script: &str,
    prepared: Option<&[u8; 32]>,
    result: &StepResultDigests,
    implicit_speak: Option<&str>,
    bridge_calls: &[CodeRunBridgeCall],
    end: StepEnd,
) -> EngineExecutorResult<[u8; 32]> {
    let mut hasher = LegacyDigest::new(purposes::engine_executor::STEP_CHECKPOINT);
    hash_bytes(&mut hasher, CHECKPOINT_DOMAIN);
    hash_bytes(&mut hasher, &previous);
    hash_u64(&mut hasher, seq);
    hash_bytes(&mut hasher, request_hash);
    hash_bytes(&mut hasher, ContentHash::of(script.as_bytes()).as_bytes());
    if let Some(identity) = prepared {
        hash_bytes(&mut hasher, PREPARED_SOURCE_DOMAIN);
        hash_bytes(&mut hasher, identity);
    }
    hash_bytes(&mut hasher, &result.observation);
    hash_bytes(&mut hasher, &[u8::from(result.done)]);
    hash_bytes(&mut hasher, &[u8::from(implicit_speak.is_some())]);
    if let Some(text) = implicit_speak {
        hash_bytes(&mut hasher, ContentHash::of(text.as_bytes()).as_bytes());
    }
    hash_u64(&mut hasher, result.outputs.len() as u64);
    for (path, digest) in &result.outputs {
        hash_str(&mut hasher, path);
        hash_bytes(&mut hasher, digest);
    }
    hash_u64(&mut hasher, result.bindings.len() as u64);
    for (name, handle) in &result.bindings {
        hash_str(&mut hasher, name);
        hash_str(&mut hasher, handle);
    }
    hash_u64(&mut hasher, bridge_calls.len() as u64);
    for call in bridge_calls {
        hash_u64(&mut hasher, call.seq);
        hash_str(&mut hasher, call.effect.as_str());
        let request =
            encode_code_run_replay_value(&call.request, "executor bridge call request hash")?;
        let outcome =
            encode_code_run_replay_value(&call.outcome, "executor bridge call outcome hash")?;
        hash_bytes(&mut hasher, &request);
        hash_bytes(&mut hasher, &outcome);
        // Rewritten rows are pinned; legacy rows hash identically (FIX 1442).
        if let Some(rewritten) = &call.rewritten_request {
            let rewritten =
                encode_code_run_replay_value(rewritten, "executor bridge call rewritten hash")?;
            hash_bytes(&mut hasher, &rewritten);
        }
    }
    hash_u64(&mut hasher, end.bridge_end);
    hash_bytes(&mut hasher, &end.context);
    Ok(hasher.finish())
}

/// Seam for `test_doors::fingerprint_keep_executor_cohort_credit` (PLAN-UC-04 3.4b): the
/// checkpoint hash of the step `step` describes.
#[cfg(oneiron_test_support)]
pub(crate) fn step_state_hash_for_test(
    step: &crate::test_doors::fingerprint_keep_executor_cohort_credit::StepState,
) -> EngineExecutorResult<[u8; 32]> {
    prepared_step_state_hash(
        step.previous,
        step.seq,
        &step.request_hash,
        &step.script,
        step.prepared.as_ref(),
        &StepResultDigests {
            observation: step.observation,
            done: step.done,
            outputs: step.outputs.clone(),
            bindings: step.bindings.clone(),
        },
        step.implicit_speak.as_deref(),
        &step.bridge_calls,
        StepEnd {
            bridge_end: step.bridge_end,
            context: step.context,
        },
    )
}

/// A number: its 8 bytes, big-endian, with no length.
fn hash_u64(hasher: &mut LegacyDigest, value: u64) {
    hasher.raw(&value.to_be_bytes());
}

/// A field: a u64 big-endian length and its bytes.
fn hash_bytes(hasher: &mut LegacyDigest, bytes: &[u8]) {
    hasher.len_u64_be(bytes.len()).raw(bytes);
}

fn hash_str(hasher: &mut LegacyDigest, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}
