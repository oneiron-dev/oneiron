use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::side_table::key::HexId;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::deletion::receipt::capture::CaptureFailure;

/// ARCH-0038 carrier-class handle for the redirect table (MS-07 / ONE-1749
/// adds it to the erase machinery's carrier list). Named here so the erase
/// ticket registers the class without re-plumbing the storage.
pub const REDIRECT_CARRIER_CLASS: &str = "redirect_table";

pub const HARD_ERASE_SWEEP_PREFIX: &[u8] = b"h:";
pub const LAST_HARD_ERASE_SWEEP_SEQ_KEY: &[u8] = b"m:last_hard_erase_sweep_seq";
pub const HARD_ERASE_SWEEP_SLA_SECS: u64 = 30 * 86_400;

/// The queue and its immutable receipt share the request's deadline.
pub fn hard_erase_sweep_deadline_at(requested_at: u64) -> u64 {
    requested_at.saturating_add(HARD_ERASE_SWEEP_SLA_SECS)
}
/// Withdrawn-generation rows, `hw:{id16}{generation:8BE}`. Not `h:` rows: a
/// withdrawn generation is no erased id, and the `h:` executor must not
/// finalize one its compaction never rewrote.
pub const WITHDRAWN_GENERATION_SWEEP_PREFIX: &[u8] = b"hw:";

/// The ARCH-0038 carrier enumeration every queued hard-erase sweep row is
/// scoped to.
///
/// The redirect table joins the historical carriers on the ARCH-0055 §9 (r6)
/// ruling — "ARCH-0038's carrier enumeration gains the redirect table" —
/// because a shell row is erasable content, not just an index: it names the
/// head an erasure removed, and a shell left readable leaks exactly what the
/// erasure hid. The class handle is owned by the family that owns the
/// keyspace, so it is read from there rather than restated here.
const ARCH0038_CARRIER_CLASSES: &[&str] = &[
    "historical_loro_updates",
    "historical_loro_snapshots",
    "derived_carriers",
    REDIRECT_CARRIER_CLASS,
];

/// The ARCH-0038 carrier classes a hard erasure must account for — the
/// enumeration every queued `h:` sweep row carries as its audit scope.
///
/// A static read of the contract, not of any one vault: the enumeration is
/// what the deletion machinery is obliged to cover, and holds before the
/// first delete as much as after it.
#[must_use]
pub fn arch0038_carrier_classes() -> Vec<String> {
    ARCH0038_CARRIER_CLASSES
        .iter()
        .map(|class| (*class).to_owned())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardEraseSweepJob {
    pub scope: HardEraseSweepScope,
    pub retry_state: HardEraseRetryState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardEraseSweepScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
    /// ARCH-0038 delete-interplay seam: "body_snapshot_ref lets the queued
    /// historical-carrier sweep locate residual snapshot/update bytes"
    /// (contracts.ts retractionRules DELETE). Opaque lowercase-hex ids only;
    /// the consuming executor is ONE-1087/ONE-1091 phase 1 (whose window
    /// compaction is global, so the refs ride the job as audit context).
    pub body_snapshot_refs: Vec<String>,
    pub carrier_classes: Vec<String>,
    /// Each erased record whose capture took the audited corrupt-CLAIM
    /// exception (FIX 7800): its subject and world were unknown, so its due job
    /// asks the sweep for every carrier, queued sends among them. Kept as the
    /// job is retried, whatever `last_error_code` a retry writes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture_failures: Vec<CaptureFailure>,
}

/// Delete-interplay refs captured from an `edge.provenance` Claim BEFORE its
/// body is purged/SoftErased, riding the QUEUED sweep row's scope (ARCH-0038).
/// Opaque lowercase-hex identifiers only — never content, names, or predicate
/// strings. Empty for non-provenance deletes.
#[derive(Debug, Clone, Default)]
pub struct HardEraseSweepExtras {
    /// Captured `source_revision_ref`s — opaque revision UUIDs joining the
    /// scope's pinned `revision_ids` slot ("entity UUIDs / revision UUIDs").
    pub revision_ids: Vec<String>,
    /// Captured `body_snapshot_ref`s — pointers to the exact body bytes the
    /// actor saw, the sweep's residual-carrier locator.
    pub body_snapshot_refs: Vec<String>,
    /// Records whose capture took the audited corrupt-CLAIM exception (FIX
    /// 7800), carried to the job scope and the receipt.
    pub capture_failures: Vec<CaptureFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardEraseRetryState {
    pub attempt_count: u32,
    pub next_attempt_at: u64,
    pub last_error_code: Option<String>,
    pub queued_at: u64,
    pub deadline_at: u64,
}

impl HardEraseRetryState {
    /// Due at queue time, with the 30-day SLA starting at the request.
    pub fn fresh(queued_at: u64, requested_at: u64) -> Self {
        Self {
            attempt_count: 0,
            next_attempt_at: queued_at,
            last_error_code: None,
            queued_at,
            deadline_at: hard_erase_sweep_deadline_at(requested_at),
        }
    }
}

/// What the historical sweep owes one withdrawn generation of a derived
/// artifact: its carriers of `generation` or older are rewritten to
/// `replacement`, and a newer generation stays. Ids and a generation only,
/// never words. Unlike [`HardEraseSweepScope::entity_ids`], this names no
/// erased id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawnGenerationScope {
    /// Lowercase hex of the artifact's id.
    pub artifact_id: String,
    /// The withdrawn body's `learned_at`, the generation its stale mark fences.
    pub generation: u64,
    pub replacement: WithdrawnReplacement,
}

impl WithdrawnGenerationScope {
    /// The cutoff this obligation stands for.
    pub fn cutoff(&self) -> WithdrawnCutoff {
        WithdrawnCutoff {
            generation: self.generation,
            replacement: self.replacement,
        }
    }
}

/// What stands in history for a withdrawn generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawnReplacement {
    /// An epoch summary's content-free keyframe, as its row now keeps it.
    EpochKeyframe,
    /// The record's exact 25-byte header and no body, as a withdrawn reply
    /// copy keeps it (FIX 931).
    Shell,
}

impl WithdrawnReplacement {
    /// The kind's tag byte in an encoded [`WithdrawnCutoff`]: a format
    /// discriminant, not a limit.
    pub const fn tag(self) -> u8 {
        match self {
            Self::EpochKeyframe => 1,
            Self::Shell => 2,
        }
    }

    pub const fn of_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::EpochKeyframe),
            2 => Some(Self::Shell),
            _ => None,
        }
    }
}

/// The bytes of an encoded [`WithdrawnCutoff`].
pub const WITHDRAWN_CUTOFF_LEN: usize = 9;

/// An artifact's newest withdrawn generation and what stands in history for
/// it (FIX 931). One strict nine-byte form serves the fence (`wg:`), this
/// vault's cutoff map and a window's carried cutoff: the generation, eight
/// bytes big-endian, then the replacement's tag byte. No other length or tag
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawnCutoff {
    /// The withdrawn body's `learned_at`: carriers of it or older are cut off.
    pub generation: u64,
    pub replacement: WithdrawnReplacement,
}

impl WithdrawnCutoff {
    pub fn encode(self) -> [u8; WITHDRAWN_CUTOFF_LEN] {
        let mut bytes = [0; WITHDRAWN_CUTOFF_LEN];
        bytes[..8].copy_from_slice(&self.generation.to_be_bytes());
        bytes[8] = self.replacement.tag();
        bytes
    }

    /// Strictly decodes an encoded cutoff; `None` for any other bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes = <[u8; WITHDRAWN_CUTOFF_LEN]>::try_from(bytes).ok()?;
        Some(Self {
            generation: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            replacement: WithdrawnReplacement::of_tag(bytes[8])?,
        })
    }

    /// Takes `other` when it names a newer generation; whether it did. At an
    /// equal generation the held cutoff stays, so none is lowered or flips.
    pub fn raise(&mut self, other: Self) -> bool {
        if other.generation > self.generation {
            *self = other;
            return true;
        }
        false
    }
}

/// Raises the cutoff `cutoffs` holds for `id` to `cutoff`.
pub fn raise_cutoff(
    cutoffs: &mut BTreeMap<EntityId, WithdrawnCutoff>,
    id: EntityId,
    cutoff: WithdrawnCutoff,
) {
    cutoffs.entry(id).or_insert(cutoff).raise(cutoff);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawnGenerationSweepJob {
    pub scope: WithdrawnGenerationScope,
    pub retry_state: HardEraseRetryState,
}

pub fn encode_withdrawn_generation_key(artifact: &EntityId, generation: u64) -> Vec<u8> {
    [
        WITHDRAWN_GENERATION_SWEEP_PREFIX,
        artifact.as_bytes(),
        &generation.to_be_bytes(),
    ]
    .concat()
}

/// Decodes a persisted `h:{seq:8BE}` job value. An undecodable job row is a
/// deletion obligation the executor can neither execute nor safely discard —
/// callers must KEEP the row and report loudly, never delete it.
pub fn decode_hard_erase_sweep_job(value: &[u8]) -> Result<HardEraseSweepJob> {
    rmp_serde::from_slice(value).map_err(|_| Error::CorruptedIndex("hard erase sweep job"))
}

/// Re-encodes a job after an in-place `retry_state` update (ONE-1087: the
/// row is REWRITTEN on failure, never deleted). Same encoder as the
/// original write (`rmp_serde::to_vec_named`), so the wire shape is stable.
pub fn encode_hard_erase_sweep_job_value(job: &HardEraseSweepJob) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

pub fn encode_hard_erase_sweep_key(seq: u64) -> [u8; 10] {
    let mut key = [0_u8; 10];
    key[..2].copy_from_slice(HARD_ERASE_SWEEP_PREFIX);
    key[2..].copy_from_slice(&seq.to_be_bytes());
    key
}

pub fn decode_hard_erase_sweep_seq(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(HARD_ERASE_SWEEP_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

/// The artifact and generation a `hw:{id16}{generation:8BE}` key names;
/// `None` for any other shape.
pub fn decode_withdrawn_generation_key(key: &[u8]) -> Option<(EntityId, u64)> {
    let rest = key.strip_prefix(WITHDRAWN_GENERATION_SWEEP_PREFIX)?;
    if rest.len() != 24 {
        return None;
    }
    let id = EntityId::from_bytes(rest[..16].try_into().ok()?).ok()?;
    Some((id, u64::from_be_bytes(rest[16..].try_into().ok()?)))
}

/// Strictly decodes one persisted `hw:` row: its key, then a value whose
/// scope names the same artifact and generation. A row that fails is an
/// obligation the sweep can neither execute nor discard; callers keep it and
/// report it, as they do an undecodable `h:` row.
pub fn decode_withdrawn_generation_row(
    key: &[u8],
    value: &[u8],
) -> Result<(EntityId, WithdrawnGenerationSweepJob)> {
    let (id, generation) = decode_withdrawn_generation_key(key)
        .ok_or(Error::CorruptedIndex("withdrawn generation sweep key"))?;
    let job: WithdrawnGenerationSweepJob = rmp_serde::from_slice(value)
        .map_err(|_| Error::CorruptedIndex("withdrawn generation sweep job"))?;
    if job.scope.artifact_id != id.to_hex() || job.scope.generation != generation {
        return Err(Error::CorruptedIndex("withdrawn generation sweep job"));
    }
    Ok((id, job))
}

/// Re-encodes a `hw:` job after an in-place `retry_state` update, with the
/// encoder of its first write.
pub fn encode_withdrawn_generation_job_value(job: &WithdrawnGenerationSweepJob) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(job)
        .map_err(|_| Error::InvariantViolation("withdrawn generation sweep job encode"))
}

/// A fence's cutoff. A fence that does not decode fails its reader.
pub fn fence_cutoff(bytes: &[u8]) -> Result<WithdrawnCutoff> {
    WithdrawnCutoff::decode(bytes).ok_or(Error::CorruptedIndex("withdrawn generation fence"))
}

/// The cutoff one pending `hw:` row stands for: its key's generation and its
/// job's replacement. A key that does not decode fences every generation, and
/// a job that does not decode reads as a keyframe's, so a reader fails closed
/// either way; the sweep inventory reports the row.
pub fn pending_cutoff(key: &[u8], value: &[u8]) -> WithdrawnCutoff {
    let generation = decode_withdrawn_generation_key(key).map_or(u64::MAX, |(_, at)| at);
    let replacement = rmp_serde::from_slice::<WithdrawnGenerationSweepJob>(value)
        .map_or(WithdrawnReplacement::EpochKeyframe, |job| {
            job.scope.replacement
        });
    WithdrawnCutoff {
        generation,
        replacement,
    }
}
