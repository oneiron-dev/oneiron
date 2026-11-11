//! Reply evidence (RAW-PROVIDER-EVIDENCE-READ): the model reply one step of a
//! canonical code run received, as the executor kept it before healing the
//! program out of it (`store::record_reply_evidence`). It is untrusted
//! evidence: a model's words, never executed and never authority, and every
//! view says so. The read is ranged by bytes, and each read checks, before
//! any metadata or byte, the reader's live grant and scope, every row the
//! run's answers were served from (as hydrate re-checks them), and the
//! reply's own taint sidecar (eiri-arch-0002, "Every read
//! checks three things"). Only a reply the run's replay record retained is
//! read; any other is absent.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::checkpoint_read::owner_read_sources;
use super::store::{RESULT_REPLY_INLINE_BYTES, clean_for_context, reply_output_path};
use crate::claim::ClaimReadStatus;
use crate::code_run::{CodeRunRawOutput, ExecutorStorage};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{Error, Vault};

/// Bytes of the inline reply budget kept for the view around the body:
/// its field names, run ref, handle, offsets and markers.
const REPLY_EVIDENCE_VIEW_RESERVE_BYTES: usize = 4096;

/// The most stored bytes one read serves: three quarters of the inline
/// reply budget (`RESULT_REPLY_INLINE_BYTES`) less the view's reserve, so the
/// whole view, base64 body included, fits the budget. A read that asks for
/// no limit reads this many; `next_byte_offset` names where the rest starts.
pub const REPLY_EVIDENCE_MAX_BYTES: u32 = 390_144;
const _: () = assert!(
    REPLY_EVIDENCE_MAX_BYTES as usize
        == (RESULT_REPLY_INLINE_BYTES - REPLY_EVIDENCE_VIEW_RESERVE_BYTES) / 4 * 3
);

/// One byte range of one step's kept reply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyEvidenceRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// The step whose model reply to read.
    pub step: u64,
    /// First stored byte to read, inclusive.
    #[serde(default)]
    pub byte_offset: u64,
    /// Bytes in this read; [`REPLY_EVIDENCE_MAX_BYTES`] when absent, at most
    /// that. Must be positive.
    #[serde(default)]
    pub byte_limit: Option<u32>,
}

/// What a reply is to its reader: evidence a model produced, never a
/// program, an observation or an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTrust {
    Untrusted,
}

/// How the stored bytes encode the reply: the provider-neutral model
/// message (`LlmMessage`) as JSON, not the provider's wire reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyEvidenceEncoding {
    LlmMessageJson,
}

/// Why a read serves nothing of a kept reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyEvidenceWithheld {
    /// The secret scan marked the reply, it is under live or stale taint,
    /// or a row it was produced from was erased or withdrawn.
    SecretOrTaint,
    /// The run's placement was never witnessed and the reader is not the
    /// owner's own key: an unknown placement is never read as base reality.
    UnknownPlacement,
}

/// One read of one step's kept reply. When `withheld` names a reason, no
/// metadata and no byte of the reply is served.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReplyEvidenceView {
    pub run_ref: String,
    pub step: u64,
    /// Always `untrusted`.
    pub trust: EvidenceTrust,
    pub encoding: ReplyEvidenceEncoding,
    pub withheld: Option<ReplyEvidenceWithheld>,
    /// The run's handle on the stored reply.
    pub output_handle: Option<String>,
    /// Bytes of the stored reply.
    pub total_bytes: Option<u64>,
    /// First stored byte of this read.
    pub byte_offset: u64,
    /// This read's bytes, base64 (standard alphabet, padded).
    pub body_base64: Option<String>,
    /// Where the next read starts; none past the reply's end.
    pub next_byte_offset: Option<u64>,
}

/// Reads one byte range of `input`'s kept reply for the vault's owner.
///
/// # Errors
///
/// A malformed request (`BAD_REQUEST`); an owner proof that no longer holds;
/// a source that does not read on `memory`'s credential (`FORBIDDEN`); and
/// storage errors. An unknown run or a step with no kept reply reads as
/// absent.
pub fn reply_evidence_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &ReplyEvidenceRequest,
) -> MemoryResult<Option<ReplyEvidenceView>> {
    owner.revalidate(memory.vault())?;
    reply_evidence_projection(memory, input)
}

/// The run `input` names, or a `BAD_REQUEST`.
pub(crate) fn reply_evidence_run(input: &ReplyEvidenceRequest) -> MemoryResult<EntityId> {
    EntityId::from_hex(input.run_ref.trim())
        .map_err(|_| MemoryError::bad_request("run_ref must be a 32-hex code-run id"))
}

/// [`reply_evidence_as_owner`]'s read once its caller is admitted: the owner
/// on its proof, or the run's own actor or a Steward
/// (`crate::snapshot_read`). Every check runs on every read, a continuation
/// too.
pub(crate) fn reply_evidence_projection(
    memory: &Memory<'_>,
    input: &ReplyEvidenceRequest,
) -> MemoryResult<Option<ReplyEvidenceView>> {
    let run = reply_evidence_run(input)?;
    let limit = match input.byte_limit {
        Some(0) => return Err(MemoryError::bad_request("byte_limit must be positive")),
        Some(limit) => limit.min(REPLY_EVIDENCE_MAX_BYTES),
        None => REPLY_EVIDENCE_MAX_BYTES,
    };
    let vault = memory.vault();
    let storage = ExecutorStorage::Canonical(vault);
    let Some(record) = storage.get_code_run_replay_record(&run)? else {
        return Ok(None);
    };
    // The reader's grant, live in this snapshot even for a reply served
    // from no row, then the run's placement under its world ceiling. Only
    // the owner's own key is known to read without bounds; every other
    // reader (a narrowed credential of the owner's too) is bounded by its
    // worlds, records, facets or grants, and never reads an unwitnessed
    // placement as base reality.
    let bounded = !memory.read_key()?.reads_as_vault_owner();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        memory.prove_read_authority_in_txn(&txn)?;
        match record.birth_world {
            Some(world) if !lane.world_readable_in(&txn, Some(world))? => return Ok(None),
            Some(_) => {}
            None if bounded => {
                return Ok(Some(withheld(
                    run,
                    input,
                    ReplyEvidenceWithheld::UnknownPlacement,
                )));
            }
            None => {}
        }
    }
    let path = reply_output_path(input.step);
    let Some(output) = record.outputs.iter().find(|output| output.path == path) else {
        return Ok(None);
    };
    // The rows the run's answers were served from, its folds' sources and
    // its compaction epochs' summaries, as step evidence and checkpoints
    // re-check them; a withdrawn fold or epoch covering this step refuses.
    let sources = owner_read_sources(&storage, &record, [input.step], "reply evidence")?;
    for source in sources {
        if memory.get_entity(&source.to_hex())?.value.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a source of the run's reply is no longer readable",
                &[],
            ));
        }
    }
    if !clean_for_context(&storage, Some(record.run_id), output)? {
        return Ok(Some(withheld(
            run,
            input,
            ReplyEvidenceWithheld::SecretOrTaint,
        )));
    }
    read_range(vault, run, input, output, limit).map(Some)
}

fn read_range(
    vault: &Vault,
    run: EntityId,
    input: &ReplyEvidenceRequest,
    output: &CodeRunRawOutput,
    limit: u32,
) -> MemoryResult<ReplyEvidenceView> {
    let offset = input.byte_offset;
    if offset > output.raw_len {
        return Err(MemoryError::bad_request(
            "byte_offset is past the end of the reply",
        ));
    }
    let len = usize::try_from(u64::from(limit).min(output.raw_len - offset))
        .map_err(|_| Error::ArithmeticOverflow("reply evidence range"))?;
    // A read at the end still reads: a kept reply whose body is gone is a
    // corrupt store, never an empty reply.
    let bytes = vault
        .read_code_run_raw_output_range(output, offset, len)?
        .ok_or(Error::CorruptedIndex("executor reply evidence body"))?;
    let read = u64::try_from(bytes.len())
        .map_err(|_| Error::ArithmeticOverflow("reply evidence range"))?;
    let end = offset
        .checked_add(read)
        .ok_or(Error::ArithmeticOverflow("reply evidence range"))?;
    Ok(ReplyEvidenceView {
        run_ref: run.to_hex(),
        step: input.step,
        trust: EvidenceTrust::Untrusted,
        encoding: ReplyEvidenceEncoding::LlmMessageJson,
        withheld: None,
        output_handle: Some(output.handle.clone()),
        total_bytes: Some(output.raw_len),
        byte_offset: offset,
        body_base64: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        next_byte_offset: (end < output.raw_len).then_some(end),
    })
}

fn withheld(
    run: EntityId,
    input: &ReplyEvidenceRequest,
    reason: ReplyEvidenceWithheld,
) -> ReplyEvidenceView {
    ReplyEvidenceView {
        run_ref: run.to_hex(),
        step: input.step,
        trust: EvidenceTrust::Untrusted,
        encoding: ReplyEvidenceEncoding::LlmMessageJson,
        withheld: Some(reason),
        output_handle: None,
        total_bytes: None,
        byte_offset: input.byte_offset,
        body_base64: None,
        next_byte_offset: None,
    }
}
