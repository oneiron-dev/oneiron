//! The agent as its own compaction writer (FIX 4465, owner 10-19: "the toggle
//! sets WHO writes, not which model"). A self-written pass answers the same
//! summary schema as every pass, and beside it the host's record of what ran
//! it: the writer (the run's authenticated actor), the admitted and served
//! model, the provider-reported usage, the call's durable-step identity, the
//! home it wore, and the snapshot of the summary the gate accepted. The agent
//! writes only the summary fields; it never chooses any of these.
//!
//! A self-written summary lands only through its packet, admitted on the
//! packet door's host-log binding against the run's retained steps.
//!
//! FIX 4465 B: each paid call of a pass, the refused tries too, is filed in
//! the model-step family on the route its run captured, and the receipt
//! names the filed steps and the retained evidence its window was cut from.
//! The summary takes a withdrawal dependency on each home part it wore, as
//! on any source (Engine 10-19), and its landing declares the Dreamer's
//! check, which never rewrites it.
//!
//! FIX 4465 C: a pass whose row reads the live context forks the run's live
//! request on the rung that admitted it, the prefix unchanged, and lands,
//! files and is checked as any other self-written pass. A flight that cannot
//! fork it keeps its window and names why.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::packet_source::{
    CompactionHostLog, CompactionSource, admit_compaction_source, admit_host_log_record,
};
use super::{
    COMPACTION_PACKET_SCHEMA_VERSION, CompactionPacket, CompactionPayloadKind, CompactionRefusal,
    CompactionSnapshotRef, CompactionSuppression, GatedCompaction, ValidatedCompactionPacket,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::SelfCompactionSource;
use crate::provenance::birth::RowBirth;
use crate::vault::Vault;

/// Why a flight could not be written as its agent. The flight keeps its raw
/// window for the turn: it is never handed to the Dreamer or to the plain
/// cheap writer instead, and the run's report names this reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfCompactionUnavailable {
    /// The policy row reads the live context, and the flight carries no
    /// capture of the run's live request from its breakpoint (FIX 4465 C):
    /// its host bound none there, or the row turned to the live context
    /// after the breakpoint.
    LiveForkNotCaptured,
    /// At the breakpoint the live route bound no rung to take the run's
    /// request: the route refused it, or every rung of its ladder rested or
    /// was held.
    LiveRungUnbound,
    /// The live request and the reply's reserve leave the live model no
    /// room for the window: the prefix is never cut to make room.
    LivePrefixTooLong,
    /// The run's driver did not admit the capture: the profile's writer is
    /// not `self`, the row it was captured under is not the live fork, or it
    /// was captured for another actor.
    LiveForkNotAdmitted,
    /// The captured rung is no longer what the live route admits for its
    /// model and offer, so the fork is not sent.
    LiveForkStale,
    /// The run's actor names no home: it is not an agent, or its agent is
    /// anchored to no PERSON.
    NoIdentity,
    /// The agent's identity could not be read under its own Grant.
    IdentityUnreadable,
    /// The vault's self-compaction row could not be read.
    PolicyUnreadable,
    /// The model the writer runs on (the agent's own compaction model, else
    /// the house route's) is not served on this host.
    ModelNotServed,
    /// The writer's model is served wider than the row's bound.
    RouteWiderThanPolicy,
    /// A pass ran before its flight froze what it wears.
    FlightNotPrepared,
}

impl SelfCompactionUnavailable {
    /// The stable name a report and a refusal carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveForkNotCaptured => "live_fork_not_captured",
            Self::LiveRungUnbound => "live_rung_unbound",
            Self::LivePrefixTooLong => "live_prefix_too_long",
            Self::LiveForkNotAdmitted => "live_fork_not_admitted",
            Self::LiveForkStale => "live_fork_stale",
            Self::NoIdentity => "no_identity",
            Self::IdentityUnreadable => "identity_unreadable",
            Self::PolicyUnreadable => "policy_unreadable",
            Self::ModelNotServed => "model_not_served",
            Self::RouteWiderThanPolicy => "route_wider_than_policy",
            Self::FlightNotPrepared => "flight_not_prepared",
        }
    }

    /// The pass's refusal: nothing produced, the window kept for this turn.
    /// The next turn's flight asks again, so an edited row or a readable
    /// home takes effect there.
    #[must_use]
    pub fn refusal(self) -> CompactionRefusal {
        CompactionRefusal {
            suppression: CompactionSuppression::TurnScoped { check: None },
            detail: format!("self_compaction_unavailable:{}", self.as_str()),
        }
    }
}

/// Provider-reported usage of one self-written call. `None` is unknown, never
/// a measured zero: an adapter that reports no cache counter leaves it unset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionUsage {
    pub input_tokens: Option<u64>,
    pub cached_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Provider usage keys that report a cache read or a cache write, as the
/// adapters receive them; a zero counter under one of them is a measured
/// miss, and a zero with none of them is unknown.
const CACHE_READ_KEYS: [&str; 4] = [
    "cache_read_input_tokens",
    "cached_tokens",
    "cachedContentTokenCount",
    "cache_read",
];
const CACHE_WRITE_KEYS: [&str; 2] = ["cache_creation_input_tokens", "cache_write"];

/// The receipt's usage counters from what the provider reported (FIX 4465):
/// input and output totals when the provider reported usage at all, and the
/// cached-read and cache-write counters only when its usage names them. A
/// ladder's served receipt holds the provider's own usage under `usage`.
#[must_use]
pub fn compaction_usage_projection(usage: &crate::LlmUsage) -> CompactionUsage {
    let raw = &usage.raw_provider;
    let provider = match raw.get("usage") {
        Some(inner) if raw.get("rung").is_some() => inner,
        _ => raw,
    };
    if provider.is_null() {
        return CompactionUsage::default();
    }
    let names = |keys: &[&str]| keys.iter().any(|key| names_key(provider, key));
    CompactionUsage {
        input_tokens: Some(usage.input.total),
        cached_read_tokens: (usage.input.cache_read > 0 || names(&CACHE_READ_KEYS))
            .then_some(usage.input.cache_read),
        cache_write_tokens: (usage.input.cache_write > 0 || names(&CACHE_WRITE_KEYS))
            .then_some(usage.input.cache_write),
        output_tokens: Some(usage.output.total),
    }
}

fn names_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(name, inner)| name == key || names_key(inner, key)),
        Value::Array(items) => items.iter().any(|inner| names_key(inner, key)),
        _ => false,
    }
}

/// The state of a home part the call wore whole: the only state that shaped
/// what it wrote. A cut part never reached the call; an absent one is named
/// by why.
pub const HOME_PART_WORN: &str = "present";

/// One part of the home a self-written call wore, by ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionHomeRef {
    /// `voice`, `self_model`, `diary` or `lessons`.
    pub part: String,
    /// The row it was read from; `None` for an absent part.
    pub row: Option<EntityId>,
    /// `present`, `truncated` (it did not fit the call's room), or
    /// `absent:<why>`.
    pub state: String,
}

/// What ran one self-written epoch or fold call: the host's record, beside
/// the summary the agent wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionExecution {
    /// The agent the summary is written as: the run's authenticated actor.
    pub writer: EntityId,
    /// The context the call read.
    pub source: SelfCompactionSource,
    /// The model the host admitted the call on.
    pub admitted_model: String,
    /// The provider of the rung that answered, as the ladder stamped it.
    pub served_provider: Option<String>,
    /// The model the provider reported answering, when it reported one.
    pub served_model: Option<String>,
    /// The answering try's usage.
    pub usage: CompactionUsage,
    /// Each try the gate refused before it, its usage its own line: paid
    /// once each, never summed into the answering try's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_tries: Vec<CompactionUsage>,
    /// The call's durable-step identity: the hex BLAKE3 of the admitted
    /// request's canonical bytes, the key the model-step family files it by.
    pub step_hash: Option<String>,
    /// The home the call wore.
    pub home: Vec<CompactionHomeRef>,
    /// The accepted summary's snapshot, stamped when the gate accepted it:
    /// the hex BLAKE3 of its bytes and their length.
    pub snapshot_hash: Option<String>,
    pub snapshot_len: Option<u64>,
    /// The answering try's filed step (FIX 4465 B): its `dreamer.step`
    /// claim, resolvable by id on the route the run's rows are on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<CompactionStepRef>,
    /// Each try the gate refused before it, filed as a step of its own, in
    /// the order the tries ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_steps: Vec<CompactionStepRef>,
    /// Why the pass's calls were not filed, when they could not be: the
    /// receipt keeps their usage either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_unfiled: Option<String>,
    /// The retained evidence its window was cut from, by revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<CompactionEvidence>,
    /// Every paid call of the pass, the refused tries first, held only until
    /// the host files them. Never part of the receipt.
    #[serde(skip)]
    pub calls: Vec<CompactionCall>,
}

/// One paid call of a self-written pass, held until its host files it in
/// the model-step family (FIX 4465 B): the admitted request and the
/// provider's whole answer, each as its JSON. The step's model, purpose and
/// params identity and its canonical hash are read from the request; the
/// answer is the step's response. It never reaches a receipt or a store of
/// its own: the filed step is the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionCall {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    /// Every record the call's words were read from: its request's sources
    /// and each home part it wore, the summary's own lineage. Its filed step
    /// and any response artifact derive from each (FIX 5977), so withdrawing
    /// one withdraws them as it withdraws the summary.
    pub sources: Vec<EntityId>,
}

/// The name of a filed compaction step's response artifact: an answer over
/// the inline bound lives in one, and its bytes leave only while it and
/// every record it was derived from stand (FIX 5977).
pub(crate) const COMPACTION_STEP_RESPONSE_NAME: &str = "compaction.step.response";

/// One filed call of a self-written pass: its terminal `dreamer.step`
/// claim, whose job is the run the pass compacted (FIX 4465 B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionStepRef {
    /// The step's claim.
    pub claim: EntityId,
    /// The hex BLAKE3 of the admitted request's canonical bytes.
    pub step_hash: String,
}

/// The retained evidence a self-written summary was cut from, by revision.
/// An executor run's (FIX 4465 B) is its committed steps `first..=last`,
/// pinned by the chained state hash the span's last checkpoint committed; a
/// conversation's (FIX 4465 D) is its SESSION, conversation and branch and
/// the ordered retained turns of the span, each pinned by its projection's
/// fingerprint. A later read that finds another pin reads other evidence.
/// Each source keeps its own fields, so an executor receipt reads as it was
/// written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompactionEvidence {
    Executor {
        run: EntityId,
        first: u64,
        last: u64,
        /// Hex of the last step's committed state hash.
        revision: String,
    },
    Conversation(super::ConversationEvidence),
}

/// Where a self-written summary landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompactionLanding {
    /// One epoch of its run: its SUMMARY row and its number.
    Epoch { summary: EntityId, epoch: u64 },
    /// One fold of its run's ledger.
    Fold { fold: u64 },
}

/// A landed self-written summary's durable receipt, read back where its
/// run's rows are (FIX 4465 B): the epoch's coverage-row tail or the fold's
/// record, verified against the row it binds. The one projection the
/// Dreamer's check and the exec board read; never a store of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionLandingReceipt {
    pub run: EntityId,
    pub landing: CompactionLanding,
    pub first: u64,
    pub last: u64,
    /// Whether the summary's words still stand: `false` once a record they
    /// came from, a home part it wore included, is withdrawn.
    pub words_live: bool,
    /// The summary's words while they stand. Only the check reads them.
    #[serde(skip)]
    pub summary: Option<String>,
    pub execution: CompactionExecution,
}

impl CompactionExecution {
    /// The answering try, once the gate accepted `summary`: its snapshot is
    /// stamped, and the tries refused before it keep their own lines.
    #[must_use]
    pub(crate) fn accepted(mut self, summary: &str, rejected: Vec<CompactionUsage>) -> Self {
        let snapshot = summary_snapshot(summary);
        self.snapshot_hash = Some(crate::entity_id::bytes_to_hex_lower(&snapshot.content_hash));
        self.snapshot_len = Some(snapshot.byte_len);
        self.rejected_tries = rejected;
        self
    }

    /// A pass no try of which landed: the last try, and the ones before it.
    #[must_use]
    pub(crate) fn with_rejected(mut self, rejected: Vec<CompactionUsage>) -> Self {
        self.rejected_tries = rejected;
        self
    }

    /// The pass with every paid call it made, in the order they ran.
    #[must_use]
    pub(crate) fn with_calls(mut self, calls: Vec<CompactionCall>) -> Self {
        self.calls = calls;
        self
    }

    /// The receipt without the calls it still holds: what a report keeps.
    #[must_use]
    pub(crate) fn without_calls(mut self) -> Self {
        self.calls = Vec::new();
        self
    }

    /// The home rows the call wore whole (FIX 4465 B, Engine 10-19): its
    /// summary depends on each for withdrawal, as on any source, so erasing
    /// a diary entry, a lesson or the voice it wore withdraws what it shaped.
    /// A part cut for room never reached the call.
    pub fn home_dependencies(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.home
            .iter()
            .filter(|part| part.state == HOME_PART_WORN)
            .filter_map(|part| part.row)
    }

    /// The accepted snapshot, when the gate accepted this pass.
    pub(crate) fn snapshot(&self) -> Option<CompactionSnapshotRef> {
        Some(CompactionSnapshotRef {
            content_hash: hex32(self.snapshot_hash.as_deref()?)?,
            byte_len: self.snapshot_len?,
        })
    }

    /// The receipt's digest, the hex BLAKE3 of its JSON: what the epoch's
    /// birth names as its process parameters, so the summary points at the
    /// receipt its run's coverage keeps.
    pub(crate) fn receipt_digest_hex(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| Error::InvariantViolation("a compaction receipt did not encode"))?;
        Ok(crate::entity_id::bytes_to_hex_lower(
            blake3::hash(&bytes).as_bytes(),
        ))
    }
}

/// A 64-character lowercase hex digest's bytes.
pub(super) fn hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The snapshot of a summary's bytes: the artifact its packet names.
pub(crate) fn summary_snapshot(summary: &str) -> CompactionSnapshotRef {
    CompactionSnapshotRef {
        content_hash: *blake3::hash(summary.as_bytes()).as_bytes(),
        byte_len: summary.len() as u64,
    }
}

/// A self-written summary's landing: what ran it, and its packet, admitted
/// against the run's retained steps. Only [`admit_self_landing`] builds one.
#[derive(Debug, Clone)]
pub(crate) struct SelfLanding {
    pub(crate) execution: CompactionExecution,
    pub(crate) packet: ValidatedCompactionPacket,
}

/// Cuts the summary's packet, a turn digest of the gated window, and admits
/// it through the packet door's host-log binding. The expected snapshot is
/// the one its pass stamped when the gate accepted the summary, so a landing
/// carrying another pass's record is refused.
pub(crate) fn admit_self_landing(
    vault: &Vault,
    log: CompactionHostLog<'_>,
    gated: &GatedCompaction,
    execution: CompactionExecution,
) -> Result<SelfLanding> {
    land_packet(gated, execution, |packet, expected| {
        admit_compaction_source(
            vault,
            packet,
            CompactionSource::HostLog(log),
            Some(expected),
        )
    })
}

/// [`admit_self_landing`] for a run whose storage hands out no base vault (a
/// room's, FIX 4465 B): the packet binds to `record`, the run's replay as
/// its captured route read it, its room's overlay over base.
pub(crate) fn admit_self_landing_on(
    record: &crate::code_run::CodeRunReplayRecord,
    log: CompactionHostLog<'_>,
    gated: &GatedCompaction,
    execution: CompactionExecution,
) -> Result<SelfLanding> {
    land_packet(gated, execution, |packet, expected| {
        admit_host_log_record(packet, log, record, Some(expected))
    })
}

/// [`admit_self_landing`] for a conversation's window (FIX 4465 D): the
/// packet admits through the door's conversation binding, each of its turns
/// proven a member of the window's SESSION by the witnessed membership rows.
pub(crate) fn admit_self_conversation_landing(
    vault: &Vault,
    gated: &GatedCompaction,
    execution: CompactionExecution,
) -> Result<SelfLanding> {
    land_packet(gated, execution, |packet, expected| {
        admit_compaction_source(
            vault,
            packet,
            CompactionSource::Conversation,
            Some(expected),
        )
    })
}

/// Cuts the gated summary's packet and has `admit` admit it against the
/// snapshot its pass stamped.
fn land_packet(
    gated: &GatedCompaction,
    execution: CompactionExecution,
    admit: impl FnOnce(CompactionPacket, &CompactionSnapshotRef) -> Result<ValidatedCompactionPacket>,
) -> Result<SelfLanding> {
    let expected = execution.snapshot().ok_or(Error::InvariantViolation(
        "a self-written pass carries no accepted snapshot",
    ))?;
    let summary = gated.summary_text();
    let mut turn_ids: Vec<EntityId> = Vec::new();
    for message in &gated.request().window {
        if !turn_ids.contains(&message.turn_id) {
            turn_ids.push(message.turn_id);
        }
    }
    let packet = CompactionPacket {
        schema_version: COMPACTION_PACKET_SCHEMA_VERSION,
        session_ref: gated.request().session_ref,
        turn_ids,
        payload_kind: CompactionPayloadKind::TurnDigest.as_u8(),
        snapshot: summary_snapshot(summary),
        digest_text: Some(summary.to_owned()),
        working_set_refs: Vec::new(),
    };
    let packet = admit(packet, &expected)?;
    Ok(SelfLanding { execution, packet })
}

/// Whether `id` is an epoch keyframe: a summary a run's compaction minted,
/// its agent's own words when it wrote as itself (FIX 4465 B). The Dreamer's
/// third-person summaries never take one as text to revise.
pub(crate) fn is_epoch_summary(vault: &Vault, id: &EntityId) -> Result<bool> {
    use crate::ports::EntityStoreRead;
    let txn = vault.store.env.read_txn()?;
    let Some(record) = vault.store.port_entity_record(&txn, id)? else {
        return Ok(false);
    };
    Ok(record.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
        && super::decode_epoch_summary_body(&record.body).is_ok())
}

/// The epoch's birth for a self-written summary: its process parameters are
/// the receipt's digest. Every other birth is unchanged.
pub(super) fn link_writer(
    mut birth: RowBirth,
    writer: Option<&CompactionExecution>,
) -> Result<RowBirth> {
    if let Some(writer) = writer {
        birth.made_by.process.params_hash = writer.receipt_digest_hex()?;
    }
    Ok(birth)
}
