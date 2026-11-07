//! The source an arm runs from (PR-S1): one captured step of a canonical
//! run, read from its capsule and frozen before the arm starts. Its request
//! as stored and its start are read through the capsule's own readers, which
//! check withholding and digests; the start's prefix row must be the run's
//! row at the step (its run, exactly as many checkpoints as the step's
//! number, its bridge log at the step's start), and the step's own calls
//! come from a record that holds the step's checkpoint, which records where
//! they end (FIX 6354): the next step's captured start, else the run's row
//! as stored, however many steps later. A step whose end nothing proves, or
//! a body that is gone, is unavailable, never assumed. The run's results and
//! observations before the step are frozen with the taint they read under,
//! so the arm reads no live state, and so is the step's replay context, the
//! responses its live guest read (FIX 6351, `context`) and what its result
//! reads saw of reader state, with the bodies of other runs those reads
//! named (FIX 6352, `reads`). A reader admitted to the step's capture (FIX
//! 8704, `admitted`) has its admission read again before each raw read of
//! it: the request, the start, the record of its end and its replay
//! context, each record a read context names, and each body frozen.

mod admitted;
mod context;
mod reads;

pub use self::admitted::ShadowSourceAdmission;
pub(super) use self::admitted::lapsed;
pub(crate) use self::admitted::prepare_admitted_shadow_step_source;
use self::context::ArmContext;
use self::reads::ForeignBody;
use super::types::{
    ShadowBodyRef, ShadowDeterminism, ShadowRequestDigest, ShadowStepIdentity, ShadowUnavailable,
    ShadowUnavailableReason as Reason,
};
use crate::code_run::{
    CapsuleRequest, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord, ExecutorStepStart,
    ReplayRoutePin, SelfDispatchOutcome, StepReplayCapsule, StepStartBody, StoredRungBinding,
    capsule_context_body, capsule_request, capsule_start_body, decode_code_run_replay_record,
    resolve_result, route_prompt_at, step_replay_capsules_in_txn,
};
use crate::engine_executor::{JsResultRef, is_result_output_path};
use crate::limit_ask::EngineLimit;
use crate::secret_rotation::ArtifactTaintState;
use crate::{EntityId, LlmRequest, Result, Vault};

/// An arm's source, or why it has none.
type Outcome<T> = std::result::Result<T, ShadowUnavailable>;

/// Whether the reader preparing a step is still admitted to its capture,
/// asked before each raw read of it.
type Admits<'a> = &'a dyn Fn() -> Result<bool>;

/// One result or observation of the step's run before the step, frozen for
/// the arm: its manifest, the taint the run's occurrence of it read under,
/// and its bytes while it is clean. A body that is not clean is never read.
pub(crate) struct FrozenBody {
    pub(crate) output: CodeRunRawOutput,
    pub(crate) state: ArtifactTaintState,
    pub(crate) secret: Option<String>,
    pub(crate) bytes: Option<Vec<u8>>,
}

/// A stored reply produced during the captured step. It becomes visible to
/// an arm only when that arm matches the recorded call that produced it.
pub(crate) struct FrozenReply {
    pub(crate) seq: u64,
    pub(crate) body: FrozenBody,
    pub(crate) name: Option<String>,
}

/// One captured step, read and frozen for an arm: its request as stored,
/// its run's row before the step, the record that holds the step's own
/// calls to their end, and the bodies the step's program may read back.
pub struct PreparedShadowStep {
    pub(crate) step: ShadowStepIdentity,
    /// The actor whose step the capsule holds: the arm's content is its
    /// source run's, and goes with an erase of this actor (FIX 5718).
    pub(crate) source_actor: EntityId,
    pub(crate) request: LlmRequest,
    pub(crate) request_digest: ShadowRequestDigest,
    /// The answering rung, its route prompt by its capsule's body only (FIX
    /// 6255): the model call reads the prompt then ([`shadow_route_prompt`]).
    pub(crate) binding: Option<StoredRungBinding>,
    pub(crate) route_pin: Option<ReplayRoutePin>,
    pub(crate) seed: Option<u64>,
    pub(crate) start: ExecutorStepStart,
    pub(crate) determinism: CodeRunDeterminism,
    /// The run's row as the step started.
    pub(crate) prefix: CodeRunReplayRecord,
    /// A row that holds the step's calls, `bridge_start..bridge_end`, cut
    /// to the step's checkpoint and the end it records (FIX 6354).
    pub(crate) window: CodeRunReplayRecord,
    pub(crate) bridge_start: u64,
    pub(crate) bridge_end: u64,
    /// The responses the step's live guest read and what its result reads
    /// saw of reader state, read and checked once (FIX 6351, FIX 6352).
    pub(crate) context: ArmContext,
    pub(crate) frozen: Vec<FrozenBody>,
    /// The bodies of other runs the step's read context names (FIX 6352).
    pub(crate) foreign: Vec<ForeignBody>,
    pub(crate) replies: Vec<FrozenReply>,
    /// The vault's `[limits]` scan row, frozen for the arm's reads.
    pub(crate) scan_bytes: u64,
}

impl PreparedShadowStep {
    /// The step it is.
    #[must_use]
    pub const fn step(&self) -> &ShadowStepIdentity {
        &self.step
    }

    /// The actor whose step its source run is (FIX 5718): an erase or
    /// actor scrub of it releases every arm of the step.
    #[must_use]
    pub const fn source_actor(&self) -> EntityId {
        self.source_actor
    }

    /// The step's request as stored, each secret in it its custody handle.
    #[must_use]
    pub const fn request(&self) -> &LlmRequest {
        &self.request
    }

    /// Which copy of its request the step keeps, by its digest.
    #[must_use]
    pub const fn request_digest(&self) -> ShadowRequestDigest {
        self.request_digest
    }

    /// The rung that answered the captured call, when one did.
    #[must_use]
    pub const fn binding(&self) -> Option<&StoredRungBinding> {
        self.binding.as_ref()
    }

    /// The route that rung went out on, when it pinned one.
    #[must_use]
    pub const fn route_pin(&self) -> Option<&ReplayRoutePin> {
        self.route_pin.as_ref()
    }

    /// The sampling seed the captured request carried, if any.
    #[must_use]
    pub const fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// The start the step runs from.
    #[must_use]
    pub const fn start(&self) -> &ExecutorStepStart {
        &self.start
    }

    /// The run's guest clock and seed.
    #[must_use]
    pub fn determinism(&self) -> ShadowDeterminism {
        self.determinism.into()
    }

    /// Where the step's calls are in its run's bridge log.
    #[must_use]
    pub const fn bridge_window(&self) -> (u64, u64) {
        (self.bridge_start, self.bridge_end)
    }

    /// Whether each of `refs` names a body granted to the arm: one of the
    /// run's results or observations before the step, frozen clean.
    ///
    /// # Errors
    ///
    /// The first ref the arm was not granted: one frozen withheld, or one
    /// that is no body of the step's run before it.
    pub fn check_refs(&self, refs: &[ShadowBodyRef]) -> Outcome<()> {
        for wanted in refs {
            let found = self.frozen.iter().find(|frozen| {
                frozen.output.path == wanted.path && frozen.output.output_ref() == wanted.body
            });
            match found {
                Some(frozen) if frozen.bytes.is_some() => {}
                Some(_) => return Err(unavailable(Reason::SourceWithheld, "body_ref")),
                None => return Err(unavailable(Reason::SourceMissing, "body_ref")),
            }
        }
        Ok(())
    }
}

/// `reason`, caused by `cause`.
fn unavailable(reason: Reason, cause: &str) -> ShadowUnavailable {
    ShadowUnavailable::new(reason, cause)
}

/// The step `capsule` captured, read and frozen for an arm, or why it
/// cannot be: an erased capsule, a withheld or unreadable request or start
/// (`SourceWithheld`), no start (`SourceMissing`), a start that is not the
/// run's row at the step, or a checkpoint end or replay context that
/// contradicts it (`SourceDigestMismatch`), a step whose end nothing proves
/// (`CapturedOutcomeMissing`), or a body of its run that is gone
/// (`SourceMissing`). Everything is read here, before the arm starts.
///
/// # Errors
///
/// Storage errors.
pub fn prepare_shadow_step_source(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<Outcome<PreparedShadowStep>> {
    prepare_step_source(vault, capsule, &|| Ok(true))
}

/// [`prepare_shadow_step_source`], asking `admits` before each raw read of
/// the step's capture: once it says no, the step is withheld, and nothing
/// more of it is read.
fn prepare_step_source(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    admits: Admits<'_>,
) -> Result<Outcome<PreparedShadowStep>> {
    let Some(source_actor) = capsule.content.actor() else {
        return Ok(Err(unavailable(Reason::SourceWithheld, "capsule_erased")));
    };
    // An actor gone by now took its step's content, though its scrub has
    // yet to reach this capsule (FIX 5718).
    if shadow_source_gone(vault, &source_actor) {
        return Ok(Err(unavailable(
            Reason::SourceWithheld,
            crate::code_run::RESPONSE_ERASED,
        )));
    }
    let Some(request_digest) = ShadowRequestDigest::of_capsule(capsule) else {
        return Ok(Err(unavailable(Reason::SourceWithheld, "request_withheld")));
    };
    let Some(start) = capsule.start.clone() else {
        return Ok(Err(unavailable(Reason::SourceMissing, "no_start")));
    };
    if !admits()? {
        return Ok(Err(admitted::lapsed()));
    }
    let Some(request) = capsule_request(vault, capsule)? else {
        let (reason, cause) =
            if matches!(&capsule.request, CapsuleRequest::Kept { erased: true, .. }) {
                (Reason::SourceErased, "request_erased")
            } else {
                (Reason::SourceWithheld, "request_unreadable")
            };
        return Ok(Err(unavailable(reason, cause)));
    };
    if !admits()? {
        return Ok(Err(admitted::lapsed()));
    }
    let (read, context_body) = {
        let _bodies = vault.pin_all_result_bodies();
        let rtxn = vault.store.env.read_txn()?;
        let read = read_step_in_txn(vault, &rtxn, capsule, &start)?;
        (read, capsule_context_body(vault, &rtxn, capsule)?)
    };
    let (prefix, window) = match read {
        Ok(read) => read,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let context = match context::freeze_context(context_body, capsule, &start, &window) {
        Ok(context) => context,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let Some(determinism) = prefix.determinism else {
        return Ok(Err(unavailable(
            Reason::SourceMissing,
            "determinism_unknown",
        )));
    };
    let frozen = match freeze_bodies(vault, capsule.run, &prefix, admits)? {
        Ok(frozen) => frozen,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let replies = match freeze_replies(vault, capsule.run, &prefix, &window, admits)? {
        Ok(replies) => replies,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let foreign = match reads::freeze_reader_bodies(vault, &context, admits)? {
        Ok(foreign) => foreign,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let bridge_end = window.bridge_calls.len() as u64;
    Ok(Ok(PreparedShadowStep {
        step: ShadowStepIdentity::of(capsule),
        source_actor,
        request,
        request_digest,
        binding: capsule.binding.clone(),
        route_pin: capsule.route_pin.clone(),
        seed: capsule.seed,
        determinism,
        bridge_start: start.bridge_start,
        bridge_end,
        context,
        start,
        prefix,
        window,
        frozen,
        foreign,
        replies,
        scan_bytes: vault.limit_watch().bound(EngineLimit::CodeResultScanBytes),
    }))
}

/// The step's start prefix and the record that holds its calls to their
/// end, read in `rtxn`.
fn read_step_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
    start: &ExecutorStepStart,
) -> Result<Outcome<(CodeRunReplayRecord, CodeRunReplayRecord)>> {
    let Some(bytes) = capsule_start_body(vault, rtxn, capsule)? else {
        let (reason, cause) = if start.erased {
            (Reason::SourceErased, "start_erased")
        } else {
            (Reason::SourceWithheld, "start_unreadable")
        };
        return Ok(Err(unavailable(reason, cause)));
    };
    let Some(prefix) = start_prefix(&bytes) else {
        return Ok(Err(unavailable(
            Reason::SourceDigestMismatch,
            "start_undecodable",
        )));
    };
    if prefix.run_id != capsule.run
        || prefix.step_checkpoints.len() as u64 != capsule.step
        || prefix.bridge_calls.len() as u64 != start.bridge_start
    {
        return Ok(Err(unavailable(
            Reason::SourceDigestMismatch,
            "start_prefix",
        )));
    }
    let Some(record) = step_end_in_txn(vault, rtxn, capsule, &prefix)? else {
        return Ok(Err(unavailable(Reason::CapturedOutcomeMissing, "step_end")));
    };
    Ok(step_window(record, &prefix, capsule.step).map(|window| (prefix, window)))
}

/// The run's row a start body holds, when it decodes as a start.
fn start_prefix(bytes: &[u8]) -> Option<CodeRunReplayRecord> {
    let body = rmp_serde::from_slice::<StepStartBody>(bytes).ok()?;
    decode_code_run_replay_record(&body.record).ok()
}

/// The record that holds the step's calls to their proved end, read in
/// `rtxn`: the next step's captured start under the same lease, else the
/// run's row as stored. Either must descend from `prefix` and hold the
/// step's checkpoint, which records where its calls end (FIX 6354). `None`
/// when neither does.
fn step_end_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
    prefix: &CodeRunReplayRecord,
) -> Result<Option<CodeRunReplayRecord>> {
    let next_step = capsule.step.saturating_add(1);
    let next = step_replay_capsules_in_txn(vault, rtxn, capsule.attempt)?
        .into_iter()
        .find(|next| {
            next.lease_generation == capsule.lease_generation
                && next.run == capsule.run
                && next.step == next_step
                && next.start.is_some()
        });
    if let Some(next) = next
        && let Some(bytes) = capsule_start_body(vault, rtxn, &next)?
        && let Some(record) = start_prefix(&bytes)
        && next
            .start
            .as_ref()
            .is_some_and(|start| start.bridge_start == record.bridge_calls.len() as u64)
        && holds_step(&record, prefix, capsule.step)
    {
        return Ok(Some(record));
    }
    let Some(mut record) = vault.get_code_run_replay_record_in_txn(rtxn, &capsule.run)? else {
        return Ok(None);
    };
    record.live_run = None;
    Ok(holds_step(&record, prefix, capsule.step).then_some(record))
}

/// Whether `record` descends from `prefix`, the run's row as step `step`
/// started (its run and clock, its checkpoints and bridge calls as the
/// prefix holds them), and holds the step's own checkpoint.
fn holds_step(record: &CodeRunReplayRecord, prefix: &CodeRunReplayRecord, step: u64) -> bool {
    let bridge_start = prefix.bridge_calls.len();
    record.run_id == prefix.run_id
        && record.determinism == prefix.determinism
        && record.step_checkpoints.len() as u64 > step
        && record.step_checkpoints.get(..prefix.step_checkpoints.len())
            == Some(prefix.step_checkpoints.as_slice())
        && record.bridge_calls.get(..bridge_start) == Some(prefix.bridge_calls.as_slice())
}

/// The step's window in `record`, a row that holds the step's checkpoint
/// (FIX 6354): the row cut to that checkpoint and to the bridge end it
/// records, so nothing past the step's own calls is read, however long the
/// row is now. A checkpoint that is not the step's, or an end before the
/// step's start, before an earlier step's end, past a later step's or past
/// the row's bridge log, is `SourceDigestMismatch`.
fn step_window(
    mut record: CodeRunReplayRecord,
    prefix: &CodeRunReplayRecord,
    step: u64,
) -> Outcome<CodeRunReplayRecord> {
    let mismatch = || unavailable(Reason::SourceDigestMismatch, "bridge_end");
    let index = usize::try_from(step).map_err(|_| mismatch())?;
    let calls = record.bridge_calls.len() as u64;
    let bridge_start = prefix.bridge_calls.len() as u64;
    let ends = |at: usize| record.step_checkpoints.get(at).map(|held| held.bridge_end);
    let Some(checkpoint) = record.step_checkpoints.get(index) else {
        return Err(mismatch());
    };
    let end = checkpoint.bridge_end;
    let before = index.checked_sub(1).and_then(ends).unwrap_or(0);
    let after = ends(index.saturating_add(1)).unwrap_or(calls);
    if checkpoint.seq != step || before > bridge_start || bridge_start > end || end > after {
        return Err(mismatch());
    }
    let end = usize::try_from(end).map_err(|_| mismatch())?;
    record.step_checkpoints.truncate(index.saturating_add(1));
    record.bridge_calls.truncate(end);
    Ok(record)
}

/// The bodies of `run` before the step its row `prefix` holds that the
/// step's program may read back, each with the taint the run's occurrence of
/// it reads under now, and its bytes while it is clean. A clean body that is
/// gone is unavailable. The bytes frozen are measured, never capped. Each is
/// read only while `admits` says the reader still may.
fn freeze_bodies(
    vault: &Vault,
    run: crate::EntityId,
    prefix: &CodeRunReplayRecord,
    admits: Admits<'_>,
) -> Result<Outcome<Vec<FrozenBody>>> {
    let mut frozen = Vec::new();
    let mut frozen_bytes = 0_u64;
    for output in crate::engine_executor::shadow_readable_outputs(prefix) {
        let body = match freeze_body(vault, run, output, admits, "prefix_body")? {
            Ok(body) => body,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        if let Some(bytes) = &body.bytes {
            frozen_bytes = frozen_bytes.saturating_add(bytes.len() as u64);
        }
        frozen.push(body);
    }
    tracing::debug!(
        bodies = frozen.len(),
        frozen_bytes,
        "a shadow step's earlier bodies are frozen"
    );
    Ok(Ok(frozen))
}

/// Freezes only the exact result occurrence named by each stored reply in
/// this step's bridge window. Future results and bindings stay invisible.
fn freeze_replies(
    vault: &Vault,
    run: EntityId,
    prefix: &CodeRunReplayRecord,
    window: &CodeRunReplayRecord,
    admits: Admits<'_>,
) -> Result<Outcome<Vec<FrozenReply>>> {
    let mut replies = Vec::new();
    for row in window.bridge_calls.iter().skip(prefix.bridge_calls.len()) {
        // Other outcomes are still decoded only when the arm matches them.
        if !row.outcome.as_map().is_some_and(|entries| {
            entries.iter().any(|(key, value)| {
                key.as_str() == Some("kind") && value.as_str() == Some("stored_reply")
            })
        }) {
            continue;
        }
        let SelfDispatchOutcome::StoredReply(reply) =
            crate::code_run::payload::decode_self_dispatch_outcome(&row.outcome)?
        else {
            continue;
        };
        let Some(reference) = reply
            .output
            .get("ref")
            .and_then(serde_json::Value::as_str)
            .filter(|reference| reference.starts_with("occurrence:"))
        else {
            return Ok(Err(unavailable(
                Reason::SourceDigestMismatch,
                "stored_reply_ref",
            )));
        };
        let reference = JsResultRef::Handle(reference.to_owned());
        let Some((output, _)) = resolve_result(
            run,
            window
                .outputs
                .iter()
                .filter(|output| is_result_output_path(&output.path)),
            &[],
            &reference,
        ) else {
            return Ok(Err(unavailable(
                Reason::SourceMissing,
                "stored_reply_output",
            )));
        };
        let body = match freeze_body(vault, run, output, admits, "stored_reply_body")? {
            Ok(body) => body,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        replies.push(FrozenReply {
            seq: row.seq,
            body,
            name: reply
                .output
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(Ok(replies))
}

/// The same admission and taint checks for a prefix body or a matched reply.
fn freeze_body(
    vault: &Vault,
    run: EntityId,
    output: CodeRunRawOutput,
    admits: Admits<'_>,
    missing: &'static str,
) -> Result<Outcome<FrozenBody>> {
    let state = vault.code_run_raw_output_taint_state(Some(run), &output)?;
    let secret = vault.code_run_raw_output_secret(Some(run), &output)?;
    let bytes = if state.is_tainted() {
        None
    } else {
        if !admits()? {
            return Ok(Err(admitted::lapsed()));
        }
        let Some(bytes) = vault.get_code_run_raw_output(&output)? else {
            return Ok(Err(unavailable(Reason::SourceMissing, missing)));
        };
        Some(bytes)
    };
    Ok(Ok(FrozenBody {
        output,
        state,
        secret,
        bytes,
    }))
}

/// The route prompt the rung `binding` names put first on the captured call
/// `step` (FIX 6255), read from its capsule's body at the arm's model call,
/// never before and never kept on the step: each secret in it its custody
/// handle, `Ok(None)` when the rung put none. Withheld, marked, released or
/// unreadable is `SourceWithheld`, retired by a restore `SourceErased`.
///
/// # Errors
///
/// Storage and custody errors.
pub fn shadow_route_prompt(
    vault: &Vault,
    step: &ShadowStepIdentity,
    binding: &StoredRungBinding,
) -> Result<Outcome<Option<String>>> {
    let key = (step.attempt, u64::from(step.lease_generation), step.step);
    route_prompt_at(vault, &key, step.run, binding)
}

/// Whether `actor`, the actor an arm's source run is for, is gone here
/// (FIX 5718): soft-deleted or erased, read in a short read transaction of
/// its own, as each read and publication of the arm asks it. A read that
/// fails counts as gone.
#[must_use]
pub fn shadow_source_gone(vault: &Vault, actor: &EntityId) -> bool {
    crate::code_run::storage::actor_gone(vault, actor)
}
