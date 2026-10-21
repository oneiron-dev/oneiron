//! A blocked report's replay source (FIX 2343, OF-380), and the exact model
//! request a code fix replays (FIX 1662), in one table. A report whose run is
//! no agent dispatch's attempt (a standalone or MCP run, or one with no
//! durable run) names nothing a code fix could replay, so the host keeps
//! what it knows of the run with the report, in the commit that files it:
//! the model request the run's executor bound before it sent the failing
//! call, whole, the run, the reporter, and the scope the run's host gave it.
//! A caller outside this engine, which never gave it a model request, keeps
//! its report and a source with no request: its replay is unavailable, and
//! nothing stands in for the instructions it never sent. Capture is
//! prospective: a report filed before it has no source. The source stays
//! after the Coach settles the report, so a later candidate replays it too,
//! and an erase of the reporter takes it.
//!
//! The table holds two kinds of row (FIX 1662). A receipt row (`Receipt`,
//! keyed by the receipt alone, as before) keeps the report's source and the
//! request the run sent, by its canonical hash: the run's replay capsule
//! holds the request when one does, and the row keeps it whole only when
//! none does. A step row (`Step`, keyed by attempt, step, lease generation
//! and call) keeps the canonical request a durable step sent, stored before
//! the call. Both are written through the side-row wall, so each secret in a
//! kept request is a custody handle; the hash of the copy kept beside the
//! hash of the request sent says whether it is the request as sent. A
//! capture that fails never fails the call or the report: its replay is then
//! not exact. An erase of an actor takes its step rows and the receipt rows
//! of its reports. A step row stamps each owner of its step (FIX 6659): its
//! actor, its subject and, once the step logs, its terminal claim. An erase
//! of any of them takes the row, and none is kept for an owner already gone.

mod response;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, LlmRequest, Result, Vault};

// FIX 6708: both row kinds in checkpoint images, as row-held responses.
pub(crate) use self::response::{blocked_capture_owners, blocked_capture_stub};

/// Receipt rows. Key: the receipt.
const SOURCE: SideTable<EntityId, BlockedReplaySource, Named> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE);

/// Step rows, in the same table. Key: [`StepSourceKey`].
const STEPS: SideTable<StepSourceKey, StepReplaySource, Named> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE);

/// The byte a step row's key leads with. A receipt row's key is the
/// receipt's 16 bytes alone, so the two never share a key's length.
const STEP_TAG: u8 = b's';

/// A step row's key length: the tag, the attempt, the step's hash, the lease
/// generation and the call.
const STEP_KEY_LEN: usize = 1 + 16 + 32 + 8 + 4;

/// One fresh model call of an attempt (FIX 1662).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepSourceKey {
    pub(crate) attempt: AttemptId,
    /// The durable step's hash: its request's canonical hash, which its
    /// terminal `dreamer.step` claim names beside the attempt.
    pub(crate) step: [u8; 32],
    /// The attempt's lease generation when the call was sent.
    pub(crate) lease: u64,
    /// The call within the step: 0 for the step's own request.
    pub(crate) call: u32,
}

impl SideKey for StepSourceKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(STEP_TAG);
        out.extend_from_slice(self.attempt.as_bytes());
        out.extend_from_slice(&self.step);
        out.extend_from_slice(&self.lease.to_be_bytes());
        out.extend_from_slice(&self.call.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        if tag != STEP_TAG || bytes.len() != STEP_KEY_LEN {
            return None;
        }
        let (attempt, rest) = rest.split_at_checked(16)?;
        let (step, rest) = rest.split_at_checked(32)?;
        let (lease, call) = rest.split_at_checked(8)?;
        Some(Self {
            attempt: AttemptId::from_bytes(attempt).ok()?,
            step: step.try_into().ok()?,
            lease: u64::from_be_bytes(lease.try_into().ok()?),
            call: u32::from_be_bytes(call.try_into().ok()?),
        })
    }
}

/// A request kept whole (FIX 1662): canonical, with each secret the
/// side-row wall found left as its custody handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeptRequest {
    /// The request as kept; its model and envelope are the route it was
    /// bound to before the call.
    pub(crate) request: LlmRequest,
    /// The canonical hash of the copy kept: the hash of the request sent,
    /// unless the wall masked a secret in it.
    pub(crate) stored: [u8; 32],
}

/// The model request a run's executor bound before its call (FIX 1662).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SentRequest {
    /// The request's canonical hash as sent: the hash its run's replay
    /// capsule keys it by.
    pub(crate) digest: [u8; 32],
    /// The request itself, kept only when no replay capsule of the run holds
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kept: Option<KeptRequest>,
}

impl SentRequest {
    /// `request` as its executor bound it, kept whole until the report is
    /// filed; `None` when it has no canonical hash.
    pub(crate) fn bound(request: &LlmRequest) -> Option<Self> {
        let digest = request.canonical_hash().ok()?;
        Some(Self {
            digest,
            kept: Some(KeptRequest {
                request: request.clone(),
                stored: digest,
            }),
        })
    }
}

/// The model request a run's executor bound to its dispatcher before it
/// sent the call, as its host assembled it: host-owned, never guest text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BlockedRunRequest {
    /// The request's instructions: its system text, whole.
    pub(crate) instructions: String,
    /// What the call was briefed with beside its task; `None` when the host
    /// put no briefing apart from the task.
    pub(crate) briefing: Option<String>,
    /// The task the run's host gave it, whole.
    pub(crate) task: Option<String>,
    /// The request itself (FIX 1662); `None` on a source filed before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sent: Option<SentRequest>,
}

/// What the run's host knows of it when it files a blocked report.
pub(crate) struct BlockedRunHost {
    /// The host's ref of the run.
    pub(crate) run_ref: String,
    /// The agent attempt the host bound the run to, if any.
    pub(crate) attempt: Option<AttemptId>,
    /// The model request the run's executor bound before the call; `None`
    /// when no request of the run reached this engine.
    pub(crate) request: Option<BlockedRunRequest>,
    /// The capture epoch the run's host holds while every answer the run was
    /// served is in its read-world ledger (FIX 6130); `None` when it holds
    /// none clean.
    pub(crate) read_worlds: Option<crate::code_run::ReadWorldSeal>,
}

/// The worlds a run's host scoped it to, as the report's filing read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RunWorlds {
    /// The agent dispatch the run served: its scope's world and its task's.
    Scoped { worlds: Vec<EntityId> },
    /// The host bound the run to no dispatch: any world it could read may
    /// have been read.
    Unscoped,
    /// A world of the dispatch it served could not be proved.
    Unproved,
}

/// One blocked report's replay source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BlockedReplaySource {
    /// `None`: no model request of the run reached this engine, so its
    /// replay is unavailable.
    pub(crate) request: Option<BlockedRunRequest>,
    pub(crate) run_ref: String,
    /// The run's durable id, its code-run ref, when it had one.
    pub(crate) code_run: Option<EntityId>,
    /// The actor the report was witnessed for.
    pub(crate) reporter: EntityId,
    pub(crate) worlds: RunWorlds,
    pub(crate) reported_at: u64,
    /// The worlds of the rows the run was served up to the report, as its
    /// complete read-world ledger stood in the filing commit (FIX 6130);
    /// `None` when the ledger was not complete there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) read_worlds: Option<crate::code_run::ReadWorldSnapshot>,
}

impl BlockedReplaySource {
    /// The longest text the source keeps, in bytes.
    pub(crate) fn longest_text(&self) -> usize {
        self.request.as_ref().map_or(0, |request| {
            [
                Some(request.instructions.as_str()),
                request.briefing.as_deref(),
                request.task.as_deref(),
            ]
            .into_iter()
            .flatten()
            .map(str::len)
            .max()
            .unwrap_or(0)
        })
    }

    /// The request kept in the row, when there is one.
    fn kept_mut(&mut self) -> Option<&mut KeptRequest> {
        self.request
            .as_mut()
            .and_then(|request| request.sent.as_mut())
            .and_then(|sent| sent.kept.as_mut())
    }
}

/// One durable step's request (FIX 1662), kept before its call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StepReplaySource {
    /// The request; the hash of the request sent is the key's step.
    pub(crate) request: KeptRequest,
    /// The actor whose call it was: the step's host-owned envelope actor.
    pub(crate) actor: EntityId,
    /// What the step was about: its context's subject, as its step-state
    /// row stamps it (FIX 6659).
    pub(crate) subject: Option<EntityId>,
    /// The terminal `dreamer.step` claim that logged the step, bound in the
    /// write that files it (FIX 6659); `None` until then.
    pub(crate) claim: Option<EntityId>,
    /// Unix milliseconds it was kept.
    pub(crate) captured_at_ms: u64,
}

impl StepReplaySource {
    /// Every owner the row stamps: an erase of any of them takes it.
    fn owners(&self) -> Vec<EntityId> {
        [Some(self.actor), self.subject, self.claim]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// The canonical hash of `request`.
fn canonical_hash(request: &LlmRequest) -> Result<[u8; 32]> {
    request
        .canonical_hash()
        .map_err(|error| crate::Error::InvalidConfig(format!("replay request: {error}")))
}

/// Keeps `source` for the report `receipt`, in the report's filing commit,
/// through the side-row wall with the vault's custody door: each secret it
/// places is a custody handle. A request the run's replay capsule holds stays
/// there, named by its hash (FIX 1662); a capsule of the same hash whose
/// request the wall withheld holds none, so the row keeps it (FIX 6349). A
/// request the wall refuses to keep is dropped from the row, and the report
/// files without it. A reporter already erased keeps no row (FIX 6252),
/// checked in this same write, so an erase that committed first never finds
/// a copy written after it; nor does one whose markers cannot be read, and
/// the report still files.
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
    source: &BlockedReplaySource,
) -> Result<()> {
    match crate::llm::owner_gone_in_txn(vault, &*txn, &[source.reporter]) {
        Ok(false) => {}
        Ok(true) => return Ok(()),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a blocked report's source was not kept: its reporter could not be read"
            );
            return Ok(());
        }
    }
    let mut source = source.clone();
    if let Some(run) = source.code_run
        && let Some(sent) = source
            .request
            .as_mut()
            .and_then(|request| request.sent.as_mut())
        && crate::code_run::step_replay_capsules_in_txn(vault, &*txn, run)?
            .iter()
            .any(|capsule| {
                capsule.request_hash == sent.digest
                    && matches!(
                        capsule.request,
                        crate::code_run::CapsuleRequest::Kept { .. }
                    )
            })
    {
        sent.kept = None;
    }
    if source.kept_mut().is_none() {
        return SOURCE.put(vault, txn, receipt, &source);
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match put_kept_in_txn(vault, &mut savepoint, receipt, source.clone()) {
        Ok(()) => {
            savepoint.commit()?;
            Ok(())
        }
        Err(error) => {
            drop(savepoint);
            tracing::warn!(
                kind = ?error.kind(),
                "a blocked report's request was not kept; its replay is not exact"
            );
            if let Some(sent) = source
                .request
                .as_mut()
                .and_then(|request| request.sent.as_mut())
            {
                sent.kept = None;
            }
            SOURCE.put(vault, txn, receipt, &source)
        }
    }
}

/// Writes a receipt row that keeps its request, the kept hash taken over the
/// copy the wall masked, as the table reads it back.
fn put_kept_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
    mut source: BlockedReplaySource,
) -> Result<()> {
    SOURCE.admit(vault, txn, receipt, &mut source)?;
    let mut source = SOURCE.decode_value(&SOURCE.encode_value(&source)?)?;
    if let Some(kept) = source.kept_mut() {
        kept.stored = canonical_hash(&kept.request)?;
    }
    SOURCE.put(vault, txn, receipt, &source)
}

/// The replay source the report `receipt` was filed with, if any.
pub(crate) fn blocked_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<Option<BlockedReplaySource>> {
    SOURCE.get(&vault.store, txn, receipt)
}

/// Keeps the request a durable step is about to send (FIX 1662), before the
/// call, under the attempt's lease generation, for the replay of a failure on
/// a deployment that exports (the only one a code fix runs on). The row
/// stamps the owners the step's Started row stamps, its `actor` and its
/// `subject` (FIX 6659). Best effort: a capture that fails is logged by kind
/// and never fails the step, whose replay is then not exact.
pub(crate) fn capture_durable_step(
    vault: &Vault,
    attempt: AttemptId,
    step: [u8; 32],
    actor: EntityId,
    subject: EntityId,
    request: &LlmRequest,
    now_ms: u64,
) {
    if !vault.config.failure_signals.exports() {
        return;
    }
    if let Err(error) = keep_durable_step(vault, attempt, step, actor, subject, request, now_ms) {
        tracing::warn!(
            kind = ?error.kind(),
            "a step's request was not kept; its replay is not exact"
        );
    }
}

fn keep_durable_step(
    vault: &Vault,
    attempt: AttemptId,
    step: [u8; 32],
    actor: EntityId,
    subject: EntityId,
    request: &LlmRequest,
    now_ms: u64,
) -> Result<()> {
    let lease = AttemptQueue::new(vault)
        .get(attempt)?
        .map_or(0, |record| u64::from(record.attempt_count));
    let key = StepSourceKey {
        attempt,
        step,
        lease,
        call: 0,
    };
    let row = StepReplaySource {
        request: KeptRequest {
            request: request.clone(),
            stored: step,
        },
        actor,
        subject: Some(subject),
        claim: None,
        captured_at_ms: now_ms,
    };
    vault.with_write_txn_grouped(|txn| {
        // An owner gone here keeps nothing (FIX 6659), checked in this same
        // write by the step-state rows' own check, so an erase that commits
        // after the step started never finds a copy written after it.
        if crate::llm::owner_gone_in_txn(vault, &*txn, &row.owners())? {
            return Ok(());
        }
        let mut row = row;
        STEPS.admit(vault, txn, &key, &mut row)?;
        let mut row = STEPS.decode_value(&STEPS.encode_value(&row)?)?;
        row.request.stored = canonical_hash(&row.request.request)?;
        STEPS.put(vault, txn, &key, &row)
    })
}

/// Every durable step request kept for `attempt`, oldest first (FIX 1662).
/// A row that does not read is not a request to replay.
pub(crate) fn step_sources_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Vec<(StepSourceKey, StepReplaySource)>> {
    let mut prefix = vec![STEP_TAG];
    prefix.extend_from_slice(attempt.as_bytes());
    let mut rows = Vec::new();
    for row in STEPS.iter_raw_from(&vault.store, txn, &prefix)? {
        let (key, bytes) = row?;
        if let (Some(key), Ok(source)) =
            (StepSourceKey::decode_key(&key), STEPS.decode_value(&bytes))
        {
            rows.push((key, source));
        }
    }
    rows.sort_by_key(|(_, source)| source.captured_at_ms);
    Ok(rows)
}

/// The key prefix every row of `attempt`'s `step` shares: each lease
/// generation and call of it.
fn step_prefix(attempt: AttemptId, step: &[u8; 32]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(STEP_KEY_LEN);
    prefix.push(STEP_TAG);
    prefix.extend_from_slice(attempt.as_bytes());
    prefix.extend_from_slice(step);
    prefix
}

/// Binds the terminal claim `claim` that logs `step` of `attempt` to every
/// request kept for the step (FIX 6659), each lease and call of it, in the
/// claim's own write, so an erase of the claim takes them once the
/// step-state row that names it is gone. A row that does not decode names
/// no owner and stays as it is. A binding that fails takes the step's kept
/// requests instead, so none is kept unbound: the claim files as before,
/// and the step's replay is then not exact.
pub(crate) fn bind_step_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    step: &[u8; 32],
    claim: EntityId,
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match bind_claim_in_txn(vault, &mut savepoint, attempt, step, claim) {
        Ok(()) => {
            savepoint.commit()?;
            Ok(())
        }
        Err(error) => {
            drop(savepoint);
            tracing::warn!(
                kind = ?error.kind(),
                "a step's kept request was not bound to its claim; it is not kept"
            );
            remove_step_sources_in_txn(vault, wtxn, attempt, step)
        }
    }
}

/// Stamps `claim` on each step row of `step` of `attempt` that decodes. A
/// row one of whose owners is gone in this write is taken instead of bound
/// (FIX 6252).
fn bind_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    step: &[u8; 32],
    claim: EntityId,
) -> Result<()> {
    let mut bound = Vec::new();
    let mut gone = Vec::new();
    for row in STEPS.iter_raw_from(&vault.store, &*wtxn, &step_prefix(attempt, step))? {
        let (key, bytes) = row?;
        if let Some(key) = StepSourceKey::decode_key(&key)
            && let Ok(mut source) = STEPS.decode_value(&bytes)
        {
            source.claim = Some(claim);
            if crate::llm::owner_gone_in_txn(vault, &*wtxn, &source.owners())? {
                gone.push(key);
            } else {
                bound.push((key, source));
            }
        }
    }
    for key in &gone {
        STEPS.delete(&vault.store, wtxn, key)?;
    }
    for (key, source) in &bound {
        STEPS.put(vault, wtxn, key, source)?;
    }
    Ok(())
}

/// Takes every request kept for `step` of `attempt` (FIX 6659), each lease
/// generation and call of it, in `wtxn`.
pub(crate) fn remove_step_sources_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    step: &[u8; 32],
) -> Result<()> {
    STEPS.delete_from(&vault.store, wtxn, &step_prefix(attempt, step))?;
    Ok(())
}

/// An erase of `actor` takes, in the erase's own writer, each receipt row of
/// a report witnessed for it (its request is that actor's run's) and each
/// step row that stamps it as an owner (FIX 6659): a call it made, a step
/// about it, or one its terminal claim logged, with the request each keeps.
/// A row that does not decode names no owner and stays as it is.
pub(crate) fn erase_blocked_source_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut receipts = Vec::new();
    let mut steps = Vec::new();
    for row in SOURCE.iter_raw_from(&vault.store, &*wtxn, &[])? {
        let (key, bytes) = row?;
        if let Ok(raw) = <[u8; 16]>::try_from(key.as_slice()) {
            if let Ok(source) = SOURCE.decode_value(&bytes)
                && source.reporter == *actor
            {
                receipts.push(EntityId::from_bytes(raw)?);
            }
        } else if let Some(step) = StepSourceKey::decode_key(&key)
            && let Ok(source) = STEPS.decode_value(&bytes)
            && source.owners().contains(actor)
        {
            steps.push(step);
        }
    }
    for receipt in &receipts {
        SOURCE.delete(&vault.store, wtxn, receipt)?;
    }
    for step in &steps {
        STEPS.delete(&vault.store, wtxn, step)?;
    }
    Ok(())
}
