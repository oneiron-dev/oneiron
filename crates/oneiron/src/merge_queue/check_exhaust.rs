//! Queue-check exhaust completion (FIX 7227 CLOSE): SAME fence plus
//! ORIGINAL receipt/approval binding plus private per-field tokens borrowing
//! actual bytes. Called ONLY from `finish_queue_check` after SAME
//! work/lease/attempt checks, in the SAME writer as work/index. No new user
//! refusal on config renew/move during execute; a stale binding is
//! `ConcurrentWrite` (defense, finish already fenced). Legitimate old
//! history (original plan/approval, SAME work/lease/attempt) attaches;
//! CURRENT plan/approval is NEVER re-read for author/scope.
//!
//! Registration DONE (Root applied, A17:12:15+K17:15:20 YES):
//! `mod check_exhaust;` (PRIVATE) plus `pub(crate) use check_exhaust::Token;`
//! at the merge-queue parent; this child imports the public parent aliases
//! (`super::{...}`) plus the pub(crate) BLOB parent fns, never the private
//! child paths. The versions authority names the token via the parent alias.
//!
//! CHECK_REF (hardened): the provenance ref carries ONLY the canonical work
//! ref plus inputs_digest plus generation/attempt plus a global numeric
//! ordinal in walk order (phase Vec order, contract/declared BTreeMap sorted
//! order, stdout/stderr/declared per command). No raw user field name (long
//! or secret-looking LEGIT filenames would otherwise NEW-refuse via the
//! 1024B plus secret_scan grammar); normal names stay as keys in the stored
//! maps. Dedupe is the parent's (same head bytes keep the actual returned
//! version/hash); no new append policy.
//!
//! P2 (qualified): the token carries the ORIGINAL repo/inputs_digest/author
//! (frozen BEFORE exec in `new_receipt`, NOT CURRENT work/config), so the
//! BLOB child materializes with ORIGINAL provenance (no CURRENT broadening).
//! Scope stamps stay default (owner-only, no repo-project copy that could
//! broaden to Member); sensitivity Restricted narrowing is an L02 remainder
//! (see BLOB child docs), NOT faked here. No arbitrary caller id/bytes.

use heed::RwTxn;

use crate::Vault;
use crate::consent::QueuedCheckApproval;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::attempt_id::AttemptId;

use super::{
    QueueCheckOutputRef, QueueCheckReceipt, QueueCheckRun, QueueCheckWork, QueueCommandReceipt,
    StoredQueueCheckReceipt,
};

/// ONE actual output field's unforgeable completion token: borrows the ACTUAL
/// returned bytes, names the FRESH artifact id minted for this receipt, and
/// carries the CLOSED completion binding (original approval + receipt).
/// Fields are private; there is NO public constructor, NO raw-ID/bytes
/// params on the native consumer. Minted ONLY in `store_receipts_in_txn`
/// after SAME-leased + closed-approval validation.
pub(crate) struct QueueCheckFieldToken<'b> {
    bytes: &'b [u8],
    artifact_id: EntityId,
    check_ref: String,
    inputs_digest: String,
    repo: EntityId,
    recorded_actor: EntityId,
}

impl<'b> QueueCheckFieldToken<'b> {
    /// Private mint: caller MUST have validated SAME work/lease/attempt/
    /// generation plus closed approval binding. No `pub` ctor exists.
    fn mint(
        bytes: &'b [u8],
        artifact_id: EntityId,
        check_ref: String,
        inputs_digest: String,
        repo: EntityId,
        recorded_actor: EntityId,
    ) -> Self {
        Self {
            bytes,
            artifact_id,
            check_ref,
            inputs_digest,
            repo,
            recorded_actor,
        }
    }

    pub(crate) fn bytes(&self) -> &'b [u8] {
        self.bytes
    }
    pub(crate) fn artifact_id(&self) -> EntityId {
        self.artifact_id
    }
    pub(crate) fn check_ref(&self) -> &str {
        &self.check_ref
    }
    pub(crate) fn inputs_digest(&self) -> &str {
        &self.inputs_digest
    }
    pub(crate) fn repo(&self) -> EntityId {
        self.repo
    }
    pub(crate) fn recorded_actor(&self) -> EntityId {
        self.recorded_actor
    }
}

/// Validated closed completion binding: SAME work fence (store/repo from
/// CURRENT, stable during Running; attempt/lease/generation fenced) plus
/// ORIGINAL receipt/approval binding (repo/inputs_digest/author from the
/// receipt frozen BEFORE exec, NOT CURRENT plan/config). Runtime prebinding
/// alone is NOT a completed token (L02); this closes over the actual
/// returned receipt in finish. `work_ref` is the canonical request digest
/// (SAME work, stable key); `generation`/`attempt` are the SAME fenced run.
struct ClosedBinding<'a> {
    approval: &'a QueuedCheckApproval,
    repo: EntityId,
    inputs_digest: &'a str,
    recorded_actor: EntityId,
    work_ref: &'a str,
    generation: u32,
    attempt: &'a AttemptId,
}

fn stale(message: &'static str) -> Error {
    Error::ConcurrentWrite(message)
}

/// Convert raw pending receipts to stored refs, in `txn` (SAME finish
/// writer). New actual runs birth ONE fresh native artifact per receipt and
/// append immutable versions per bytefield; retained stored refs are never
/// republished (caller only passes NEW raw receipts; no output read for
/// judge here — judge already ran over bytes before store).
///
/// Required signature (told to Root): KEEP
/// `(vault, txn, &current, raw_receipts)` — NO `&ran` needed (finish already
/// fenced SAME status/attempt/lease; `current` IS the reread ran), NO clock
/// params (native child derives clock in-writer).
pub(crate) fn store_receipts_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    current: &QueueCheckWork,
    raw_receipts: Vec<QueueCheckReceipt>,
) -> Result<Vec<StoredQueueCheckReceipt>> {
    // Global numeric ordinal across every field in walk order (all receipts
    // in this update, all commands/contract/declared per receipt). BTreeMap
    // iteration is sorted (canonical), Vec is plan order, stdout/stderr/
    // declared per command is fixed order: the ordinal is deterministic for
    // the same inputs, unique per field, and carries NO raw user name.
    let mut ordinal: u64 = 0;
    let mut stored = Vec::with_capacity(raw_receipts.len());
    for raw in raw_receipts {
        stored.push(store_one_receipt_in_txn(
            vault,
            txn,
            current,
            raw,
            &mut ordinal,
        )?);
    }
    Ok(stored)
}

fn store_one_receipt_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    current: &QueueCheckWork,
    raw: QueueCheckReceipt,
    ordinal: &mut u64,
) -> Result<StoredQueueCheckReceipt> {
    // Metadata-only receipts (Held/Needs/Reused with no run): no artifact,
    // clear runtime proof (serde skip anyway, defense).
    let Some(raw_run) = raw.run else {
        return Ok(StoredQueueCheckReceipt {
            inputs_digest: raw.inputs_digest,
            inputs: raw.inputs,
            recorded_actor: raw.recorded_actor,
            completion_approval: None,
            attempt: raw.attempt,
            attempt_count: raw.attempt_count,
            lease_owner: raw.lease_owner,
            generation: raw.generation,
            run: None,
            hold: raw.hold,
            need: raw.need,
            reused_from: raw.reused_from,
            tests_passed: raw.tests_passed,
            verdict_ref: raw.verdict_ref,
        });
    };

    // Actual run: require runtime proof cloned at new_receipt BEFORE execute.
    let approval = raw.completion_approval.as_ref().ok_or_else(|| {
        stale("a queue-check completion without its runtime approval attaches nothing")
    })?;

    // TOKEN hardening (CLOSE): validate against the ORIGINAL receipt plus
    // approval (frozen BEFORE exec), NOT CURRENT work/config (which may have
    // renewed/moved during execute). A renew/move must NOT reject legitimate
    // old history; CURRENT is used ONLY for the SAME fence (store/repo,
    // stable for this Running work; attempt/lease/generation, stable during
    // Running and already fenced by finish). No CURRENT plan/approval
    // re-read for author, and no fresh authority from CURRENT.
    if !approval.matches_completion_binding(raw.inputs.repo, &raw.inputs.plan_digest) {
        return Err(stale(
            "a queue-check completion for another plan attaches nothing",
        ));
    }
    // The receipt digest binds its inputs (frozen as inputs.digest() BEFORE
    // exec); a mismatch attaches nothing (defense, ConcurrentWrite like the
    // other binding failures, no new user refusal).
    let recomputed = raw
        .inputs
        .digest()
        .map_err(|_| stale("a queue-check completion with undecodable inputs attaches nothing"))?;
    if recomputed != raw.inputs_digest {
        return Err(stale(
            "a queue-check completion for another input attaches nothing",
        ));
    }
    if raw.recorded_actor != approval.recorded_actor() {
        return Err(stale(
            "a queue-check completion with mismatched author attaches nothing",
        ));
    }
    // SAME work identity (store plus repo, never updated for an existing
    // Running work) plus SAME attempt/lease/generation fence. No CURRENT
    // plan check: the ORIGINAL plan above (approval plus inputs) binds.
    if raw.inputs.store != current.store || raw.inputs.repo != current.repo {
        return Err(stale(
            "a queue-check completion for another work attaches nothing",
        ));
    }
    if current.attempt.as_ref() != Some(&raw.attempt)
        || raw.generation != current.generation
        || current.lease.as_ref().is_none_or(|lease| {
            raw.lease_owner != lease.owner || raw.attempt_count != lease.attempt_count
        })
    {
        return Err(stale("a stale queue-check completion attaches nothing"));
    }

    let binding = ClosedBinding {
        approval,
        repo: raw.inputs.repo,
        inputs_digest: &raw.inputs_digest,
        recorded_actor: raw.recorded_actor,
        work_ref: current.work_ref(),
        generation: raw.generation,
        attempt: &raw.attempt,
    };

    // ONE fresh native artifact id for this receipt (native clock, NOT hash).
    // Minted in native child (provenance/clock owner); no authority in mint.
    let artifact_id = crate::blob_artifact::mint_queue_check_artifact_id(vault)?;

    // Per-field tokens share the artifact; versions chain within it. The
    // global ordinal keeps walk order (phase Vec order, contract BTreeMap
    // sorted order); normal names stay as keys in the stored maps, never in
    // the provenance ref.
    let mut stored_commands = Vec::with_capacity(raw_run.commands.len());
    for command in raw_run.commands.iter() {
        stored_commands.push(store_command_in_txn(
            vault,
            txn,
            &binding,
            artifact_id,
            ordinal,
            command,
        )?);
    }
    let mut stored_contract = std::collections::BTreeMap::new();
    for (name, command) in raw_run.contract_outputs.iter() {
        // Contract names stay as keys (existing semantics); the ref is numeric.
        stored_contract.insert(
            name.clone(),
            store_command_in_txn(vault, txn, &binding, artifact_id, ordinal, command)?,
        );
    }

    let stored_run = QueueCheckRun {
        commands: stored_commands,
        contract_outputs: stored_contract,
        session: raw_run.session,
        input_before: raw_run.input_before,
        input_after: raw_run.input_after,
    };

    Ok(StoredQueueCheckReceipt {
        inputs_digest: raw.inputs_digest,
        inputs: raw.inputs,
        recorded_actor: raw.recorded_actor,
        completion_approval: None,
        attempt: raw.attempt,
        attempt_count: raw.attempt_count,
        lease_owner: raw.lease_owner,
        generation: raw.generation,
        run: Some(stored_run),
        hold: raw.hold,
        need: raw.need,
        reused_from: raw.reused_from,
        tests_passed: raw.tests_passed,
        verdict_ref: raw.verdict_ref,
    })
}

/// Store ONE command's bytefields (stdout/stderr/declared) as immutable
/// version refs. Empty bytes are valid (truthful empty version). Dedupe is
/// the native append's (exact-head-bytes no-op); the returned ref is the
/// EXACT version/hash the native append committed.
fn store_command_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    binding: &ClosedBinding<'_>,
    artifact_id: EntityId,
    ordinal: &mut u64,
    command: &QueueCommandReceipt,
) -> Result<QueueCommandReceipt<QueueCheckOutputRef>> {
    // Fixed per-command order (stdout, stderr, then declared in BTreeMap
    // sorted order): deterministic for the same inputs, unique via the
    // global ordinal, NO raw user name in the ref.
    let stdout = store_field_in_txn(vault, txn, binding, artifact_id, ordinal, &command.stdout)?;
    let stderr = store_field_in_txn(vault, txn, binding, artifact_id, ordinal, &command.stderr)?;
    let mut declared = std::collections::BTreeMap::new();
    for (name, bytes) in command.declared_outputs.iter() {
        // Declared paths stay as keys (existing semantics); the ref is numeric.
        declared.insert(
            name.clone(),
            store_field_in_txn(vault, txn, binding, artifact_id, ordinal, bytes)?,
        );
    }
    Ok(QueueCommandReceipt {
        argv: command.argv.clone(),
        status: command.status,
        signal: command.signal,
        stdout,
        stderr,
        declared_outputs: declared,
    })
}

fn store_field_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    binding: &ClosedBinding<'_>,
    artifact_id: EntityId,
    ordinal: &mut u64,
    bytes: &[u8],
) -> Result<QueueCheckOutputRef> {
    // Bounded honest check_ref: canonical work ref plus ORIGINAL
    // inputs_digest plus SAME generation/attempt plus global numeric ordinal
    // in walk order. No raw user field name (contract/declared names would
    // otherwise NEW-refuse via 1024B/secret_scan); the artifact BODY name
    // stays fixed generic (never this). Provenance validation enforces the
    // grammar; total length stays well under 1024B (hex plus numbers).
    let check_ref = format!(
        "queue-check:v1:{}:{}:{}:{:?}:{}",
        binding.work_ref, binding.inputs_digest, binding.generation, binding.attempt, *ordinal,
    );
    *ordinal += 1;
    let _ = binding.approval;
    let token = QueueCheckFieldToken::mint(
        bytes,
        artifact_id,
        check_ref,
        binding.inputs_digest.to_owned(),
        binding.repo,
        binding.recorded_actor,
    );
    crate::blob_artifact::append_queue_check_output_in_txn(vault, txn, &token)
}
