//! A capsule's bodies, admitted and published in the capsule's own writer
//! (FIX 6144, KEY STORE = A): the request (its canonical JSON), the step's
//! start (its MessagePack, the run's row inside it) and a contribution
//! fork's answer each go through the side-row wall's body admission, with
//! the vault's custody door and an origin named by the capsule's key, so no
//! secret in them reaches a body file: each is its custody handle. A body is
//! published from the masked bytes in the transaction that mints their
//! custody records and puts the capsule, and its ref and digest are the
//! masked bytes'. The live request a provider is sent is never touched, and
//! a body past the inline bound still spills whole: nothing is capped. A
//! request the wall refuses outright is withheld, never stored raw: the
//! capsule keeps the step's start without it when the start admits, so a
//! continuation still finds its checkpoint (FIX 6254).

use std::borrow::Cow;
use std::ops::Range;

use heed::RwTxn;

use super::super::super::replay_capsule::{
    CapsuleContent, CapsuleDraft, CapsuleRequest, ExecutorStepStart, ExposureSlot, StepCapture,
    StepReplayCapsule, StepStartBody, StepStartCapture, StoredSpan,
};
use super::super::records::{REPLAY_RECORDS, finish_output};
use super::super::spawn_erase::fence_spawn_targets_in_txn;
use super::erase::actor_gone_in_txn;
use super::{CAPSULES, capsule_key};
use crate::batch::secret_scan::{
    SidePart, TextReplacements, admit_side_parts, admit_tracked_side_parts,
};
use crate::code_run::{decode_code_run_replay_record, encode_code_run_replay_record};
use crate::compaction::output::OutputRef;
use crate::error::GateError;
use crate::store::{BodyMint, BodySink};
use crate::{ContentPart, EntityId, Error, LlmRequest, LlmResponse, Result, Vault};

/// Where the wall's custody records name what they lifted from a capsule's
/// request, start and fork answers, beside the capsule's key.
const REQUEST_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:request";
const START_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:start";
const RESPONSE_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:fork_response";

/// Why a capsule writer's transaction rolled back.
enum Unwritten {
    /// Its masked bodies past the inline bound need this many body
    /// instances, minted before a writer opens: a writer never mints.
    Unreserved(usize),
    Failed(Error),
}

impl From<Error> for Unwritten {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// How many bodies of `lens` bytes spill past `bound`.
fn spilling(bound: u64, lens: &[usize]) -> usize {
    lens.iter().filter(|&&len| len as u64 > bound).count()
}

/// Where a writer's bodies go: inline within the bound, past it into the
/// instances minted before the writer opened.
struct Spill {
    bound: u64,
    mint: BodyMint,
    reserved: usize,
}

impl Spill {
    /// Rolls the writer back, before anything spills, when bodies of `lens`
    /// bytes need more instances than it holds.
    fn holds(&self, lens: &[usize]) -> std::result::Result<(), Unwritten> {
        let needed = spilling(self.bound, lens);
        if needed > self.reserved {
            return Err(Unwritten::Unreserved(needed));
        }
        Ok(())
    }

    /// Publishes `bytes` as the complete body run `owner` holds at `path`, in
    /// `wtxn`: its row, the secret mark of the run's occurrence when the
    /// sink's own scan hits, and its descriptor. Its size is measured.
    fn publish_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        owner: EntityId,
        path: &str,
        bytes: &[u8],
    ) -> Result<OutputRef> {
        let mut sink = BodySink::new(vault.store.body_dir()?, self.bound, Some(self.mint.clone()));
        sink.write(bytes)?;
        let finished = finish_output(path.to_owned(), sink, true, vault.limit_watch(), |digest| {
            vault.pin_result_body(digest)
        })?;
        vault.put_code_run_output_in_txn(wtxn, &finished, &finished.output, Some(owner))?;
        tracing::debug!(bytes = bytes.len(), "a replay capsule body is published");
        Ok(finished.output.output_ref())
    }
}

/// Runs `write` in one write transaction with `reserved` body instances
/// minted before it opens. When its masked bodies need more, it rolls back,
/// and runs again with as many minted first.
fn with_spill<T>(
    vault: &Vault,
    mut reserved: usize,
    write: impl Fn(&mut RwTxn<'_>, &Spill) -> std::result::Result<T, Unwritten>,
) -> Result<T> {
    let bound = vault.code_result_inline_bytes();
    loop {
        let spill = Spill {
            bound,
            mint: vault.store.body_mint()?.reserve(reserved)?,
            reserved,
        };
        match vault.try_with_write_txn_grouped(|wtxn| write(wtxn, &spill)) {
            Ok(written) => return Ok(written),
            Err(Unwritten::Unreserved(needed)) if needed > reserved => reserved = needed,
            Err(Unwritten::Unreserved(_)) => {
                return Err(Error::InvariantViolation(
                    "a capsule body spilled past the instances minted for it",
                ));
            }
            Err(Unwritten::Failed(error)) => return Err(error),
        }
    }
}

/// Writes `draft` as its attempt's capsule: its request and start bodies as
/// the wall admits them, published, and its row, in one transaction. `None`,
/// with nothing written, when the step's actor is gone by now.
pub(crate) fn put_staged_capsule(
    vault: &Vault,
    draft: &CapsuleDraft<'_>,
) -> Result<Option<StepReplayCapsule>> {
    let lens = [draft.request.len(), start_estimate(vault, draft.capture)?];
    let reserved = spilling(vault.code_result_inline_bytes(), &lens);
    with_spill(vault, reserved, |wtxn, spill| {
        write_capsule_in_txn(vault, wtxn, spill, draft)
    })
}

/// About how large the step's start body is, read before the writer opens:
/// at most twice the run's row as stored (its bytes ride as MessagePack
/// integers), and the task.
fn start_estimate(vault: &Vault, capture: &StepCapture<'_>) -> Result<usize> {
    if capture.start.is_none() {
        return Ok(0);
    }
    let rtxn = vault.store.env.read_txn()?;
    let row = REPLAY_RECORDS
        .get_borrowed(&vault.store, &rtxn, &capture.run)?
        .as_deref()
        .map_or(0, <[u8]>::len);
    Ok(row.saturating_mul(2).saturating_add(capture.task.len()))
}

/// The capsule's bodies admitted and published, and its row put, in `wtxn`.
fn write_capsule_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    spill: &Spill,
    draft: &CapsuleDraft<'_>,
) -> std::result::Result<Option<StepReplayCapsule>, Unwritten> {
    // A capture after its actor is gone writes nothing: the erase has run,
    // or runs, over what it would keep.
    if actor_gone_in_txn(vault, wtxn, &draft.actor) {
        return Ok(None);
    }
    let key = draft.key();
    let key_bytes = CAPSULES.key_bytes(&key);
    let (capture, actor) = (draft.capture, draft.actor);
    let run = capture.run;
    let admitted = admit_request_or_refusal_in_txn(vault, wtxn, &key_bytes, &draft.request)?;
    let start = admit_start_in_txn(vault, wtxn, &key_bytes, capture)?;
    // FIX 6254: a request the wall refused outright is withheld, and the
    // capsule keeps the step's start without it. With no start to keep, it
    // is not written, as before.
    let request = match admitted {
        Ok(request) => request,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) if start.is_some() => {
            tracing::debug!("a step's request is withheld; its capsule keeps the start");
            return write_withheld_in_txn(vault, wtxn, spill, draft, start, &reason_codes);
        }
        Err(refusal) => return Err(refusal.into()),
    };
    let start_len = start.as_ref().map_or(0, |(bytes, _)| bytes.len());
    spill.holds(&[request.bytes.len(), start_len])?;
    let stored = &request.bytes;
    let request_ref = spill.publish_in_txn(vault, wtxn, run, &draft.request_path, stored)?;
    let start = publish_start_in_txn(vault, wtxn, spill, draft, start)?;
    let capsule = StepReplayCapsule {
        attempt: draft.attempt,
        lease_generation: capture.lease_generation,
        run,
        step: capture.step,
        host: capture.host,
        request: CapsuleRequest::Kept {
            body: request_ref,
            path: draft.request_path.clone(),
            stored_hash: *blake3::hash(stored).as_bytes(),
        },
        request_hash: *blake3::hash(&draft.request).as_bytes(),
        messages_digest: draft.messages_digest,
        source_rows: capture.source_rows.clone(),
        exposures: stored_slots(&draft.exposures, capture.request, &request),
        seed: request_seed(capture),
        binding: None,
        route_pin: None,
        captured_at: crate::unix_seconds_now(),
        start,
        content: CapsuleContent::Kept { actor },
    };
    CAPSULES.put(vault, wtxn, &key, &capsule)?;
    Ok(Some(capsule))
}

/// The capsule of a step whose request the wall refused outright (FIX
/// 6254), in `wtxn`: its start published and its row put, the request
/// withheld for `reasons`, each exposure kept without a stored span.
fn write_withheld_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    spill: &Spill,
    draft: &CapsuleDraft<'_>,
    start: Option<(Vec<u8>, u64)>,
    reasons: &[&'static str],
) -> std::result::Result<Option<StepReplayCapsule>, Unwritten> {
    let capture = draft.capture;
    let start_len = start.as_ref().map_or(0, |(bytes, _)| bytes.len());
    spill.holds(&[0, start_len])?;
    let start = publish_start_in_txn(vault, wtxn, spill, draft, start)?;
    let capsule = StepReplayCapsule {
        attempt: draft.attempt,
        lease_generation: capture.lease_generation,
        run: capture.run,
        step: capture.step,
        host: capture.host,
        request: CapsuleRequest::Withheld {
            reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
        },
        request_hash: *blake3::hash(&draft.request).as_bytes(),
        messages_digest: draft.messages_digest,
        source_rows: capture.source_rows.clone(),
        exposures: draft
            .exposures
            .iter()
            .map(|slot| ExposureSlot {
                stored: None,
                ..slot.clone()
            })
            .collect(),
        seed: request_seed(capture),
        binding: None,
        route_pin: None,
        captured_at: crate::unix_seconds_now(),
        start,
        content: CapsuleContent::Kept { actor: draft.actor },
    };
    CAPSULES.put(vault, wtxn, &draft.key(), &capsule)?;
    Ok(Some(capsule))
}

/// The sampling seed the request as sent carried, if any.
fn request_seed(capture: &StepCapture<'_>) -> Option<u64> {
    capture
        .request
        .params
        .get("seed")
        .and_then(serde_json::Value::as_u64)
}

/// The step's start, admitted before, published as a body the run owns.
fn publish_start_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    spill: &Spill,
    draft: &CapsuleDraft<'_>,
    start: Option<(Vec<u8>, u64)>,
) -> Result<Option<ExecutorStepStart>> {
    let run = draft.capture.run;
    Ok(match start {
        Some((bytes, bridge_start)) => Some(ExecutorStepStart {
            body: spill.publish_in_txn(vault, wtxn, run, &draft.start_path, &bytes)?,
            path: draft.start_path.clone(),
            digest: *blake3::hash(&bytes).as_bytes(),
            bridge_start,
        }),
        None => None,
    })
}

/// A request as the wall admitted it: its canonical bytes as stored, its
/// typed copy, and where each handle went in each text the wall masked;
/// `None` there when it was written as given.
struct AdmittedRequest {
    bytes: Vec<u8>,
    request: LlmRequest,
    replaced: Option<TextReplacements>,
}

/// [`admit_request_in_txn`] in a savepoint of `wtxn`: the request as the
/// wall admits it, or the error its admission met with nothing it wrote
/// kept. A refusal of the wall's is a withheld request (FIX 6254).
fn admit_request_or_refusal_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8],
    sent: &[u8],
) -> Result<std::result::Result<AdmittedRequest, Error>> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match admit_request_in_txn(vault, &mut savepoint, key, sent) {
        Ok(admitted) => {
            savepoint.commit()?;
            Ok(Ok(admitted))
        }
        Err(error) => Ok(Err(error)),
    }
}

/// `sent`, a request's canonical bytes as sent, through the wall's tracked
/// body admission under the capsule's `key`, and made canonical again once
/// masked, so its stored hash is the stored bytes'.
fn admit_request_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8],
    sent: &[u8],
) -> Result<AdmittedRequest> {
    let mut parts = [SidePart::Body(sent.to_vec())];
    let at = (REQUEST_PLACE, key);
    let replaced = admit_tracked_side_parts(vault, wtxn, at, &mut parts, reads_request)?;
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted capsule request is no longer a body",
        ));
    };
    let request: LlmRequest = serde_json::from_slice(&admitted)
        .map_err(|error| Error::InvalidConfig(format!("capsule request: {error}")))?;
    let bytes = if replaced.is_some() {
        request
            .canonical_bytes()
            .map_err(|error| Error::InvalidConfig(format!("capsule request: {error}")))?
    } else {
        admitted
    };
    Ok(AdmittedRequest {
        bytes,
        request,
        replaced,
    })
}

/// Whether an admitted copy still reads as a request.
fn reads_request(parts: &[SidePart]) -> bool {
    matches!(parts, [SidePart::Body(body)] if serde_json::from_slice::<LlmRequest>(body).is_ok())
}

/// The step's start as the wall admits it, with the bridge log's length at
/// it, in a savepoint of `wtxn`. `None`, the savepoint rolled back and the
/// capsule written without a start, for a workflow step, when no row is
/// stored or the stored row is not the one the step starts from, and when
/// the wall refuses the body, which is logged.
fn admit_start_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8],
    capture: &StepCapture<'_>,
) -> Result<Option<(Vec<u8>, u64)>> {
    let Some(start) = &capture.start else {
        return Ok(None);
    };
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match admitted_start(vault, &mut savepoint, key, capture, start) {
        Ok(Some(admitted)) => {
            savepoint.commit()?;
            Ok(Some(admitted))
        }
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a step start was not captured");
            Ok(None)
        }
    }
}

/// The start body from one admitted view of the run's row: the row as
/// stored, read as the wall would store it now and kept so where that
/// differs, and the prefix the body carries taken from that same view, so
/// the run's row still descends from it byte for byte. The body goes through
/// the wall too, and the prefix it carries must come back as it went in.
fn admitted_start(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    key: &[u8],
    capture: &StepCapture<'_>,
    start: &StepStartCapture<'_>,
) -> Result<Option<(Vec<u8>, u64)>> {
    let Some(stored) = REPLAY_RECORDS.get(&vault.store, wtxn, &capture.run)? else {
        return Ok(None);
    };
    let generation = stored.generation()?;
    if generation != start.record.generation()? {
        return Ok(None);
    }
    let mut source = stored.clone();
    REPLAY_RECORDS.admit(vault, wtxn, &capture.run, &mut source)?;
    // A spawn whose target an erase took keeps no ask in the row or in the
    // prefix taken from it (FIX 9180).
    let source = fence_spawn_targets_in_txn(&vault.store, wtxn, Cow::Owned(source))?.into_owned();
    if source != stored {
        if source.generation()? != generation {
            return Ok(None);
        }
        REPLAY_RECORDS.put(vault, wtxn, &capture.run, &source)?;
    }
    let mut prefix = source;
    prefix.live_run = None;
    let record = encode_code_run_replay_record(&prefix)?;
    let body = StepStartBody {
        record: record.clone(),
        task: capture.task.to_owned(),
        model: start.model.clone(),
        model_locality: start.model_locality,
        seat_effort: start.seat_effort,
        global_tier: start.global_tier.clone(),
        soft_steps: start.soft_steps,
        prompt_fingerprint: start.prompt_fingerprint.to_owned(),
    };
    let mut parts = [SidePart::Body(encode_start(&body)?)];
    admit_side_parts(vault, wtxn, (START_PLACE, key), &mut parts, reads_start)?;
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted step start is no longer a body",
        ));
    };
    let body = decode_start(&admitted)?;
    if body.record != record {
        return Err(Error::InvariantViolation(
            "the wall changed a step start's admitted prefix",
        ));
    }
    Ok(Some((
        encode_start(&body)?,
        prefix.bridge_calls.len() as u64,
    )))
}

fn encode_start(body: &StepStartBody) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(body)
        .map_err(|error| Error::InvalidConfig(format!("capsule start: {error}")))
}

fn decode_start(bytes: &[u8]) -> Result<StepStartBody> {
    rmp_serde::from_slice(bytes)
        .map_err(|error| Error::InvalidConfig(format!("capsule start: {error}")))
}

/// Whether an admitted copy still reads as a start, its prefix row too.
fn reads_start(parts: &[SidePart]) -> bool {
    let [SidePart::Body(body)] = parts else {
        return false;
    };
    rmp_serde::from_slice::<StepStartBody>(body)
        .is_ok_and(|start| decode_code_run_replay_record(&start.record).is_ok())
}

/// `slots`, located in `sent`, moved to where they sit in the request as
/// the wall admitted it.
fn stored_slots(
    slots: &[ExposureSlot],
    sent: &LlmRequest,
    admitted: &AdmittedRequest,
) -> Vec<ExposureSlot> {
    let Some(replaced) = &admitted.replaced else {
        return slots.to_vec();
    };
    slots
        .iter()
        .map(|slot| ExposureSlot {
            stored: stored_span(slot, sent, &admitted.request, replaced),
            ..slot.clone()
        })
        .collect()
}

/// Where `slot` sits in `stored`, the request as the wall admitted it: its
/// bounds moved by the replacements the wall made in its text, and the hash
/// of the masked bytes between them. `None` when a bound falls inside a
/// replaced span, or the text changed by more than those replacements.
fn stored_span(
    slot: &ExposureSlot,
    sent: &LlmRequest,
    stored: &LlmRequest,
    replaced: &TextReplacements,
) -> Option<StoredSpan> {
    let span = slot.stored?;
    let (sent_text, stored_text) = (text_part(sent, slot)?, text_part(stored, slot)?);
    let Some(moves) = replaced.get(blake3::hash(sent_text.as_bytes()).as_bytes()) else {
        // The wall left this text as it was.
        return (sent_text == stored_text).then_some(span);
    };
    if !moved_only(sent_text, stored_text, moves) {
        return None;
    }
    let start = remap_bound(usize::try_from(span.start).ok()?, moves)?;
    let end = remap_bound(usize::try_from(span.end).ok()?, moves)?;
    let bytes = stored_text.get(start..end)?;
    Some(StoredSpan {
        start: start as u64,
        end: end as u64,
        content_hash: *blake3::hash(bytes.as_bytes()).as_bytes(),
    })
}

/// Where `bound`, a byte offset in a text as sent, is in the text as the
/// wall masked it, by the replacements it made there in order (FIX 6144):
/// moved past each one before it. `None` when it falls inside a replaced
/// span, where a secret's handle now stands: an exposure cut there is
/// unavailable, never guessed at.
fn remap_bound(bound: usize, moves: &[(Range<usize>, Range<usize>)]) -> Option<usize> {
    let mut moved = bound;
    for (replaced, handle) in moves {
        if bound <= replaced.start {
            break;
        }
        if bound < replaced.end {
            return None;
        }
        moved = handle.end + (bound - replaced.end);
    }
    Some(moved)
}

/// Whether `stored` is `sent` with exactly `moves` made: every byte outside
/// the replaced spans where the moves put it.
fn moved_only(sent: &str, stored: &str, moves: &[(Range<usize>, Range<usize>)]) -> bool {
    let (sent, stored) = (sent.as_bytes(), stored.as_bytes());
    let (mut from, mut to) = (0, 0);
    for (cut, put) in moves {
        if !same_bytes(sent.get(from..cut.start), stored.get(to..put.start)) {
            return false;
        }
        (from, to) = (cut.end, put.end);
    }
    same_bytes(sent.get(from..), stored.get(to..))
}

/// Whether both are there and the same bytes.
fn same_bytes(kept: Option<&[u8]>, held: Option<&[u8]>) -> bool {
    kept.is_some() && kept == held
}

/// The text of `slot`'s part in `request`.
fn text_part<'r>(request: &'r LlmRequest, slot: &ExposureSlot) -> Option<&'r str> {
    let message = request.messages.get(usize::try_from(slot.message).ok()?)?;
    match message.content.get(usize::try_from(slot.part).ok()?)? {
        ContentPart::Text { text } => Some(text.as_str()),
        _ => None,
    }
}

/// Stores a fork's answer as a body the original run owns, admitted as the
/// capsule's own bodies are, in a writer that reads the capsule again first:
/// `None`, with nothing written, once the capsule is erased or gone, or its
/// actor is (FIX 6144).
pub(crate) fn store_fork_response(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    path: &str,
    response: &LlmResponse,
) -> Result<Option<OutputRef>> {
    let sent = serde_json::to_vec(response)
        .map_err(|error| Error::InvalidConfig(format!("fork response: {error}")))?;
    let key = capsule_key(capsule);
    let reserved = spilling(vault.code_result_inline_bytes(), &[sent.len()]);
    with_spill(vault, reserved, |wtxn, spill| {
        let Some(held) = CAPSULES.get(&vault.store, wtxn, &key)? else {
            return Ok(None);
        };
        let Some(actor) = held.content.actor() else {
            return Ok(None);
        };
        if actor_gone_in_txn(vault, wtxn, &actor) {
            return Ok(None);
        }
        let key_bytes = CAPSULES.key_bytes(&key);
        let mut parts = [SidePart::Body(sent.clone())];
        let at = (RESPONSE_PLACE, key_bytes.as_slice());
        let bytes = if admit_side_parts(vault, wtxn, at, &mut parts, reads_response)? {
            admitted_response(&parts)?
        } else {
            sent.clone()
        };
        spill.holds(&[bytes.len()])?;
        Ok(Some(
            spill.publish_in_txn(vault, wtxn, held.run, path, &bytes)?,
        ))
    })
}

/// A fork's answer as the wall admitted it, encoded again from its typed
/// copy.
fn admitted_response(parts: &[SidePart]) -> Result<Vec<u8>> {
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted fork answer is no longer a body",
        ));
    };
    let response: LlmResponse = serde_json::from_slice(admitted)
        .map_err(|error| Error::InvalidConfig(format!("fork response: {error}")))?;
    serde_json::to_vec(&response)
        .map_err(|error| Error::InvalidConfig(format!("fork response: {error}")))
}

/// Whether an admitted copy still reads as a model's answer.
fn reads_response(parts: &[SidePart]) -> bool {
    matches!(parts, [SidePart::Body(body)] if serde_json::from_slice::<LlmResponse>(body).is_ok())
}
