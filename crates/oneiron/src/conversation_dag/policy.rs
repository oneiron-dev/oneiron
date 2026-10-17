//! Actor-bound write-policy preflight for the append operation, and the
//! caller binding of its two public doors (OF-063): every typed ref an
//! append names reads for its writer in the append's own transaction, and
//! an AI writer's prose links are receipted when they do not. The stages are
//! crate-visible for appends made inside another door's writer, such as a
//! summary's header reply.

use super::{AppendRecord, AppendedRecord};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimReadStatus, ClaimSource,
    ClaimSubject, ScopedRead,
};
use crate::error::{Error, ErrorKind, Result};
use crate::gate::record_references::{PROSE_LINK_SCHEME, admit_prose_text, invented_reference};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};
use crate::{EdgeActorClass, EntityId, Vault, WriteEnvelope, WriteProvenance};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// The row an append's receipts name.
pub(crate) const APPEND_ROW: &str = "conversation.append_record";
/// The row a thread reply's receipts name.
pub(super) const REPLY_ROW: &str = "conversation.reply_in_thread";
/// The longest field pointer a reference-refusal receipt holds.
const MAX_POINTER_BYTES: usize = 256;

/// Why a caller-bound append did not land.
pub(crate) enum AppendFailure {
    /// The engine refused or failed the append.
    Engine(Error),
    /// The ref at this pointer does not read for the writer; the append's
    /// transaction aborted with nothing staged.
    Unresolved(String),
}

impl From<Error> for AppendFailure {
    fn from(error: Error) -> Self {
        Self::Engine(error)
    }
}

/// What a public append does before its write transaction: `writer` must be
/// this vault's surface for the byline `input` names, and the writer's read
/// lane is opened here, since it takes its own snapshot and so never runs
/// inside the writer. An AI writer's prose links are receipted only once the
/// append has landed ([`settle_append`]).
pub(super) fn open_append<'m>(
    vault: &Vault,
    writer: &'m Memory<'_>,
    row: &'static str,
    input: &AppendRecord,
) -> MemoryResult<ScopedRead<'m>> {
    if !std::ptr::eq(writer.vault(), vault)
        || writer.actor() != input.actor.entity_ref()
        || writer.actor_class() != input.actor.actor_class()
    {
        return Err(MemoryError::bad_request(
            "the append's byline is not its writer's",
        ));
    }
    writer.read_lane(ClaimReadStatus::Recorded)
}

/// The typed refs an append names, each at its pointer: the conversation,
/// the parent (a thread reply's is the door's, checked once chosen), the
/// reply target, the quoted MESSAGE, the session, the thread's trunk and
/// every recipient. Ids are typed; no body field or prose is read as a ref.
pub(crate) fn append_references(
    input: &AppendRecord,
    trunk: Option<EntityId>,
) -> Vec<(String, EntityId)> {
    let mut refs = vec![("/conversation".to_owned(), input.conversation)];
    if trunk.is_none()
        && let Some(parent) = input.parent
    {
        refs.push(("/parent".to_owned(), parent));
    }
    if let Some(reply_to) = input.reply_to {
        refs.push(("/reply_to".to_owned(), reply_to));
    }
    if let Some(quote) = input.quote {
        refs.push(("/quote/message".to_owned(), quote.message));
    }
    if let Some(session) = input.session {
        refs.push(("/session".to_owned(), session));
    }
    if let Some(trunk) = trunk {
        refs.push(("/thread_ref".to_owned(), trunk));
    }
    for (index, recipient) in input.recipients.iter().enumerate() {
        refs.push((format!("/recipients/{index}"), *recipient));
    }
    refs
}

/// The pointer of the first of `refs` the writer's `lane` does not read in
/// this write transaction: an invented, a missing and an unreadable record
/// are one answer. The lane rechecks live grants, deletion and policy here.
pub(super) fn unresolved_append_reference_in_txn(
    lane: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    refs: &[(String, EntityId)],
) -> Result<Option<String>> {
    let ids: Vec<EntityId> = refs.iter().map(|(_, id)| *id).collect();
    let readable = lane.entities_readable_in_txn(txn, &ids)?;
    Ok(refs
        .iter()
        .zip(readable)
        .find(|(_, readable)| !readable)
        .map(|((pointer, _), _)| pointer.clone()))
}

/// [`unresolved_append_reference_in_txn`] over `refs`, then over the TURN
/// holding a quoted MESSAGE: the MESSAGE is read first, so an unreadable one
/// says nothing of its TURN.
pub(crate) fn require_append_references_in_txn(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    input: &AppendRecord,
    refs: &[(String, EntityId)],
) -> std::result::Result<(), AppendFailure> {
    if let Some(pointer) = unresolved_append_reference_in_txn(lane, txn, refs)? {
        return Err(AppendFailure::Unresolved(pointer));
    }
    if let Some(quote) = input.quote {
        let turn = super::quote::owning_turn_in(&vault.store, txn, &quote.message)?;
        if let Some(pointer) =
            unresolved_append_reference_in_txn(lane, txn, &[("/quote/turn".to_owned(), turn)])?
        {
            return Err(AppendFailure::Unresolved(pointer));
        }
    }
    Ok(())
}

/// A caller-bound append's answer. An unresolved ref is receipted only now,
/// once the refused append's transaction has aborted.
pub(super) fn settle_append(
    writer: &Memory<'_>,
    row: &'static str,
    input: &AppendRecord,
    outcome: std::result::Result<AppendedRecord, AppendFailure>,
) -> MemoryResult<AppendedRecord> {
    match outcome {
        // The unlinked-prose receipt means landed speech only (Engine ruling
        // 10-18): an append that never landed leaves none.
        Ok(appended) => {
            admit_append_prose(writer, row, input);
            Ok(appended)
        }
        Err(AppendFailure::Engine(error)) => Err(append_engine_error(error)),
        Err(AppendFailure::Unresolved(pointer)) => {
            Err(receipt_append_refusal(writer, row, &pointer))
        }
    }
}

/// An engine refusal of an append, answered as the DAG doors always have: a
/// conversation's or HEAD's state is a conflict, and a writer the
/// conversation denies is refused its standing, not its request's form.
fn append_engine_error(error: Error) -> MemoryError {
    let code = match error.kind() {
        ErrorKind::ConversationDenied => MEMORY_CODE_FORBIDDEN,
        ErrorKind::ConversationState
        | ErrorKind::HeadAdvanceOffTrunk
        | ErrorKind::DagParentOutsideConversation
        | ErrorKind::CycleDetected
        | ErrorKind::ChildOfCardinality => MEMORY_CODE_INVALID_STATE,
        _ => return error.into(),
    };
    MemoryError::new(code, error.to_string(), &[])
}

/// Receipts a refused append on its own write, naming the writer, `row` and
/// the field pointer, never the ref, and returns the refusal; if the receipt
/// cannot be written, the store's error instead. Inside an anonymous
/// off-record session the refusal stands with no receipt.
pub(crate) fn receipt_append_refusal(
    writer: &Memory<'_>,
    row: &'static str,
    pointer: &str,
) -> MemoryError {
    let facts = ReferenceRefusalFacts {
        actor: writer.actor(),
        actor_class: writer.actor_class(),
        row,
        field: pointer.to_owned(),
        outcome: ReferenceOutcome::Refused,
    };
    match receipt_reference_refusals(writer, &[facts]) {
        Ok(recorded) => invented_reference(pointer, recorded),
        Err(error) => error.into(),
    }
}

/// An AI writer's TURN prose, read for `oneiron://` links as a streamed
/// finalize reads its text: each explicit text field at `/text/{index}/1`
/// and each top-level string of the body at `/body/<key>`, a text held in
/// both read once. A link that does not resolve for the writer leaves an
/// `unlinked` receipt; the text is never refused or rewritten. A body that
/// does not decode is refused later, by the append.
pub(crate) fn admit_append_prose(writer: &Memory<'_>, row: &'static str, input: &AppendRecord) {
    if writer.actor_class() == EdgeActorClass::Human {
        return;
    }
    let mut bytes = input.body.as_slice();
    let body = rmpv::decode::read_value(&mut bytes).ok();
    let mut slots: Vec<(String, &str)> = input
        .text
        .iter()
        .enumerate()
        .map(|(index, (_, text))| (format!("/text/{index}/1"), text.as_str()))
        .collect();
    if let Some(Value::Map(entries)) = &body {
        for (key, value) in entries {
            if let (Some(key), Some(text)) = (key.as_str(), value.as_str()) {
                slots.push((body_pointer(key), text));
            }
        }
    }
    let mut read: Vec<&str> = Vec::new();
    for (pointer, text) in slots {
        if !text.contains(PROSE_LINK_SCHEME) || read.contains(&text) {
            continue;
        }
        read.push(text);
        admit_prose_text(writer, row, &pointer, text, 0);
    }
}

/// `/body/<key>`, JSON-pointer escaped; a key a receipt cannot name (not
/// printable ASCII, or too long) is receipted at `/body`.
fn body_pointer(key: &str) -> String {
    let pointer = format!("/body/{}", key.replace('~', "~0").replace('/', "~1"));
    if pointer.len() <= MAX_POINTER_BYTES && pointer.bytes().all(|byte| byte.is_ascii_graphic()) {
        pointer
    } else {
        "/body".to_owned()
    }
}

pub(super) fn check_append_policy(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    input: &AppendRecord,
    bytes: &[u8],
) -> Result<()> {
    let envelope = WriteEnvelope::new(
        input.actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("kind"),
            Value::from("conversation_append"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    // A synthetic operation body is checked, never stored as an extra CLAIM.
    // This is the same operation-effect mode as the typed memory write doors.
    let mut body = ClaimBody::new(
        "conversation.append_record",
        ClaimSubject::Entity(input.conversation),
        Value::Map(vec![
            (Value::from("record"), Value::from(id.to_hex())),
            (Value::from("body"), Value::Binary(bytes.to_vec())),
            (
                Value::from("parent"),
                input.parent.map_or(Value::Nil, |p| Value::from(p.to_hex())),
            ),
            (Value::from("advance"), Value::Boolean(input.advance)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(envelope.source());
    body.evidence = Some(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ));
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    crate::gate::check_claim_policy_for_write(
        &vault.store,
        txn,
        id,
        crate::gate::ClaimGateWrite::plain(&body, Some(&envelope)),
        &policy,
        crate::gate::GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: false,
            include_source_in_gate_input: true,
        },
        true,
    )
}
