//! MessagePack claim codecs, map accessors, envelope builders, and malformed-claim
//! quarantine.

use super::model::{
    ANNOTATION_BRIEF_PREDICATE, ANNOTATION_COMMENT_PREDICATE, ANNOTATION_LOCATOR_TEXT_MAX_BYTES,
    ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationComment, DriftMarker, FORMAT_DOCX, FORMAT_PPTX,
    FORMAT_XLSX, Locator, TaskBrief, ThreadState,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

const KEY_THREAD_ID: &str = "thread_id";

const KEY_ORIGIN_VERSION: &str = "origin_version";

const KEY_ANCHOR_VERSION: &str = "anchor_version";

const KEY_STATE: &str = "state";

const KEY_LOCATOR: &str = "locator";

const KEY_DRIFT: &str = "drift";

const KEY_DRIFTED_AT_VERSION: &str = "drifted_at_version";

const KEY_PINNED_VERSION: &str = "pinned_version";

const KEY_AUTHOR: &str = "author";

const KEY_TEXT: &str = "text";

const KEY_AT: &str = "at";

const KEY_TASK_ID: &str = "task_id";

const KEY_BRIEF_REF: &str = "brief_ref";

const KEY_ASSIGNEE: &str = "assignee";

const KEY_TRANSCRIPT: &str = "transcript";

const KEY_FORMAT: &str = "format";

const KEY_SHEET: &str = "sheet";

const KEY_RANGE: &str = "range";

const KEY_PARA_PATH: &str = "para_path";

const KEY_CHAR_START: &str = "char_start";

const KEY_CHAR_END: &str = "char_end";

const KEY_SLIDE: &str = "slide";

const KEY_SHAPE_ID: &str = "shape_id";

/// Task role byte for the productivity `role` body ("role": <byte>).
const TASK_BODY_ROLE_KEY: &str = "role";

// ---------------------------------------------------------------------------
// Value codecs
// ---------------------------------------------------------------------------

pub(super) struct ThreadHead {
    pub(super) thread_id: EntityId,
    pub(super) origin_version: u64,
    pub(super) anchor_version: u64,
    pub(super) state: ThreadState,
    pub(super) locator: Locator,
    pub(super) drift: Option<DriftMarker>,
}

pub(super) fn validate_locator_text(text: &str, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > ANNOTATION_LOCATOR_TEXT_MAX_BYTES {
        return Err(match context {
            "xlsx locator sheet" => Error::Artifact(ArtifactError::InvalidAnchor(
                "xlsx locator sheet is empty or too long",
            )),
            "docx locator para_path" => Error::Artifact(ArtifactError::InvalidAnchor(
                "docx locator para_path is empty or too long",
            )),
            _ => Error::Artifact(ArtifactError::InvalidAnchor(
                "pptx locator shape_id is empty or too long",
            )),
        });
    }
    Ok(())
}

pub(crate) fn encode_locator(locator: &Locator) -> Value {
    match locator {
        Locator::Xlsx { sheet, range } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_XLSX)),
            (Value::from(KEY_SHEET), Value::from(sheet.as_str())),
            (Value::from(KEY_RANGE), Value::from(range.to_a1())),
        ]),
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_DOCX)),
            (Value::from(KEY_PARA_PATH), Value::from(para_path.as_str())),
            (Value::from(KEY_CHAR_START), Value::from(*char_start)),
            (Value::from(KEY_CHAR_END), Value::from(*char_end)),
        ]),
        Locator::Pptx { slide, shape_id } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_PPTX)),
            (Value::from(KEY_SLIDE), Value::from(*slide)),
            (Value::from(KEY_SHAPE_ID), Value::from(shape_id.as_str())),
        ]),
    }
}

pub(crate) fn decode_locator(value: &Value) -> Result<Locator> {
    let format = map_str(value, KEY_FORMAT)?;
    match format {
        FORMAT_XLSX => {
            let sheet = map_str(value, KEY_SHEET)?.to_owned();
            let range = map_str(value, KEY_RANGE)?;
            Locator::xlsx(sheet, range)
        }
        FORMAT_DOCX => {
            let para_path = map_str(value, KEY_PARA_PATH)?.to_owned();
            let char_start = map_u64(value, KEY_CHAR_START)?;
            let char_end = map_u64(value, KEY_CHAR_END)?;
            Locator::docx(para_path, char_start, char_end)
        }
        FORMAT_PPTX => {
            let slide = map_u64(value, KEY_SLIDE)?;
            let shape_id = map_str(value, KEY_SHAPE_ID)?.to_owned();
            Locator::pptx(slide, shape_id)
        }
        _ => Err(Error::Artifact(ArtifactError::InvalidAnchor(
            "unknown locator format",
        ))),
    }
}

pub(super) fn encode_thread_head_value(head: &ThreadHead) -> Value {
    let mut entries = vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(head.thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_ORIGIN_VERSION),
            Value::from(head.origin_version),
        ),
        (
            Value::from(KEY_ANCHOR_VERSION),
            Value::from(head.anchor_version),
        ),
        (Value::from(KEY_STATE), Value::from(head.state.as_str())),
        (Value::from(KEY_LOCATOR), encode_locator(&head.locator)),
    ];
    if let Some(drift) = head.drift {
        entries.push((
            Value::from(KEY_DRIFT),
            Value::Map(vec![
                (
                    Value::from(KEY_DRIFTED_AT_VERSION),
                    Value::from(drift.drifted_at_version),
                ),
                (
                    Value::from(KEY_PINNED_VERSION),
                    Value::from(drift.pinned_version),
                ),
            ]),
        ));
    }
    Value::Map(entries)
}

pub(super) fn decode_thread_head(value: &Value) -> Result<ThreadHead> {
    let thread_id = map_entity(value, KEY_THREAD_ID)?;
    let origin_version = map_u64(value, KEY_ORIGIN_VERSION)?;
    let anchor_version = map_u64(value, KEY_ANCHOR_VERSION)?;
    let state = ThreadState::parse(map_str(value, KEY_STATE)?).ok_or(Error::Artifact(
        ArtifactError::InvalidAnchor("thread state is unknown"),
    ))?;
    let locator = decode_locator(map_get(value, KEY_LOCATOR).ok_or(Error::Artifact(
        ArtifactError::InvalidAnchor("thread head missing locator"),
    ))?)?;
    let drift = match map_get(value, KEY_DRIFT) {
        None | Some(Value::Nil) => None,
        Some(drift_value) => Some(DriftMarker {
            drifted_at_version: map_u64(drift_value, KEY_DRIFTED_AT_VERSION)?,
            pinned_version: map_u64(drift_value, KEY_PINNED_VERSION)?,
        }),
    };
    Ok(ThreadHead {
        thread_id,
        origin_version,
        anchor_version,
        state,
        locator,
        drift,
    })
}

pub(super) fn encode_comment_value(
    thread_id: &EntityId,
    author: &EntityId,
    text: &str,
    at: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_AUTHOR),
            Value::Binary(author.as_bytes().to_vec()),
        ),
        (Value::from(KEY_TEXT), Value::from(text)),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

pub(super) fn decode_comment(value: &Value, claim_id: EntityId) -> Result<AnnotationComment> {
    Ok(AnnotationComment {
        thread_id: map_entity(value, KEY_THREAD_ID)?,
        author: map_entity(value, KEY_AUTHOR)?,
        text: map_str(value, KEY_TEXT)?.to_owned(),
        at: map_u64(value, KEY_AT)?,
        claim_id,
    })
}

pub(super) fn encode_brief_value(
    thread_id: &EntityId,
    task_id: &EntityId,
    brief_ref: &str,
    anchor_version: u64,
    locator: &Locator,
    assignee: Option<&EntityId>,
    transcript: &str,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_TASK_ID),
            Value::Binary(task_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_BRIEF_REF), Value::from(brief_ref)),
        (Value::from(KEY_ANCHOR_VERSION), Value::from(anchor_version)),
        (Value::from(KEY_LOCATOR), encode_locator(locator)),
        (
            Value::from(KEY_ASSIGNEE),
            assignee.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (Value::from(KEY_TRANSCRIPT), Value::from(transcript)),
    ])
}

pub(super) fn decode_brief_value(value: &Value, artifact_id: EntityId) -> Result<TaskBrief> {
    let thread_id = map_entity(value, KEY_THREAD_ID)?;
    let task_id = map_entity(value, KEY_TASK_ID)?;
    let brief_ref = map_str(value, KEY_BRIEF_REF)?.to_owned();
    let anchor_version = map_u64(value, KEY_ANCHOR_VERSION)?;
    let locator = decode_locator(map_get(value, KEY_LOCATOR).ok_or(Error::Artifact(
        ArtifactError::InvalidAnchor("brief missing locator"),
    ))?)?;
    let assignee = match map_get(value, KEY_ASSIGNEE) {
        None | Some(Value::Nil) => None,
        Some(_) => Some(map_entity(value, KEY_ASSIGNEE)?),
    };
    let thread_text = map_str(value, KEY_TRANSCRIPT)?.to_owned();
    Ok(TaskBrief {
        brief_ref,
        task_id,
        thread_id,
        anchor: Anchor {
            artifact_id,
            version: anchor_version,
            locator,
        },
        artifact_version: anchor_version,
        thread_text,
        assignee,
    })
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, entry_value)| entry_value)
}

fn map_str<'a>(value: &'a Value, key: &'static str) -> Result<&'a str> {
    map_get(value, key)
        .and_then(Value::as_str)
        .ok_or(Error::Artifact(ArtifactError::InvalidAnchor(key)))
}

fn map_u64(value: &Value, key: &'static str) -> Result<u64> {
    map_get(value, key)
        .and_then(Value::as_u64)
        .ok_or(Error::Artifact(ArtifactError::InvalidAnchor(key)))
}

fn map_entity(value: &Value, key: &'static str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = map_get(value, key) else {
        return Err(Error::Artifact(ArtifactError::InvalidAnchor(key)));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Artifact(ArtifactError::InvalidAnchor(key)))?;
    EntityId::from_bytes(raw).map_err(|_| Error::Artifact(ArtifactError::InvalidAnchor(key)))
}

fn annotation_stances(actor_class: EdgeActorClass) -> (ClaimSource, ClaimApprovalStatus) {
    match actor_class {
        EdgeActorClass::Human => (ClaimSource::UserStated, ClaimApprovalStatus::Auto),
        EdgeActorClass::Agent => (ClaimSource::Generated, ClaimApprovalStatus::Proposed),
        EdgeActorClass::System => (ClaimSource::Observed, ClaimApprovalStatus::Auto),
    }
}

pub(super) fn annotation_envelope(actor: WriteActor, op: &'static str) -> Result<WriteEnvelope> {
    let (source, approval) = annotation_stances(actor.actor_class());
    let provenance = WriteProvenance::new(Value::Map(vec![
        (Value::from("surface"), Value::from("anchored_annotation")),
        (Value::from("op"), Value::from(op)),
    ]))?;
    Ok(WriteEnvelope::new(actor, source, provenance, approval))
}

pub(super) fn task_role_body(role: TaskRole) -> Result<Vec<u8>> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .map_err(|_| Error::InvariantViolation("TASK role body MessagePack encode failed"))?;
    Ok(bytes)
}

/// Quarantines a single malformed annotation claim value on a read path.
///
/// Annotation predicates ride the generic CLAIM band, so a malformed value can
/// be written through the generic claim API. Failing the whole listing on one
/// such value would let a single garbage claim take down every thread/comment
/// read for the artifact, so the read helpers skip the bad value (tracing it)
/// and keep serving the well-formed claims.
pub(super) fn warn_malformed_annotation_claim(claim_id: EntityId, predicate: &str, err: &Error) {
    tracing::warn!(
        claim_id = %claim_id.to_hex(),
        predicate,
        error = ?err,
        "skipping malformed annotation claim value on read",
    );
}

pub(super) fn is_annotation_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        ANNOTATION_THREAD_PREDICATE | ANNOTATION_COMMENT_PREDICATE | ANNOTATION_BRIEF_PREDICATE
    )
}
