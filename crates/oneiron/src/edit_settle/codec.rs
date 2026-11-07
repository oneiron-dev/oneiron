//! Row and anchor codec.

use std::io::Cursor;

use rmpv::Value;

use super::keys::{
    KEY_ACTOR_REF, KEY_ANCHOR_DRIFTED, KEY_ANCHOR_LOCATOR, KEY_ANCHOR_THREAD_ID, KEY_ANCHORS,
    KEY_BEFORE_VERSION, KEY_BRIEF_REF, KEY_CONTENT_HASH, KEY_DECK, KEY_DISCARDED_WORDS,
    KEY_DOCX_JUDGMENTS, KEY_GRANT_REF, KEY_MANIFEST_OPS, KEY_MANIFEST_REF, KEY_OUTCOME,
    KEY_PPTX_JUDGMENTS, KEY_PPTX_MINTS, KEY_PPTX_REVIEW_IDENTITIES, KEY_PROPOSAL_REF, KEY_REASON,
    KEY_SCHEMA_VERSION, KEY_SETTLED_AT, KEY_SHEET_ANSWERS, KEY_VERSION, SETTLE_VERB_CLASS,
    SETTLEMENT_RECORD_KEYS, SETTLEMENT_SCHEMA_VERSION,
};
use super::records::{PptxReviewIdentity, SettleOutcomeKind, SettledAnchor, SettlementRecord};
use crate::anchored_annotation::{decode_locator, encode_locator};
use crate::consent::{
    ActionClass as ConsentActionClass, ActionEnvelope as ConsentActionEnvelope,
    ActorBound as ConsentActorBound, GrantBound as ConsentGrantBound,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Consume-once settlement ledger row. Key: id16 + hash32(blake3 of the proposal ref).
pub(super) const RECORD: SideTable<(EntityId, [u8; 32]), SettlementRecord, Raw> =
    SideTable::new(&side_table::EDIT_SETTLE_RECORD);

impl RawValue for SettlementRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_settlement_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_settlement_record(bytes)?)
    }
}

/// OF-222 (FIX 3681) archive seam: the consume-once settlement ledger an archive carries
/// beside each artifact, lent with its own key type and codec. The live settle work
/// (pending, stranded, undo, withdrawals, organ waits) is runtime work and is not lent.
pub(crate) fn archive_settlement_table() -> crate::batch::export::LentSideTable {
    &RECORD
}

/// Each entity row a stored settlement record names, read through its table's
/// own codec (fix list row 15416): its settling actor, each exported
/// comment's thread, asker and answerer, each moved anchor's thread, each
/// typed answer's and judgment's thread, principal, question and decision (the
/// rows it read and its receipt's questions, rule and project), a deck's
/// maker and thread, and the same in the review it keeps once its words
/// left. A brief, a grant and a proposal ref are refs of their own, no rows.
/// `None` when the record does not read.
pub(crate) fn archive_settlement_rows(value: &[u8]) -> Option<Vec<EntityId>> {
    let record = RECORD.decode_value(value).ok()?;
    let mut rows = Vec::new();
    rows.extend(
        record
            .actor_ref
            .as_deref()
            .and_then(|actor| EntityId::from_hex(actor).ok()),
    );
    for identity in &record.pptx_review_identities {
        rows.extend([identity.thread_id, identity.asked_by, identity.answered_by]);
    }
    rows.extend(record.anchors.iter().map(|anchor| anchor.thread_id));
    if let Some(bundle) = &record.sheet_answers {
        sheet_answer_rows(bundle, &mut rows);
    }
    for judgment in &record.pptx_judgments {
        slide_judgment_rows(judgment, &mut rows);
    }
    for judgment in &record.docx_judgments {
        decision_rows(&judgment.decision, &mut rows);
    }
    if let Some(deck) = &record.deck {
        rows.extend(deck.context.made_by);
        rows.extend(deck.context.thread);
    }
    if let Some(kept) = &record.discarded_words {
        if let Some(bundle) = &kept.sheet_answers {
            sheet_answer_rows(bundle, &mut rows);
        }
        for judgment in &kept.slide_judgments {
            slide_judgment_rows(judgment, &mut rows);
        }
        for judgment in &kept.paragraph_judgments {
            decision_rows(&judgment.decision, &mut rows);
        }
        if let Some(deck) = &kept.deck {
            rows.extend(deck.context.made_by);
            rows.extend(deck.context.thread);
        }
    }
    Some(rows)
}

/// The rows a typed sheet answer bundle names: its principal, its question
/// and each answer's decision and source file.
fn sheet_answer_rows(bundle: &crate::edit_roundtrip::SheetAnswerBundle, rows: &mut Vec<EntityId>) {
    rows.extend([bundle.principal, bundle.question.id]);
    for answer in &bundle.answers {
        decision_rows(&answer.decision, rows);
        rows.extend(answer.source.as_ref().map(|source| source.id));
    }
}

/// The rows a slide judgment names: its thread, its decisions and the
/// evidence each medium it read is of.
fn slide_judgment_rows(
    judgment: &crate::edit_roundtrip::slides_review::SlideJudgment,
    rows: &mut Vec<EntityId>,
) {
    rows.push(judgment.thread_id);
    decision_rows(&judgment.decision, rows);
    if let Some(presence) = &judgment.presence {
        decision_rows(presence, rows);
    }
    rows.extend(
        judgment
            .media
            .iter()
            .map(|media| media.reference.evidence().id),
    );
}

/// The rows a typed decision names: its evidence, and its receipt's question,
/// principal, read versions, paired and person questions, image evidence,
/// rule row and the projects its ask names.
fn decision_rows(decision: &crate::llm::decision::TypedDecision, rows: &mut Vec<EntityId>) {
    rows.extend(decision.evidence.iter().copied());
    let receipt = &decision.receipt;
    rows.extend([receipt.question, receipt.principal]);
    rows.extend(receipt.evidence_versions.iter().map(|version| version.id));
    rows.extend(
        receipt
            .paired
            .iter()
            .chain(&receipt.person)
            .map(|reading| reading.question),
    );
    rows.extend(receipt.images.iter().map(|image| image.evidence.id));
    rows.extend(receipt.rule.map(|rule| rule.id));
    if let Some(asked) = &receipt.asked {
        rows.extend(asked.project);
        rows.extend(
            asked
                .answered
                .as_ref()
                .and_then(|answerer| answerer.project),
        );
    }
}

pub(super) fn settlement_key_parts(
    artifact_id: &EntityId,
    proposal_ref: &str,
) -> (EntityId, [u8; 32]) {
    (
        *artifact_id,
        *blake3::hash(proposal_ref.as_bytes()).as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// Codec (pinned-key MessagePack)
// ---------------------------------------------------------------------------

pub(super) fn encode_settlement_record(record: &SettlementRecord) -> Result<Vec<u8>> {
    crate::edit_roundtrip::slides_review::validate_judgment_rows(&record.pptx_judgments)?;
    let anchors: Vec<Value> = record.anchors.iter().map(encode_settled_anchor).collect();
    let sheet_answers = record
        .sheet_answers
        .as_ref()
        .map(|bundle| {
            rmp_serde::to_vec_named(bundle)
                .map(Value::Binary)
                .map_err(|_| Error::InvariantViolation("typed answer receipt encode failed"))
        })
        .transpose()?
        .unwrap_or(Value::Nil);
    let docx_judgments = rmp_serde::to_vec_named(&record.docx_judgments)
        .map(Value::Binary)
        .map_err(|_| Error::InvariantViolation("paragraph judgment encode failed"))?;
    let deck = record
        .deck
        .as_ref()
        .map(|evidence| {
            rmp_serde::to_vec_named(evidence)
                .map(Value::Binary)
                .map_err(|_| Error::InvariantViolation("deck settle evidence encode failed"))
        })
        .transpose()?
        .unwrap_or(Value::Nil);
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SETTLEMENT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROPOSAL_REF),
            Value::from(record.proposal_ref.as_str()),
        ),
        (
            Value::from(KEY_OUTCOME),
            Value::from(record.outcome.as_str()),
        ),
        (Value::from(KEY_SETTLED_AT), Value::from(record.settled_at)),
        (
            Value::from(KEY_ACTOR_REF),
            option_str_value(record.actor_ref.as_deref()),
        ),
        (
            Value::from(KEY_BRIEF_REF),
            option_str_value(record.brief_ref.as_deref()),
        ),
        (
            Value::from(KEY_BEFORE_VERSION),
            record.before_version.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_VERSION),
            record.version.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            record
                .content_hash
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            record
                .manifest_ref
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_OPS),
            Value::from(record.manifest_ops),
        ),
        (Value::from(KEY_ANCHORS), Value::Array(anchors)),
        (
            Value::from(KEY_PPTX_MINTS),
            Value::Array(
                record
                    .pptx_slide_creation_id_mints
                    .iter()
                    .map(|(slide, id)| Value::Array(vec![Value::from(*slide), Value::from(*id)]))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_PPTX_REVIEW_IDENTITIES),
            Value::Array(
                record
                    .pptx_review_identities
                    .iter()
                    .map(|identity| {
                        Value::Array(vec![
                            Value::Binary(identity.thread_id.as_bytes().to_vec()),
                            Value::Binary(identity.asked_by.as_bytes().to_vec()),
                            Value::Binary(identity.answered_by.as_bytes().to_vec()),
                            Value::from(identity.export_author_guid.as_str()),
                            Value::from(identity.export_author_name.as_str()),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_PPTX_JUDGMENTS),
            Value::Array(
                record
                    .pptx_judgments
                    .iter()
                    .map(|judgment| {
                        rmp_serde::to_vec_named(judgment)
                            .map(Value::Binary)
                            .map_err(|_| Error::InvariantViolation("slide judgment encode failed"))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        ),
        (
            Value::from(KEY_REASON),
            option_str_value(record.reason.as_deref()),
        ),
        (Value::from(KEY_SHEET_ANSWERS), sheet_answers),
        (Value::from(KEY_DECK), deck),
        (Value::from(KEY_DOCX_JUDGMENTS), docx_judgments),
        (
            Value::from(KEY_GRANT_REF),
            option_str_value(record.grant_ref.as_deref()),
        ),
    ];
    // Only a record whose words left carries the key, so every other row
    // keeps its bytes (FIX 14534).
    if let Some(kept) = &record.discarded_words {
        entries.push((
            Value::from(KEY_DISCARDED_WORDS),
            rmp_serde::to_vec_named(kept)
                .map(Value::Binary)
                .map_err(|_| Error::InvariantViolation("discarded settle words encode failed"))?,
        ));
    }
    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("settlement record MessagePack encode failed"))?;
    Ok(out)
}

fn encode_settled_anchor(anchor: &SettledAnchor) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_ANCHOR_THREAD_ID),
            Value::Binary(anchor.thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_ANCHOR_LOCATOR),
            encode_locator(&anchor.locator),
        ),
        (Value::from(KEY_ANCHOR_DRIFTED), Value::from(anchor.drifted)),
    ])
}

pub(super) fn decode_settlement_record(bytes: &[u8]) -> Result<SettlementRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt());
    }
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    let mut seen = std::collections::BTreeSet::new();
    for (key, _) in &entries {
        let key = key.as_str().ok_or_else(corrupt)?;
        if !SETTLEMENT_RECORD_KEYS.contains(&key) || !seen.insert(key) {
            return Err(corrupt());
        }
    }
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64)
        != Some(SETTLEMENT_SCHEMA_VERSION)
    {
        return Err(corrupt());
    }
    let outcome =
        SettleOutcomeKind::parse(field_str(&entries, KEY_OUTCOME)?).ok_or_else(corrupt)?;
    let anchors = decode_anchors(field(&entries, KEY_ANCHORS).ok_or_else(corrupt)?)?;
    Ok(SettlementRecord {
        proposal_ref: field_str(&entries, KEY_PROPOSAL_REF)?.to_owned(),
        outcome,
        settled_at: field_u64(&entries, KEY_SETTLED_AT)?,
        actor_ref: field_opt_str(&entries, KEY_ACTOR_REF)?,
        brief_ref: field_opt_str(&entries, KEY_BRIEF_REF)?,
        grant_ref: field_opt_str(&entries, KEY_GRANT_REF)?,
        before_version: field_opt_u64(&entries, KEY_BEFORE_VERSION)?,
        version: field_opt_u64(&entries, KEY_VERSION)?,
        content_hash: field_opt_hash(&entries, KEY_CONTENT_HASH)?,
        manifest_ref: field_opt_hash(&entries, KEY_MANIFEST_REF)?,
        manifest_ops: field_u64(&entries, KEY_MANIFEST_OPS)?,
        pptx_slide_creation_id_mints: decode_mints(
            field(&entries, KEY_PPTX_MINTS).ok_or_else(corrupt)?,
        )?,
        pptx_review_identities: decode_review_identities(
            field(&entries, KEY_PPTX_REVIEW_IDENTITIES).ok_or_else(corrupt)?,
        )?,
        pptx_judgments: decode_judgments(field(&entries, KEY_PPTX_JUDGMENTS).ok_or_else(corrupt)?)?,
        docx_judgments: match field(&entries, KEY_DOCX_JUDGMENTS) {
            Some(Value::Binary(bytes)) => {
                let rows: Vec<crate::edit_roundtrip::ParagraphJudgment> =
                    rmp_serde::from_slice(bytes).map_err(|_| corrupt())?;
                rows
            }
            _ => return Err(corrupt()),
        },
        anchors,
        reason: field_opt_str(&entries, KEY_REASON)?,
        sheet_answers: match field(&entries, KEY_SHEET_ANSWERS) {
            Some(Value::Nil) => None,
            Some(Value::Binary(bytes)) => {
                let bundle: crate::edit_roundtrip::SheetAnswerBundle =
                    rmp_serde::from_slice(bytes).map_err(|_| corrupt())?;
                bundle.ops().map_err(|_| corrupt())?;
                Some(Box::new(bundle))
            }
            _ => return Err(corrupt()),
        },
        deck: match field(&entries, KEY_DECK) {
            Some(Value::Nil) => None,
            Some(Value::Binary(bytes)) => Some(Box::new(
                rmp_serde::from_slice(bytes).map_err(|_| corrupt())?,
            )),
            _ => return Err(corrupt()),
        },
        discarded_words: match field(&entries, KEY_DISCARDED_WORDS) {
            None => None,
            Some(Value::Binary(bytes)) => {
                Some(rmp_serde::from_slice(bytes).map_err(|_| corrupt())?)
            }
            Some(_) => return Err(corrupt()),
        },
    })
}

fn decode_judgments(
    value: &Value,
) -> Result<Vec<crate::edit_roundtrip::slides_review::SlideJudgment>> {
    let Value::Array(items) = value else {
        return Err(corrupt());
    };
    let rows: Vec<_> = items
        .iter()
        .map(|item| {
            let Value::Binary(bytes) = item else {
                return Err(corrupt());
            };
            rmp_serde::from_slice(bytes).map_err(|_| corrupt())
        })
        .collect::<Result<_>>()?;
    crate::edit_roundtrip::slides_review::validate_judgment_rows(&rows).map_err(|_| corrupt())?;
    Ok(rows)
}

fn decode_mints(value: &Value) -> Result<Vec<(u64, u32)>> {
    let Value::Array(items) = value else {
        return Err(corrupt());
    };
    let mut seen = std::collections::BTreeSet::new();
    items
        .iter()
        .map(|item| {
            let Value::Array(pair) = item else {
                return Err(corrupt());
            };
            if pair.len() != 2 {
                return Err(corrupt());
            }
            let slide = pair[0].as_u64().filter(|n| *n > 0).ok_or_else(corrupt)?;
            let id = pair[1]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(corrupt)?;
            if !seen.insert(slide) {
                return Err(corrupt());
            }
            Ok((slide, id))
        })
        .collect()
}

fn decode_review_identities(value: &Value) -> Result<Vec<PptxReviewIdentity>> {
    let Value::Array(rows) = value else {
        return Err(corrupt());
    };
    rows.iter()
        .map(|row| {
            let Value::Array(fields) = row else {
                return Err(corrupt());
            };
            let [
                Value::Binary(thread),
                Value::Binary(asker),
                Value::Binary(answerer),
                guid,
                name,
            ] = fields.as_slice()
            else {
                return Err(corrupt());
            };
            let id = |bytes: &[u8]| -> Result<EntityId> {
                let raw: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| corrupt())?;
                EntityId::from_bytes(raw).map_err(|_| corrupt())
            };
            Ok(PptxReviewIdentity {
                thread_id: id(thread)?,
                asked_by: id(asker)?,
                answered_by: id(answerer)?,
                export_author_guid: guid.as_str().ok_or_else(corrupt)?.to_owned(),
                export_author_name: name.as_str().ok_or_else(corrupt)?.to_owned(),
            })
        })
        .collect()
}

fn decode_anchors(value: &Value) -> Result<Vec<SettledAnchor>> {
    let Value::Array(items) = value else {
        return Err(corrupt());
    };
    items.iter().map(decode_settled_anchor).collect()
}

fn decode_settled_anchor(value: &Value) -> Result<SettledAnchor> {
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    let thread_id = field_entity(entries, KEY_ANCHOR_THREAD_ID)?;
    let locator = decode_locator(field(entries, KEY_ANCHOR_LOCATOR).ok_or_else(corrupt)?)?;
    let drifted = field(entries, KEY_ANCHOR_DRIFTED)
        .and_then(Value::as_bool)
        .ok_or_else(corrupt)?;
    Ok(SettledAnchor {
        thread_id,
        locator,
        drifted,
    })
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn field_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    field(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(corrupt)
}

fn field_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or_else(corrupt)
}

fn field_opt_str(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_str().ok_or_else(corrupt)?.to_owned())),
    }
}

fn field_opt_u64(entries: &[(Value, Value)], key: &str) -> Result<Option<u64>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_u64().ok_or_else(corrupt)?)),
    }
}

fn field_opt_hash(entries: &[(Value, Value)], key: &str) -> Result<Option<[u8; 32]>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(Value::Binary(bytes)) => Ok(Some(bytes.as_slice().try_into().map_err(|_| corrupt())?)),
        Some(_) => Err(corrupt()),
    }
}

fn field_entity(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(corrupt());
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt())
}

fn option_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub(super) fn corrupt() -> Error {
    Error::CorruptedIndex("blob artifact settlement record")
}

/// The exact DEC-0006 bound a standing settle must be covered by:
/// acting actor × [`SETTLE_VERB_CLASS`] × this brief, target-pinned.
///
/// Target-pinning is what makes a wider-target assumption fail: a grant whose
/// envelope does not name this brief does not contain this bound.
pub(super) fn settle_grant_bound(actor: WriteActor, brief_ref: &str) -> Result<ConsentGrantBound> {
    // `brief_ref` is used VERBATIM as both selector and target: the caller's
    // refs already carry their own namespace (`brief:acme`), and re-prefixing
    // here would mint a bound no grant can ever match.
    let brief_ref = brief_ref.trim().to_owned();
    ConsentGrantBound::action(
        ConsentActorBound::new(actor.entity_ref().to_hex())?,
        ConsentActionClass::new(SETTLE_VERB_CLASS)?,
        ConsentActionEnvelope::new([brief_ref.clone()])?.with_target(brief_ref)?,
    )
}
