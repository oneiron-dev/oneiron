//! Immutable question versions and a CAS-updated scheduling head in the typed `TYPED_QUESTION`
//! side table: one declaration, four row shapes (version/head/answer/label) tagged by family.

use super::super::types::invalid;
use super::records::*;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::Serialize;

/// The bytes before a family's suffix: `id16 ":" family ":"`.
pub(super) fn family_prefix(id: EntityId, family: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 1 + family.len() + 1);
    out.extend_from_slice(id.as_bytes());
    out.push(b':');
    out.extend_from_slice(family);
    out.push(b':');
    out
}

fn decode_family<'b>(bytes: &'b [u8], family: &[u8]) -> Option<(EntityId, &'b [u8])> {
    let (id_bytes, rest) = bytes.split_at_checked(16)?;
    let id = EntityId::from_bytes(id_bytes.try_into().ok()?).ok()?;
    let suffix = rest
        .strip_prefix(b":")?
        .strip_prefix(family)?
        .strip_prefix(b":")?;
    Some((id, suffix))
}

/// Key of one immutable question version. Family: `version`, suffix: u32be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VersionKey {
    pub(super) id: EntityId,
    pub(super) version: u32,
}

impl SideKey for VersionKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.id, b"version"));
        out.extend_from_slice(&self.version.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, suffix) = decode_family(bytes, b"version")?;
        Some(Self {
            id,
            version: u32::from_be_bytes(suffix.try_into().ok()?),
        })
    }
}

/// Key of one question's scheduling head. Family: `head`, suffix: empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HeadKey(pub(super) EntityId);

impl SideKey for HeadKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.0, b"head"));
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, suffix) = decode_family(bytes, b"head")?;
        suffix.is_empty().then_some(Self(id))
    }
}

/// Key of one immutable answer receipt. Family: `answer`, suffix: id16(claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AnswerKey {
    pub(super) question: EntityId,
    pub(super) claim: EntityId,
}

impl SideKey for AnswerKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.question, b"answer"));
        out.extend_from_slice(self.claim.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, suffix) = decode_family(bytes, b"answer")?;
        Some(Self {
            question,
            claim: EntityId::from_bytes(suffix.try_into().ok()?).ok()?,
        })
    }
}

/// Key of one bound outcome label. Family: `label`, suffix: id16(claim) + id16(fact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LabelKey {
    pub(super) question: EntityId,
    pub(super) claim: EntityId,
    pub(super) fact: EntityId,
}

impl SideKey for LabelKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.question, b"label"));
        out.extend_from_slice(self.claim.as_bytes());
        out.extend_from_slice(self.fact.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, suffix) = decode_family(bytes, b"label")?;
        let (claim, fact) = suffix.split_at_checked(16)?;
        Some(Self {
            question,
            claim: EntityId::from_bytes(claim.try_into().ok()?).ok()?,
            fact: EntityId::from_bytes(fact.try_into().ok()?).ok()?,
        })
    }
}

pub(super) const QUESTION_VERSION: SideTable<VersionKey, QuestionRecord, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);
pub(super) const QUESTION_HEAD: SideTable<HeadKey, QuestionHead, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);
pub(super) const QUESTION_ANSWER: SideTable<AnswerKey, AnswerRecord, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);
pub(super) const QUESTION_LABEL: SideTable<LabelKey, OutcomeLabel, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

pub fn create_question(
    vault: &Vault,
    principal: EntityId,
    mut definition: QuestionDefinition,
    now: u64,
) -> Result<QuestionRecord> {
    definition.question.id = EntityId::now();
    definition.question.version = 1;
    definition.validate()?;
    let record = QuestionRecord {
        schema_version: 1,
        principal,
        definition,
        created_at: now,
    };
    vault.with_write_txn(|txn| {
        let id = record.definition.question.id;
        super::arrival::watch(&vault.store, txn, &record)?;
        secret_scan_before_put(&record)?;
        QUESTION_VERSION.put(&vault.store, txn, &VersionKey { id, version: 1 }, &record)?;
        let head = QuestionHead {
            version: 1,
            paused: false,
            last_refresh: None,
        };
        secret_scan_before_put(&head)?;
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(id), &head)
    })?;
    Ok(record)
}

pub fn read_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    version: Option<u32>,
) -> Result<Option<QuestionRecord>> {
    let txn = vault.store.env.read_txn()?;
    let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(id))? else {
        return Ok(None);
    };
    let record: Option<QuestionRecord> = QUESTION_VERSION.get(
        &vault.store,
        &txn,
        &VersionKey {
            id,
            version: version.unwrap_or(head.version),
        },
    )?;
    if let Some(record) = &record {
        if record.schema_version != 1 {
            return Err(invalid("unsupported question schema"));
        }
        record.definition.validate()?;
    }
    Ok(record.filter(|r| r.principal == principal))
}

pub fn edit_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    expected_version: u32,
    mut definition: QuestionDefinition,
    now: u64,
) -> Result<QuestionRecord> {
    vault.with_write_txn(|txn| {
        let mut head = owned_head(vault, txn, principal, id)?;
        if head.version != expected_version {
            return Err(Error::ConcurrentWrite("standing question changed"));
        }
        let version = head
            .version
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("question version"))?;
        definition.question.id = id;
        definition.question.version = version;
        definition.validate()?;
        let record = QuestionRecord {
            schema_version: 1,
            principal,
            definition,
            created_at: now,
        };
        secret_scan_before_put(&record)?;
        QUESTION_VERSION.put(&vault.store, txn, &VersionKey { id, version }, &record)?;
        super::arrival::watch(&vault.store, txn, &record)?;
        head.version = version;
        secret_scan_before_put(&head)?;
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(id), &head)?;
        Ok(record)
    })
}

pub fn pause_question(
    vault: &Vault,
    principal: EntityId,
    id: EntityId,
    paused: bool,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut head = owned_head(vault, txn, principal, id)?;
        head.paused = paused;
        secret_scan_before_put(&head)?;
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(id), &head)
    })
}

pub(super) fn owned_head(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    id: EntityId,
) -> Result<QuestionHead> {
    let head: QuestionHead = QUESTION_HEAD
        .get(&vault.store, txn, &HeadKey(id))?
        .ok_or(Error::EntityNotFound)?;
    let record: QuestionRecord = QUESTION_VERSION
        .get(
            &vault.store,
            txn,
            &VersionKey {
                id,
                version: head.version,
            },
        )?
        .ok_or(Error::EntityNotFound)?;
    if record.principal != principal {
        return Err(Error::EntityNotFound);
    }
    Ok(head)
}

/// General MessagePack encoding shared beyond this table's own storage: task-ask and outcome
/// evaluation both need the exact wire form of a value they do not persist here.
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("typed question encoding failed"))
}

/// Every row this table stores is scanned for leaked secrets before it is written, exactly as a
/// pre-migration write did. Callers run this immediately before a `QUESTION_*` table `put`.
pub(super) fn secret_scan_before_put<T: Serialize>(value: &T) -> Result<()> {
    let text =
        serde_json::to_string(value).map_err(|_| invalid("typed question encoding failed"))?;
    crate::batch::secret_scan::scan_metadata_field(&text)
}
