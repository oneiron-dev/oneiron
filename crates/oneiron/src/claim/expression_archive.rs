//! Foreign expression histories restored by their owning source-aware writer.
//! Archive evidence is data, never a local actor, grant, or provenance stamp.

use super::expression_preference::{ExpressionPreferenceWrite, ExpressionWriteOrigin};
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// An untrusted archived row plus an explicitly mapped local subject.
pub(crate) struct ArchivedExpressionPreference {
    pub(crate) id: EntityId,
    pub(crate) body: ClaimBody,
    pub(crate) subject: EntityId,
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
}

/// A complete, unambiguous linear history for exactly one subject/predicate.
pub(crate) struct ExpressionPreferenceArchive {
    rows: Vec<ArchivedExpressionPreference>,
}

impl ExpressionPreferenceArchive {
    pub(crate) fn new(mut rows: Vec<ArchivedExpressionPreference>) -> Result<Self> {
        rows.sort_by_key(|row| (row.learned_at, row.id));
        let first = rows.first().ok_or_else(|| invalid("empty history"))?;
        for (index, row) in rows.iter().enumerate() {
            let body = &row.body;
            // Revalidate even at this crate-private door. Never normalize away
            // scope, demotion or a parked consent that the native writer cannot replay.
            decode_claim_body(&encode_claim_body(body)?, false)?;
            if !is_expression_preference_predicate(&body.predicate)
                || row.subject != first.subject
                || body.subject != first.body.subject
                || body.predicate != first.body.predicate
                || body.source != first.body.source
                || !matches!(
                    body.source,
                    Some(ClaimSource::UserStated | ClaimSource::Inferred | ClaimSource::Imported)
                )
                || body.approval != ClaimApprovalStatus::Auto
                || body.confidence != 1.0
                || body.valid_from.is_none()
                || body.salience.is_some()
                || body.world.is_some()
                || body.rel.is_some()
                || body.scope.is_some()
                || body.session_tag.is_some()
                || body.stale
            {
                return Err(invalid(
                    "mixed precedence or unsupported native history shape",
                ));
            }
            if let Some(next) = rows.get(index + 1) {
                if row.learned_at >= next.learned_at
                    || body.valid_from > next.body.valid_from
                    || body.lifecycle != ClaimLifecycleStatus::Superseded
                    || body.valid_to != Some(next.learned_at)
                    || row.occurred.end != next.learned_at
                {
                    return Err(invalid("ambiguous or incomplete supersession history"));
                }
            } else if body.lifecycle != ClaimLifecycleStatus::Active || body.valid_to.is_some() {
                return Err(invalid("history must end in one active head"));
            }
        }
        Ok(Self { rows })
    }

    pub(crate) fn subject(&self) -> EntityId {
        self.rows[0].subject
    }

    pub(crate) fn ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.rows.iter().map(|row| row.id)
    }

    pub(crate) fn supersessions(&self) -> impl Iterator<Item = (EntityId, EntityId, u64)> + '_ {
        self.rows
            .windows(2)
            .map(|pair| (pair[1].id, pair[0].id, pair[1].learned_at))
    }

    /// Caller must abort the WHOLE transaction on any error. No JSON field is
    /// accepted as a local repeat binding or a claim-materialization capability.
    pub(crate) fn restore_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: &WriteActor,
    ) -> Result<(usize, usize)> {
        let mut existing_count = 0;
        for row in &self.rows {
            if vault.store.off_record_sessions.contains_entity(&row.id)? {
                return Err(invalid("ID belongs to an off-record overlay"));
            }
            if let Some(raw) = vault.store.entities.get(txn, row.id.as_bytes())? {
                if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &row.id)?.is_live() {
                    return Err(invalid("ID collides with a deleted entity"));
                }
                let expected = binding(row, &raw)?;
                if vault
                    .store
                    .vault_meta
                    .get(txn, &binding_key(row.id))?
                    .as_deref()
                    != Some(expected.as_slice())
                {
                    return Err(invalid("ID collision or locally changed restore result"));
                }
                existing_count += 1;
            } else if vault
                .store
                .vault_meta
                .get(txn, &binding_key(row.id))?
                .is_some()
            {
                return Err(invalid("restore binding has no live result"));
            }
        }
        // An overlap is not proof that the missing segment belongs to this
        // history. In particular, never reopen a previously closed generation.
        if existing_count != 0 && existing_count != self.rows.len() {
            return Err(invalid("partial history overlaps existing local rows"));
        }
        if existing_count == 0 {
            for (index, row) in self.rows.iter().enumerate() {
                let result = vault.write_expression_preference_in_txn(
                    txn,
                    actor,
                    row.id,
                    &write_spec(row)?,
                    row.occurred,
                    row.learned_at,
                )?;
                let expected: Vec<_> = index
                    .checked_sub(1)
                    .map(|i| self.rows[i].id)
                    .into_iter()
                    .collect();
                if result.superseded_claim_ids != expected {
                    return Err(invalid(
                        "local precedence cannot reconstruct the archived history",
                    ));
                }
            }
        }
        // Only source and provenance change. Lifecycle, validity and header
        // times must be reconstructed exactly by the native transitions.
        for row in &self.rows {
            let raw = vault
                .store
                .entities
                .get(txn, row.id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("expression archive header"))?;
            let actual = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
            let mut expected = row.body.clone();
            expected.subject = ClaimSubject::Entity(row.subject);
            expected.source = Some(ClaimSource::Imported);
            expected.evidence = actual.evidence.clone();
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || header.occurred_start != row.occurred.start
                || header.occurred_end != row.occurred.end
                || header.learned_at != row.learned_at
                || actual != expected
            {
                return Err(invalid("final lifecycle or body not reconstructed"));
            }
            if existing_count == 0 {
                vault
                    .store
                    .vault_meta
                    .put(txn, &binding_key(row.id), &binding(row, &raw)?)?;
            }
        }
        Ok((self.rows.len() - existing_count, existing_count))
    }
}

fn write_spec(row: &ArchivedExpressionPreference) -> Result<ExpressionPreferenceWrite> {
    let value = row
        .body
        .value
        .as_str()
        .ok_or_else(|| invalid("value is not a string"))?;
    let value = match (row.body.predicate.as_str(), value) {
        (PREDICATE_COMPANION_EXPRESSION_LANGUAGE, value) => {
            ExpressionPreferenceValue::Language(value.to_owned())
        }
        (PREDICATE_COMPANION_EXPRESSION_STYLE, value) => {
            ExpressionPreferenceValue::Style(value.to_owned())
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "casual") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Casual)
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "neutral") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Neutral)
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "formal") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Formal)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "none") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::None)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "teineigo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Teineigo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "sonkeigo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Sonkeigo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "kenjogo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Kenjogo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "adaptive") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Adaptive)
        }
        _ => return Err(invalid("invalid expression value")),
    };
    Ok(ExpressionPreferenceWrite {
        subject: row.subject,
        value,
        valid_from: row
            .body
            .valid_from
            .ok_or_else(|| invalid("missing validity start"))?,
        origin: ExpressionWriteOrigin::Imported,
    })
}

fn binding_key(id: EntityId) -> Vec<u8> {
    let mut key = b"expression/archive-binding/v1\0".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn binding(row: &ArchivedExpressionPreference, actual: &[u8]) -> Result<Vec<u8>> {
    let mut archive = blake3::Hasher::new();
    archive.update(row.id.as_bytes());
    archive.update(&row.occurred.start.to_be_bytes());
    archive.update(&row.occurred.end.to_be_bytes());
    archive.update(&row.learned_at.to_be_bytes());
    archive.update(&encode_claim_body(&row.body)?);
    let mut result = archive.finalize().as_bytes().to_vec();
    // Include the actual header as well as body, so a later local lifecycle
    // edit invalidates the binding even if only its end timestamp changes.
    result.extend_from_slice(blake3::hash(actual).as_bytes());
    Ok(result)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("expression preference archive: {reason}"))
}
