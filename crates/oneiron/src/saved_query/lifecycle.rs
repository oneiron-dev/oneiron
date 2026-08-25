use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::ModelId;

use super::definition::{
    CreateSavedQueryRequest, SAVED_QUERY_SCHEMA_VERSION, SavedQueryDefinition, SavedQueryLifecycle,
    SavedQueryRecord, UpdateSavedQueryRequest,
};
use super::filter::{MatcherSpec, validate_per_entity_decidable};
use super::storage::{load_record, load_record_in_txn, saved_query_type_byte, store_record_in_txn};
use super::support::{MICROS_PER_UNIT, invalid, validate_bounded_text};

/// Creates a saved query owned by the authenticated principal.
///
/// `owner_actor` is set from `authenticated_principal` and from nowhere else —
/// [`CreateSavedQueryRequest`] has no owner field, so an untrusted request
/// cannot name a different owner even by accident.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the definition fails validation or the
/// SAVED_QUERY kind is not registered in this vault; storage errors propagate
/// unchanged.
pub fn create_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    request: &CreateSavedQueryRequest,
    now: u64,
) -> Result<SavedQueryRecord> {
    let definition = SavedQueryDefinition {
        schema_version: request.schema_version,
        owner_actor: authenticated_principal,
        scope: request.scope.clone(),
        definition_version: 1,
        filter: request.filter.clone(),
        matcher: request.matcher.clone(),
        eval: request.eval,
        lifecycle: SavedQueryLifecycle::Active,
    };
    validate_definition(&definition)?;
    let record = SavedQueryRecord {
        query_ref: EntityId::now(),
        definition,
        created_at: now,
        updated_at: now,
    };
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| store_record_in_txn(vault, wtxn, &record, kind))?;
    Ok(record)
}

/// Reads a saved query the principal owns.
///
/// A principal that does not own the query gets `Ok(None)` — the same answer as
/// a query that does not exist. Ownership is not a filter applied after the
/// caller already learned the row exists; it IS the read.
///
/// # Errors
///
/// Storage or decode errors propagate unchanged.
pub fn read_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
) -> Result<Option<SavedQueryRecord>> {
    Ok(load_record(vault, query_ref)?
        .filter(|record| record.definition.owner_actor == authenticated_principal))
}

/// Replaces a saved query's definition under a version CAS.
///
/// The compare and the write share ONE write transaction. LMDB's single-writer
/// rule serializes the writes but not a compare performed before the writer
/// transaction opens: two callers that both read version 1 outside the txn
/// would both store "version 2", and the first update would vanish with no
/// error. The CAS is only a CAS inside the txn that performs it.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent OR owned by another
/// principal, [`Error::ConcurrentWrite`] when the expected version is not
/// current, and [`Error::InvalidConfig`] when the replacement fails validation.
pub fn update_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    request: &UpdateSavedQueryRequest,
    now: u64,
) -> Result<SavedQueryRecord> {
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_record_in_txn(vault, wtxn, authenticated_principal, query_ref, kind)?;
        require_expected_version(&record, request.expected_definition_version)?;
        let definition = SavedQueryDefinition {
            schema_version: record.definition.schema_version,
            owner_actor: record.definition.owner_actor,
            scope: request.scope.clone(),
            definition_version: next_version(record.definition.definition_version)?,
            filter: request.filter.clone(),
            matcher: request.matcher.clone(),
            eval: request.eval,
            // An update is the operator's answer to a paused query, so it
            // clears the pause. Archived is terminal and is not reopened here.
            lifecycle: match record.definition.lifecycle {
                SavedQueryLifecycle::Archived => SavedQueryLifecycle::Archived,
                SavedQueryLifecycle::Active | SavedQueryLifecycle::Paused { .. } => {
                    SavedQueryLifecycle::Active
                }
            },
        };
        validate_definition(&definition)?;
        record.definition = definition;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Archives a saved query. A lifecycle transition, never a delete: the record
/// stays readable so ONE-1778 can still address it.
///
/// Shares [`update_saved_query`]'s single-transaction CAS for the same reason.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent or owned by another
/// principal; [`Error::ConcurrentWrite`] when the expected version is stale.
pub fn archive_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    expected_definition_version: u64,
    now: u64,
) -> Result<SavedQueryRecord> {
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_record_in_txn(vault, wtxn, authenticated_principal, query_ref, kind)?;
        require_expected_version(&record, expected_definition_version)?;
        record.definition.definition_version = next_version(record.definition.definition_version)?;
        record.definition.lifecycle = SavedQueryLifecycle::Archived;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Loads a record the principal owns THROUGH the caller's transaction, or
/// reports it as absent. Ownership is part of the read, not a post-filter.
fn owned_record_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    kind: u8,
) -> Result<SavedQueryRecord> {
    load_record_in_txn(vault, wtxn, query_ref, kind)?
        .filter(|record| record.definition.owner_actor == authenticated_principal)
        .ok_or(Error::EntityNotFound)
}

fn require_expected_version(record: &SavedQueryRecord, expected: u64) -> Result<()> {
    if record.definition.definition_version == expected {
        return Ok(());
    }
    Err(Error::ConcurrentWrite(
        "saved query definition version is not current",
    ))
}

pub(super) fn next_version(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("saved query definition version"))
}

pub(super) fn validate_definition(definition: &SavedQueryDefinition) -> Result<()> {
    if definition.schema_version != SAVED_QUERY_SCHEMA_VERSION {
        return Err(invalid("saved query schema_version is unsupported"));
    }
    validate_per_entity_decidable(&definition.filter)?;
    validate_matcher(&definition.matcher)?;
    for facet in &definition.scope.facets {
        validate_bounded_text(facet, "scope facet")?;
    }
    // A zero bound is not "unbounded" and it is not a working budget either: a
    // zero-judge wake would still spend the first judge before the post-hoc
    // count stopped it, and a zero-entity wake reports "exhausted" without
    // visiting anything. Both are budget lies, so the definition never stores
    // one.
    if definition.eval.max_entities_per_wake == 0 || definition.eval.max_judges_per_wake == 0 {
        return Err(invalid("saved query wake bounds must be at least one"));
    }
    Ok(())
}

fn validate_matcher(matcher: &MatcherSpec) -> Result<()> {
    match matcher {
        MatcherSpec::Hard { expression } => validate_per_entity_decidable(expression),
        MatcherSpec::SemanticThreshold {
            minimum_similarity_micros,
            ..
        } => {
            if *minimum_similarity_micros > MICROS_PER_UNIT {
                return Err(invalid(
                    "saved query similarity floor exceeds one unit of similarity",
                ));
            }
            Ok(())
        }
        MatcherSpec::LlmJudge {
            model_id,
            rubric_version,
            ..
        } => {
            ModelId::new(model_id.clone())
                .map_err(|_| invalid("saved query judge model_id is not provider/name@revision"))?;
            validate_bounded_text(rubric_version, "rubric_version")
        }
    }
}
