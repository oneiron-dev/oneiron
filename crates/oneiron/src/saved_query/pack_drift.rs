use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::definition::{SavedQueryDefinition, SavedQueryLifecycle, SavedQueryRecord};
use super::filter::{FilterAst, MatcherSpec};
use super::lifecycle::{next_version, validate_definition};
use super::storage::{
    keys, load_record_in_txn, meta_row, put_meta_row, saved_query_type_byte, store_record_in_txn,
};
use super::support::{canonical_json_bytes, invalid};

/// A pack version move that touches predicates a query reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackDrift {
    /// Pack the definition was written against.
    pub from_pack_id: String,
    /// Version the definition was written against.
    pub from_version: String,
    /// Pack now installed.
    pub to_pack_id: String,
    /// Version now installed.
    pub to_version: String,
    /// Predicates whose meaning or spelling moved.
    pub affected_predicates: Vec<String>,
}

/// How one affected predicate can be carried across a pack move.
///
/// The CLASSIFICATION lives on the map entry, supplied by whoever authored the
/// pack move, because only that author knows whether a rename preserves
/// meaning. The engine's job is to apply the ladder faithfully, not to guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PackPredicateRewrite {
    /// Pure rename. Auto-migrates.
    Rename {
        /// New predicate.
        to: String,
    },
    /// Different spelling, same meaning. Auto-rewrites with a notice.
    Equivalent {
        /// New predicate.
        to: String,
        /// Notice recorded on the receipt.
        note: String,
    },
    /// Meaning changed. Requires an owner proposal.
    SemanticsChanging {
        /// Proposed new predicate.
        to: String,
        /// What changed.
        note: String,
    },
}

/// Per-predicate rewrites for one pack move.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackMigrationMap {
    /// Old predicate to its rewrite.
    pub rewrites: BTreeMap<String, PackPredicateRewrite>,
}

/// The rung the repair ladder settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackDriftResolution {
    /// Every affected predicate had a rename; the definition was migrated.
    AutoMigrated {
        /// Receipt row recording the migration.
        receipt_ref: EntityId,
    },
    /// A semantics-preserving rewrite was applied with a notice.
    AutoRewritten {
        /// Receipt row recording the rewrite and its notices.
        receipt_ref: EntityId,
    },
    /// A meaning-changing rewrite needs the owner's answer; nothing changed.
    ProposalRequired {
        /// Proposal row the owner rules on.
        proposal_ref: EntityId,
    },
    /// No viable rewrite. The query is paused with a visible error.
    Paused {
        /// Operator-visible reason.
        error: String,
    },
}

/// Records the migration map for one pack move.
///
/// # Errors
///
/// Storage errors propagate unchanged.
pub fn put_pack_migration_map(
    vault: &Vault,
    drift: &PackDrift,
    map: &PackMigrationMap,
) -> Result<()> {
    let encoded = serde_json::to_vec(map)
        .map_err(|_| Error::InvariantViolation("pack migration map encode failed"))?;
    put_meta_row(vault, &keys::migration_map(drift), &encoded)
}

/// Runs the ratified pack-drift ladder, in order.
///
/// Rung order is worst-case-wins across the affected predicates: an unmapped
/// predicate pauses the query even if every other predicate renames cleanly. So
/// the WHOLE affected set is classified before a rung is chosen — returning on
/// the first bad predicate would make the outcome depend on the order the pack
/// author happened to list them in, and could leave a query Active whose other
/// predicate has no rewrite at all. A partially-migrated query would evaluate
/// against a definition nobody wrote, which is the one outcome the ladder
/// exists to prevent.
///
/// `definition` is the snapshot the repair was PLANNED from: the replacement is
/// built from the stored record, and a version that has moved since planning
/// loses rather than overwriting the owner's concurrent update.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent, [`Error::ConcurrentWrite`]
/// when the plan is stale, [`Error::InvalidConfig`] when the query is archived;
/// storage errors propagate.
pub fn repair_pack_drift(
    vault: &Vault,
    query_ref: EntityId,
    definition: &SavedQueryDefinition,
    drift: &PackDrift,
    now: u64,
) -> Result<PackDriftResolution> {
    let map = load_migration_map(vault, drift)?.unwrap_or_default();
    let mut unmapped = Vec::new();
    let mut proposals = Vec::new();
    let mut renames = BTreeMap::new();
    let mut notices = Vec::new();
    for predicate in &drift.affected_predicates {
        match map.rewrites.get(predicate) {
            None => unmapped.push(predicate.clone()),
            Some(PackPredicateRewrite::SemanticsChanging { to, note }) => {
                proposals.push(format!("{predicate} -> {to} ({note})"));
            }
            Some(PackPredicateRewrite::Rename { to }) => {
                renames.insert(predicate.clone(), to.clone());
            }
            Some(PackPredicateRewrite::Equivalent { to, note }) => {
                renames.insert(predicate.clone(), to.clone());
                notices.push(format!("{predicate} -> {to} ({note})"));
            }
        }
    }
    let moved = format!(
        "pack move {}@{} -> {}@{}",
        drift.from_pack_id, drift.from_version, drift.to_pack_id, drift.to_version
    );
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            load_record_in_txn(vault, wtxn, query_ref, kind)?.ok_or(Error::EntityNotFound)?;
        if record.definition.definition_version != definition.definition_version {
            return Err(Error::ConcurrentWrite(
                "saved query definition version is not current",
            ));
        }
        if record.definition.lifecycle == SavedQueryLifecycle::Archived {
            return Err(invalid(
                "saved query is archived; pack drift repair does not reopen it",
            ));
        }
        if !unmapped.is_empty() {
            let error = format!(
                "{moved} has no rewrite for predicate(s) {}",
                unmapped.join(", ")
            );
            return pause_in_txn(vault, wtxn, record, kind, error, now);
        }
        if !proposals.is_empty() {
            let summary = format!("proposal: {}", proposals.join("; "));
            return record_repair_in_txn(vault, wtxn, query_ref, drift, &summary, now)
                .map(|proposal_ref| PackDriftResolution::ProposalRequired { proposal_ref });
        }
        let migrated = SavedQueryDefinition {
            filter: rewrite_predicates(&record.definition.filter, &renames),
            matcher: rewrite_matcher(&record.definition.matcher, &renames),
            definition_version: next_version(record.definition.definition_version)?,
            lifecycle: SavedQueryLifecycle::Active,
            ..record.definition.clone()
        };
        // The ladder's own last rung: a rewrite target the write door would
        // never have accepted is no viable rewrite, so it PAUSES rather than
        // being persisted as an active definition nobody could have authored.
        if let Err(error) = validate_definition(&migrated) {
            let error = format!("{moved} produced an invalid definition: {error}");
            return pause_in_txn(vault, wtxn, record, kind, error, now);
        }
        record.definition = migrated;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        let summary = if notices.is_empty() {
            format!("auto-migrated {} predicate(s)", renames.len())
        } else {
            format!("auto-rewritten with notices: {}", notices.join("; "))
        };
        let receipt_ref = record_repair_in_txn(vault, wtxn, query_ref, drift, &summary, now)?;
        Ok(if notices.is_empty() {
            PackDriftResolution::AutoMigrated { receipt_ref }
        } else {
            PackDriftResolution::AutoRewritten { receipt_ref }
        })
    })
}

fn pause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: SavedQueryRecord,
    kind: u8,
    error: String,
    now: u64,
) -> Result<PackDriftResolution> {
    record.definition.lifecycle = SavedQueryLifecycle::Paused {
        error: error.clone(),
    };
    record.updated_at = now;
    store_record_in_txn(vault, wtxn, &record, kind)?;
    Ok(PackDriftResolution::Paused { error })
}

fn record_repair_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    query_ref: EntityId,
    drift: &PackDrift,
    summary: &str,
    now: u64,
) -> Result<EntityId> {
    let repair_ref = EntityId::now();
    let mut row = JsonMap::new();
    row.insert("query_ref".to_owned(), Value::String(query_ref.to_hex()));
    row.insert("summary".to_owned(), Value::String(summary.to_owned()));
    row.insert("recorded_at".to_owned(), Value::from(now));
    row.insert(
        "drift".to_owned(),
        serde_json::to_value(drift)
            .map_err(|_| Error::InvariantViolation("pack drift encode failed"))?,
    );
    let encoded = canonical_json_bytes(&Value::Object(row))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &keys::repair(&repair_ref), &encoded)?;
    Ok(repair_ref)
}

fn rewrite_predicates(ast: &FilterAst, renames: &BTreeMap<String, String>) -> FilterAst {
    match ast {
        FilterAst::All { terms } => FilterAst::All {
            terms: rewrite_terms(terms, renames),
        },
        FilterAst::Any { terms } => FilterAst::Any {
            terms: rewrite_terms(terms, renames),
        },
        FilterAst::Not { term } => FilterAst::Not {
            term: Box::new(rewrite_predicates(term, renames)),
        },
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => FilterAst::Claim {
            predicate: renames
                .get(predicate)
                .cloned()
                .unwrap_or_else(|| predicate.clone()),
            cmp: *cmp,
            value: value.clone(),
        },
        FilterAst::EdgeExists { .. } => ast.clone(),
    }
}

fn rewrite_terms(terms: &[FilterAst], renames: &BTreeMap<String, String>) -> Vec<FilterAst> {
    terms
        .iter()
        .map(|term| rewrite_predicates(term, renames))
        .collect()
}

fn rewrite_matcher(matcher: &MatcherSpec, renames: &BTreeMap<String, String>) -> MatcherSpec {
    match matcher {
        MatcherSpec::Hard { expression } => MatcherSpec::Hard {
            expression: rewrite_predicates(expression, renames),
        },
        other => other.clone(),
    }
}

fn load_migration_map(vault: &Vault, drift: &PackDrift) -> Result<Option<PackMigrationMap>> {
    let Some(raw) = meta_row(vault, &keys::migration_map(drift))? else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("saved query pack migration map"))
}
