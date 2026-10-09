use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;

use super::definition::{SavedQueryDefinition, SavedQueryLifecycle, SavedQueryRecord};
use super::filter::{FilterAst, MatcherSpec, filter_dependencies};
use super::lifecycle::{next_version, validate_definition};
use super::storage::{
    PACK_MIGRATION_MAPS, REPAIRS, RepairReceipt, load_record_in_txn, migration_map_key,
    saved_query_type_byte, store_record_in_txn,
};
use super::support::invalid;

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
        /// The affected predicates the migration map had NO rewrite for.
        ///
        /// This is one of the two pause causes; the other — a migrated
        /// definition the write door rejects — pauses with this list EMPTY, so
        /// the field is what tells the two apart. The names are already
        /// computed before `error` joins them into prose; carrying them as
        /// data means an operator surface listing which predicates broke a
        /// query never has to parse them back out of the sentence.
        ///
        /// In-memory only: the persisted
        /// [`SavedQueryLifecycle::Paused`] keeps the same `error` string it
        /// always did, so no stored bytes change.
        unmapped_predicates: Vec<String>,
    },
}

/// One repair the drift ladder recorded: a migration, a rewrite and its
/// notice, or a proposal the query's owner decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackDriftRepair {
    pub repair_ref: EntityId,
    pub query_ref: EntityId,
    pub summary: String,
    pub recorded_at: u64,
    pub drift: PackDrift,
}

/// Every repair the drift ladder recorded, in id order.
///
/// # Errors
///
/// Storage errors; a row that does not decode.
pub fn pack_drift_repairs(vault: &Vault) -> Result<Vec<PackDriftRepair>> {
    let rtxn = vault.store.env.read_txn()?;
    REPAIRS
        .iter_from(&vault.store, &rtxn, &[])?
        .map(|row| {
            let (repair_ref, receipt) = row?;
            Ok(PackDriftRepair {
                repair_ref,
                query_ref: receipt.query_ref,
                summary: receipt.summary,
                recorded_at: receipt.recorded_at,
                drift: receipt.drift,
            })
        })
        .collect()
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
    vault.with_write_txn(|wtxn| {
        PACK_MIGRATION_MAPS.put(&vault.store, wtxn, &migration_map_key(drift), map)?;
        Ok(())
    })
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
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let record =
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
        run_ladder_in_txn(vault, wtxn, record, kind, drift, &map, Resume::Yes, now)
    })
}

/// Whether a successful rewrite makes the query active again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resume {
    /// The caller is repairing this query: a viable rewrite resumes it.
    Yes,
    /// A pack moved under the query: its lifecycle stays as it was, so a
    /// pause with another cause stays visible until its owner resolves it.
    No,
}

/// The ladder over one loaded record, in the caller's write transaction.
#[allow(clippy::too_many_arguments)]
fn run_ladder_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: SavedQueryRecord,
    kind: u8,
    drift: &PackDrift,
    map: &PackMigrationMap,
    resume: Resume,
    now: u64,
) -> Result<PackDriftResolution> {
    let query_ref = record.query_ref;
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
    if !unmapped.is_empty() {
        let error = format!(
            "{moved} has no rewrite for predicate(s) {}",
            unmapped.join(", ")
        );
        return pause_in_txn(vault, wtxn, record, kind, error, unmapped, resume, now);
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
        lifecycle: match resume {
            Resume::Yes => SavedQueryLifecycle::Active,
            Resume::No => record.definition.lifecycle.clone(),
        },
        ..record.definition.clone()
    };
    // The ladder's own last rung: a rewrite target the write door would
    // never have accepted is no viable rewrite, so it PAUSES rather than
    // being persisted as an active definition nobody could have authored.
    if let Err(error) = validate_definition(&migrated) {
        let error = format!("{moved} produced an invalid definition: {error}");
        // The OTHER pause cause: every predicate mapped, so the unmapped
        // list is empty and that emptiness is how a caller tells this rung
        // from the no-rewrite one.
        return pause_in_txn(vault, wtxn, record, kind, error, Vec::new(), resume, now);
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
}

/// One installed pack moving to another source, as the install door sees it.
pub(crate) struct PackMove<'a> {
    pub(crate) pack: &'a str,
    pub(crate) from_version: &'a str,
    pub(crate) to_version: &'a str,
    /// Predicates the installed source declared.
    pub(crate) from_predicates: &'a BTreeSet<String>,
    /// Predicates the new source declares.
    pub(crate) to_predicates: &'a BTreeSet<String>,
}

/// The pack-update rung of the drift ladder (ARCH-0059 §4), in the install's
/// own write transaction, so the new pack and the repairs it forces commit
/// together or not at all. Every saved query that is not archived and reads a
/// predicate the move dropped, or one the move's migration map rewrites, runs
/// the ladder. Its lifecycle is kept: a query paused for another cause stays
/// paused.
///
/// # Errors
///
/// Storage errors propagate, and abort the install with them.
pub(crate) fn repair_saved_queries_after_pack_move_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    moved: &PackMove<'_>,
    now: u64,
) -> Result<Vec<(EntityId, PackDriftResolution)>> {
    let mut drift = PackDrift {
        from_pack_id: moved.pack.to_owned(),
        from_version: moved.from_version.to_owned(),
        to_pack_id: moved.pack.to_owned(),
        to_version: moved.to_version.to_owned(),
        affected_predicates: Vec::new(),
    };
    let map = PACK_MIGRATION_MAPS
        .get(&vault.store, wtxn, &migration_map_key(&drift))?
        .unwrap_or_default();
    let touched: BTreeSet<&String> = moved
        .from_predicates
        .difference(moved.to_predicates)
        .chain(
            map.rewrites
                .keys()
                .filter(|predicate| moved.from_predicates.contains(*predicate)),
        )
        .collect();
    if touched.is_empty() {
        return Ok(Vec::new());
    }
    // A vault without the saved-query kind holds no saved queries.
    let Ok(kind) = saved_query_type_byte(vault) else {
        return Ok(Vec::new());
    };
    let query_refs = vault
        .store
        .port_entity_ids_by_type(wtxn, kind, None)?
        .collect::<Result<Vec<_>>>()?;
    let mut repaired = Vec::new();
    for query_ref in query_refs {
        let Some(record) = load_record_in_txn(vault, wtxn, query_ref, kind)? else {
            continue;
        };
        if record.definition.lifecycle == SavedQueryLifecycle::Archived {
            continue;
        }
        drift.affected_predicates =
            filter_dependencies(&record.definition.filter, &record.definition.matcher)
                .claim_predicates
                .into_iter()
                .filter(|predicate| touched.contains(predicate))
                .collect();
        if drift.affected_predicates.is_empty() {
            continue;
        }
        let resolution =
            run_ladder_in_txn(vault, wtxn, record, kind, &drift, &map, Resume::No, now)?;
        repaired.push((query_ref, resolution));
    }
    Ok(repaired)
}

#[allow(clippy::too_many_arguments)]
fn pause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: SavedQueryRecord,
    kind: u8,
    error: String,
    unmapped_predicates: Vec<String>,
    resume: Resume,
    now: u64,
) -> Result<PackDriftResolution> {
    // Under a pack move, a query already paused keeps the cause it was
    // paused for beside the new one.
    let shown = match (&record.definition.lifecycle, resume) {
        (SavedQueryLifecycle::Paused { error: earlier }, Resume::No) => {
            format!("{earlier}; {error}")
        }
        _ => error.clone(),
    };
    record.definition.lifecycle = SavedQueryLifecycle::Paused { error: shown };
    record.updated_at = now;
    store_record_in_txn(vault, wtxn, &record, kind)?;
    Ok(PackDriftResolution::Paused {
        error,
        unmapped_predicates,
    })
}

fn record_repair_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    query_ref: EntityId,
    drift: &PackDrift,
    summary: &str,
    now: u64,
) -> Result<EntityId> {
    let repair_ref = vault.store.clock.entity_id()?;
    REPAIRS.put(
        &vault.store,
        wtxn,
        &repair_ref,
        &RepairReceipt {
            query_ref,
            summary: summary.to_owned(),
            recorded_at: now,
            drift: drift.clone(),
        },
    )?;
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
        FilterAst::EdgeExists { .. } | FilterAst::TaskOwner { .. } => ast.clone(),
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
    let rtxn = vault.store.env.read_txn()?;
    PACK_MIGRATION_MAPS.get(&vault.store, &rtxn, &migration_map_key(drift))
}
