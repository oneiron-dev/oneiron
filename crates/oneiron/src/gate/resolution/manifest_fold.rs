//! Store-scanning manifest fold plus budget-guard and trust adapters.

use std::collections::BTreeSet;

use crate::claim::{ClaimBody, claim_sensitivity_band};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::vault::Vault;
use crate::write_envelope::{SourceLineage, WriteActor};

use super::manifest_types::PolicyManifestResolution;
use crate::gate::breaker::{GateBreakerThresholds, resolve_gate_breaker_thresholds};
use crate::gate::ceiling::{
    DelegationFoldCache, DelegationGrantRecord, PolicyOwnerPolicyRow, check_source_trust,
    fold_delegated_grants,
};
use crate::gate::decode::decode_policy_manifest;

pub(crate) fn resolve_policy_manifest(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();
    let mut delegated_rows: Vec<DelegationGrantRecord> = Vec::new();
    // ONE-1453: only VALID overrides enter the fold; a malformed one
    // contributed no candidate at decode.
    let mut actor_burst_breaker_candidates: Vec<GateBreakerThresholds> = Vec::new();

    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_POLICY_MANIFEST) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        }

        match decode_policy_manifest(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]) {
            Some(decoded) => {
                resolution.diagnostics.manifest_count += 1;
                resolution.diagnostics.malformed_manifest_seen |=
                    decoded.source_trust.malformed_manifest_seen;
                resolution.diagnostics.unsupported_schema_seen |= decoded.unsupported_schema;
                resolution.diagnostics.engine_version_floor_seen |= decoded.engine_version_floor;
                resolution.diagnostics.unknown_axis_seen |= decoded.unknown_axis_seen;
                resolution.source_trust.merge(decoded.source_trust);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                delegated_rows.extend(decoded.delegated_grants);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                resolution
                    .owner_policy_rows
                    .extend(decoded.owner_policy_rows);
                resolution.owner_policy_rows_dropped |= decoded.owner_policy_rows_dropped;
                resolution.owner_policy_enabled |= decoded.owner_policy_enabled;
                resolution
                    .owner_policy_patterns
                    .extend(decoded.owner_policy_patterns);
                resolution.owner_policy_patterns_dropped |= decoded.owner_policy_patterns_dropped;
                // One document per plane. Two manifests each naming one is an
                // ambiguity nothing downstream could resolve, so it drops the
                // owner plane's model classification rather than picking a
                // winner.
                merge_single_owner_string(
                    &mut resolution.owner_policy_document,
                    decoded.owner_policy_document,
                    &mut resolution.diagnostics.malformed_manifest_seen,
                );
                merge_single_owner_string(
                    &mut resolution.owner_policy_output_contract,
                    decoded.owner_policy_output_contract,
                    &mut resolution.diagnostics.malformed_manifest_seen,
                );
                resolution.signatures.extend(decoded.signatures);
                if let Some(on_budget_exhausted) = decoded.on_budget_exhausted {
                    match resolution.on_budget_exhausted {
                        None => resolution.on_budget_exhausted = Some(on_budget_exhausted),
                        Some(existing) if existing == on_budget_exhausted => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                // Unlike `on_budget_exhausted`, disagreement here is NOT
                // malformed: the posture has a restrictive pole, so two packs
                // that disagree have a deterministic, safe answer — hold the
                // send. Marking that malformed would fail the whole vault
                // closed over a question the axis can answer itself.
                if let Some(posture) = decoded.comm_opt_out_posture {
                    resolution.comm_opt_out_posture = Some(
                        resolution
                            .comm_opt_out_posture
                            .map_or(posture, |existing| existing.restrict(posture)),
                    );
                }
                // One checker per vault (ONE-1296), folded exactly like the
                // budget policy above: the first value wins, a second manifest
                // stating the SAME ref is one configuration written twice, and
                // two manifests naming different checkers is a policy state
                // nothing downstream could resolve — so it fails closed rather
                // than picking a winner.
                if let Some(auto_checker) = decoded.auto_checker {
                    match &resolution.auto_checker {
                        None => resolution.auto_checker = Some(auto_checker),
                        Some(existing) if *existing == auto_checker => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                // Deterministic resolved order: type-index manifest scan
                // order, then row order inside each manifest. Row indices in
                // ladder events index this concatenation.
                resolution.budget_policy.extend_rows(decoded.budget_policy);
                if let Some(thresholds) = decoded.actor_burst_breaker {
                    actor_burst_breaker_candidates.push(thresholds);
                }
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    // Duplicate owner rows are refused per manifest by
    // `parse_owner_policy_rows`, but the RESOLVED table is the concatenation
    // of every manifest's rows and `active_owner_policy_rows` first-matches
    // over that concatenation. Two manifests naming the same `(row_ref,
    // world_ref)` pair once each are individually well formed and still shadow
    // one another here — the same rule that can never fire, however strict its
    // action, only assembled across entities instead of inside one. So the
    // question is asked again of the resolved set, and answered the same way:
    // drop the rows rather than let one silently swallow the other.
    if has_duplicate_owner_policy_row(&resolution.owner_policy_rows) {
        resolution.owner_policy_rows.clear();
        resolution.owner_policy_rows_dropped = true;
    }

    // ONE-1453: the distinct-valid-value rule alone decides. One distinct
    // valid value applies; two or more are an ambiguity, and both that case
    // and the zero-candidate case take engine defaults. A conflicting dial is
    // NOT a malformed manifest: it does not fail-close the write gate.
    resolution.actor_burst_breaker =
        resolve_gate_breaker_thresholds(&actor_burst_breaker_candidates);

    // A resolved table must stay addressable by a u16 row index: up to 65,536
    // rows (indices 0..=65535) are valid; the 65,537th row marks the whole
    // resolution malformed, fail-closing the write gate exactly like any
    // malformed manifest and refusing the budget-policy accessor. Never wrap
    // or silently truncate a row index.
    if resolution.budget_policy.rows().len() > usize::from(u16::MAX) + 1 {
        resolution.diagnostics.malformed_manifest_seen = true;
    }

    match fold_delegated_grants(&delegated_rows) {
        Some(fold) => resolution.delegation_fold = fold,
        None => {
            resolution.diagnostics.malformed_manifest_seen = true;
            resolution.delegation_fold = DelegationFoldCache::default();
        }
    }

    if resolution.diagnostics.loaded_manifest_forces_fail_closed() {
        resolution.source_trust.fail_closed();
    }

    Ok(resolution)
}

/// Folds a once-per-vault owner string across manifests. A second manifest
/// naming the same field differently is a malformed policy state, not a
/// precedence question.
fn merge_single_owner_string(
    resolved: &mut Option<String>,
    decoded: Option<String>,
    malformed: &mut bool,
) {
    let Some(decoded) = decoded else {
        return;
    };
    match resolved {
        None => *resolved = Some(decoded),
        Some(existing) if *existing == decoded => {}
        Some(_) => *malformed = true,
    }
}

/// Whether any two rows that could be in force TOGETHER claim the same
/// `(row_ref, world_ref)` pair.
///
/// The PAIR, not the ref alone: one ref written under two worlds is the
/// scoped-override shape `active_owner_policy_rows` exists to resolve, and only
/// rows that would land in the same rubric together can shadow each other.
/// Same key as the per-manifest check in `parse_owner_policy_rows`.
///
/// And only ACTIVE rows, for exactly the reason the sentence above gives.
/// `active_owner_policy_rows` filters on `row.active` before it resolves
/// anything, so a disabled row is never a candidate and cannot shadow
/// anything. Counting one made a historical row a landmine: pairing it with
/// the live row that replaced it dropped the WHOLE resolved table and left an
/// enabled owner plane refusing to classify — a fail-closed answer to a
/// question that was never ambiguous.
fn has_duplicate_owner_policy_row(rows: &[PolicyOwnerPolicyRow]) -> bool {
    let mut seen = BTreeSet::new();
    rows.iter()
        .filter(|row| row.active)
        .any(|row| !seen.insert((row.row_ref.as_str(), row.world_ref.as_deref())))
}

impl Vault {
    /// Builds the ONE policy-aware LLM budget meter for one wake pass: the
    /// same `BudgetGuard`, bound at construction to the engine-stamped actor
    /// and to the live manifest's resolved `budget_policy` table.
    ///
    /// The factory resolves the manifest itself and is fail-closed: when the
    /// loaded resolution forces fail-closed (malformed manifest, unsupported
    /// schema version, engine-version floor, unknown axis, row-count
    /// overflow) it refuses with [`Error::InvalidConfig`] and never
    /// substitutes an empty or fabricated table. Production callers keep
    /// admitting with `guard.admit_for_request(&request)` exactly as before.
    pub fn policy_budget_guard(
        &self,
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
    ) -> Result<BudgetGuard> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let table = resolution.budget_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "policy manifest resolution is fail-closed; refusing to build a policy budget guard"
                    .to_owned(),
            )
        })?;
        Ok(BudgetGuard::with_policy_table(
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            actor,
            table,
        ))
    }
}

/// `actor_ref` is the hex entity ref of the actor presenting this write, or
/// `None` for an unattributed one. Actor-bound source-trust rows answer only
/// the actor they name, so an unattributed write never rides one.
///
/// `lineage` comes from the write's envelope. A door without an envelope
/// passes `None` and keeps its declared-source-only verdict.
pub(crate) fn check_claim_source_trust(
    body: &ClaimBody,
    actor_ref: Option<&str>,
    policy: &PolicyManifestResolution,
    lineage: Option<&SourceLineage>,
) -> Result<()> {
    check_source_trust(
        body.source,
        body.approval,
        claim_sensitivity_band(body),
        actor_ref,
        &policy.source_trust,
        lineage,
    )
}

pub(crate) fn type_index_entity_id(key: &[u8], entity_type: u8) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != entity_type {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}
