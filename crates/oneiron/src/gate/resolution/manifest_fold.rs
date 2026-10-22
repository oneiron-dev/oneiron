//! Store-scanning manifest fold plus budget-guard and trust adapters.

use crate::ports::EntityStoreRead;
use std::collections::BTreeSet;

use crate::claim::{ClaimBody, claim_sensitivity_band};
use crate::error::{Error, Result};
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::vault::Vault;
use crate::write_envelope::{SourceLineage, WriteActor};

use super::manifest_types::ConnectorClassPrecedence;
use super::manifest_types::{
    GateDecisionRetentionPolicy, PolicyManifestResolution, TeacherProbeRow,
};
use crate::gate::ceiling::{
    DelegationFoldCache, DelegationGrantRecord, PolicyOwnerPolicyRow, check_source_trust,
    fold_delegated_grants,
};
use crate::gate::decode::ConnectorClassRole;
use crate::gate::decode::{DecodedManifestCarrier, decode_policy_manifest};

mod doors;
mod fold;

pub(crate) use self::fold::resolve_policy_manifest;

/// The vault ceiling on any project's depth row: the resolved manifest row,
/// capped by the shipped ceiling. A loaded malformed manifest fails closed to
/// the most restrictive ceiling (DEC-0005); it never bricks the vault.
pub(crate) fn resolve_project_depth_max(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u8> {
    let policy = resolve_policy_manifest(store, txn)?;
    if policy.diagnostics.loaded_manifest_forces_fail_closed() {
        return Ok(0);
    }
    let ceiling = crate::gate::default_manifest::SEEDED_PROJECT_DEPTH_MAX;
    Ok(policy.project_depth_max.unwrap_or(ceiling).min(ceiling))
}

/// Resolve in the caller's mint/issuance transaction so policy and the
/// resulting log or pending link observe one LMDB snapshot.
pub(crate) fn resolve_credential_lifetimes(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<super::manifest_types::CredentialLifetimePolicy> {
    let resolved = resolve_policy_manifest(store, txn)?;
    if resolved.is_fail_closed() {
        return Err(Error::InvalidConfig(
            "credential lifetime policy is unavailable".into(),
        ));
    }
    resolved.credential_lifetimes.ok_or_else(|| {
        Error::InvalidConfig(
            "credential lifetime policy missing from trusted vault manifests".into(),
        )
    })
}

/// The stored manifests [`resolve_policy_manifest`] folds on `txn`, by id:
/// each row it reads into the resolution, trusted or not, and each one whose
/// shape only sets a diagnostic. A quarantined manifest and a project-depth
/// row its own causal fold resolves contribute nothing, so they are left
/// out. A listing door names these as the rows a resolved frontier is read
/// from; the frontier's hash is no row.
///
/// # Errors
///
/// A store failure, as the fold's own.
pub(crate) fn policy_manifest_contributors(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<crate::EntityId>> {
    let mut ids = Vec::new();
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_POLICY_MANIFEST, None)? {
        let id = match index_entry {
            Ok(id) => id,
            Err(Error::CorruptedIndex(_)) => continue,
            Err(error) => return Err(error),
        };
        let raw = match store.port_entity_record(txn, &id) {
            Ok(Some(row)) => row,
            Ok(None) | Err(Error::CorruptedIndex("entity header")) => continue,
            Err(error) => return Err(error),
        };
        if raw.entity_type == ENTITY_TYPE_POLICY_MANIFEST {
            // Only a project-depth carrier is decoded here (FIX 5987).
            if crate::gate::project_depth::is_project_depth_id(&id)
                || crate::gate::project_depth::is_project_depth_contribution(&raw.body)
            {
                if matches!(
                    &store.manifest_memo().row(&raw.body).carrier,
                    Some(DecodedManifestCarrier::ProjectDepth(_))
                ) {
                    continue;
                }
            } else if crate::gate::manifest_authenticity::manifest_is_quarantined(
                store, txn, &id, &raw.body,
            )? {
                continue;
            }
        }
        ids.push(id);
    }
    Ok(ids)
}

/// Resolve the trusted retention setting in the caller's transaction, so a
/// sweep observes the same committed owner setting as the rows it examines.
/// A missing setting never authorizes age pruning; a malformed or ambiguous
/// manifest is an error, not a silent fallback to a different horizon.
pub(crate) fn resolve_gate_decision_retention(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<GateDecisionRetentionPolicy>> {
    let resolution = resolve_policy_manifest(store, txn)?;
    if resolution.diagnostics.is_fail_closed() {
        return Err(Error::InvalidConfig(
            "gate decision retention policy manifest is fail-closed".into(),
        ));
    }
    Ok(resolution.gate_decision_retention)
}

/// The only carrier a narrow owner retention edit may rewrite. Determine the
/// effective trusted row in the same snapshot as resolution, never by a fixed
/// ID whose body may have been replaced by an untrusted peer contribution.
pub(crate) fn retention_edit_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<(GateDecisionRetentionPolicy, crate::EntityId)> {
    let policy = resolve_gate_decision_retention(store, txn)?.ok_or(Error::InvalidConfig(
        "gate decision retention manifest missing".into(),
    ))?;
    let default_id = crate::gate::default_manifest::default_policy_manifest_id()?;
    let mut owner_ids = Vec::new();
    let mut default_present = false;
    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_POLICY_MANIFEST, None)? {
        let id = index_entry?;
        let Some(raw) = store.port_entity_record(txn, &id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_POLICY_MANIFEST
            || crate::gate::manifest_authenticity::manifest_is_quarantined(
                store, txn, &id, &raw.body,
            )?
            || !crate::gate::manifest_authenticity::manifest_is_trusted(store, txn, &id, &raw.body)?
        {
            continue;
        }
        let decoded = decode_policy_manifest(&raw.body)
            .ok_or(Error::CorruptedIndex("trusted retention manifest"))?;
        if decoded.gate_decision_retention.is_none() {
            continue;
        }
        if id == default_id
            && crate::gate::manifest_authenticity::manifest_is_seeded_default(
                store, txn, &id, &raw.body,
            )?
        {
            default_present = true;
        } else {
            owner_ids.push(id);
        }
    }
    let target = match owner_ids.as_slice() {
        [one] => *one,
        [] if default_present => default_id,
        _ => {
            return Err(Error::InvalidConfig(
                "retention edit has no unique trusted carrier".into(),
            ));
        }
    };
    Ok((policy, target))
}

fn merge_teacher_probe_row(resolution: &mut PolicyManifestResolution, row: TeacherProbeRow) {
    let vault_min = resolution.teacher_probe_vault_min.get_or_insert(0);
    *vault_min = (*vault_min).max(row.min_f1_millionths);
    for (holder, minimum) in row.holders {
        let floor = resolution.teacher_probe_holders.entry(holder).or_insert(0);
        *floor = (*floor).max(minimum);
    }
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
/// `(row_ref, world_ref, project_ref)` triple.
///
/// The TRIPLE, not the ref alone: one ref written under separate scopes is a
/// scoped override, and only rows in the same exact slot shadow each other.
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
    rows.iter().filter(|row| row.active).any(|row| {
        !seen.insert((
            row.row_ref.as_str(),
            row.world_ref.as_deref(),
            row.project_ref.as_deref(),
        ))
    })
}

/// `actor_ref` is the hex entity ref of the actor presenting this write, or
/// `None` for an unattributed one. Actor-bound source-trust rows answer only
/// the actor they name, so an unattributed write never rides one.
///
/// `lineage` comes from the write's envelope. A door without an envelope
/// passes `None` and keeps its declared-source-only verdict.
pub(in crate::gate) fn check_claim_source_trust(
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
