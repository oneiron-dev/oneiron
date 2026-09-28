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
use crate::gate::decode::decode_policy_manifest;

pub(crate) fn resolve_policy_manifest(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();
    // The shipped manifest supplies bootstrap policy even when a replacement
    // omits optional count rows; a peer cannot replace these trusted defaults.
    let shipped = decode_policy_manifest(&crate::gate::default_manifest::default_policy_manifest())
        .ok_or(Error::InvariantViolation(
            "shipped sheet-answer policy manifest invalid",
        ))?;
    resolution.sheet_answer_default_max_count = shipped
        .sheet_answer_limits
        .iter()
        .find(|row| row.artifact_ref.is_none() && row.sheet.is_none())
        .map(|row| row.max_count);
    resolution.sheet_answer_precedence = shipped.sheet_answer_precedence;
    if resolution.sheet_answer_default_max_count.is_none()
        || resolution.sheet_answer_precedence.is_none()
    {
        return Err(Error::InvariantViolation(
            "shipped sheet-answer policy rows missing",
        ));
    }
    let mut untrusted_source_rows = Vec::new();
    let mut untrusted_teacher_rows = Vec::new();
    let mut untrusted_sheet_limits = Vec::new();
    let mut delegated_rows: Vec<DelegationGrantRecord> = Vec::new();
    let mut default_retention = None;
    let mut owner_retention = None;
    let default_manifest_id = crate::gate::default_manifest::default_policy_manifest_id()?;
    let mut vault_class_carry: Option<BTreeSet<(String, String)>> = None;
    let mut holder_class_carry: Vec<BTreeSet<(String, String)>> = Vec::new();
    let mut vault_precedence: Option<ConnectorClassPrecedence> = None;
    let mut shipped_pptx_limits: Option<crate::edit_roundtrip::pptx::PptxOperationalLimits> = None;
    let mut owner_pptx_limits: Option<crate::edit_roundtrip::pptx::PptxOperationalLimits> = None;
    let mut authored_confidence: Option<crate::gate::carry_forward_policy::CarryForwardPolicy> =
        None;
    let mut seeded_confidence: Option<crate::gate::carry_forward_policy::CarryForwardPolicy> = None;

    for index_entry in store.port_entity_ids_by_type(txn, ENTITY_TYPE_POLICY_MANIFEST, None)? {
        let id = match index_entry {
            Ok(id) => id,
            Err(Error::CorruptedIndex(_)) => {
                resolution.diagnostics.malformed_manifest_seen = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        let raw = match store.port_entity_record(txn, &id) {
            Ok(Some(row)) => row,
            Ok(None) | Err(Error::CorruptedIndex("entity header")) => {
                resolution.diagnostics.malformed_manifest_seen = true;
                continue;
            }
            Err(error) => return Err(error),
        };

        if raw.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        }

        let body = &raw.body;
        if crate::gate::manifest_authenticity::manifest_is_quarantined(store, txn, &id, body)? {
            continue;
        }
        let trusted =
            crate::gate::manifest_authenticity::manifest_is_trusted(store, txn, &id, body)?;
        match decode_policy_manifest(body) {
            Some(decoded) => {
                resolution.diagnostics.manifest_count += 1;
                if !trusted {
                    untrusted_source_rows.push(decoded.source_trust);
                    if let Some(row) = decoded.teacher_probe {
                        untrusted_teacher_rows.push(row);
                    }
                    untrusted_sheet_limits.extend(decoded.sheet_answer_limits);
                    continue;
                }
                // Only trusted packs can authorize the no-LLM lane. Each must agree.
                if resolution.packs.is_empty() {
                    resolution.single_valued_predicates = decoded.single_valued_predicates;
                } else {
                    resolution
                        .single_valued_predicates
                        .retain(|p| decoded.single_valued_predicates.contains(p));
                }
                resolution.diagnostics.malformed_manifest_seen |=
                    decoded.source_trust.malformed_manifest_seen;
                resolution.diagnostics.unsupported_schema_seen |= decoded.unsupported_schema;
                resolution.diagnostics.engine_version_floor_seen |= decoded.engine_version_floor;
                resolution.diagnostics.unknown_axis_seen |= decoded.unknown_axis_seen;
                if let Some(row) = decoded.teacher_probe {
                    resolution.teacher_probe_trusted = true;
                    merge_teacher_probe_row(&mut resolution, row);
                }
                resolution.source_trust.merge(decoded.source_trust);
                resolution
                    .experiment_selection
                    .extend(decoded.experiment_selection);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                delegated_rows.extend(decoded.delegated_grants);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                resolution.room_policy_rows.extend(decoded.room_policy_rows);
                resolution
                    .federation_grant_rows
                    .extend(decoded.federation_grant_rows);
                resolution
                    .owner_policy_rows
                    .extend(decoded.owner_policy_rows);
                resolution.owner_policy_rows_dropped |= decoded.owner_policy_rows_dropped;
                resolution.owner_policy_precedence = if resolution.packs.is_empty() {
                    decoded.owner_policy_precedence
                } else {
                    resolution
                        .owner_policy_precedence
                        .restrict(decoded.owner_policy_precedence)
                };
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
                if let Some(retention) = decoded.gate_decision_retention {
                    if retention.rows.iter().any(|row| row.override_parent)
                        && !crate::gate::manifest_authenticity::retention_holder_verified(
                            store, txn, &id, body,
                        )?
                    {
                        resolution.diagnostics.malformed_manifest_seen = true;
                    }
                    // The seeded D7 row is a FALLBACK, not an owner vote.
                    // Byte-exact matching avoids treating a later owner update
                    // at that same ID as another copy of the seeded default.
                    if id == default_manifest_id
                        && body.as_slice()
                            == crate::gate::default_manifest::default_policy_manifest().as_slice()
                    {
                        default_retention = Some(retention);
                    } else {
                        match owner_retention.as_ref() {
                            None => owner_retention = Some(retention),
                            Some(existing) if *existing == retention => {}
                            Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                        }
                    }
                }
                if let Some(on_budget_exhausted) = decoded.on_budget_exhausted {
                    match resolution.on_budget_exhausted {
                        None => resolution.on_budget_exhausted = Some(on_budget_exhausted),
                        Some(existing) if existing == on_budget_exhausted => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
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
                match decoded.connector_class_role {
                    ConnectorClassRole::Vault => {
                        if let Some(rows) = decoded.connector_class_carry {
                            match &mut vault_class_carry {
                                None => vault_class_carry = Some(rows),
                                Some(existing) => existing.retain(|row| rows.contains(row)),
                            }
                        }
                        if let Some(precedence) = decoded.connector_class_precedence {
                            match vault_precedence {
                                None => vault_precedence = Some(precedence),
                                Some(existing) if existing == precedence => {}
                                Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                            }
                        }
                    }
                    ConnectorClassRole::Holder => {
                        if decoded.connector_class_precedence.is_some() {
                            resolution.diagnostics.malformed_manifest_seen = true;
                        }
                        if let Some(rows) = decoded.connector_class_carry {
                            holder_class_carry.push(rows);
                        }
                    }
                }
                resolution.budget_policy.extend_rows(decoded.budget_policy);
                if let Some(voice_serving) = decoded.voice_serving {
                    resolution.voice_serving.push(voice_serving);
                }
                if let Some(policy) = decoded.pack_install_policy {
                    if let Some(existing) = &mut resolution.pack_install_policy {
                        existing.restrict(policy);
                    } else {
                        resolution.pack_install_policy = Some(policy);
                    }
                }
                if let Some(rows) = decoded.retrieval_retention {
                    resolution.retrieval_retention.narrow(rows);
                }
                if let Some(settings) = decoded.room_thread {
                    resolution.room_thread = match resolution.room_thread.take() {
                        None => Some(settings),
                        Some(current) => match current.restrict(settings) {
                            Some(folded) => Some(folded),
                            None => {
                                resolution.diagnostics.malformed_manifest_seen = true;
                                None
                            }
                        },
                    };
                }
                if let Some(limits) = decoded.pptx_comment_limits {
                    // The shipped row is a DEFAULT, not a permanent ceiling:
                    // an authenticated vault row may adjust it up or down.
                    // Multiple owner rows and holder caps compose restrictively.
                    let slot = if id == crate::gate::default_policy_manifest_id()? {
                        &mut shipped_pptx_limits
                    } else {
                        &mut owner_pptx_limits
                    };
                    *slot = Some(slot.map_or(limits, |previous| previous.narrow(limits)));
                }
                resolution
                    .booking_conversion_rows
                    .extend(decoded.booking_conversion_rows);
                // Resolve class policy restrictively across trusted manifests.
                resolution.wait_policy.extend_rows(decoded.wait_policy);
                resolution.act_policy.extend_rows(decoded.act_policy);
                resolution.hosted_tts.rows.extend(decoded.hosted_tts.rows);
                if let Some(bounds) = decoded.docedit_resource_policy {
                    let baseline = crate::gate::docedit_resource::DoceditResourcePolicy::shipped();
                    resolution.docedit_resource_policy = Some(
                        resolution
                            .docedit_resource_policy
                            .unwrap_or(baseline)
                            .restrict(bounds),
                    );
                }

                if let Some(limits) = decoded.livequery_tracker_limits {
                    if let Some(existing) = &mut resolution.livequery_tracker_limits {
                        existing.restrict(limits);
                    } else {
                        resolution.livequery_tracker_limits = Some(limits);
                    }
                }
                if !resolution
                    .slide_review_policy
                    .restrict(decoded.slide_review_policy)
                {
                    resolution.diagnostics.malformed_manifest_seen = true;
                }
                if let Some(limits) = decoded.docx_archive_limits {
                    resolution.docx_archive_limits.push(limits);
                }

                if let Some(bounds) = decoded.diagnostic_bounds {
                    match resolution.diagnostic_bounds {
                        None => resolution.diagnostic_bounds = Some(bounds),
                        Some(existing) if existing == bounds => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                resolution.policy_values.extend(decoded.policy_values);
                if let Some(ask_policy) = decoded.ask_policy {
                    match &mut resolution.ask_policy {
                        Some(current) => {
                            if current.restrict(&ask_policy).is_none() {
                                resolution.diagnostics.malformed_manifest_seen = true;
                            }
                        }
                        None => resolution.ask_policy = Some(ask_policy),
                    }
                }
                if let Some(limits) = decoded.attribution_limits {
                    if resolution.attribution_limits_set {
                        resolution.attribution_limits.restrict(limits);
                    } else {
                        resolution.attribution_limits = limits;
                        resolution.attribution_limits_set = true;
                    }
                }
                resolution
                    .sheet_answer_limits
                    .extend(decoded.sheet_answer_limits);
                if let Some(limits) = decoded.goal_limits {
                    resolution.goal_limits = Some(
                        resolution
                            .goal_limits
                            .map_or(limits, |old| old.restrict(limits)),
                    );
                }
                if let Some(limits) = decoded.voice_ref_limits {
                    if id == crate::gate::default_policy_manifest_id()? {
                        resolution.voice_ref_defaults = Some(limits);
                    } else {
                        if let Some(precedence) = limits.precedence {
                            match resolution.voice_ref_limits.precedence {
                                None => resolution.voice_ref_limits.precedence = Some(precedence),
                                Some(existing) if existing == precedence => {}
                                Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                            }
                        }
                        resolution.voice_ref_limits.narrow(limits);
                    }
                }
                if let Some(row) = decoded.linear_mirror {
                    resolution.linear_mirror = Some(
                        resolution
                            .linear_mirror
                            .map_or(row, |old| old.restrict(row)),
                    );
                }
                if let Some(row) = decoded.linear_sync {
                    resolution.linear_sync =
                        Some(resolution.linear_sync.map_or(row, |old| old.restrict(row)));
                }
                if let Some(row) = decoded.wave_handoff {
                    resolution.wave_handoff =
                        Some(resolution.wave_handoff.map_or(row, |old| old.restrict(row)));
                }
                if let Some(precedence) = decoded.operational_precedence {
                    match resolution.operational_precedence {
                        None => resolution.operational_precedence = Some(precedence),
                        Some(existing) if existing == precedence => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                if let Some(quota) = decoded.weave_correction_policy {
                    match &mut resolution.weave_correction_policy {
                        Some(existing) => existing.restrict(quota),
                        slot @ None => *slot = Some(quota),
                    }
                }
                resolution
                    .retry_source_policy
                    .extend(decoded.retry_source_policy);
                if let Some(policy) = decoded.compilation_policy {
                    resolution.compilation_policies.push(policy);
                }
                if let Some(confidence) = decoded.carry_forward_confidence {
                    // Trust answers WHO may author; this body-bound local marker
                    // answers whether the bytes are still the untouched seed.
                    // ID and pack name are document identity, never origin.
                    let seeded = crate::gate::manifest_authenticity::manifest_is_seeded_default(
                        store, txn, &id, body,
                    )?;
                    let target = if seeded {
                        &mut seeded_confidence
                    } else {
                        &mut authored_confidence
                    };
                    if let Some(existing) = target {
                        if !existing.restrict(confidence) {
                            resolution.diagnostics.malformed_manifest_seen = true;
                        }
                    } else {
                        *target = Some(confidence);
                    }
                }
                if let Some(policy) = decoded.judge_calibration {
                    resolution.judge_calibration = Some(
                        resolution
                            .judge_calibration
                            .map_or(policy, |old| old.restrict(policy)),
                    );
                }
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    // A trusted owner-authored row wins over the immutable shipped fallback.
    // A conflict among owner rows never silently picks a pruning horizon.
    resolution.gate_decision_retention = owner_retention.or(default_retention);

    // `None` only when no trusted manifest names a class row, so the frontier
    // of such manifests keeps its established bytes.
    let class_policy_named =
        vault_class_carry.is_some() || vault_precedence.is_some() || !holder_class_carry.is_empty();
    resolution.connector_class_precedence = vault_precedence.unwrap_or_default();
    let mut carry = vault_class_carry.unwrap_or_default();
    match resolution.connector_class_precedence {
        ConnectorClassPrecedence::Nested => {
            for holder in holder_class_carry {
                carry.retain(|row| holder.contains(row));
            }
        }
        ConnectorClassPrecedence::HolderOverride => {
            if holder_class_carry.len() > 1 {
                resolution.diagnostics.malformed_manifest_seen = true;
                carry.clear();
            } else if let Some(holder) = holder_class_carry.pop() {
                carry.retain(|row| holder.contains(row));
            }
        }
    }
    resolution.connector_class_carry = class_policy_named.then_some(carry);

    resolution.pptx_comment_limits = owner_pptx_limits.or(shipped_pptx_limits);
    resolution.carry_forward_authored = authored_confidence.is_some();
    resolution.carry_forward_confidence = authored_confidence
        .or(seeded_confidence)
        .unwrap_or_default();

    resolution.untrusted_sheet_answer_limits = untrusted_sheet_limits;
    for contribution in untrusted_source_rows {
        resolution.source_trust.restrict_only(contribution);
    }
    // Untrusted manifests may only RAISE a trusted vault floor, never seed
    // the teacher policy by themselves or lower an existing holder floor.
    for row in untrusted_teacher_rows {
        merge_teacher_probe_row(&mut resolution, row);
    }

    // Two manifests carrying the identical row (a copy of the shipped defaults,
    // say) state one value and keep one copy. Different rows for one key/scope
    // slot cannot silently depend on entity scan order, and a stored row at a
    // level its key's door cannot resolve fails closed.
    let mut value_slots = std::collections::BTreeMap::new();
    let mut value_rows = Vec::with_capacity(resolution.policy_values.len());
    for row in std::mem::take(&mut resolution.policy_values) {
        match value_slots.get(&(row.key, row.scope)) {
            Some(&index) if value_rows[index] == row => {}
            Some(_) => {
                resolution.diagnostics.malformed_manifest_seen = true;
                value_rows.push(row);
            }
            None => {
                value_slots.insert((row.key, row.scope), value_rows.len());
                value_rows.push(row);
            }
        }
    }
    resolution.policy_values = value_rows;
    if crate::gate::policy_values::unadmitted_row(&resolution.policy_values).is_some() {
        resolution.diagnostics.malformed_manifest_seen = true;
    }

    // Duplicate owner rows are refused per manifest by
    // `parse_owner_policy_rows`, but the RESOLVED table is the concatenation
    // of every manifest's rows and scope selection first-matches over that
    // concatenation. Two manifests naming the same
    // `(row_ref, world_ref, project_ref)` triple once each are individually
    // well formed and still shadow
    // one another here — the same rule that can never fire, however strict its
    // action, only assembled across entities instead of inside one. So the
    // question is asked again of the resolved set, and answered the same way:
    // drop the rows rather than let one silently swallow the other.
    if has_duplicate_owner_policy_row(&resolution.owner_policy_rows) {
        resolution.owner_policy_rows.clear();
        resolution.owner_policy_rows_dropped = true;
    }

    // A resolved table must stay addressable by a u16 row index: up to 65,536
    // rows (indices 0..=65535) are valid; the 65,537th row marks the whole
    // resolution malformed, fail-closing the write gate exactly like any
    // malformed manifest and refusing the budget-policy accessor. Never wrap
    // or silently truncate a row index.
    if resolution.hosted_tts.rows.len() > usize::from(u16::MAX) + 1 {
        resolution.diagnostics.malformed_manifest_seen = true;
    }
    if resolution.budget_policy.rows().len() > usize::from(u16::MAX) + 1
        || resolution.booking_conversion_rows.len() > 128
    {
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
    let seeded = crate::gate::default_manifest::default_policy_manifest();
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
        if id == default_id && raw.body == seeded {
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

impl Vault {
    /// Resolve the live document package limits from trusted policy rows.
    /// A missing or invalid manifest is a refusal, never an organ fallback.
    pub fn docedit_package_limits(&self) -> Result<oneiron_docedit::retained_opc::Limits> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let policy = resolution.docedit_resource_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "document resource policy is unavailable or fail-closed".to_owned(),
            )
        })?;
        Ok(policy.organ_limits())
    }

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
