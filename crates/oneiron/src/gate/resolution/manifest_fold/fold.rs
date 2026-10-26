//! The whole policy-manifest fold; `manifest_fold` re-exports it.

use super::*;

// One fold per manifest row, in manifest order: splitting it would scatter one manifest.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub(crate) fn resolve_policy_manifest(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();
    // The shipped manifest supplies bootstrap policy even when a replacement
    // omits optional count rows; a peer cannot replace these trusted defaults.
    let shipped = store.manifest_memo().shipped()?;
    resolution.sheet_answer_default_max_count = Some(shipped.sheet_answer_default_max_count);
    resolution.sheet_answer_precedence = Some(shipped.sheet_answer_precedence);
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
    // The document resource and DOCX archive rows follow the PPTX rows: the
    // shipped row is a default, an owner's trusted rows replace it, and rows
    // within each group meet restrictively (FIX 8763, 8764).
    let mut shipped_docedit_resource: Option<crate::gate::docedit_resource::DoceditResourcePolicy> =
        None;
    let mut owner_docedit_resource: Option<crate::gate::docedit_resource::DoceditResourcePolicy> =
        None;
    let mut shipped_docx_limits = Vec::new();
    let mut owner_docx_limits = Vec::new();
    let mut authored_confidence: Option<crate::gate::carry_forward_policy::CarryForwardPolicy> =
        None;
    let mut seeded_confidence: Option<crate::gate::carry_forward_policy::CarryForwardPolicy> = None;
    // Shipped values are fallbacks; holder-authored rows replace them (C1).
    let mut conversion_tasks = AuthoredMin::default();
    let mut depth_default = AuthoredMin::default();
    let mut depth_max = AuthoredMin::default();

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
        // Quarantine and trust are judged before a decode is kept (FIX 5987):
        // a signed project-depth carrier is told by its id or bytes and kept
        // as before; a quarantined pack is never decoded; an untrusted one is
        // decoded for this fold alone.
        if crate::gate::project_depth::is_project_depth_id(&id)
            || crate::gate::project_depth::is_project_depth_contribution(body)
        {
            match &store.manifest_memo().row(body).carrier {
                Some(DecodedManifestCarrier::ProjectDepth(row)) => {
                    // Its policy is resolved by the project-scoped causal fold,
                    // not by a local manifest:trusted sidecar or a global pack.
                    let _ = row;
                }
                _ => resolution.diagnostics.malformed_manifest_seen = true,
            }
            continue;
        }
        if crate::gate::manifest_authenticity::manifest_is_quarantined(store, txn, &id, body)? {
            continue;
        }
        let trusted =
            crate::gate::manifest_authenticity::manifest_is_trusted(store, txn, &id, body)?;
        let decoded_row = if trusted {
            store.manifest_memo().row(body)
        } else {
            store.manifest_memo().transient(body)
        };
        match &decoded_row.carrier {
            Some(DecodedManifestCarrier::Pack(pack)) => {
                let decoded = pack.clone();
                resolution.diagnostics.manifest_count += 1;
                if !trusted {
                    untrusted_source_rows.push(decoded.source_trust);
                    if let Some(row) = decoded.teacher_probe {
                        untrusted_teacher_rows.push(row);
                    }
                    untrusted_sheet_limits.extend(decoded.sheet_answer_limits);
                    continue;
                }
                // Authored vault values replace the shipped defaults; holder
                // values narrow them (FIX 8783).
                if let Some(row) = decoded.residence_operation_budgets {
                    resolution.residence_budget_fold.add(&row);
                    resolution.residence_operation_budgets =
                        resolution.residence_budget_fold.resolve();
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
                if let Some(lifetimes) = decoded.credential_lifetimes {
                    if let Some(resolved) = &mut resolution.credential_lifetimes {
                        resolved.restrict(lifetimes);
                    } else {
                        resolution.credential_lifetimes = Some(lifetimes);
                    }
                }
                if let Some(default_all) = decoded.sync_world_default {
                    resolution.sync_world_default =
                        Some(resolution.sync_world_default.unwrap_or(true) && default_all);
                }
                if let Some(worlds) = decoded.sync_world_ceiling {
                    resolution.sync_world_ceiling =
                        Some(match resolution.sync_world_ceiling.take() {
                            Some(existing) => existing.intersection(&worlds).copied().collect(),
                            None => worlds,
                        });
                }
                resolution
                    .persona_core_prefixes
                    .extend(decoded.persona_core_prefixes);
                resolution.source_trust.merge(decoded.source_trust);
                resolution
                    .experiment_selection
                    .extend(decoded.experiment_selection);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                delegated_rows.extend(decoded.delegated_grants);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                if let Some(goal) = decoded.skill_edit_goal {
                    resolution.skill_edit_goal.push(goal);
                }
                // Every row is kept, however many (rule 5); past its
                // threshold row the fold asks whether everything is okay.
                if !decoded.room_policy_rows.is_empty() {
                    let mut rows =
                        ScanCount::start(store, txn, EngineScan::RoomPolicyRows, id.as_bytes())?;
                    rows.rows(decoded.room_policy_rows.len());
                    rows.defer(store);
                }
                resolution.room_policy_rows.extend(decoded.room_policy_rows);
                resolution
                    .weave_report_policy
                    .extend(decoded.weave_report_policy);
                resolution.weave_report_policy_empty |= decoded.weave_report_policy_empty;
                // The most restrictive authored order wins across trusted packs.
                resolution.weave_report_precedence = resolution
                    .weave_report_precedence
                    .max(decoded.weave_report_precedence);
                // Every trusted pack's mail rows join one set; resolution
                // narrows them together, so a pack can only tighten.
                resolution
                    .native_mail_policy
                    .extend(decoded.native_mail_policy);
                resolution
                    .federation_grant_rows
                    .extend(decoded.federation_grant_rows);
                // One act-policy table per vault: the same table twice is one
                // configuration; two different tables have no deterministic
                // answer, so every act they would govern fails closed.
                if let Some(rows) = decoded.shared_act_policies {
                    match &resolution.shared_act_policies {
                        None => resolution.shared_act_policies = Some(rows),
                        Some(existing) if *existing == rows => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                // Every valid row carries its version's pinned membership, so
                // the newest version among trusted packs is the floor.
                if let Some(floor) = decoded.catastrophe_floor
                    && resolution
                        .catastrophe_floor
                        .as_ref()
                        .is_none_or(|current| current.version() < floor.version())
                {
                    resolution.catastrophe_floor = Some(floor);
                }
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
                if decoded.project_depth_default.is_some()
                    || decoded.project_depth_max.is_some()
                    || decoded.project_conversion.is_some()
                {
                    let origin = crate::gate::manifest_authenticity::policy_row_origin(
                        store, txn, &id, body,
                    )?;
                    if let Some(value) = decoded.project_depth_default {
                        depth_default.add(origin, value);
                    }
                    if let Some(value) = decoded.project_depth_max {
                        depth_max.add(origin, value);
                    }
                    if let Some(policy) = decoded.project_conversion {
                        conversion_tasks.add(origin, policy.max_tasks);
                    }
                }
                resolution.signatures.extend(decoded.signatures);
                if let Some(retention) = decoded.gate_decision_retention {
                    if retention.rows.iter().any(|row| row.override_parent)
                        && !crate::gate::manifest_authenticity::retention_holder_verified(
                            store, txn, &id, body,
                        )?
                    {
                        resolution.diagnostics.malformed_manifest_seen = true;
                    }
                    // The seeded D7 row is a FALLBACK, not an owner vote. The
                    // seed marker, not today's shipped bytes, says so: any
                    // local re-authoring at that ID clears it, and a vault
                    // seeded by an earlier release keeps its standing.
                    if id == default_manifest_id
                        && crate::gate::manifest_authenticity::manifest_is_seeded_default(
                            store, txn, &id, body,
                        )?
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
                resolution
                    .skill_tradeoff_rows
                    .extend(decoded.skill_tradeoff_rows);
                if let Some(on_budget_exhausted) = decoded.on_budget_exhausted {
                    match resolution.on_budget_exhausted {
                        None => resolution.on_budget_exhausted = Some(on_budget_exhausted),
                        Some(existing) if existing == on_budget_exhausted => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                if let Some(policy) = decoded.project_collaboration {
                    resolution.project_collaboration = Some(
                        resolution
                            .project_collaboration
                            .map_or(policy, |old| old.restrict(policy)),
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
                if let Some(admission) = decoded.connector_admission {
                    resolution.connector_admission.restrict(admission);
                }
                if let Some(voice_serving) = decoded.voice_serving {
                    resolution.voice_serving.push(voice_serving);
                }
                resolution
                    .failure_signal_policy
                    .extend(decoded.failure_signal_policy);
                if let Some(policy) = decoded.project_conversion {
                    resolution.project_conversion = resolution.project_conversion.restrict(policy);
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
                    if settings.holder_rows() > 0 {
                        let mut holders = ScanCount::start(
                            store,
                            txn,
                            EngineScan::RoomThreadHolderRows,
                            id.as_bytes(),
                        )?;
                        holders.rows(settings.holder_rows());
                        holders.defer(store);
                    }
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
                resolution
                    .dreamer_failure_rules
                    .extend(decoded.dreamer_failure_rules);
                if let Some(precedence) = decoded.dreamer_failure_precedence {
                    resolution.dreamer_failure_precedence = Some(
                        resolution
                            .dreamer_failure_precedence
                            .map_or(precedence, |prior| prior.restrict(precedence)),
                    );
                }
                // Resolve class policy restrictively across trusted manifests.
                resolution.wait_policy.extend_rows(decoded.wait_policy);
                resolution.act_policy.extend_rows(decoded.act_policy);
                resolution.hosted_tts.rows.extend(decoded.hosted_tts.rows);
                if let Some(bounds) = decoded.docedit_resource_policy {
                    let slot = if id == crate::gate::default_policy_manifest_id()? {
                        &mut shipped_docedit_resource
                    } else {
                        &mut owner_docedit_resource
                    };
                    *slot = Some(slot.map_or(bounds, |previous| previous.restrict(bounds)));
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
                    if id == crate::gate::default_policy_manifest_id()? {
                        shipped_docx_limits.push(limits);
                    } else {
                        owner_docx_limits.push(limits);
                    }
                }

                if let Some(row) = decoded.diagnostic_bounds {
                    match resolution.diagnostic_bounds {
                        None => resolution.diagnostic_bounds = Some(row.bounds),
                        Some(existing) if existing == row.bounds => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                    row.attribute(
                        &mut resolution.diagnostic_bounds_origin,
                        resolution.diagnostic_bounds,
                        id,
                        body,
                    );
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
                if let Some(threshold) = decoded.consult_fanout_approval_threshold {
                    resolution.consult_fanout_approval_threshold = Some(
                        resolution
                            .consult_fanout_approval_threshold
                            .map_or(threshold, |old| old.min(threshold)),
                    );
                }
                if let Some(controls) = decoded.consult_fanout_controls {
                    resolution.consult_fanout_controls =
                        Some(resolution.consult_fanout_controls.as_ref().map_or_else(
                            || controls.clone(),
                            |prior| crate::gate::fanout_policy::merge_controls(prior, &controls),
                        ));
                }
                if let Some(precedence) = decoded.consult_fanout_precedence {
                    // Trusted manifests compose restrictively: any pack that
                    // withdraws holder lifts withdraws them for the vault.
                    resolution.consult_fanout_precedence = Some(
                        resolution
                            .consult_fanout_precedence
                            .map_or(precedence, |prior| prior.stricter(precedence)),
                    );
                }
                resolution
                    .consult_fanout_scope_rows
                    .extend(decoded.consult_fanout_scope_rows);
                resolution.packs.push(decoded.pack);
            }
            Some(DecodedManifestCarrier::ProjectDepth(_)) => {
                // A project contribution never becomes a global policy pack.
                continue;
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    // A trusted owner-authored row wins over the immutable shipped fallback.
    // A conflict among owner rows never silently picks a pruning horizon.
    resolution.gate_decision_retention = owner_retention.or(default_retention);
    resolution.project_depth_default = depth_default.resolve();
    resolution.project_depth_max = depth_max.resolve();
    resolution.project_conversion.max_tasks = conversion_tasks
        .resolve()
        .unwrap_or(crate::gate::ProjectConversionPolicy::default().max_tasks);

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
    resolution.docedit_resource_policy = owner_docedit_resource.or(shipped_docedit_resource);
    resolution.docx_archive_limits = if owner_docx_limits.is_empty() {
        shipped_docx_limits
    } else {
        owner_docx_limits
    };
    resolution.carry_forward_authored = authored_confidence.is_some();
    resolution.carry_forward_confidence = authored_confidence
        .or(seeded_confidence)
        .unwrap_or_default();

    resolution.untrusted_sheet_answer_limits = untrusted_sheet_limits;

    let mut fanout_row_refs = std::collections::BTreeSet::new();
    if resolution
        .consult_fanout_scope_rows
        .iter()
        .any(|row| !fanout_row_refs.insert(&row.row_ref))
    {
        resolution.diagnostics.malformed_manifest_seen = true;
    }

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
