use super::*;

/// The actual native P1-P4 output, kept with every body owner until the
/// immediate P5-P6 completion in the same writer.
pub(super) struct CapturedPut<'a> {
    pub(super) original_data: &'a [u8],
    pub(super) fixed: admission::FixedPut<'a>,
    pub(super) owners: admission::Owners,
    pub(super) dispatch: admission::Dispatch,
    pub(super) revision: admission::RevisionSlot,
    pub(super) old_record: old_record::OldRecord,
    pub(super) hub_origin_marker: Option<crate::side_table::StagedRow>,
    pub(super) agent_id_pin: Option<crate::side_table::StagedRow>,
    pub(super) short_id_plan: Option<crate::batch::short_id::ShortIdPlan>,
    pub(super) authority_first_seen_key: Option<String>,
    pub(super) evicted_shell_sources: BTreeSet<EntityId>,
    pub(super) project_revisions: Vec<(EntityId, Vec<u8>)>,
    pub(super) portable_agent_source: Option<(EntityId, Vec<u8>)>,
}

impl CapturedPut<'_> {
    pub(super) fn apply(
        self,
        write: &crate::secret_custody::CustodyWrite<'_>,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<AppliedPut> {
        let Self {
            original_data,
            fixed,
            owners,
            dispatch,
            revision,
            old_record,
            hub_origin_marker,
            agent_id_pin,
            short_id_plan,
            authority_first_seen_key,
            evicted_shell_sources,
            project_revisions,
            portable_agent_source,
        } = self;
        let data = owners.normalized_policy.as_deref().unwrap_or(original_data);
        let data = owners.project.as_deref().unwrap_or(data);
        let data = owners.escalated_skill_body.as_deref().unwrap_or(data);
        let data = owners.task_body_without_streaks.as_deref().unwrap_or(data);
        let data = owners.pad_stored_body.as_deref().unwrap_or(data);
        let old_record::OldRecord {
            body_changed,
            consolidation_dirty,
            stored_before,
            previous_skill_record,
            optimizer_birth_marker,
        } = old_record;
        audit::audit_and_stage_body(
            write,
            wtxn,
            data,
            &fixed,
            &dispatch,
            body_changed,
            &previous_skill_record,
            audit::StagedMarkers {
                hub_origin_marker,
                optimizer_birth_marker,
                agent_id_pin,
            },
        )?;
        projections::stage_put_projections(
            write,
            wtxn,
            data,
            &fixed,
            &dispatch,
            &revision,
            body_changed,
            consolidation_dirty,
            stored_before,
            &previous_skill_record,
            short_id_plan,
            authority_first_seen_key,
            evicted_shell_sources,
            project_revisions,
            portable_agent_source,
        )
    }
}
