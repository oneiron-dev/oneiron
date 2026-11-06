//! Campaign + saved-query wrappers over the store's native record hooks.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::*;

use crate::entity_id::EntityId;

impl Memory<'_> {
    // ── campaign + saved query `self.*` surface (CA-07) ──────────────────
    //
    // Eleven verbs, one rule: the BOUND actor is the authenticated principal, and
    // it is the only owner any of these writes can name. None of the domain
    // request types carries an owner field, so there is no payload key to
    // spoof — the owner is an argument this facade supplies, not data a caller
    // sends. Writes re-verify the actor binding before the domain opens its
    // transaction; reads take the same check so a caller cannot enumerate a
    // cohort from an actor the store never admitted.
    //
    // `crate::campaign::surface::invoke_campaign_surface` is the verb-name
    // dispatcher over exactly these methods; the typed methods stay public so
    // an in-process SDK caller never has to build a JSON envelope to reach the
    // same behavior a transport reaches.

    /// `self.campaign.create` — mints a CAMPAIGN owned by the bound actor.
    pub fn campaign_create(
        &self,
        request: &crate::memory::campaign_records::CreateCampaignRequest,
        now: u64,
    ) -> MemoryResult<crate::memory::campaign_records::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .create_campaign(self.vault, self.actor, request, now)?)
    }

    /// `self.campaign.launch` — launches a Draft or resumes a Paused campaign.
    /// A person who owns it always can; an agent needs the campaign-launch Grant.
    pub fn campaign_launch(
        &self,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> MemoryResult<crate::memory::campaign_records::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.vault.store.record_hooks.launch_campaign(
            self.vault,
            self.actor,
            self.actor_class,
            campaign_ref,
            expected_definition_version,
            now,
        )?)
    }

    /// `self.campaign.read` — reads a CAMPAIGN the bound actor owns.
    pub fn campaign_read(
        &self,
        campaign_ref: EntityId,
    ) -> MemoryResult<Option<crate::memory::campaign_records::CampaignRecord>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .read_campaign(self.vault, self.actor, campaign_ref)?)
    }

    /// `self.campaign.update` — replaces a CAMPAIGN definition under a CAS.
    pub fn campaign_update(
        &self,
        campaign_ref: EntityId,
        request: &crate::memory::campaign_records::UpdateCampaignRequest,
        now: u64,
    ) -> MemoryResult<crate::memory::campaign_records::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.vault.store.record_hooks.update_campaign(
            self.vault,
            self.actor,
            campaign_ref,
            request,
            now,
        )?)
    }

    /// `self.campaign.archive` — the ARCH-0059 lifecycle transition. There is
    /// no campaign delete verb on this facade, by design.
    pub fn campaign_archive(
        &self,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> MemoryResult<crate::memory::campaign_records::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.vault.store.record_hooks.archive_campaign(
            self.vault,
            self.actor,
            campaign_ref,
            expected_definition_version,
            now,
        )?)
    }

    /// `self.campaign.members` — a cursor-bounded, read-only cohort page.
    ///
    /// The projection selects on the CAMPAIGN, not on the owner, so ownership
    /// is established HERE, by the same owner-filtered read `self.campaign.read`
    /// performs: a campaign this actor does not own answers exactly as an absent
    /// one does, and a caller holding a foreign campaign's id learns neither its
    /// cohort nor its existence.
    pub fn campaign_members(
        &self,
        request: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> MemoryResult<crate::memory::campaign_records::MembershipPage> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if self
            .vault
            .store
            .record_hooks
            .read_campaign(self.vault, self.actor, request.owner_ref)?
            .is_none()
        {
            return Ok(crate::memory::campaign_records::MembershipPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .read_campaign_members(&read, request)?)
    }

    /// `self.saved_query.create` — CA-02's lifecycle door, owner-bound here.
    pub fn saved_query_create(
        &self,
        request: &crate::memory::query_records::CreateSavedQueryRequest,
        now: u64,
    ) -> MemoryResult<crate::memory::query_records::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.vault.store.record_hooks.create_saved_query(
            self.vault,
            self.actor,
            self.actor_class,
            request,
            now,
        )?)
    }

    /// `self.saved_query.read` — reads a SAVED_QUERY the bound actor owns.
    pub fn saved_query_read(
        &self,
        query_ref: EntityId,
    ) -> MemoryResult<Option<crate::memory::query_records::SavedQueryRecord>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .read_saved_query(self.vault, self.actor, query_ref)?)
    }

    /// `self.saved_query.update` — CA-02 validates the replacement filter AST,
    /// matcher, and version CAS; this surface reimplements none of it.
    pub fn saved_query_update(
        &self,
        query_ref: EntityId,
        request: &crate::memory::query_records::UpdateSavedQueryRequest,
        now: u64,
    ) -> MemoryResult<crate::memory::query_records::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .update_saved_query(self.vault, self.actor, query_ref, request, now)?)
    }

    /// `self.saved_query.archive` — the lifecycle transition, never a delete.
    pub fn saved_query_archive(
        &self,
        query_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> MemoryResult<crate::memory::query_records::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.vault.store.record_hooks.archive_saved_query(
            self.vault,
            self.actor,
            query_ref,
            expected_definition_version,
            now,
        )?)
    }

    /// `self.saved_query.members` — a cursor-bounded, read-only page of the
    /// membership this query derived, causes preserved as CA-02 wrote them.
    ///
    /// Owner-scoped the same way [`Self::campaign_members`] is, and for the same
    /// reason: the projection filters on the QUERY, so the owner check is this
    /// method's to make.
    pub fn saved_query_members(
        &self,
        request: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> MemoryResult<crate::memory::campaign_records::MembershipPage> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if self
            .vault
            .store
            .record_hooks
            .read_saved_query(self.vault, self.actor, request.owner_ref)?
            .is_none()
        {
            return Ok(crate::memory::campaign_records::MembershipPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .read_saved_query_members(&read, request)?)
    }

    // ── saved-query verb-table rows (`self.saved_query.*`) ──────────────
    //
    // The typed SDK doors over the ten-verb surface above: each takes its
    // row's wire request whole, goes through the same owner-bound methods
    // the resource routes reach, and answers the row's wire record. Manual
    // evaluation is not here: a rubric judge runs on a server's own model
    // seats, so `self.saved_query.evaluate` is a host door.

    /// `self.saved_query.create` — a SAVED_QUERY owned by the bound actor.
    pub fn create_saved_query(
        &self,
        request: &crate::memory::query_records::surface::SavedQueryCreateRequest,
    ) -> MemoryResult<crate::memory::query_records::surface::SavedQueryRecordView> {
        let record = self.saved_query_create(
            &request.engine_request(),
            self.vault.store.clock.now_recorded_at(),
        )?;
        Ok(crate::memory::query_records::surface::saved_query_record_view(&record))
    }

    /// `self.saved_query.read` — a SAVED_QUERY the bound actor owns; any
    /// other reads as not found.
    pub fn read_saved_query(
        &self,
        request: &crate::memory::query_records::surface::SavedQueryReadRequest,
    ) -> MemoryResult<crate::memory::query_records::surface::SavedQueryReadResult> {
        let record = self.saved_query_read(request.query_ref)?;
        Ok(
            crate::memory::query_records::surface::SavedQueryReadResult {
                found: record.is_some(),
                record: record
                    .as_ref()
                    .map(crate::memory::query_records::surface::saved_query_record_view),
            },
        )
    }

    /// `self.saved_query.update` — replaces a query's definition whole
    /// under its version CAS.
    pub fn update_saved_query(
        &self,
        request: &crate::memory::query_records::surface::SavedQueryUpdateRequest,
    ) -> MemoryResult<crate::memory::query_records::surface::SavedQueryRecordView> {
        let record = self.saved_query_update(
            request.query_ref,
            &request.engine_request(),
            self.vault.store.clock.now_recorded_at(),
        )?;
        Ok(crate::memory::query_records::surface::saved_query_record_view(&record))
    }

    /// `self.saved_query.archive` — the lifecycle transition, never a delete.
    pub fn archive_saved_query(
        &self,
        request: &crate::memory::query_records::surface::SavedQueryArchiveRequest,
    ) -> MemoryResult<crate::memory::query_records::surface::SavedQueryRecordView> {
        let record = self.saved_query_archive(
            request.query_ref,
            request.expected_definition_version,
            self.vault.store.clock.now_recorded_at(),
        )?;
        Ok(crate::memory::query_records::surface::saved_query_record_view(&record))
    }

    /// `self.saved_query.members` — one page of the membership this query
    /// derived, causes preserved.
    pub fn saved_query_members_page(
        &self,
        request: &crate::memory::query_records::surface::SavedQueryMembersRequest,
    ) -> MemoryResult<crate::memory::query_records::surface::SavedQueryMembershipPageView> {
        let page = self.saved_query_members(&request.read_request())?;
        Ok(crate::memory::query_records::surface::saved_query_membership_page_view(&page))
    }

    // ── campaign program `vault.campaign.program.*` verbs (decide-host 1193) ─
    //
    // The campaign doors' rule, unchanged: the BOUND actor is re-verified and
    // is the principal the domain checks. A program's owner is its
    // campaign's, so each write proves the caller owns the campaign through
    // the owned read `self.campaign.update` makes, inside the write's own
    // transaction. Before it opens, each step's basis evidence and sender
    // must resolve under the caller's own scoped read (OF-063's admission,
    // here rather than as row `refs` so the resource routes meet it too).

    /// `vault.campaign.program.create` — an authored program under a
    /// campaign the bound actor owns. Files every outbound step's body
    /// after the program write: the program ref is minted inside
    /// `create_campaign_program`, so the filer cannot run first (FIX 11513).
    pub fn campaign_program_create(
        &self,
        request: &crate::memory::campaign_records::program::CreateCampaignProgramRequest,
    ) -> MemoryResult<crate::memory::campaign_records::program::CampaignProgramRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        crate::gate::record_references::admit_row_references(
            self,
            crate::memory::campaign_records::verb_names::VAULT_CAMPAIGN_PROGRAM_CREATE,
            request,
            crate::memory::campaign_records::program::CAMPAIGN_PROGRAM_STEP_REFS,
        )?;
        Ok(self.vault.store.record_hooks.create_campaign_program(
            self.vault,
            self.actor,
            request,
            &|| self.write_actor(),
        )?)
    }

    /// `vault.campaign.program.read` — a program under a campaign the bound
    /// actor owns; any other reads as not found.
    pub fn campaign_program_read(
        &self,
        request: &crate::memory::campaign_records::program::CampaignProgramReadRequest,
    ) -> MemoryResult<crate::memory::campaign_records::program::CampaignProgramReadResult> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .read_campaign_program(self.vault, self.actor, request)?)
    }

    /// `vault.campaign.program.update` — replaces a program's definition,
    /// steps and audience whole, under a CAS. Files every outbound step's
    /// body before the program write: the program ref rides the request, so
    /// a filer failure aborts first and no unfiled update persists
    /// (FIX 11513).
    pub fn campaign_program_update(
        &self,
        request: &crate::memory::campaign_records::program::UpdateCampaignProgramRequest,
    ) -> MemoryResult<crate::memory::campaign_records::program::CampaignProgramRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        crate::gate::record_references::admit_row_references(
            self,
            crate::memory::campaign_records::verb_names::VAULT_CAMPAIGN_PROGRAM_UPDATE,
            request,
            crate::memory::campaign_records::program::CAMPAIGN_PROGRAM_STEP_REFS,
        )?;
        Ok(self.vault.store.record_hooks.update_campaign_program(
            self.vault,
            self.actor,
            request,
            &|| self.write_actor(),
        )?)
    }

    /// `vault.campaign.program.archive` — the lifecycle transition; there is
    /// no program delete verb, by design.
    pub fn campaign_program_archive(
        &self,
        request: &crate::memory::campaign_records::program::ArchiveCampaignProgramRequest,
    ) -> MemoryResult<crate::memory::campaign_records::program::CampaignProgramRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self
            .vault
            .store
            .record_hooks
            .archive_campaign_program(self.vault, self.actor, request)?)
    }
}
