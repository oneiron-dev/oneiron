//! Campaign + saved-query thin delegating wrappers over the domain surfaces
//! (`crate::campaign::surface`, `crate::saved_query::surface`).
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::*;

use crate::entity_id::EntityId;

impl Memory<'_> {
    // ── campaign + saved query `self.*` surface (CA-07) ──────────────────
    //
    // Ten verbs, one rule: the BOUND actor is the authenticated principal, and
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
        request: &crate::campaign::surface::CreateCampaignRequest,
        now: u64,
    ) -> MemoryResult<crate::campaign::surface::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::campaign::surface::create_campaign(
            self.vault, self.actor, request, now,
        )?)
    }

    /// `self.campaign.read` — reads a CAMPAIGN the bound actor owns.
    pub fn campaign_read(
        &self,
        campaign_ref: EntityId,
    ) -> MemoryResult<Option<crate::campaign::surface::CampaignRecord>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::campaign::surface::read_campaign(
            self.vault,
            self.actor,
            campaign_ref,
        )?)
    }

    /// `self.campaign.update` — replaces a CAMPAIGN definition under a CAS.
    pub fn campaign_update(
        &self,
        campaign_ref: EntityId,
        request: &crate::campaign::surface::UpdateCampaignRequest,
        now: u64,
    ) -> MemoryResult<crate::campaign::surface::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::campaign::surface::update_campaign(
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
    ) -> MemoryResult<crate::campaign::surface::CampaignRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::campaign::surface::archive_campaign(
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
        request: &crate::campaign::surface::MembershipReadRequest,
    ) -> MemoryResult<crate::campaign::surface::MembershipPage> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if crate::campaign::surface::read_campaign(self.vault, self.actor, request.owner_ref)?
            .is_none()
        {
            return Ok(crate::campaign::surface::MembershipPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        Ok(crate::campaign::surface::read_campaign_members(
            self.vault, request,
        )?)
    }

    /// `self.saved_query.create` — CA-02's lifecycle door, owner-bound here.
    pub fn saved_query_create(
        &self,
        request: &crate::saved_query::CreateSavedQueryRequest,
        now: u64,
    ) -> MemoryResult<crate::saved_query::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::saved_query::create_saved_query(
            self.vault, self.actor, request, now,
        )?)
    }

    /// `self.saved_query.read` — reads a SAVED_QUERY the bound actor owns.
    pub fn saved_query_read(
        &self,
        query_ref: EntityId,
    ) -> MemoryResult<Option<crate::saved_query::SavedQueryRecord>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::saved_query::read_saved_query(
            self.vault, self.actor, query_ref,
        )?)
    }

    /// `self.saved_query.update` — CA-02 validates the replacement filter AST,
    /// matcher, and version CAS; this surface reimplements none of it.
    pub fn saved_query_update(
        &self,
        query_ref: EntityId,
        request: &crate::saved_query::UpdateSavedQueryRequest,
        now: u64,
    ) -> MemoryResult<crate::saved_query::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::saved_query::update_saved_query(
            self.vault, self.actor, query_ref, request, now,
        )?)
    }

    /// `self.saved_query.archive` — the lifecycle transition, never a delete.
    pub fn saved_query_archive(
        &self,
        query_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> MemoryResult<crate::saved_query::SavedQueryRecord> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::saved_query::archive_saved_query(
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
        request: &crate::campaign::surface::MembershipReadRequest,
    ) -> MemoryResult<crate::campaign::surface::MembershipPage> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if crate::saved_query::read_saved_query(self.vault, self.actor, request.owner_ref)?
            .is_none()
        {
            return Ok(crate::campaign::surface::MembershipPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        Ok(crate::campaign::surface::read_saved_query_members(
            self.vault, request,
        )?)
    }
}
