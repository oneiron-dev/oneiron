//! Served hub skill doors (OF-213): the owner imports a skill from a
//! configured hub ref, refetches one at its ref's policy, and reads the hub
//! refs it came from. Import and sync both query OSV before the writer.
use super::ref_sync::{RefFetch, pinned_tracking};
use super::support::map_value;
use super::{
    HubPackage, HubPin, HubRef, HubSyncDisposition, MarketplaceFit, MarketplaceFitDecision,
    MarketplaceFitEvaluator, PREDICATE_SKILL_HUB_PROVENANCE, SkillHubAdapter, SkillScanReceipt,
    package_codec::invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, TimeRange, Vault, error::Result};

/// The fit rung for a skill the owner asked for: its requested permissions
/// still reach the owner as one ask.
struct OwnerAskedSkillFit;
impl MarketplaceFitEvaluator for OwnerAskedSkillFit {
    fn evaluate(
        &self,
        source: &HubRef,
        package: &HubPackage,
        static_scan: &SkillScanReceipt,
    ) -> Result<MarketplaceFitDecision> {
        MarketplaceFitDecision::new(
            source,
            package,
            MarketplaceFit::Ask,
            "the owner asked for this skill; its requested permissions wait for the owner",
            static_scan,
        )
    }
}

impl Vault {
    /// Owner door: import the skill at `folder` of a configured hub, at a
    /// pin. The named publisher is admitted for this hub first. The skill
    /// lands Candidate behind one permission ask
    /// ([`Vault::approve_marketplace_permission_ask`]).
    pub fn import_skill_from_hub_ref(
        &self,
        owner: &AuthenticatedOwner,
        hub: EntityId,
        folder: &str,
        pin: HubPin,
        publisher: &str,
    ) -> Result<EntityId> {
        let publisher = self.admit_skill_publisher(owner, publisher, hub)?;
        let source = HubRef::new(hub, folder, pin)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let osv = Some(&super::osv::OsvDevClient as &dyn super::osv::OsvQuery);
        match self.hub_ref_fetch(&pinned_tracking(source.clone())?, None)? {
            RefFetch::Git(adapter, _) => self.import_marketplace_skill_with_query(
                &adapter,
                &source,
                &publisher,
                &OwnerAskedSkillFit,
                osv,
                occurred,
                at,
            ),
            RefFetch::Http(adapter, _) => self.import_marketplace_skill_with_query(
                &adapter,
                &source,
                &publisher,
                &OwnerAskedSkillFit,
                osv,
                occurred,
                at,
            ),
        }
    }

    /// The hub refs an imported skill's provenance names.
    pub fn skill_hub_sources(&self, entity: &EntityId) -> Result<Vec<HubRef>> {
        self.active_claims_for_predicate(entity, PREDICATE_SKILL_HUB_PROVENANCE)?
            .into_iter()
            .map(|(_, body)| {
                HubRef::from_value(
                    map_value(&body.value, "hubRef")
                        .ok_or_else(|| invalid("hub provenance claim is missing hubRef"))?,
                )
            })
            .collect()
    }

    /// Owner door: refetch an imported skill from its hub ref at the ref's
    /// stored policy, else the policy its pin implies, and apply the bytes
    /// through the policy-checked sync: same or narrower applies, widening
    /// proposes, a pinned commit refuses. A fetch marks its revision seen;
    /// only Applied marks it trusted.
    pub fn sync_skill_from_hub_ref(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
    ) -> Result<HubSyncDisposition> {
        self.check_restore_owner_in_txn(&self.store.env.read_txn()?, owner)?;
        let source = self
            .skill_hub_sources(entity)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("the skill has no hub source"))?;
        let tracked = match self.hub_ref_sync(&source.hub_id, &source.ref_string)? {
            Some(tracked) => tracked,
            None => pinned_tracking(source.clone())?,
        };
        let fallback = match &source.pin {
            HubPin::Commit(commit) => Some(commit.as_str()),
            _ => None,
        };
        // The ref itself is the provenance alias the sync matches; the
        // transport fetches what it names now.
        let (package, revision) = match self.hub_ref_fetch(&tracked, fallback)? {
            RefFetch::Git(adapter, _) => (
                adapter.fetch_package(&tracked.hub_ref)?,
                adapter.resolved_commit().to_owned(),
            ),
            RefFetch::Http(adapter, _) => {
                let package = adapter.fetch_package(&tracked.hub_ref)?;
                let revision = package.content_hash()?.to_hex();
                (package, revision)
            }
        };
        self.mark_hub_ref(&tracked, &revision, false)?;
        let at = self.now_recorded_at();
        let disposition = self.sync_skill_from_hub(
            entity,
            &tracked.hub_ref,
            &package,
            tracked.sync_policy,
            TimeRange { start: at, end: at },
            at,
        )?;
        if disposition == HubSyncDisposition::Applied {
            self.mark_hub_ref(&tracked, &revision, true)?;
        }
        Ok(disposition)
    }
}
