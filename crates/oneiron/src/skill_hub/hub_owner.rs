//! Served hub skill doors (OF-213): the owner imports a skill from a
//! configured hub ref, refetches one at its ref's policy, and reads the hub
//! refs it came from. Import and sync both query OSV before the writer.
use super::ref_sync::{RefFetch, pinned_tracking};
use super::support::map_value;
use super::{
    HubPackage, HubPin, HubRef, HubSyncDisposition, MarketplaceFit, MarketplaceFitDecision,
    MarketplaceFitEvaluator, PREDICATE_SKILL_HUB_PROVENANCE, SkillHubAdapter, SkillScanReceipt,
    TrackedHubRef, package_codec::invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, TimeRange, Vault, error::Result};

/// The fit rung for a skill the owner asked for: its requested permissions
/// still reach the owner as one ask. The owner's skill fit setting can also
/// pick it for every ordinary install (FIX 9752).
pub(super) struct OwnerAskedSkillFit;
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

/// Refuses a fetched skill that is not the one a caller named: its declared
/// id, and its version when one was asked for (FIX 10202). It runs on the
/// fetched package, before any skill write.
pub(super) fn check_expected_skill(
    record: &crate::skill::SkillRecord,
    skill_id: &str,
    version: Option<&str>,
) -> Result<()> {
    if record.skill_id != skill_id || version.is_some_and(|version| version != record.version) {
        return Err(crate::error::Error::InvalidConfig(format!(
            "the source carries {} version {}, not the requested skill; nothing was written",
            record.skill_id, record.version
        )));
    }
    Ok(())
}

/// The pin naming `version` itself (FIX 2665): a full commit id pins that
/// commit, anything else the tag of that name.
fn named_version_pin(version: &str) -> HubPin {
    if matches!(version.len(), 40 | 64) && version.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        HubPin::Commit(version.to_owned())
    } else {
        HubPin::Tag(version.to_owned())
    }
}

/// One package already fetched, handed to an import door as its adapter's
/// fetch: the door commits the bytes the identity check read, and never
/// fetches again (FIX 10202).
struct PrefetchedPackage<'a, A> {
    adapter: &'a A,
    source: &'a HubRef,
    package: HubPackage,
}

impl<A: SkillHubAdapter> SkillHubAdapter for PrefetchedPackage<'_, A> {
    fn hub_id(&self) -> EntityId {
        self.adapter.hub_id()
    }

    fn kind(&self) -> super::SkillHubKind {
        self.adapter.kind()
    }

    fn endpoint(&self) -> Option<&str> {
        self.adapter.endpoint()
    }

    fn fetch_package(&self, hub_ref: &HubRef) -> Result<HubPackage> {
        if hub_ref != self.source {
            return Err(invalid("a checked import fetches only the ref it checked"));
        }
        Ok(self.package.clone())
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

    /// [`Self::import_skill_from_hub_ref`] for a caller that names the skill
    /// it asked for (FIX 10202): the package is fetched once, its declared id
    /// and the requested version are checked before the publisher is
    /// admitted or a candidate is born, and the import commits that same
    /// package. A mismatch writes nothing. `importing` turns true as the
    /// import proper (its fit and its writer) begins: a refusal before then
    /// read no vault row but the hub's record (FIX 3513).
    #[expect(
        clippy::too_many_arguments,
        reason = "the owner door's inputs plus the skill identity the caller asked for"
    )]
    pub(crate) fn import_skill_from_hub_ref_expecting(
        &self,
        owner: &AuthenticatedOwner,
        hub: EntityId,
        folder: &str,
        pin: HubPin,
        publisher: &str,
        skill_id: &str,
        version: Option<&str>,
        importing: &mut bool,
    ) -> Result<EntityId> {
        let source = HubRef::new(hub, folder, pin)?;
        let fetch = self.hub_ref_fetch(&pinned_tracking(source.clone())?, None)?;
        let package = match &fetch {
            RefFetch::Git(adapter, _) => adapter.fetch_package(&source)?,
            RefFetch::Http(adapter, _) => adapter.fetch_package(&source)?,
        };
        // The door reads the record from the package's files, so the check
        // does too.
        let parsed = super::folder::package_from_files(package.files.clone())?;
        check_expected_skill(&parsed.record, skill_id, version)?;
        let publisher = self.admit_skill_publisher(owner, publisher, hub)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let osv = Some(&super::osv::OsvDevClient as &dyn super::osv::OsvQuery);
        *importing = true;
        match &fetch {
            RefFetch::Git(adapter, _) => self.import_marketplace_skill_with_query(
                &PrefetchedPackage {
                    adapter,
                    source: &source,
                    package,
                },
                &source,
                &publisher,
                &OwnerAskedSkillFit,
                osv,
                occurred,
                at,
            ),
            RefFetch::Http(adapter, _) => self.import_marketplace_skill_with_query(
                &PrefetchedPackage {
                    adapter,
                    source: &source,
                    package,
                },
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

    /// [`Self::sync_skill_from_hub_ref`] for a caller that names the version
    /// it asked for (FIX 10202): the refetched package's id and version are
    /// checked before the ref is marked seen or the skill moves, and the
    /// sync applies that same package. A mismatch writes nothing. When what
    /// the ref names now is another version, the same ref pinned at the
    /// named one is fetched instead (FIX 2665), and the sync still runs
    /// under the ref's stored policy.
    pub(crate) fn sync_skill_from_hub_ref_expecting(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        version: &str,
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
        let (mut package, mut revision) = self.fetch_tracked_package(&tracked, fallback)?;
        let current = self
            .get_skill_record(entity)?
            .ok_or_else(|| invalid("the skill has no record"))?;
        if check_expected_skill(&package.record, &current.skill_id, Some(version)).is_err() {
            // The named version, fetched by name; a hub that has none of
            // that name leaves the mismatch as it was.
            let named = TrackedHubRef {
                hub_ref: HubRef::new(
                    tracked.hub_ref.hub_id,
                    tracked.hub_ref.ref_string.clone(),
                    named_version_pin(version),
                )?,
                ..tracked.clone()
            };
            if let Ok(found) = self.fetch_tracked_package(&named, None) {
                (package, revision) = found;
            }
        }
        check_expected_skill(&package.record, &current.skill_id, Some(version))?;
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

    /// The package `tracked` names now, and the revision it resolved to.
    fn fetch_tracked_package(
        &self,
        tracked: &TrackedHubRef,
        fallback: Option<&str>,
    ) -> Result<(HubPackage, String)> {
        match self.hub_ref_fetch(tracked, fallback)? {
            RefFetch::Git(adapter, _) => Ok((
                adapter.fetch_package(&tracked.hub_ref)?,
                adapter.resolved_commit().to_owned(),
            )),
            RefFetch::Http(adapter, _) => {
                let package = adapter.fetch_package(&tracked.hub_ref)?;
                let revision = package.content_hash()?.to_hex();
                Ok((package, revision))
            }
        }
    }
}
