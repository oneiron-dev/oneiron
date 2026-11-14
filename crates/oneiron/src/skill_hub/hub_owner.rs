//! Served hub skill doors (OF-213): the owner imports a skill from a
//! configured hub ref, refetches one at its ref's policy, and reads the hub
//! refs it came from. Import and sync both query OSV before the writer; a
//! local folder hub's query sends nothing and leaves advisories unknown.
use super::osv::OsvQuery;
use super::ref_sync::{RefFetch, pinned_tracking};
use super::support::map_value;
use super::{
    HoldsNothing, HubPackage, HubPin, HubRef, HubSyncDisposition, MarketplaceFit,
    MarketplaceFitDecision, MarketplaceFitEvaluator, PREDICATE_SKILL_HUB_PROVENANCE,
    SkillHubAdapter, SkillScanReceipt, TrackedHubRef, package_codec::invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, TimeRange, Vault, error::Result};

/// The fit rung that asks for every install: the owner's skill fit setting
/// picks it when the owner chose to be asked for everything (FIX 9752).
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

#[doc(hidden)]
pub use oneiron_verb_wire::skill_hub::hub_owner::{ClawHubImportReply, ClawHubImportRequest};

impl Vault {
    /// Downloads an explicitly selected public-registry skill, then imports the
    /// same checked bytes through the configured hub's normal marketplace doors.
    /// The import's commit writer records the decision it ran on: the owner's
    /// own proof, and with `applied` another asker's approved check-in for this
    /// exact import, spent there (ROLES-CHECKIN 2k8; P25-2K8-SCOPE Q1 = A). A
    /// provider error, or any refusal before the commit, spends nothing.
    pub(crate) fn import_clawhub_skill(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClawHubImportRequest,
        applied: Option<&crate::check_in::AppliedCheckIn<'_>>,
    ) -> Result<ClawHubImportReply> {
        owner.revalidate(self)?;
        // The publisher is admitted in a writer of its own, before the
        // import's: a refused check-in is refused before any fetch, and
        // admits no one.
        if let Some(applied) = applied {
            crate::check_in::require_spendable_check_in(
                self,
                crate::check_in::ActClass::GrantWiden,
                applied,
            )?;
        }
        let configured = self.skill_hub_record(&input.hub)?;
        if configured.kind != super::SkillHubKind::HttpIndex {
            return Err(invalid("ClawHub import requires a configured HTTP hub"));
        }
        // Validate a caller's native pin before fetching, without claiming that
        // the provider's unrelated contentHash has this algorithm.
        let expected = input
            .expected_content_hash
            .as_deref()
            .map(crate::skill::SkillContentHash::parse_hex)
            .transpose()?;
        let adapter = super::HttpEndpointSkillHubAdapter::new(input.hub, &configured.endpoint)?;
        let (package, github_handoff) = match adapter.download_clawhub(
            &input.slug,
            input.version.as_deref(),
            input.tag.as_deref(),
            input.response_limit_bytes,
        )? {
            super::http_fetch::ClawHubDownload::Package {
                package,
                github_handoff,
            } => (package, github_handoff),
            super::http_fetch::ClawHubDownload::ProviderError {
                status,
                retry_after,
                body,
            } => {
                return Ok(ClawHubImportReply::ProviderError {
                    status,
                    retry_after,
                    body,
                });
            }
        };
        check_expected_skill(
            &package.record,
            input
                .expected_skill_id
                .as_deref()
                .unwrap_or(&package.record.skill_id),
            input.expected_skill_version.as_deref(),
        )?;
        let hash = package.content_hash()?;
        if expected.is_some_and(|expected| expected != hash) {
            return Err(invalid(
                "ClawHub skill differs from the expected native content hash",
            ));
        }
        let source = HubRef::new(input.hub, &input.slug, HubPin::ContentHash(hash.to_hex()))?;
        let publisher = self.admit_skill_publisher(owner, &input.publisher, input.hub)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let osv = Some(&super::osv::OsvDevClient as &dyn super::osv::OsvQuery);
        let caller = HoldsNothing;
        let fit = self.chosen_skill_fit(&caller)?;
        let (entity, decision) = self.import_marketplace_skill_applying(
            &PrefetchedPackage {
                adapter: &adapter,
                source: &source,
                package,
            },
            &source,
            &publisher,
            &*fit,
            osv,
            occurred,
            at,
            applied,
        )?;
        Ok(ClawHubImportReply::Imported {
            entity,
            source,
            github_handoff,
            check_in: Some(decision),
        })
    }

    /// Owner door: import the skill at `folder` of a configured hub, at a
    /// pin. The named publisher is admitted for this hub first. The owner's
    /// chosen skill fit decides: a clean reversible import activates through
    /// the install plan, anything else lands Candidate behind one permission
    /// ask ([`Vault::approve_marketplace_permission_ask`]).
    pub fn import_skill_from_hub_ref(
        &self,
        owner: &AuthenticatedOwner,
        hub: EntityId,
        folder: &str,
        pin: HubPin,
        publisher: &str,
    ) -> Result<EntityId> {
        self.import_skill_from_hub_ref_applying(owner, hub, folder, pin, publisher, None)
            .map(|(entity, _)| entity)
    }

    /// [`Self::import_skill_from_hub_ref`] with the decision it ran on: the
    /// owner's own proof, and with `applied` another asker's approved
    /// check-in for this exact import, spent in the import's commit writer
    /// (ROLES-CHECKIN 2k8; P25-SHAPE Q1 = A).
    pub(crate) fn import_skill_from_hub_ref_applying(
        &self,
        owner: &AuthenticatedOwner,
        hub: EntityId,
        folder: &str,
        pin: HubPin,
        publisher: &str,
        applied: Option<&crate::check_in::AppliedCheckIn<'_>>,
    ) -> Result<(EntityId, crate::check_in::CheckInDecision)> {
        // The publisher is admitted in a writer of its own, before the
        // import's: a refused check-in is refused first, and admits no one.
        if let Some(applied) = applied {
            owner.revalidate(self)?;
            crate::check_in::require_spendable_check_in(
                self,
                crate::check_in::ActClass::GrantWiden,
                applied,
            )?;
        }
        let publisher = self.admit_skill_publisher(owner, publisher, hub)?;
        let source = HubRef::new(hub, folder, pin)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let caller = HoldsNothing;
        let fit = self.chosen_skill_fit(&caller)?;
        let fetch = self.hub_ref_fetch(&pinned_tracking(source.clone())?, None)?;
        let osv = Some(super::osv::hub_advisory_query(fetch.kind()));
        self.import_marketplace_skill_applying(
            &fetch, &source, &publisher, &*fit, osv, occurred, at, applied,
        )
    }

    /// [`Self::import_skill_from_hub_ref`] for a caller that names the skill
    /// it asked for (FIX 10202): the package is fetched once, its declared id
    /// and the requested version are checked before the publisher is
    /// admitted or a candidate is born, and the import commits that same
    /// package. A mismatch writes nothing. `rows` notes the hub once its row
    /// is read and the stored skill a content dedup answers, landed or
    /// refused (FIX 11699).
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
        rows: &mut super::SkillImportRows,
    ) -> Result<EntityId> {
        // The owner is checked before any host path is read.
        self.check_restore_owner_in_txn(&self.store.env.read_txn()?, owner)?;
        let source = HubRef::new(hub, folder, pin)?;
        let tracked = pinned_tracking(source.clone())?;
        // [`Self::hub_ref_fetch`], with the hub's read noted first.
        let row = self.skill_hub_record(&hub);
        rows.hub_read(hub, &row);
        let fetch = super::ref_sync::configured_ref_fetch(hub, &row?, &tracked, None)?;
        let package = fetch.fetch_package(&source)?;
        // The door reads the record from the package's files, so the check
        // does too.
        let parsed = super::folder::package_from_files(package.files.clone())?;
        check_expected_skill(&parsed.record, skill_id, version)?;
        let publisher = self.admit_skill_publisher(owner, publisher, hub)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let osv = Some(super::osv::hub_advisory_query(fetch.kind()));
        let caller = HoldsNothing;
        let fit = self.chosen_skill_fit(&caller)?;
        self.import_marketplace_skill_with_query(
            &PrefetchedPackage {
                adapter: &fetch,
                source: &source,
                package,
            },
            &source,
            &publisher,
            &*fit,
            osv,
            occurred,
            at,
            rows,
        )
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
        let (package, revision, advisories) = self.fetch_tracked_package(&tracked, fallback)?;
        self.mark_hub_ref(&tracked, &revision, false)?;
        let at = self.now_recorded_at();
        let disposition = self.sync_skill_from_hub_with_query(
            entity,
            &tracked.hub_ref,
            &package,
            tracked.sync_policy,
            TimeRange { start: at, end: at },
            at,
            advisories,
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
        let (mut package, mut revision, advisories) =
            self.fetch_tracked_package(&tracked, fallback)?;
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
            if let Ok((found, found_revision, _)) = self.fetch_tracked_package(&named, None) {
                package = found;
                revision = found_revision;
            }
        }
        check_expected_skill(&package.record, &current.skill_id, Some(version))?;
        self.mark_hub_ref(&tracked, &revision, false)?;
        let at = self.now_recorded_at();
        let disposition = self.sync_skill_from_hub_with_query(
            entity,
            &tracked.hub_ref,
            &package,
            tracked.sync_policy,
            TimeRange { start: at, end: at },
            at,
            advisories,
        )?;
        if disposition == HubSyncDisposition::Applied {
            self.mark_hub_ref(&tracked, &revision, true)?;
        }
        Ok(disposition)
    }

    /// The package `tracked` names now, the revision it resolved to (a
    /// commit, or an index hub's content hash), and the advisory query its
    /// hub's kind uses.
    fn fetch_tracked_package(
        &self,
        tracked: &TrackedHubRef,
        fallback: Option<&str>,
    ) -> Result<(HubPackage, String, &'static dyn OsvQuery)> {
        let fetch = self.hub_ref_fetch(tracked, fallback)?;
        let package = fetch.fetch_package(&tracked.hub_ref)?;
        let revision = match &fetch {
            RefFetch::Http(..) => package.content_hash()?.to_hex(),
            RefFetch::Git(..) | RefFetch::Local(..) => fetch.resolved_commit()?.to_owned(),
        };
        Ok((
            package,
            revision,
            super::osv::hub_advisory_query(fetch.kind()),
        ))
    }
}
