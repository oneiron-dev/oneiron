//! The marketplace import in two halves (FIX 9752). The fit stage fetches
//! the folder, scans it, runs the caller's fit and queries advisories, all
//! outside the writer. The commit lands it inside one writer, at a caller's
//! preallocated id when it names one, so a section install can land its
//! skill, claim and receipt in the same transaction. Every marketplace
//! import runs these same two halves; there is no second import path.
use super::{
    CODE_AUTO_INSTALL, MarketplaceFit, MarketplaceFitDecision, MarketplaceFitEvaluator,
    MarketplaceSwitch, marketplace_hash_blocked_in_txn, permission_labels,
};
use crate::skill_hub::install_transition::{InstallBinding, InstallPlan};
use crate::skill_hub::package_codec::invalid;
use crate::skill_hub::publisher::skill_publisher_grant;
use crate::skill_hub::{
    ForeignSkillPublisher, HubPackage, HubRef, SkillHubAdapter, SkillHubRecord, SkillScanReceipt,
};
use crate::{Vault, entity_id::EntityId, error::Result, temporal::TimeRange};

/// One marketplace import's fit stage: the configured source, the parsed
/// folder, the fit decision bound to them and the co-committing advisory
/// scans. The commit rechecks every binding under its writer.
pub(crate) struct FittedSkill {
    source: HubRef,
    publisher: ForeignSkillPublisher,
    configured: SkillHubRecord,
    parsed: HubPackage,
    fit: MarketplaceFitDecision,
    advisory_scans: Vec<SkillScanReceipt>,
    occurred: TimeRange,
    learned_at: u64,
}

impl FittedSkill {
    /// The fit rung the evaluator reached.
    pub(crate) const fn outcome(&self) -> MarketplaceFit {
        self.fit.outcome
    }

    /// The evaluator's analysis of what the folder requests.
    pub(crate) fn analysis(&self) -> &str {
        &self.fit.analysis
    }

    /// The exact parsed folder the commit lands.
    pub(crate) const fn package(&self) -> &HubPackage {
        &self.parsed
    }

    /// The folder's source-derived permission requests, as its import
    /// receipt records them.
    pub(crate) fn requested_permissions(&self) -> Vec<String> {
        permission_labels(&self.parsed.capabilities)
    }
}

impl Vault {
    /// The skill publisher the owner already admitted for `hub`: one whose
    /// offer-only `skill.offer` grant for that hub is live. It mints and
    /// widens nothing. Several admitted publishers resolve to the first
    /// identity in byte order, so the same vault always picks the same one.
    pub(crate) fn admitted_skill_publisher(
        &self,
        hub: EntityId,
    ) -> Result<Option<ForeignSkillPublisher>> {
        let txn = self.store.env.read_txn()?;
        let mut admitted: Option<(String, String)> = None;
        for grant in crate::consent::load_active_standing_grants(&self.store, &txn)? {
            let bound = grant.bound();
            let Some(actor) = bound.actor() else {
                continue;
            };
            if actor.actor_class() != Some("foreign-publisher") {
                continue;
            }
            let identity = actor.actor_ref();
            let Ok(expected) = skill_publisher_grant(identity, hub) else {
                continue;
            };
            if expected != *bound {
                continue;
            }
            if admitted
                .as_ref()
                .is_none_or(|(prior, _)| identity < prior.as_str())
            {
                admitted = Some((identity.to_owned(), bound.digest().to_hex()));
            }
        }
        Ok(admitted.map(|(identity, grant_ref)| ForeignSkillPublisher {
            identity,
            hub,
            grant_ref,
        }))
    }

    /// Whether the owner's rule blocks the content `hash`, read in the
    /// caller's transaction.
    pub(crate) fn skill_hash_blocked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: crate::skill::SkillContentHash,
    ) -> Result<bool> {
        marketplace_hash_blocked_in_txn(&self.store, txn, hash)
    }

    /// The fit stage: fetches from the configured source, parses and scans
    /// the folder, runs `fit`, and with `advisories` queries the bytes' OSV
    /// receipts. It writes nothing.
    #[expect(
        clippy::too_many_arguments,
        reason = "the marketplace import plus an optional dependency advisory transport"
    )]
    pub(crate) fn fit_marketplace_skill<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        source: &HubRef,
        publisher: &ForeignSkillPublisher,
        fit: &dyn MarketplaceFitEvaluator,
        advisories: Option<&dyn crate::skill_hub::osv::OsvQuery>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<FittedSkill> {
        let configured = {
            let txn = self.store.env.read_txn()?;
            self.check_publisher_in_txn(&txn, publisher)?;
            let hub = self.hub_record_in_txn(&txn, &source.hub_id)?;
            if publisher.hub != source.hub_id
                || adapter.hub_id() != source.hub_id
                || adapter.kind() != hub.kind
                || adapter.endpoint() != Some(hub.endpoint.as_str())
            {
                return Err(invalid(
                    "marketplace adapter is not the configured publisher source",
                ));
            }
            hub
        };
        let package = adapter.fetch_package(source)?;
        let parsed = crate::skill_hub::package_from_files(package.files)?;
        let static_scan = crate::skill_scan::run_static_skill_scan(&parsed, learned_at)?;
        let fit = fit.evaluate(source, &parsed, &static_scan)?;
        let advisory_scans = match advisories {
            Some(query) => {
                let inventory = crate::skill_hub::osv::dependency_inventory(&parsed)?;
                self.dependency_advisories(parsed.content_hash()?, &inventory, query, learned_at)?
                    .2
            }
            None => Vec::new(),
        };
        Ok(FittedSkill {
            source: source.clone(),
            publisher: publisher.clone(),
            configured,
            parsed,
            fit,
            advisory_scans,
            occurred,
            learned_at,
        })
    }

    /// The commit: rechecks the publisher, the configured hub and the fit's
    /// binding to the fetched source and permissions, imports at `preferred`
    /// (a fresh id when `None`; content dedup may still answer an existing
    /// holder), co-commits the advisory scans, runs the shared install plan
    /// and writes the source receipt. The caller owns the writer.
    pub(crate) fn commit_fitted_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fitted: &FittedSkill,
        preferred: Option<EntityId>,
    ) -> Result<EntityId> {
        let FittedSkill {
            source,
            publisher,
            configured,
            parsed,
            fit,
            advisory_scans,
            occurred,
            learned_at,
        } = fitted;
        let (occurred, learned_at) = (*occurred, *learned_at);
        self.check_publisher_in_txn(txn, publisher)?;
        if self.hub_record_in_txn(txn, &source.hub_id)? != *configured {
            return Err(invalid("configured hub moved while fetching"));
        }
        let hash = parsed.content_hash()?;
        if fit.source != *source
            || fit.hash != hash
            || fit.capabilities != parsed.capabilities
            || fit.static_scan != crate::skill_scan::run_static_skill_scan(parsed, learned_at)?
        {
            return Err(invalid(
                "marketplace fit does not bind fetched source and permissions",
            ));
        }
        let preferred = match preferred {
            Some(id) => id,
            None => self.store.clock.entity_id()?,
        };
        let entity = self
            .import_skill_from_hub_in_txn(txn, source, parsed, preferred, occurred, learned_at)?;
        for scan in advisory_scans {
            self.ingest_skill_scan_verdict_in_txn(txn, &entity, hash, scan, occurred, learned_at)?;
        }
        let rule_blocked = marketplace_hash_blocked_in_txn(&self.store, txn, hash)?;
        let code_bearing = parsed
            .files
            .iter()
            .any(|file| file.path.starts_with("scripts/"));
        let code_enabled = CODE_AUTO_INSTALL
            .get(&self.store, txn, &())?
            .is_some_and(|MarketplaceSwitch(enabled)| enabled);
        let record = self.read_skill_record_in_txn(txn, &entity)?;
        let plan = InstallPlan::marketplace(
            &record,
            InstallBinding::new(source, hash, &parsed.capabilities),
            fit.outcome,
            rule_blocked,
            !code_bearing || code_enabled,
        );
        let result =
            self.execute_hub_install_plan_in_txn(txn, &entity, &plan, occurred, learned_at, None)?;
        self.write_hub_import_receipt_in_txn(
            txn,
            &entity,
            hash,
            source,
            Some((publisher, result, fit.analysis.as_str())),
            learned_at,
        )?;
        Ok(entity)
    }
}
