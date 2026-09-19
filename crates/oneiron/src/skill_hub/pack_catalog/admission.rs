//! Human-gated installation of exact pack source; requested powers stay inert.
use super::{
    PackInstallAsk, PackInstallDisposition, PackInstallReceipt, PackKind, PackQualification,
    PackQualifier, PackSource, invalid,
};
use crate::{
    Vault,
    consent::{AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectFacts, UndoFidelity},
    entity_id::EntityId,
    error::Result,
    skill_hub::{ForeignSkillPublisher, HubAskSurface, HubPin, HubRef, SkillHubTrustTier},
};
use heed::RoTxn;

fn install_key(name: &str) -> Vec<u8> {
    [b"pack.install.v1/".as_slice(), name.as_bytes()].concat()
}
fn predicate_key(name: &str) -> Vec<u8> {
    [b"pack.predicate.v1/".as_slice(), name.as_bytes()].concat()
}

impl Vault {
    pub fn prepare_pack_install(
        &self,
        source_id: EntityId,
        hub: &HubRef,
        publisher: &ForeignSkillPublisher,
        qualifier: &dyn PackQualifier,
    ) -> Result<PackInstallAsk> {
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        // Real host suite runs outside the writer lock over immutable source bytes.
        let qualification = qualifier.qualify(&source)?;
        let txn = self.store.env.read_txn()?;
        let (binding, surface) =
            self.pack_install_binding(&txn, source_id, hub, publisher, &qualification)?;
        let effect = ComposedEffect::new(
            EffectFacts::new(format!("pack.install:{binding}"))?
                .with_undo_fidelity(UndoFidelity::None),
        )
        .digest();
        Ok(PackInstallAsk {
            source_id,
            hub: hub.clone(),
            publisher: publisher.clone(),
            binding,
            effect,
            qualification,
            manifest: source.manifest().clone(),
            surface,
        })
    }
    pub fn approve_pack_install(
        &self,
        ask: &PackInstallAsk,
        owner: &AuthenticatedOwner,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|txn| {
            self.check_pack_install_ask(txn, ask)?;
            self.approve_once_in_txn(txn, owner, ask.effect)
        })
    }
    pub fn install_pack(&self, ask: &PackInstallAsk) -> Result<PackInstallDisposition> {
        self.with_write_txn(|txn| {
            let source = self.check_pack_install_ask(txn, ask)?;
            let Some(authorization) =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &ask.effect)?
            else {
                return Ok(PackInstallDisposition::PendingConsent);
            };
            let identities = source.kind_identities()?;
            // No nested write transaction: catalog, interning, candidates and spend co-commit.
            self.install_pack_kinds_in_txn(txn, &identities)?;
            for predicate in &source.manifest.predicates {
                if let Some(prior) = self.store.vault_meta.get(txn, &predicate_key(predicate))?
                    && prior.as_ref() != source.manifest.name.as_bytes()
                {
                    return Err(invalid("predicate name owned by another pack"));
                }
            }
            let old = self.installed_pack_in_txn(txn, &source.manifest.name)?;
            if let Some(old) = old {
                for predicate in old.predicates {
                    self.store
                        .vault_meta
                        .delete(txn, &predicate_key(&predicate))?;
                }
            }
            for predicate in &source.manifest.predicates {
                self.store.vault_meta.put(
                    txn,
                    &predicate_key(predicate),
                    source.manifest.name.as_bytes(),
                )?;
            }
            let at = crate::unix_seconds_now();
            let candidates = self.import_pack_skills_in_txn(txn, &source, at)?;
            let receipt = PackInstallReceipt {
                source_id: ask.source_id.to_hex(),
                pack_name: source.manifest.name.clone(),
                content_hash: source.content_hash().to_hex(),
                consent_digest: ask.effect.to_hex(),
                qualification_report_hash: ask.qualification.report_hash.clone(),
                runtime: ask.qualification.runtime.clone(),
                hub_id: ask.hub.hub_id.to_hex(),
                publisher: ask.publisher.identity().to_owned(),
                requested_grants: source.manifest.requested_grants.iter().cloned().collect(),
                wake_subscriptions: source.manifest.wake_subscriptions.iter().cloned().collect(),
                predicates: source.manifest.predicates.iter().cloned().collect(),
                kinds: source.manifest.kinds.iter().cloned().collect(),
                candidate_skills: candidates.into_iter().map(|id| id.to_hex()).collect(),
                installed_at: at,
            };
            let bytes =
                serde_json::to_vec(&receipt).map_err(|_| invalid("pack receipt encoding"))?;
            self.store
                .vault_meta
                .put(txn, &install_key(&source.manifest.name), &bytes)?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(PackInstallDisposition::Installed(receipt))
        })
    }
    pub fn installed_pack(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.installed_pack_in_txn(&txn, name)
    }
    pub fn pack_for_predicate(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&txn, &predicate_key(name))? else {
            return Ok(None);
        };
        let pack =
            std::str::from_utf8(&raw).map_err(|_| invalid("pack predicate catalog corrupt"))?;
        let installed = self
            .installed_pack_in_txn(&txn, pack)?
            .ok_or_else(|| invalid("pack predicate has no installation"))?;
        if !installed.predicates.iter().any(|p| p == name) {
            return Err(invalid("pack predicate catalog disagrees"));
        }
        Ok(Some(installed))
    }
    fn installed_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        self.store
            .vault_meta
            .get(txn, &install_key(name))?
            .map(|raw| {
                let receipt: PackInstallReceipt = serde_json::from_slice(&raw)
                    .map_err(|_| invalid("pack install catalog corrupt"))?;
                if receipt.pack_name != name {
                    return Err(invalid("pack install name mismatch"));
                }
                let source_id = EntityId::from_hex(&receipt.source_id)?;
                let source = self
                    .pack_source_in_txn(txn, &source_id)?
                    .ok_or_else(|| invalid("installed source is unavailable"))?;
                if source.manifest.name != name
                    || source.content_hash().to_hex() != receipt.content_hash
                {
                    return Err(invalid("installed source identity drift"));
                }
                Ok(receipt)
            })
            .transpose()
    }
    fn check_pack_install_ask(&self, txn: &RoTxn<'_>, ask: &PackInstallAsk) -> Result<PackSource> {
        let (binding, _) = self.pack_install_binding(
            txn,
            ask.source_id,
            &ask.hub,
            &ask.publisher,
            &ask.qualification,
        )?;
        if binding != ask.binding {
            return Err(invalid(
                "pack source, publisher, hub or installation changed; re-consent required",
            ));
        }
        self.pack_source_in_txn(txn, &ask.source_id)?
            .ok_or_else(|| invalid("pack source missing"))
    }
    fn pack_install_binding(
        &self,
        txn: &RoTxn<'_>,
        source_id: EntityId,
        hub: &HubRef,
        publisher: &ForeignSkillPublisher,
        qualification: &PackQualification,
    ) -> Result<(String, HubAskSurface)> {
        self.check_publisher_in_txn(txn, publisher)?;
        if publisher.hub != hub.hub_id {
            return Err(invalid("publisher and source hub differ"));
        }
        hub.validate()?;
        let source = self
            .pack_source_in_txn(txn, &source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let HubPin::ContentHash(hash) = &hub.pin else {
            return Err(invalid("pack install requires verified source-tree pin"));
        };
        if *hash != source.content_hash().to_hex() {
            return Err(invalid("pack source pin drift"));
        }
        source.kind_identities()?;
        validate_qualification(&source, qualification)?;
        let config = self.hub_record_in_txn(txn, &hub.hub_id)?;
        let prior = self.installed_pack_in_txn(txn, &source.manifest.name)?;
        let binding = blake3::hash(format!("pack-install-v1:{source_id:?}:{hub:?}:{publisher:?}:{config:?}:{qualification:?}:{prior:?}").as_bytes()).to_hex().to_string();
        let surface = match config.trust_tier {
            SkillHubTrustTier::Verified => HubAskSurface::OneTap,
            SkillHubTrustTier::Community => HubAskSurface::SummarizedReview,
            SkillHubTrustTier::Untrusted => HubAskSurface::FullReview,
        };
        Ok((binding, surface))
    }
}
fn validate_qualification(source: &PackSource, result: &PackQualification) -> Result<()> {
    if !result.passed
        || !result.advisory_accepted
        || result.suite.is_empty()
        || result.suite.len() > 256
        || result.advisory.is_empty()
        || result.advisory.len() > 16384
    {
        return Err(invalid("pack qualification or advisory refused"));
    }
    crate::skill::SkillContentHash::parse_hex(&result.report_hash)?;
    for text in [&result.suite, &result.advisory] {
        crate::batch::secret_scan::scan_metadata_field(text)?;
    }
    if source.manifest.kind == PackKind::Connector
        || source.files.iter().any(|f| f.path.starts_with("scripts/"))
    {
        let runtime = result
            .runtime
            .as_ref()
            .ok_or_else(|| invalid("code pack requires qualified runtime recipe"))?;
        if Some(&runtime.adapter) != source.manifest.adapter.as_ref()
            || runtime.runtime_id.is_empty()
            || runtime.runtime_id.len() > 1024
        {
            return Err(invalid("runtime recipe does not bind declared adapter"));
        }
        crate::skill::SkillContentHash::parse_hex(&runtime.runtime_hash)?;
        crate::batch::secret_scan::scan_metadata_field(&runtime.runtime_id)?;
    }
    Ok(())
}
