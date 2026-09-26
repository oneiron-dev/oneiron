//! Post-fit installation of pinned pack source; requested powers stay inert.
use super::{
    BundledSkillPermissions, PackCandidateReason, PackFitPolicy, PackFitVerdict, PackInstallAsk,
    PackInstallDisposition, PackInstallReceipt, PackInstallStatus, PackPermissions, PackSource,
    invalid,
};
use crate::{
    Vault,
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
    /// Evaluate the immutable source and permission card outside the writer lock.
    /// The host owns the fit ladder; the engine binds its answer to source and hub.
    pub fn prepare_pack_install(
        &self,
        source_id: EntityId,
        hub: &HubRef,
        publisher: &ForeignSkillPublisher,
        policy: &dyn PackFitPolicy,
    ) -> Result<PackInstallAsk> {
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let prior = {
            let txn = self.store.env.read_txn()?;
            self.installed_pack_in_txn(&txn, &source.manifest.name)?
        };
        let permissions = pack_permissions(&source, prior.as_ref())?;
        let verdict = policy.evaluate(&source, &permissions)?;
        if !verdict.fits {
            return Err(invalid("pack did not pass fit"));
        }
        let txn = self.store.env.read_txn()?;
        let (binding, surface) =
            self.pack_install_binding(&txn, source_id, hub, publisher, verdict)?;
        Ok(PackInstallAsk {
            source_id,
            hub: hub.clone(),
            publisher: publisher.clone(),
            binding,
            verdict,
            surface,
            manifest: source.manifest().clone(),
            permissions,
        })
    }
    /// The copied object is not a grant. Requested powers remain on its card;
    /// a code flag or rules hit leaves it Candidate, without registering verbs.
    pub fn install_pack(&self, ask: &PackInstallAsk) -> Result<PackInstallDisposition> {
        self.with_write_txn(|txn| {
            let source = self.check_pack_install_ask(txn, ask)?;
            let at = crate::unix_seconds_now();
            let skills = self.import_pack_skills_in_txn(
                txn, &source, &ask.hub, &ask.publisher, at,
            )?;
            let mut candidate_reason = if ask.verdict.rules_hit {
                Some(PackCandidateReason::RulesHit)
            } else if source.has_code() && !ask.verdict.code_auto_install {
                Some(PackCandidateReason::CodeAutoInstallOff)
            } else { None };
            if candidate_reason.is_none() {
                for id in &skills {
                    let record = self.read_skill_record_in_txn(txn, id)?;
                    let hash = record.content_hash.ok_or_else(|| invalid("bundled skill hash missing"))?;
                    if matches!(crate::skill_scan::scan_gate_for_activation_in_txn(
                        &self.store, txn, hash,
                    )?, crate::skill_scan::ActivationPosture::ProposedRequired { .. }) {
                        candidate_reason = Some(PackCandidateReason::RulesHit);
                        break;
                    }
                }
            }
            let status = if candidate_reason.is_some() {
                PackInstallStatus::Candidate
            } else { PackInstallStatus::Active };
            if status == PackInstallStatus::Active {
                self.activate_pack_skills_in_txn(txn, &skills, at)?;
                if let Some(prior) = self.installed_pack_in_txn(txn, &source.manifest.name)? {
                    self.supersede_pack_skills_in_txn(txn, &prior, &skills, at)?;
                }
            }
            let receipt = PackInstallReceipt {
                source_id: ask.source_id.to_hex(),
                pack_name: source.manifest.name.clone(),
                content_hash: source.content_hash().to_hex(),
                status,
                candidate_reason,
                hub_id: ask.hub.hub_id.to_hex(),
                hub_ref: ask.hub.ref_string.clone(),
                pin_type: ask.hub.pin.pin_type().to_owned(),
                pin_value: match &ask.hub.pin {
                    HubPin::Semver(value) | HubPin::Tag(value) | HubPin::Commit(value)
                    | HubPin::ContentHash(value) => value.clone(),
                    HubPin::None => return Err(invalid("pack install requires a pinned hub reference")),
                },
                publisher: ask.publisher.identity().to_owned(),
                permissions: ask.permissions.clone(),
                sections: source.sections().to_vec(),
                predicates: source.manifest.predicates.iter().cloned().collect(),
                kinds: source.manifest.kinds.iter().cloned().collect(),
                skills: skills.into_iter().map(|id| id.to_hex()).collect(),
                installed_at: at,
            };
            let bytes =
                serde_json::to_vec(&receipt).map_err(|_| invalid("pack receipt encoding"))?;
            if status == PackInstallStatus::Candidate {
                self.store
                    .vault_meta
                    .put(txn, &candidate_key(&source), &bytes)?;
                return Ok(PackInstallDisposition::Candidate(Box::new(receipt)));
            }
            let identities = source.kind_identities()?;
            self.install_pack_kinds_in_txn(txn, &identities)?;
            for predicate in &source.manifest.predicates {
                if let Some(prior) = self.store.vault_meta.get(txn, &predicate_key(predicate))?
                    && prior.as_ref() != source.manifest.name.as_bytes()
                {
                    return Err(invalid("predicate name owned by another pack"));
                }
            }
            if let Some(old) = self.installed_pack_in_txn(txn, &source.manifest.name)? {
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
            self.store.vault_meta.delete(txn, &candidate_key(&source))?;
            self.store
                .vault_meta
                .put(txn, &install_key(&source.manifest.name), &bytes)?;
            Ok(PackInstallDisposition::Installed(Box::new(receipt)))
        })
    }
    /// Active installations only, verified against their still-live exact source.
    /// A Candidate never enters the section/board projection.
    pub fn installed_packs(&self) -> Result<Vec<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&txn, b"pack.install.v1/")?
        {
            if rows.len() >= 4096 {
                return Err(invalid("installed pack catalog exceeds bound"));
            }
            let (key, _) = entry?;
            let name = std::str::from_utf8(&key[b"pack.install.v1/".len()..])
                .map_err(|_| invalid("pack install catalog name corrupt"))?;
            let receipt = self
                .installed_pack_in_txn(&txn, name)?
                .ok_or_else(|| invalid("pack install catalog missing"))?;
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let source = self
                .pack_source_in_txn(&txn, &source_id)?
                .ok_or_else(|| invalid("installed pack source missing"))?;
            if receipt.sections != source.sections() || receipt.status != PackInstallStatus::Active
            {
                return Err(invalid("installed pack sections disagree with source"));
            }
            rows.push(receipt);
        }
        Ok(rows)
    }
    /// Claim-family state for one Active pack section, limited to the pack's
    /// own declared predicates. Hosts must still scope each returned id before
    /// serving any row; this is an inventory door, not read authority.
    pub fn pack_section_claim_ids(
        &self,
        pack_name: &str,
        section_id: &str,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let pack = self
            .installed_pack_in_txn(&txn, pack_name)?
            .ok_or_else(|| invalid("pack section is not installed"))?;
        if !pack.sections.iter().any(|section| {
            section.section_id == section_id
                && section.state_family.family == "claim"
                && section.state_family.version == 1
                && section.authority_lane.0 == "read"
        }) {
            return Err(invalid("pack section has no claim reader"));
        }
        let mut ids = Vec::new();
        for predicate in &pack.predicates {
            for (id, _) in self.claims_with_predicate_in_txn(&txn, predicate)? {
                if ids.len() >= 128 {
                    break;
                }
                ids.push(id);
            }
        }
        ids.sort_by_key(|id| *id.as_bytes());
        ids.dedup();
        Ok(ids)
    }
    pub fn candidate_pack(&self, source: &PackSource) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &candidate_key(source))?
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|_| invalid("candidate receipt corrupt"))
            })
            .transpose()
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
        let (binding, _) =
            self.pack_install_binding(txn, ask.source_id, &ask.hub, &ask.publisher, ask.verdict)?;
        if binding != ask.binding {
            return Err(invalid(
                "pack source, publisher, hub or installation changed",
            ));
        }
        let source = self
            .pack_source_in_txn(txn, &ask.source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let prior = self.installed_pack_in_txn(txn, &source.manifest.name)?;
        if pack_permissions(&source, prior.as_ref())? != ask.permissions {
            return Err(invalid("pack permission card drift"));
        }
        Ok(source)
    }
    fn pack_install_binding(
        &self,
        txn: &RoTxn<'_>,
        source_id: EntityId,
        hub: &HubRef,
        publisher: &ForeignSkillPublisher,
        verdict: PackFitVerdict,
    ) -> Result<(String, HubAskSurface)> {
        self.check_publisher_in_txn(txn, publisher)?;
        if publisher.hub != hub.hub_id {
            return Err(invalid("publisher and source hub differ"));
        }
        hub.validate()?;
        let source = self
            .pack_source_in_txn(txn, &source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        match &hub.pin {
            HubPin::ContentHash(hash) if *hash != source.content_hash().to_hex() => {
                return Err(invalid("pack source pin drift"));
            }
            HubPin::None => return Err(invalid("pack install requires a pinned hub reference")),
            _ => {}
        }
        let alias_key = super::transport::source_hub_alias_key(&source_id, hub)?;
        let expected = serde_json::to_vec(&(publisher.identity(), publisher.grant_ref()))
            .map_err(|_| invalid("pack publisher receipt encoding"))?;
        if self.store.vault_meta.get(txn, &alias_key)?.as_deref() != Some(expected.as_slice()) {
            return Err(invalid(
                "pack source was not fetched from this publisher hub",
            ));
        }
        source.kind_identities()?;
        let config = self.hub_record_in_txn(txn, &hub.hub_id)?;
        let prior = self.installed_pack_in_txn(txn, &source.manifest.name)?;
        let binding = blake3::hash(format!("pack-install-v2:{source_id:?}:{hub:?}:{publisher:?}:{config:?}:{verdict:?}:{prior:?}").as_bytes()).to_hex().to_string();
        let surface = match config.trust_tier {
            SkillHubTrustTier::Verified => HubAskSurface::OneTap,
            SkillHubTrustTier::Community => HubAskSurface::SummarizedReview,
            SkillHubTrustTier::Untrusted => HubAskSurface::FullReview,
        };
        Ok((binding, surface))
    }
}
fn candidate_key(source: &PackSource) -> Vec<u8> {
    [
        b"pack.candidate.v1/".as_slice(),
        source.content_hash().to_hex().as_bytes(),
    ]
    .concat()
}
fn pack_permissions(
    source: &PackSource,
    prior: Option<&PackInstallReceipt>,
) -> Result<PackPermissions> {
    let mut section_verbs = std::collections::BTreeSet::new();
    let mut section_authorities = std::collections::BTreeSet::new();
    for section in source.sections() {
        section_verbs.extend(section.verbs.iter().map(|verb| verb.0.clone()));
        section_authorities.insert(section.authority_lane.0.clone());
    }
    let grants: Vec<_> = source.manifest.requested_grants.iter().cloned().collect();
    let wakes: Vec<_> = source.manifest.wake_subscriptions.iter().cloned().collect();
    let section_verbs: Vec<_> = section_verbs.into_iter().collect();
    let section_authorities: Vec<_> = section_authorities.into_iter().collect();
    let added = |requested: &[String], previous: &[String]| {
        requested
            .iter()
            .filter(|power| !previous.contains(power))
            .cloned()
            .collect()
    };
    let empty: &[String] = &[];
    let mut folders = std::collections::BTreeMap::<String, Vec<crate::skill_hub::HubFile>>::new();
    for file in source.files() {
        if let Some(relative) = file.path.strip_prefix("skills/") {
            let (folder, path) = relative
                .split_once('/')
                .ok_or_else(|| invalid("pack skill must have a folder"))?;
            folders
                .entry(folder.to_owned())
                .or_default()
                .push(crate::skill_hub::HubFile::new(path, file.content.clone()));
        }
    }
    let mut bundled_skills = Vec::<BundledSkillPermissions>::new();
    for files in folders.into_values() {
        let package = super::super::folder::package_from_files(files)?;
        let caps = &package.capabilities;
        let skill = BundledSkillPermissions {
            skill_id: package.record.skill_id,
            bins: caps.bins.iter().cloned().collect(),
            env: caps.env.iter().cloned().collect(),
            mcp: caps.mcp.iter().cloned().collect(),
            allowed_tools: caps.allowed_tools.iter().cloned().collect(),
        };
        if bundled_skills
            .iter()
            .any(|prior| prior.skill_id == skill.skill_id)
        {
            return Err(invalid("duplicate bundled skill identity"));
        }
        bundled_skills.push(skill);
    }
    bundled_skills.sort_by(|a, b| a.skill_id.cmp(&b.skill_id));
    let mut widening_bundled_skills = Vec::new();
    for skill in &bundled_skills {
        let previous = prior.and_then(|receipt| {
            receipt
                .permissions
                .bundled_skills
                .iter()
                .find(|previous| previous.skill_id == skill.skill_id)
        });
        let widening = BundledSkillPermissions {
            skill_id: skill.skill_id.clone(),
            bins: added(&skill.bins, previous.map_or(empty, |prior| &prior.bins)),
            env: added(&skill.env, previous.map_or(empty, |prior| &prior.env)),
            mcp: added(&skill.mcp, previous.map_or(empty, |prior| &prior.mcp)),
            allowed_tools: added(
                &skill.allowed_tools,
                previous.map_or(empty, |prior| &prior.allowed_tools),
            ),
        };
        if !widening.bins.is_empty()
            || !widening.env.is_empty()
            || !widening.mcp.is_empty()
            || !widening.allowed_tools.is_empty()
        {
            widening_bundled_skills.push(widening);
        }
    }
    Ok(PackPermissions {
        bundled_skills,
        widening_bundled_skills,
        widening_grants: added(&grants, prior.map_or(empty, |row| &row.permissions.grants)),
        widening_wakes: added(&wakes, prior.map_or(empty, |row| &row.permissions.wakes)),
        widening_section_verbs: added(
            &section_verbs,
            prior.map_or(empty, |row| &row.permissions.section_verbs),
        ),
        widening_section_authorities: added(
            &section_authorities,
            prior.map_or(empty, |row| &row.permissions.section_authorities),
        ),
        grants,
        wakes,
        section_verbs,
        section_authorities,
    })
}
