//! Post-fit installation of pinned pack source; requested powers stay inert.
use super::super::install_transition::{InstallBinding, InstallDisposition, InstallPlan};
use super::{
    BundledSkillPermissions, PackAdapter, PackCandidateReason, PackFitPolicy, PackFitVerdict,
    PackInstallAsk, PackInstallDisposition, PackInstallReceipt, PackInstallStatus, PackPermissions,
    PackQualification, PackRuntimeRecipe, PackSource, invalid,
};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{
    Vault,
    entity_id::EntityId,
    error::{Error, RegistryError, Result},
    skill_hub::{ForeignSkillPublisher, HubAskSurface, HubPin, HubRef, SkillHubTrustTier},
};
use heed::RoTxn;

/// Installed knowledge-pack receipt, keyed by pack name.
pub(super) const PACK_INSTALL: SideTable<String, PackInstallReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_PACK_INSTALL);
/// Index from a claim predicate name to the pack name that owns it
/// (exclusivity check).
const PACK_PREDICATE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::SKILL_HUB_PACK_PREDICATE);
/// Candidate receipt keyed by the source content hash in lowercase hex.
const PACK_CANDIDATE: SideTable<String, PackInstallReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_PACK_CANDIDATE);

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
        let observed_tools = policy.observed_tools(&source)?;
        if observed_tools.len() > 256
            || observed_tools.iter().any(|tool| {
                tool.name.is_empty()
                    || tool.name.len() > 128
                    || tool.description.len() > 16_384
                    || serde_json::to_vec(&tool.input_schema).map_or(true, |bytes| {
                        bytes.len() > crate::skill_hub::MAX_HUB_FILE_BYTES
                    })
            })
        {
            return Err(invalid("observed tool manifest exceeds bounds"));
        }
        // Even a flag-off Candidate has a qualified *shape*. Running code
        // also needs the host's source-bound sandbox suite and runtime pin.
        let qualification = if let Some(adapter @ PackAdapter::Script(_)) = &source.manifest.adapter
        {
            let shape_recipe = PackRuntimeRecipe {
                adapter: adapter.clone(),
                runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.to_owned(),
                runtime_hash: String::new(),
            };
            super::script_plan::ScriptExecutionPlan::from_source(&source, &shape_recipe)?
                .qualified_shape()?;
            if verdict.code_auto_install && !verdict.rules_hit {
                let qualified = policy
                    .qualify_script(&source)?
                    .ok_or_else(|| invalid("script pack requires a qualified runtime"))?;
                validate_qualification(&source, &qualified)?;
                Some(qualified)
            } else {
                None
            }
        } else {
            None
        };
        let txn = self.store.env.read_txn()?;
        let (binding, surface) = self.pack_install_binding(
            &txn,
            source_id,
            hub,
            publisher,
            verdict,
            qualification.as_ref(),
        )?;
        let blocked_reason =
            self.screen_pack_in_txn(&txn, &source, &observed_tools, publisher.identity())?;
        let scan_risk = self.pack_scan_risk_in_txn(&txn, source.content_hash())?;
        Ok(PackInstallAsk {
            source_id,
            hub: hub.clone(),
            publisher: publisher.clone(),
            binding,
            verdict,
            surface,
            manifest: source.manifest().clone(),
            permissions,
            qualification,
            observed_tools,
            blocked_reason,
            scan_risk,
        })
    }
    /// The copied object is not a grant. Requested powers remain on its card;
    /// a code flag or rules hit leaves it Candidate, without registering verbs.
    pub fn install_pack(&self, ask: &PackInstallAsk) -> Result<PackInstallDisposition> {
        self.with_write_txn(|txn| {
            let source = self.check_pack_install_ask(txn, ask)?;
            if let Some(reason) = self.screen_pack_in_txn(
                txn,
                &source,
                &ask.observed_tools,
                ask.publisher.identity(),
            )? {
                return Ok(PackInstallDisposition::Blocked { reason });
            }
            let at = crate::unix_seconds_now();
            let (skills, skill_sources) =
                self.import_pack_skills_in_txn(txn, &source, &ask.hub, at)?;
            let candidate_reason = if ask.verdict.rules_hit {
                Some(PackCandidateReason::RulesHit)
            } else if source.has_code() && !ask.verdict.code_auto_install {
                Some(PackCandidateReason::CodeAutoInstallOff)
            } else {
                None
            };
            let status = if candidate_reason.is_some() {
                PackInstallStatus::Candidate
            } else {
                PackInstallStatus::Active
            };
            // One transition owns each bundled skill's admission and final receipt.
            // No intermediate Candidate label can escape this transaction.
            for source in &skill_sources {
                let record = self.read_skill_record_in_txn(txn, &source.entity)?;
                let capabilities = self
                    .read_admitted_capability_surface_in_txn(txn, &source.entity)?
                    .ok_or_else(|| invalid("bundled skill capability surface missing"))?;
                let plan = InstallPlan::pack(
                    &record,
                    InstallBinding::new(&source.reference, source.hash, &capabilities),
                    status == PackInstallStatus::Active,
                    candidate_reason == Some(PackCandidateReason::RulesHit),
                    candidate_reason != Some(PackCandidateReason::CodeAutoInstallOff),
                );
                let result = self.execute_hub_install_plan_in_txn(
                    txn,
                    &source.entity,
                    &plan,
                    crate::TimeRange { start: at, end: at },
                    at,
                    None,
                )?;
                if status == PackInstallStatus::Active
                    && !matches!(
                        result.disposition,
                        InstallDisposition::Installed | InstallDisposition::AlreadyInstalled
                    )
                {
                    return Err(invalid("pack cannot install an unloadable bundled skill"));
                }
                self.write_hub_import_receipt_in_txn(
                    txn,
                    &source.entity,
                    source.hash,
                    &source.reference,
                    Some((&ask.publisher, result, "")),
                    at,
                )?;
            }
            if status == PackInstallStatus::Active
                && let Some(prior) = self.installed_pack_in_txn(txn, &source.manifest.name)?
            {
                self.supersede_pack_skills_in_txn(txn, &prior, &skills, at)?;
            }
            let receipt = PackInstallReceipt {
                source_id: ask.source_id.to_hex(),
                pack_name: source.manifest.name.clone(),
                content_hash: source.content_hash().to_hex(),
                kind: source.manifest.kind,
                adapter: source.manifest.adapter.clone(),
                engine_version: None,
                status,
                candidate_reason,
                hub_id: ask.hub.hub_id.to_hex(),
                hub_ref: ask.hub.ref_string.clone(),
                pin_type: ask.hub.pin.pin_type().to_owned(),
                pin_value: match &ask.hub.pin {
                    HubPin::Semver(value)
                    | HubPin::Tag(value)
                    | HubPin::Commit(value)
                    | HubPin::ContentHash(value) => value.clone(),
                    HubPin::None => {
                        return Err(invalid("pack install requires a pinned hub reference"));
                    }
                },
                publisher: ask.publisher.identity().to_owned(),
                permissions: ask.permissions.clone(),
                qualification_report_hash: ask
                    .qualification
                    .as_ref()
                    .map(|q| q.report_hash.clone()),
                runtime: if status == PackInstallStatus::Active {
                    ask.qualification.as_ref().and_then(|q| q.runtime.clone())
                } else {
                    None
                },
                sections: source.sections().to_vec(),
                predicates: source.manifest.predicates.iter().cloned().collect(),
                kinds: source.manifest.kinds.iter().cloned().collect(),
                skills: skills.into_iter().map(|id| id.to_hex()).collect(),
                installed_at: at,
            };
            if status == PackInstallStatus::Candidate {
                PACK_CANDIDATE.put(&self.store, txn, &candidate_key(&source), &receipt)?;
                return Ok(PackInstallDisposition::Candidate(Box::new(receipt)));
            }
            let identities = source.kind_identities()?;
            self.install_pack_kinds_in_txn(txn, &identities)?;
            for predicate in &source.manifest.predicates {
                if let Some(prior) =
                    PACK_PREDICATE
                        .get(&self.store, txn, predicate)
                        .map_err(|error| {
                            if error.kind() == crate::error::ErrorKind::SideTableRow {
                                invalid("pack predicate catalog corrupt")
                            } else {
                                error
                            }
                        })?
                    && prior != source.manifest.name
                {
                    return Err(Error::Registry(RegistryError::PackPredicateNameCollision {
                        predicate: predicate.clone(),
                        installed_pack: prior,
                        installing_pack: source.manifest.name.clone(),
                    }));
                }
            }
            if let Some(old) = self.installed_pack_in_txn(txn, &source.manifest.name)? {
                for predicate in old.predicates {
                    PACK_PREDICATE.delete(&self.store, txn, &predicate)?;
                }
            }
            for predicate in &source.manifest.predicates {
                PACK_PREDICATE.put(&self.store, txn, predicate, &source.manifest.name)?;
            }
            PACK_CANDIDATE.delete(&self.store, txn, &candidate_key(&source))?;
            PACK_INSTALL.put(&self.store, txn, &source.manifest.name, &receipt)?;
            Ok(PackInstallDisposition::Installed(Box::new(receipt)))
        })
    }
    /// Each pack name whose install receipt selects a script, with the source
    /// it selects, read without the catalog listing's bound: a restore asks
    /// `installed_script_pack` about every one, however many packs it holds.
    pub(crate) fn script_pack_selections(&self) -> Result<Vec<(String, EntityId)>> {
        let txn = self.store.env.read_txn()?;
        let mut selections = Vec::new();
        for entry in PACK_INSTALL.iter_from(&self.store, &txn, &[])? {
            let (name, receipt) = entry.map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if matches!(receipt.adapter, Some(PackAdapter::Script(_))) {
                selections.push((name, EntityId::from_hex(&receipt.source_id)?));
            }
        }
        Ok(selections)
    }
    /// Active installations only, verified against their still-live exact source.
    /// A Candidate never enters the section/board projection.
    pub fn installed_packs(&self) -> Result<Vec<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for (seen, entry) in PACK_INSTALL.iter_from(&self.store, &txn, &[])?.enumerate() {
            if seen >= 4096 {
                return Err(invalid("installed pack catalog exceeds bound"));
            }
            let (name, _) = entry.map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            // The lens uses the same snapshot to distinguish a deleted source
            // (not live) from a malformed receipt or a drifting live source.
            let Some(receipt) = self.mounted_pack_in_txn(&txn, &name)? else {
                continue;
            };
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
        PACK_CANDIDATE
            .get(&self.store, &txn, &candidate_key(source))
            .map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("candidate receipt corrupt")
                } else {
                    error
                }
            })
    }
    pub fn installed_pack(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.installed_pack_in_txn(&txn, name)
    }
    pub fn pack_for_predicate(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let Some(pack) = PACK_PREDICATE.get(&self.store, &txn, &name.to_owned())? else {
            return Ok(None);
        };
        let installed = self
            .installed_pack_in_txn(&txn, &pack)?
            .ok_or_else(|| invalid("pack predicate has no installation"))?;
        if !installed.predicates.iter().any(|p| p == name) {
            return Err(invalid("pack predicate catalog disagrees"));
        }
        Ok(Some(installed))
    }
    /// A script run compares the exact selected receipt in its own writer
    /// transaction; Candidates are never runnable installations.
    #[cfg(any(test, feature = "microvm-firecracker"))]
    pub(crate) fn installed_pack_for_script_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        self.installed_pack_in_txn(txn, name)
    }

    /// A lens treats a deleted source as an absent installation. Parse the
    /// receipt first so a malformed catalog still fails closed, and use one
    /// snapshot for both this deletion check and normal source validation.
    pub(crate) fn mounted_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        let Some(receipt) = PACK_INSTALL
            .get(&self.store, txn, &name.to_owned())
            .map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?
        else {
            return Ok(None);
        };
        if receipt.pack_name != name {
            return Err(invalid("pack install name mismatch"));
        }
        let source_id = EntityId::from_hex(&receipt.source_id)?;
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, &source_id)?.is_live() {
            return Ok(None);
        }
        self.installed_pack_in_txn(txn, name)
    }
    fn installed_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        PACK_INSTALL
            .get(&self.store, txn, &name.to_owned())?
            .map(|receipt| {
                if receipt.pack_name != name {
                    return Err(invalid("pack install name mismatch"));
                }
                let source_id = EntityId::from_hex(&receipt.source_id)?;
                let source = self
                    .pack_source_in_txn(txn, &source_id)?
                    .ok_or_else(|| invalid("installed source is unavailable"))?;
                if source.manifest.name != name
                    || source.content_hash().to_hex() != receipt.content_hash
                    || source.manifest.kind != receipt.kind
                    || source.manifest.adapter != receipt.adapter
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
            ask.verdict,
            ask.qualification.as_ref(),
        )?;
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
        if let Some(qualified) = ask.qualification.as_ref() {
            validate_qualification(&source, qualified)?;
        } else if matches!(source.manifest.adapter, Some(PackAdapter::Script(_))) {
            let shape_recipe = PackRuntimeRecipe {
                adapter: source
                    .manifest
                    .adapter
                    .clone()
                    .ok_or_else(|| invalid("missing adapter"))?,
                runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.to_owned(),
                runtime_hash: String::new(),
            };
            super::script_plan::ScriptExecutionPlan::from_source(&source, &shape_recipe)?
                .qualified_shape()?;
            if ask.verdict.code_auto_install && !ask.verdict.rules_hit {
                return Err(invalid("active script pack needs qualified runtime"));
            }
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
        qualification: Option<&PackQualification>,
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
        let expected = (
            publisher.identity().to_owned(),
            publisher.grant_ref().to_owned(),
        );
        let expected_bytes = super::transport::SOURCE_HUB_ALIAS
            .encode_value(&expected)
            .map_err(|_| invalid("pack publisher receipt encoding"))?;
        if super::transport::SOURCE_HUB_ALIAS
            .get_bytes(&self.store, txn, &alias_key)?
            .as_deref()
            != Some(expected_bytes.as_slice())
        {
            return Err(invalid(
                "pack source was not fetched from this publisher hub",
            ));
        }
        source.kind_identities()?;
        let config = self.hub_record_in_txn(txn, &hub.hub_id)?;
        let prior = self.installed_pack_in_txn(txn, &source.manifest.name)?;
        let binding = blake3::hash(format!("pack-install-v2:{source_id:?}:{hub:?}:{publisher:?}:{config:?}:{verdict:?}:{qualification:?}:{prior:?}").as_bytes()).to_hex().to_string();
        let surface = match config.trust_tier {
            SkillHubTrustTier::Verified => HubAskSurface::OneTap,
            SkillHubTrustTier::Community => HubAskSurface::SummarizedReview,
            SkillHubTrustTier::Untrusted => HubAskSurface::FullReview,
        };
        Ok((binding, surface))
    }
}
fn candidate_key(source: &PackSource) -> String {
    source.content_hash().to_hex()
}
pub(super) fn pack_permissions(
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
    let runtime = result
        .runtime
        .as_ref()
        .ok_or_else(|| invalid("script pack requires qualified runtime recipe"))?;
    if Some(&runtime.adapter) != source.manifest.adapter.as_ref()
        || runtime.runtime_id.is_empty()
        || runtime.runtime_id.len() > 1024
    {
        return Err(invalid("runtime recipe does not bind declared adapter"));
    }
    crate::skill::SkillContentHash::parse_hex(&runtime.runtime_hash)?;
    super::script_plan::ScriptExecutionPlan::from_source(source, runtime)?.qualified_shape()?;
    crate::batch::secret_scan::scan_metadata_field(&runtime.runtime_id)?;
    Ok(())
}
