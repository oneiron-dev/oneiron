//! Validate source identities, facet/body agreement and explicit archive-only omissions.
use super::archive_index::{self, IndexedArchive, Loc, Section, Tag, edge_key};
use super::*;
use crate::batch::export::agent_knowledge_format::KnowledgeFormat;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_SKILL_CONTENT_ANCHOR, ENTITY_TYPE_SKILL_HUB,
};
use crate::serialize::{ExportBody, ExportSecrets};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

impl<R: Read + Seek> IndexedArchive<'_, R> {
    /// The bundles' checks against the import's row index (FIX 3678): each
    /// skill and agent bundle is read and checked alone, each agent's facets
    /// are recomputed from its own native rows, and the manifest's omission
    /// lists are compared as the rows declare them, in their order. Skill
    /// source trees validate under the archive's `secrets`; agent bundles
    /// and facets stay Nulled.
    pub(super) fn validate_bundles(&mut self, secrets: ExportSecrets) -> Result<()> {
        let mut skills = self.spool.rows(ArchiveRecordKind::Skill);
        while let Some((loc, _)) = skills.next(&self.spool)? {
            let bundle: ExportSkillBundle = self.hydrated(loc)?;
            if bundle.source_tree.is_some() != bundle.source_format.is_some() {
                return Err(invalid(
                    "skill source format and tree must be present together",
                ));
            }
            if let Some(tree) = &bundle.source_tree {
                tree.validate_in_with(&self.files, secrets)?;
                if let Some(hash) = &tree.content_hash {
                    let body = crate::write_envelope::skill_record::decode_skill_record(
                        &bundle.entity.body.to_bytes()?,
                    )?;
                    if body.content_hash.map(|h| h.to_hex()).as_ref() != Some(hash) {
                        return Err(invalid("skill source hash disagrees with its native row"));
                    }
                    crate::store::skill_package::package_from_source(
                        &body,
                        tree.import_files_in_with(&self.files, secrets)?,
                        bundle
                            .source_format
                            .ok_or_else(|| invalid("skill source format missing"))?,
                    )?;
                }
            }
        }
        let mut agents = self.spool.rows(ArchiveRecordKind::AgentPack);
        while let Some((loc, _)) = agents.next(&self.spool)? {
            let bundle: ExportAgentBundle = self.hydrated(loc)?;
            let id = document_import::parse_id(&bundle.entity_id)?;
            if !self
                .index
                .insert(Tag::Agent, id.as_bytes(), &loc.encode())?
            {
                return Err(invalid("duplicate agent source bundle"));
            }
            if let Some(hash) = &bundle.fork_hash {
                crate::write_envelope::skill_record::SkillContentHash::parse_hex(hash)?;
            }
            if let Some(tree) = &bundle.source_tree {
                tree.validate_in(&self.files)?;
            }
        }
        // Recompute every typed facet from the native AGENT_DEF and selected
        // knowledge/skill records. A caller cannot replace policy.md or add
        // code. An archive an older engine wrote carries the first knowledge
        // form.
        if !self.agent_facets_match(KnowledgeFormat::CURRENT)?
            && !self.agent_facets_match(KnowledgeFormat::V1)?
        {
            return Err(invalid("agent facets disagree with native rows"));
        }
        self.validate_omissions()
    }

    /// Whether every agent bundle, in archive order, is the one its AGENT_DEF
    /// row (in id order) yields with knowledge in `knowledge`, and no bundle
    /// is left over.
    fn agent_facets_match(&self, knowledge: KnowledgeFormat) -> Result<bool> {
        let mut bundles = self.spool.rows(ArchiveRecordKind::AgentPack);
        let mut after = None;
        while let Some(id) = self.next_of_type(ENTITY_TYPE_AGENT_DEF, after.as_ref())? {
            after = Some(id);
            let (at, row) = self
                .entity(&id)?
                .ok_or(Error::InvariantViolation("archive index lost an agent"))?;
            if at.section != Section::Ledger {
                continue;
            }
            let Some((loc, _)) = bundles.next(&self.spool)? else {
                return Ok(false);
            };
            let archived: ExportAgentBundle = self.hydrated(loc)?;
            let fork_hash = match self.index.get(Tag::Agent, id.as_bytes())? {
                Some(loc) => {
                    self.spool
                        .parse::<AgentForkHash>(Loc::decode(&loc)?)?
                        .fork_hash
                }
                None => None,
            };
            if archived != self.agent_bundle(&id, &row, fork_hash, knowledge)? {
                return Ok(false);
            }
        }
        Ok(bundles.next(&self.spool)?.is_none())
    }

    /// The bundle the AGENT_DEF `row` yields: its named skills and the
    /// claims about it are read from the index, alone.
    fn agent_bundle(
        &self,
        id: &EntityId,
        row: &ExportEntity,
        fork_hash: Option<String>,
        knowledge: KnowledgeFormat,
    ) -> Result<ExportAgentBundle> {
        let mut skills = Vec::new();
        let mut claims = Vec::new();
        if let Some(definition) = row.body.to_bytes().ok().and_then(|bytes| {
            crate::store::agent_definition_codec::decode_agent_definition(&bytes).ok()
        }) {
            let mut named = BTreeSet::new();
            for dependency in &definition.skills {
                if named.insert(dependency.skill_id.as_str()) {
                    self.skills_named(&dependency.skill_id, &mut skills)?;
                }
            }
            let about = id.as_bytes();
            let mut after: Option<Vec<u8>> = None;
            while let Some((key, _)) = self.index.next(Tag::About, about, after.as_deref())? {
                let claim = archive_index::id_at(&key, ENTITY_ID_LEN)?;
                let (_, row) = self
                    .entity(&claim)?
                    .ok_or(Error::InvariantViolation("archive index lost a claim"))?;
                claims.push(row);
                after = Some(key);
            }
        }
        crate::serialize::agent_bundle(row, &skills, &claims, fork_hash, knowledge)
    }

    /// Each skill row whose record decodes under `skill_id`, decoded.
    fn skills_named(
        &self,
        skill_id: &str,
        skills: &mut Vec<(EntityId, crate::write_envelope::skill_record::SkillRecord)>,
    ) -> Result<()> {
        let name = skill_name_key(skill_id);
        let mut after: Option<Vec<u8>> = None;
        while let Some((key, _)) = self.index.next(Tag::SkillName, &name, after.as_deref())? {
            let id = archive_index::id_at(&key, name.len())?;
            let (_, row) = self
                .entity(&id)?
                .ok_or(Error::InvariantViolation("archive index lost a skill"))?;
            if let Ok(record) =
                crate::write_envelope::skill_record::decode_skill_record(&row.body.to_bytes()?)
                && record.skill_id == skill_id
            {
                skills.push((id, record));
            }
            after = Some(key);
        }
        Ok(())
    }

    /// The manifest's omission and refusal lists against what the rows
    /// declare, each list compared in its own order as the rows are read.
    fn validate_omissions(&mut self) -> Result<()> {
        let mut refusals = Declared::new(&self.manifest.import_refusals);
        let mut imports = Declared::new(&self.manifest.import_omissions);
        let mut bundles = Declared::new(&self.manifest.bundle_omissions);
        let mut after = None;
        while let Some((id, at)) = self.next_entity(after.as_ref())? {
            after = Some(id);
            let row = self.entity_row(&at)?;
            match entity_omission(&row)? {
                Some(EntityOmission::ArchiveOnly(reason)) => {
                    imports.next(&ExportImportOmission {
                        entity_id: row.id.clone(),
                        reason,
                    });
                }
                Some(EntityOmission::Refused(reason)) => {
                    refusals.next(&ExportImportRefusal::Entity {
                        entity_id: row.id.clone(),
                        reason,
                    });
                }
                None => {}
            }
            if at.section == Section::Skill {
                let shape: SkillTreeShape = self.spool.parse(at.loc)?;
                let (omission, refused) = skill_omission(
                    shape
                        .source_tree
                        .as_ref()
                        .map(|tree| tree.content_hash.as_deref()),
                );
                if refused {
                    self.index.put(Tag::SourceRefusal, id.as_bytes(), &[])?;
                }
                if let Some(reason) = omission {
                    bundles.next(&ExportBundleOmission {
                        entity_id: row.id.clone(),
                        reason,
                    });
                }
            }
            if at.section == Section::Ledger && row.entity_type == ENTITY_TYPE_AGENT_DEF {
                let loc =
                    self.index
                        .get(Tag::Agent, id.as_bytes())?
                        .ok_or(Error::InvariantViolation(
                            "archive index lost an agent bundle",
                        ))?;
                let bundle: AgentOmissionShape = self.spool.parse(Loc::decode(&loc)?)?;
                for reason in agent_omissions(
                    &row.id,
                    bundle.fork_hash.as_deref(),
                    bundle.omission,
                    |carrier| {
                        let (at, row) = self.entity(carrier).ok()??;
                        (at.entity_type == crate::registry::ENTITY_TYPE_ASSET)
                            .then(|| row.body.to_bytes().ok())
                            .flatten()
                    },
                ) {
                    bundles.next(&ExportBundleOmission {
                        entity_id: row.id.clone(),
                        reason,
                    });
                }
            }
        }
        let mut after: Option<Vec<u8>> = None;
        while let Some((key, _)) = self.index.next(Tag::SourceRefusal, &[], after.as_deref())? {
            refusals.next(&ExportImportRefusal::Entity {
                entity_id: archive_index::id_at(&key, 0)?.to_hex(),
                reason: ImportRefusalReason::RedactedSource,
            });
            after = Some(key);
        }
        let mut after: Option<Vec<u8>> = None;
        while let Some((key, value)) = self.index.next(Tag::Edge, &[], after.as_deref())? {
            let source = archive_index::id_at(&key, 0)?;
            let target = archive_index::id_at(&key, ENTITY_ID_LEN + 1)?;
            if value.get(Loc::LEN) == Some(&1)
                && !self.index.contains(Tag::ProvenanceSubject, &key)?
                && !self.archive_only(&source)?
                && !self.archive_only(&target)?
            {
                refusals.next(&ExportImportRefusal::ProvenancedEdge {
                    source: source.to_hex(),
                    edge_kind: key[ENTITY_ID_LEN],
                    target: target.to_hex(),
                });
            }
            after = Some(key);
        }
        if !(refusals.whole() && imports.whole() && bundles.whole()) {
            return Err(invalid(
                "manifest omission declaration disagrees with document",
            ));
        }
        Ok(())
    }

    fn archive_only(&self, id: &EntityId) -> Result<bool> {
        Ok(self
            .entity_at(id)?
            .is_some_and(|at| at.has(archive_index::FLAG_ARCHIVE_ONLY)))
    }
}

/// The skill-name key of `skill_id` in the row index: its BLAKE3, cut to
/// an id's width (the rows under it are decoded and compared whole).
pub(super) fn skill_name_key(skill_id: &str) -> Vec<u8> {
    blake3::hash(skill_id.as_bytes()).as_bytes()[..ENTITY_ID_LEN].to_vec()
}

/// A manifest list compared item by item as the rows declare it.
struct Declared<'m, T> {
    list: &'m [T],
    at: usize,
    differs: bool,
}

impl<'m, T: PartialEq> Declared<'m, T> {
    fn new(list: &'m [T]) -> Self {
        Self {
            list,
            at: 0,
            differs: false,
        }
    }

    fn next(&mut self, item: &T) {
        if self.list.get(self.at) != Some(item) {
            self.differs = true;
        }
        self.at += 1;
    }

    fn whole(&self) -> bool {
        !self.differs && self.at == self.list.len()
    }
}

/// A skill row's source tree, as far as its omissions read it.
#[derive(Deserialize)]
struct SkillTreeShape {
    source_tree: Option<TreeHashShape>,
}

#[derive(Deserialize)]
struct TreeHashShape {
    content_hash: Option<String>,
}

/// An agent bundle row, as far as its omissions read it.
#[derive(Deserialize)]
struct AgentOmissionShape {
    #[serde(rename = "forkHash")]
    fork_hash: Option<String>,
    omission: Option<AgentBundleOmission>,
}

/// An agent bundle row's fork hash.
#[derive(Deserialize)]
struct AgentForkHash {
    #[serde(rename = "forkHash")]
    fork_hash: Option<String>,
}

/// What one entity row declares in the manifest: an archive-only omission
/// or an import refusal.
pub(super) enum EntityOmission {
    ArchiveOnly(ImportOmissionReason),
    Refused(ImportRefusalReason),
}

/// The provenance subject edge of an edge-provenance claim row.
fn provenance_subject(row: &ExportEntity) -> Option<(EntityId, u8, EntityId)> {
    if row.entity_type != ENTITY_TYPE_CLAIM || !super::provenance_import::is_provenance(row) {
        return None;
    }
    match row
        .body
        .to_bytes()
        .ok()
        .and_then(|bytes| crate::write_envelope::claim_body::decode_claim_body(&bytes, true).ok())
        .map(|claim| claim.subject)
    {
        Some(crate::write_envelope::claim_body::ClaimSubject::Edge {
            source,
            kind,
            target,
        }) => Some((source, kind as u8, target)),
        _ => None,
    }
}

/// [`provenance_subject`] as the row index keys it.
pub(super) fn provenance_subject_key(row: &ExportEntity) -> Option<Vec<u8>> {
    provenance_subject(row).map(|(source, kind, target)| edge_key(&source, kind, &target))
}

/// What one entity row declares, before the document's second credential
/// pass.
pub(super) fn entity_omission(row: &ExportEntity) -> Result<Option<EntityOmission>> {
    if let Some(reason) = archive_only_reason(row) {
        return Ok(Some(EntityOmission::ArchiveOnly(reason)));
    }
    let reason = if matches!(&row.body,ExportBody::HubSource(source) if source.redacted())
        || matches!(row.body, ExportBody::Nulled)
        || matches!(&row.body, ExportBody::Pack(value) if matches!(value.payload, ExportBody::Nulled))
    {
        Some(ImportRefusalReason::RedactedBody)
    } else if row.entity_type == crate::registry::ENTITY_TYPE_MODEL
        || super::provenance_import::is_provenance(row)
    {
        None
    } else if crate::registry::zone_of(row.entity_type) != crate::registry::TypeByteZone::PackHandle
        && crate::registry::validate_public_entity_type(row.entity_type).is_err()
    {
        Some(ImportRefusalReason::OwningEntityAdapterRequired)
    } else if super::expression_import::is_expression(row) {
        Some(ImportRefusalReason::LocalExpressionWriterRequired)
    } else if row.entity_type == ENTITY_TYPE_CLAIM
        && crate::write_envelope::claim_body::decode_claim_body(&row.body.to_bytes()?, false)
            .is_err()
        && !crate::write_envelope::claim_body::decode_claim_body(&row.body.to_bytes()?, true)
            .is_ok_and(|body| {
                crate::write_envelope::subject_record::imported_subject_body(&body).is_ok()
                    || crate::actor_claims::imported_actor_body(&body).is_ok()
                    || crate::skill_reliability::imported_reliability_body(&body).is_ok()
                    || crate::claim::archived_default_facet(&body).is_ok()
            })
    {
        Some(ImportRefusalReason::OwningClaimAdapterRequired)
    } else {
        None
    };
    Ok(reason.map(EntityOmission::Refused))
}

/// A skill's bundle omission from its source tree (`None` when it has none,
/// else its content hash), and whether its redacted source is refused.
fn skill_omission(tree: Option<Option<&str>>) -> (Option<BundleOmissionReason>, bool) {
    match tree {
        None => (Some(BundleOmissionReason::SkillSourceUnavailable), false),
        Some(None) => (Some(BundleOmissionReason::SkillSourceRedacted), true),
        Some(Some(_)) => (None, false),
    }
}

/// One agent bundle's omissions, in the order an export declares them;
/// `birth` reads the bytes of the birth-source ASSET under an id.
fn agent_omissions(
    entity_id: &str,
    fork_hash: Option<&str>,
    omission: Option<AgentBundleOmission>,
    birth: impl FnOnce(&crate::entity_id::EntityId) -> Option<Vec<u8>>,
) -> Vec<BundleOmissionReason> {
    let mut reasons = Vec::new();
    if let Some(hash) = fork_hash {
        let available = document_import::parse_id(entity_id)
            .ok()
            .is_some_and(|child| {
                crate::store::agent_birth_identity::birth_source_id(&child)
                    .ok()
                    .and_then(|carrier| birth(&carrier))
                    .is_some_and(|bytes| {
                        crate::agent_def::archived_birth_source_matches(&child, hash, &bytes)
                    })
            });
        if !available {
            reasons.push(BundleOmissionReason::AgentBirthSourceUnavailable);
        }
    }
    if let Some(omission) = omission {
        reasons.push(agent_omission_reason(omission));
    }
    reasons
}

/// The manifest's reason for an agent bundle's own `omission`, declared after
/// its birth source's.
pub(super) fn agent_omission_reason(omission: AgentBundleOmission) -> BundleOmissionReason {
    match omission {
        AgentBundleOmission::ForkBindingUnavailable => {
            BundleOmissionReason::AgentForkBindingUnavailable
        }
        AgentBundleOmission::UnresolvedSkill => BundleOmissionReason::AgentUnresolvedSkill,
        AgentBundleOmission::CredentialRedaction => BundleOmissionReason::AgentCredentialRedaction,
    }
}

/// The manifest's import refusals, import omissions and bundle omissions,
/// gathered one row at a time (FIX 2766): an export streams its rows past
/// this ledger, and an import's validation feeds it the same rows again.
#[derive(Default)]
pub(crate) struct OmissionLedger {
    entity_refusals: Vec<(String, ImportRefusalReason)>,
    source_refusals: Vec<String>,
    archive_only: BTreeMap<String, ImportOmissionReason>,
    provenance_subjects: BTreeSet<(String, u8, String)>,
    provenanced_edges: Vec<(String, u8, String)>,
    bundle_omissions: Vec<ExportBundleOmission>,
}

impl OmissionLedger {
    /// One entity row, before the document's second credential pass.
    pub(crate) fn entity(&mut self, row: &ExportEntity) -> Result<()> {
        if let Some((source, kind, target)) = provenance_subject(row) {
            self.provenance_subjects
                .insert((source.to_hex(), kind, target.to_hex()));
        }
        match entity_omission(row)? {
            Some(EntityOmission::ArchiveOnly(reason)) => {
                self.archive_only.insert(row.id.clone(), reason);
            }
            Some(EntityOmission::Refused(reason)) => {
                self.entity_refusals.push((row.id.clone(), reason));
            }
            None => {}
        }
        Ok(())
    }

    /// One skill's source bundle.
    pub(crate) fn skill(&mut self, bundle: &ExportSkillBundle) {
        let (reason, refused) = skill_omission(
            bundle
                .source_tree
                .as_ref()
                .map(|tree| tree.content_hash.as_deref()),
        );
        if refused {
            self.source_refusals.push(bundle.entity.id.clone());
        }
        if let Some(reason) = reason {
            self.bundle_omissions.push(ExportBundleOmission {
                entity_id: bundle.entity.id.clone(),
                reason,
            });
        }
    }

    /// One graph edge: a provenanced edge needs its owning claim adapter.
    pub(crate) fn edge(&mut self, edge: &ExportEdge) {
        if edge.provenance.is_some() {
            self.provenanced_edges
                .push((edge.source.clone(), edge.kind, edge.target.clone()));
        }
    }

    /// One agent's bundle; `asset` lends the body of an ASSET row the
    /// document holds under an id.
    pub(crate) fn agent<'a>(
        &mut self,
        bundle: &ExportAgentBundle,
        asset: impl Fn(&crate::entity_id::EntityId) -> Option<&'a ExportBody>,
    ) {
        for reason in agent_omissions(
            &bundle.entity_id,
            bundle.fork_hash.as_deref(),
            bundle.omission,
            |carrier| asset(carrier).and_then(|body| body.to_bytes().ok()),
        ) {
            self.bundle_omissions.push(ExportBundleOmission {
                entity_id: bundle.entity_id.clone(),
                reason,
            });
        }
    }

    /// Forgets rows that left the archive after the snapshot (OF-490: a
    /// diary whose read could not be logged).
    pub(crate) fn forget(&mut self, ids: &BTreeSet<String>) {
        self.archive_only.retain(|id, _| !ids.contains(id));
        self.entity_refusals.retain(|(id, _)| !ids.contains(id));
    }

    /// The import refusals, import omissions and bundle omissions, each in
    /// the manifest's order.
    pub(crate) fn finish(
        mut self,
    ) -> (
        Vec<ExportImportRefusal>,
        Vec<ExportImportOmission>,
        Vec<ExportBundleOmission>,
    ) {
        self.entity_refusals.sort_by(|a, b| a.0.cmp(&b.0));
        self.source_refusals.sort();
        self.provenanced_edges.sort();
        let mut refusals: Vec<_> = self
            .entity_refusals
            .into_iter()
            .map(|(entity_id, reason)| ExportImportRefusal::Entity { entity_id, reason })
            .collect();
        refusals.extend(self.source_refusals.into_iter().map(|entity_id| {
            ExportImportRefusal::Entity {
                entity_id,
                reason: ImportRefusalReason::RedactedSource,
            }
        }));
        for (source, edge_kind, target) in self.provenanced_edges {
            if !self
                .provenance_subjects
                .contains(&(source.clone(), edge_kind, target.clone()))
                && !self.archive_only.contains_key(&source)
                && !self.archive_only.contains_key(&target)
            {
                refusals.push(ExportImportRefusal::ProvenancedEdge {
                    source,
                    edge_kind,
                    target,
                });
            }
        }
        let imports = self
            .archive_only
            .into_iter()
            .map(|(entity_id, reason)| ExportImportOmission { entity_id, reason })
            .collect();
        self.bundle_omissions
            .sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        (refusals, imports, self.bundle_omissions)
    }
}

/// This is a closed list of archive-only families, not a reserved-claim import
/// bypass: a reserved claim is archive-only where [`reserved_claim_import`]
/// names its reason, and is never stored. A reserved family that list does
/// not cover still fails its ordinary import door. A claim of any other
/// predicate whose evidence carries a MACHINE signature is archive-only too
/// (`MachineSignedClaimNotRestored`): the signature binds the source vault's
/// id, this vault holds neither that MACHINE nor its omitted history, and
/// dropping the proof would pass a signed write off as an unsigned one, as
/// the guest-claim rule (FIX 3497) holds. Only the owner's restore brings it
/// back, as the owner's restore of it, its MACHINE author and proof inert.
///
/// Each maintenance kind the raw entity walk exports and no import door
/// restores is named here, so one such row never stops the whole import
/// (L10-23, OF-222): a WORLD_KEY_PAD is key material that only a recovery-kit
/// restore carries (`world_keys::bundle`); a RECEIPT_RECORD and an ISSUE are
/// audit evidence, never a permit here; a raw EMBEDDING_SETUP row is the
/// published form of the spaces and slot bindings the import admits from the
/// archive's own sections, and the import publishes it again from them.
pub(super) fn archive_only_reason(row: &ExportEntity) -> Option<ImportOmissionReason> {
    match row.entity_type {
        ENTITY_TYPE_SKILL_CONTENT_ANCHOR => Some(ImportOmissionReason::SkillAnchorRecomputed),
        ENTITY_TYPE_SKILL_HUB => Some(ImportOmissionReason::HubConfigurationNotRestored),
        ENTITY_TYPE_POLICY_MANIFEST => Some(ImportOmissionReason::PolicyAuthorityNotRestored),
        crate::registry::ENTITY_TYPE_AUTHORITY_LOG
        | crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        | crate::registry::ENTITY_TYPE_ACCESS_GRANT
        | crate::registry::ENTITY_TYPE_CONNECTOR_KEY
        | crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY
        | crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT
        | crate::registry::ENTITY_TYPE_OUTBOUND_GRANT
        | crate::registry::ENTITY_TYPE_WORLD_KEY_PAD => {
            Some(ImportOmissionReason::LocalAuthorityNotRestored)
        }
        crate::registry::ENTITY_TYPE_DIAGNOSTIC
        | crate::registry::ENTITY_TYPE_REDACTION_AUDIT
        | crate::registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT
        | crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
        | crate::registry::ENTITY_TYPE_COMM_RECORD
        | crate::registry::ENTITY_TYPE_RECEIPT_RECORD
        | crate::registry::ENTITY_TYPE_ISSUE => Some(ImportOmissionReason::LocalHistoryNotRestored),
        crate::registry::ENTITY_TYPE_PSYCH_PROFILE
        | crate::registry::ENTITY_TYPE_EMBEDDING_SETUP => {
            Some(ImportOmissionReason::LocalProjectionNotRestored)
        }
        ENTITY_TYPE_CLAIM => {
            // Decode a reserved claim only for classification; NEVER store it.
            let field = |name: &str| match &row.body {
                ExportBody::MessagePack(crate::serialize::ExportValue::Map(entries)) => {
                    entries.iter().find_map(|(k, v)| match k {
                        crate::serialize::ExportValue::String(k) if k == name => Some(v),
                        _ => None,
                    })
                }
                _ => None,
            };
            let predicate = field("pred").and_then(|value| match value {
                crate::serialize::ExportValue::String(value) => Some(value.as_str()),
                _ => None,
            });
            match predicate.and_then(reserved_claim_import) {
                Some(ReservedClaimImport::ArchiveOnly(reason)) => Some(reason),
                Some(ReservedClaimImport::Restore(_)) => None,
                None if field("evid").is_some_and(carries_machine_signature) => {
                    Some(ImportOmissionReason::MachineSignedClaimNotRestored)
                }
                None => None,
            }
        }
        _ => None,
    }
}

/// Whether an archived claim's evidence names a MACHINE signature, whatever
/// the archive kept of its bytes (an archive without secrets nulls raw
/// binary).
fn carries_machine_signature(evidence: &crate::serialize::ExportValue) -> bool {
    matches!(evidence, crate::serialize::ExportValue::Map(entries)
        if entries.iter().any(|(key, _)| matches!(key,
            crate::serialize::ExportValue::String(key)
                if key == crate::authority::MACHINE_SIGNATURE_KEY)))
}

/// The door the whole-vault import restores a reserved claim through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservedClaimRestore {
    /// `edge.provenance`: the provenance pass (`provenance_import`).
    EdgeProvenance,
    /// `person.substrate` and `actor.subject_ref`: the subject-model restore.
    SubjectModel,
    /// `actor.lesson`, `actor.failure_mode`, `actor.scope_note` and
    /// `actor.skill_fit`: the actor-projection restore.
    ActorProjection,
    /// `vault.default_facet`: the owner's setter, in the owner's restore into
    /// a fresh vault only; otherwise the import keeps it as archive data
    /// (`TargetDefaultFacetKept`).
    OwnerDefaultFacet,
}

/// What the whole-vault import does with a claim of a reserved predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservedClaimImport {
    Restore(ReservedClaimRestore),
    /// The manifest declares the row an import omission with this reason.
    ArchiveOnly(ImportOmissionReason),
}

/// The import's one decision for each reserved predicate family
/// (ARCHIVE-IMPORT-RESERVED-CLAIM-ABORTS): the door that restores it, or the
/// reason [`archive_only_reason`] declares it archive-only with. A family
/// with neither returns `None`, as a predicate outside every reserved family
/// does; the generic claim door then refuses it, and the whole import fails.
/// A test names every reserved family and fails on such a `None`.
pub(crate) fn reserved_claim_import(predicate: &str) -> Option<ReservedClaimImport> {
    use ImportOmissionReason as Omit;
    use ReservedClaimImport::{ArchiveOnly, Restore};
    if !crate::write_envelope::claim_predicate::is_reserved_predicate(predicate) {
        return None;
    }
    if predicate == crate::write_envelope::provenance::PREDICATE_EDGE_PROVENANCE {
        return Some(Restore(ReservedClaimRestore::EdgeProvenance));
    }
    if crate::write_envelope::subject_record::is_subject_model_predicate(predicate) {
        return Some(Restore(ReservedClaimRestore::SubjectModel));
    }
    if crate::write_envelope::actor_predicate::is_actor_claim_predicate(predicate) {
        return Some(Restore(ReservedClaimRestore::ActorProjection));
    }
    if predicate == crate::claim::PREDICATE_VAULT_DEFAULT_FACET {
        return Some(Restore(ReservedClaimRestore::OwnerDefaultFacet));
    }
    let reason = match predicate {
        crate::store::skill_hub_predicates::PREDICATE_SKILL_HUB_PROVENANCE
        | crate::store::skill_hub_predicates::PREDICATE_SKILL_SCAN_VERDICT => {
            Omit::ForeignSkillSignalNotRestored
        }
        // A stamp token resolves its own vault's stamps (FIX 10930): a
        // binding no other vault holds, as a peer binding is.
        "actor.peer_binding" | "actor.confidence_prior" | "actor.stamp_token" => {
            Omit::LocalActorConfigurationNotRestored
        }
        // The hub rows the proposal names are omitted with this reason too.
        crate::skill_hub::PREDICATE_SKILL_HUB_UPDATE_PROPOSAL => Omit::HubConfigurationNotRestored,
        // The next floor check derives it again from the rebuilt cells.
        crate::skill_reliability::PREDICATE_SKILL_QUARANTINE_PROPOSAL => {
            Omit::LocalProjectionNotRestored
        }
        _ => match predicate.split('.').next() {
            Some(crate::write_envelope::claim_predicate::LEARNING_NAMESPACE) => {
                Omit::LearningCellsRebuiltFromReceipts
            }
            // Board history and the engine-signed machine carriers: the
            // target's own turns and pairings write their own.
            Some("world_access" | "activated" | "machine") => Omit::LocalHistoryNotRestored,
            Some("repo") => Omit::RepoClaimsNotRestored,
            Some("actor") => Omit::LocalActorConfigurationNotRestored,
            // Signature events, section fit receipts and the engine's other
            // skill and edge records.
            Some("esign" | "skill" | "edge") => Omit::EngineAttestationNotRestored,
            _ => return None,
        },
    };
    Some(ArchiveOnly(reason))
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault bundle: {reason}"))
}
