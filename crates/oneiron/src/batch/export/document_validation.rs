//! Import-time validation of the serializer's full document, not its claims.
//! FIX 3678: the rows are validated one at a time from the import's row
//! index, and the cross-row checks join through it; no row stays in memory.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use super::archive_index::{
    self, EntityAt, FLAG_ARCHIVE_ONLY, FLAG_EXPRESSION, FLAG_FILE, FLAG_PACK_BODY,
    FLAG_PACK_SOURCE, FLAG_PROVENANCE, IndexedArchive, Loc, Section, Tag, edge_key,
};
use super::document_import::parse_id;
use super::{
    ArchiveRecordKind, ExportDerivationEnvelope, ExportEdge, ExportEntity, ExportEpochFloor,
    ExportPack,
};
use crate::Vault;
use crate::claim::ClaimSubject;
use crate::edge::{EdgeKind, EdgeValueLayout, edge_value_layout_for_kind};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_SKILL,
};
use crate::serialize::{ExportBody, ExportValue};

impl<R: Read + Seek> IndexedArchive<'_, R> {
    /// The archive's attached files are read one at a time and checked
    /// against their names: an ASSET's file body is validated against them
    /// (OF-222).
    pub(super) fn validate(&mut self, vault: &Vault) -> Result<()> {
        self.manifest.validate()?;
        let mut floors = self.spool.rows(ArchiveRecordKind::EpochFloor);
        while let Some((_, floor)) = floors.next_parsed::<ExportEpochFloor>(&self.spool)? {
            parse_id(&floor.session)?;
        }
        let mut wrong_section = false;
        for (kind, section) in [
            (ArchiveRecordKind::Entity, Section::Ledger),
            (ArchiveRecordKind::Claim, Section::Claim),
            (ArchiveRecordKind::Skill, Section::Skill),
        ] {
            let mut rows = self.spool.rows(kind);
            while let Some((loc, line)) = rows.next(&self.spool)? {
                let row = archive_index::entity_of(section, &line)?;
                wrong_section |= match section {
                    Section::Ledger => {
                        matches!(row.entity_type, ENTITY_TYPE_CLAIM | ENTITY_TYPE_SKILL)
                    }
                    Section::Claim => row.entity_type != ENTITY_TYPE_CLAIM,
                    Section::Skill => row.entity_type != ENTITY_TYPE_SKILL,
                };
                self.validate_entity(vault, section, loc, &row)?;
            }
        }
        // FIX 2768: each side row reads back through its own table and names
        // only records and carriers this document holds.
        super::archive_side_tables::validate_side_rows(self)?;
        if wrong_section {
            return Err(invalid("entity is in the wrong document section"));
        }
        self.validate_edges()?;
        self.validate_derivations()?;
        self.validate_packs()?;
        let mut after = None;
        while let Some(id) = self.next_of_type(ENTITY_TYPE_ASSET, after.as_ref())? {
            if self
                .entity_at(&id)?
                .is_some_and(|at| at.has(FLAG_PACK_SOURCE))
                && !self.index.contains(Tag::PackSource, id.as_bytes())?
            {
                return Err(invalid("source asset missing pack facet"));
            }
            after = Some(id);
        }
        self.validate_bundles()?;
        self.validate_embedding_setup()?;
        Ok(())
    }

    /// One entity row's own checks, and its place in the index with what
    /// the later joins read of it.
    fn validate_entity(
        &mut self,
        vault: &Vault,
        section: Section,
        loc: Loc,
        row: &ExportEntity,
    ) -> Result<()> {
        let id = parse_id(&row.id)?;
        if self.index.contains(Tag::Entity, id.as_bytes())? {
            return Err(invalid("duplicate entity ID"));
        }
        if row.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
            return Err(invalid("custody rows cannot appear in exports"));
        }
        if crate::registry::zone_of(row.entity_type) != crate::registry::TypeByteZone::PackHandle {
            vault.store.validate_entity_type(row.entity_type)?;
        } else if !matches!(row.body, ExportBody::Pack(_) | ExportBody::Nulled) {
            return Err(invalid("runtime pack row lacks name-bearing envelope"));
        }
        if row.occurred_start > row.occurred_end {
            return Err(invalid("invalid entity time range"));
        }
        row.body.validate_in(row.entity_type, &self.files)?;
        let mut flags = 0;
        if matches!(row.body, ExportBody::File(_)) {
            flags |= FLAG_FILE;
        }
        if matches!(row.body, ExportBody::Pack(_)) {
            flags |= FLAG_PACK_BODY;
        }
        if super::provenance_import::is_provenance(row) {
            flags |= FLAG_PROVENANCE;
            if let Some(key) = super::bundle_validation::provenance_subject_key(row) {
                self.index.put(Tag::ProvenanceSubject, &key, &[])?;
            }
        }
        if super::expression_import::is_expression(row) {
            flags |= FLAG_EXPRESSION;
            self.expressions = true;
        }
        if super::bundle_validation::archive_only_reason(row).is_some() {
            flags |= FLAG_ARCHIVE_ONLY;
        }
        if section == Section::Ledger
            && row.entity_type == ENTITY_TYPE_ASSET
            && let Ok(bytes) = row.body.to_bytes()
            && crate::skill_hub::pack_catalog::decode_source_body(&bytes)?.is_some()
        {
            flags |= FLAG_PACK_SOURCE;
        }
        if section == Section::Skill
            && let Ok(body) = row.body.to_bytes()
            && let Ok(record) = crate::skill::decode_skill_record(&body)
        {
            let mut key = super::bundle_validation::skill_name_key(&record.skill_id);
            key.extend_from_slice(id.as_bytes());
            self.index.put(Tag::SkillName, &key, &[])?;
        }
        if section == Section::Claim
            && let Ok(body) = row.body.to_bytes()
            && let Ok(claim) = crate::claim::decode_claim_body(&body, false)
            && let ClaimSubject::Entity(subject) = claim.subject
        {
            let mut key = subject.as_bytes().to_vec();
            key.extend_from_slice(id.as_bytes());
            self.index.put(Tag::About, &key, &[])?;
        }
        let at = EntityAt {
            section,
            entity_type: row.entity_type,
            flags,
            loc,
        };
        self.index.put(Tag::Entity, id.as_bytes(), &at.encode())?;
        self.index.put(
            Tag::ByType,
            &archive_index::typed_key(row.entity_type, &id),
            &[],
        )
    }

    fn validate_edges(&mut self) -> Result<()> {
        let mut edges = self.spool.rows(ArchiveRecordKind::Edge);
        while let Some((loc, edge)) = edges.next_parsed::<ExportEdge>(&self.spool)? {
            let source = parse_id(&edge.source)?;
            let target = parse_id(&edge.target)?;
            if !self.index.contains(Tag::Entity, source.as_bytes())?
                || !self.index.contains(Tag::Entity, target.as_bytes())?
            {
                return Err(invalid("edge endpoint is absent from document"));
            }
            let mut value = loc.encode().to_vec();
            value.push(u8::from(edge.provenance.is_some()));
            if !self
                .index
                .insert(Tag::Edge, &edge_key(&source, edge.kind, &target), &value)?
            {
                return Err(invalid("duplicate edge"));
            }
            let kind =
                EdgeKind::try_from_u8(edge.kind).ok_or_else(|| invalid("unknown edge kind"))?;
            if !edge.weight.is_finite() || !(0.0..=1.0).contains(&edge.weight) {
                return Err(invalid("invalid edge weight"));
            }
            let structural = edge_value_layout_for_kind(kind, edge.provenance.is_some())
                == EdgeValueLayout::Structural;
            if structural != edge.vad.is_none() || (structural && edge.provenance.is_some()) {
                return Err(invalid("invalid edge value layout"));
            }
            if let Some(vad) = edge.vad {
                let vad = crate::affect::Vad {
                    valence: vad[0],
                    arousal: vad[1],
                    dominance: vad[2],
                };
                if !vad.is_finite() || !vad.is_in_range() {
                    return Err(invalid("invalid edge VAD"));
                }
            }
            if edge
                .provenance
                .is_some_and(|flags| flags[0] > 3 || flags[1] > 2)
            {
                return Err(invalid("invalid edge provenance flags"));
            }
        }
        Ok(())
    }

    /// The derivation index is exactly the claims' evidence, keyed by claim,
    /// and each envelope's receipts are exactly its claim's citations.
    fn validate_derivations(&mut self) -> Result<()> {
        let mut disagrees = false;
        let mut envelopes = 0_u64;
        let mut rows = self.spool.rows(ArchiveRecordKind::DerivationEnvelope);
        while let Some((loc, envelope)) =
            rows.next_parsed::<ExportDerivationEnvelope>(&self.spool)?
        {
            envelopes += 1;
            match parse_id(&envelope.id) {
                Ok(id) => {
                    disagrees |=
                        !self
                            .index
                            .insert(Tag::Derivation, id.as_bytes(), &loc.encode())?;
                }
                Err(_) => disagrees = true,
            }
        }
        let mut expected = 0_u64;
        let mut claims = self.spool.rows(ArchiveRecordKind::Claim);
        while let Some((_, row)) = claims.next_parsed::<ExportEntity>(&self.spool)? {
            let Some(evidence) = claim_evidence(&row.body) else {
                continue;
            };
            expected += 1;
            match self
                .index
                .get(Tag::Derivation, parse_id(&row.id)?.as_bytes())?
            {
                Some(loc) => {
                    let envelope: ExportDerivationEnvelope =
                        self.spool.parse(Loc::decode(&loc)?)?;
                    disagrees |= envelope.evidence != *evidence;
                }
                None => disagrees = true,
            }
        }
        if disagrees || expected != envelopes {
            return Err(invalid("derivation index disagrees with claim evidence"));
        }
        let mut rows = self.spool.rows(ArchiveRecordKind::DerivationEnvelope);
        while let Some((_, envelope)) = rows.next_parsed::<ExportDerivationEnvelope>(&self.spool)? {
            let row = match self.entity(&parse_id(&envelope.id)?)? {
                Some((at, row)) if at.section == Section::Claim => row,
                _ => return Err(invalid("derivation claim is absent")),
            };
            let expected = super::receipt_sources::task_receipt_refs_from_body(&row.body);
            let mut actual = BTreeSet::new();
            for receipt in &envelope.receipts {
                receipt.validate()?;
                if !actual.insert(receipt.receipt_id().to_owned()) {
                    return Err(invalid("duplicate receipt source"));
                }
            }
            if actual != expected {
                return Err(invalid("receipt source set disagrees with citations"));
            }
        }
        Ok(())
    }

    /// Built-in registrations are descriptors, not installable code. Unknown
    /// descriptors must not be silently ignored as if their adapter exists.
    fn validate_packs(&mut self) -> Result<()> {
        let known: BTreeMap<_, _> = crate::ingest::INGEST_SOURCE_REGISTRY
            .source_configs()
            .map(|config| (config.source_id, config.adapter_skill))
            .collect();
        // Each source is a known one or the import stops: no more than the
        // registry holds.
        let mut sources = BTreeSet::new();
        let mut packs = self.spool.rows(ArchiveRecordKind::Pack);
        while let Some((loc, _)) = packs.next(&self.spool)? {
            let source = match self.hydrated::<ExportPack>(ArchiveRecordKind::Pack, loc)? {
                ExportPack::Source(source) => source,
                ExportPack::BuiltinAdapter(descriptor) => {
                    if !sources.insert(descriptor.source_id.clone()) {
                        return Err(invalid("duplicate import adapter descriptor"));
                    }
                    let adapter = known
                        .get(descriptor.source_id.as_str())
                        .ok_or_else(|| invalid("unknown import adapter descriptor"))?;
                    if descriptor.adapter_skill_id.as_deref() != adapter.map(|a| a.skill_id)
                        || descriptor.adapter_version.as_deref() != adapter.map(|a| a.version)
                    {
                        return Err(invalid("unsupported import adapter version"));
                    }
                    continue;
                }
            };
            let id = parse_id(&source.entity_id)?;
            if !self.index.insert(Tag::PackSource, id.as_bytes(), &[])? {
                return Err(invalid("duplicate pack source"));
            }
            source.source_tree.validate()?;
            let row = match self.entity(&id)? {
                Some((at, row)) if at.section == Section::Ledger => row,
                _ => return Err(invalid("pack source entity missing")),
            };
            if row.entity_type != ENTITY_TYPE_ASSET {
                return Err(invalid("pack source is not an asset"));
            }
            if source.source_tree.content_hash.is_some() {
                let pack = crate::skill_hub::pack_catalog::PackSource::from_files(
                    source.source_tree.import_files()?,
                )?;
                if crate::skill_hub::pack_catalog::export_source_body(&pack)? != row.body
                    || pack.entity_id()? != id
                {
                    return Err(invalid("pack source disagrees with its evidence row"));
                }
            }
        }
        Ok(())
    }
}

/// A claim row's `evid`, the evidence its derivation envelope indexes.
fn claim_evidence(body: &ExportBody) -> Option<&ExportValue> {
    let ExportBody::MessagePack(ExportValue::Map(entries)) = body else {
        return None;
    };
    entries.iter().find_map(|(key, value)| match key {
        ExportValue::String(key) if key == "evid" => Some(value),
        _ => None,
    })
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}
