//! Import-time validation of the serializer's full document, not its claims.
use std::collections::{BTreeMap, BTreeSet};

use super::WholeVaultDocument;
use super::document_import::parse_id;
use crate::Vault;
use crate::edge::{EdgeKind, EdgeValueLayout, edge_value_layout_for_kind};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_SKILL};
use crate::serialize::{ExportBody, ExportValue};

impl WholeVaultDocument {
    pub(super) fn validate(&self, vault: &Vault) -> Result<()> {
        self.manifest.validate_json()?;
        let mut ids = BTreeSet::new();
        for row in self.entities() {
            let id = parse_id(&row.id)?;
            if !ids.insert(id) {
                return Err(invalid("duplicate entity ID"));
            }
            if row.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
                return Err(invalid("custody rows cannot appear in exports"));
            }
            if crate::registry::zone_of(row.entity_type)
                != crate::registry::TypeByteZone::PackHandle
            {
                vault.store.validate_entity_type(row.entity_type)?;
            } else if !matches!(row.body, ExportBody::Pack(_) | ExportBody::Nulled) {
                return Err(invalid("runtime pack row lacks name-bearing envelope"));
            }
            if row.occurred_start > row.occurred_end {
                return Err(invalid("invalid entity time range"));
            }
            row.body.validate(row.entity_type)?;
        }
        if self
            .claims
            .iter()
            .any(|row| row.entity_type != ENTITY_TYPE_CLAIM)
            || self
                .skills
                .iter()
                .any(|bundle| bundle.entity.entity_type != ENTITY_TYPE_SKILL)
            || self
                .evidence_ledger
                .entities
                .iter()
                .any(|row| matches!(row.entity_type, ENTITY_TYPE_CLAIM | ENTITY_TYPE_SKILL))
        {
            return Err(invalid("entity is in the wrong document section"));
        }
        let mut edge_keys = BTreeSet::new();
        for edge in &self.evidence_ledger.edges {
            let source = parse_id(&edge.source)?;
            let target = parse_id(&edge.target)?;
            if !ids.contains(&source) || !ids.contains(&target) {
                return Err(invalid("edge endpoint is absent from document"));
            }
            if !edge_keys.insert((source, edge.kind, target)) {
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
        let expected: BTreeMap<_, _> = self
            .claims
            .iter()
            .filter_map(|row| {
                let ExportBody::MessagePack(ExportValue::Map(entries)) = &row.body else {
                    return None;
                };
                entries.iter().find_map(|(key, value)| match key {
                    ExportValue::String(key) if key == "evid" => Some((row.id.as_str(), value)),
                    _ => None,
                })
            })
            .collect();
        let actual: BTreeMap<_, _> = self
            .derivation_envelopes
            .iter()
            .map(|row| (row.id.as_str(), &row.evidence))
            .collect();
        if actual.len() != self.derivation_envelopes.len() || actual != expected {
            return Err(invalid("derivation index disagrees with claim evidence"));
        }
        for envelope in &self.derivation_envelopes {
            let row = self
                .claims
                .iter()
                .find(|row| row.id == envelope.id)
                .ok_or_else(|| invalid("derivation claim is absent"))?;
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
        // Built-in registrations are descriptors, not installable code. Unknown
        // descriptors must not be silently ignored as if their adapter exists.
        let known: BTreeMap<_, _> = crate::ingest::INGEST_SOURCE_REGISTRY
            .source_configs()
            .map(|config| (config.source_id, config.adapter_skill))
            .collect();
        let mut sources = BTreeSet::new();
        let mut pack_ids = BTreeSet::new();
        for pack in &self.packs {
            let super::ExportPack::BuiltinAdapter(descriptor) = pack else {
                let super::ExportPack::Source(source) = pack else {
                    unreachable!()
                };
                let id = parse_id(&source.entity_id)?;
                if !pack_ids.insert(id) {
                    return Err(invalid("duplicate pack source"));
                }
                source.source_tree.validate()?;
                let row = self
                    .evidence_ledger
                    .entities
                    .iter()
                    .find(|row| row.id == source.entity_id)
                    .ok_or_else(|| invalid("pack source entity missing"))?;
                if row.entity_type != crate::registry::ENTITY_TYPE_ASSET {
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
                continue;
            };
            if !sources.insert(descriptor.source_id.as_str()) {
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
        }
        for row in &self.evidence_ledger.entities {
            if row.entity_type == crate::registry::ENTITY_TYPE_ASSET
                && let Ok(bytes) = row.body.to_bytes()
                && crate::skill_hub::pack_catalog::decode_source_body(&bytes)?.is_some()
                && !pack_ids.contains(&parse_id(&row.id)?)
            {
                return Err(invalid("source asset missing pack facet"));
            }
        }
        self.validate_bundles()?;
        Ok(())
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}
