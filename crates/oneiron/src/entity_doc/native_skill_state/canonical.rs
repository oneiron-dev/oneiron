//! Exact native values restored only from an owned Store capture.

use loro::{LoroDoc, LoroValue, ValueOrContainer};

use super::codec::SkillStateFact;
use super::register::{CURRENT, ROOT};
use crate::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::recovery::StoreCapturedCanonical;
use crate::store::canonical_document::CanonicalEntityDocument;

/// The source owns this exact row. It grants no peer, owner or grant standing.
pub(in crate::entity_doc) struct CanonicalSkillState<'a> {
    row: &'a CanonicalEntityDocument,
}

fn invalid() -> Error {
    ArtifactError::InvalidRecoveryArtifact("native SKILL state restore source").into()
}

pub(in crate::entity_doc) fn has_witness(row: &CanonicalEntityDocument) -> bool {
    row.native_skill_state.is_some()
        || row.history.as_ref().is_some_and(|history| {
            history
                .versions
                .iter()
                .any(|version| version.native_skill_state.is_some())
                || history
                    .forks
                    .iter()
                    .any(|fork| fork.output_native_skill_state.is_some())
        })
}

impl<'a> CanonicalSkillState<'a> {
    pub(in crate::entity_doc) fn from_source(
        row: &'a CanonicalEntityDocument,
        source: &StoreCapturedCanonical,
    ) -> Result<Self> {
        source.require_entity_document(row)?;
        let entity = EntityId::from_bytes(row.entity_id)?;
        let document = EntityId::from_bytes(row.document_id)?;
        let validate = |bytes: Option<&[u8]>| -> Result<()> {
            if let Some(bytes) = bytes {
                let fact = SkillStateFact::decode(bytes)?;
                if !fact.target_is(entity, document, row.birth_at) {
                    return Err(invalid());
                }
            }
            Ok(())
        };
        validate(row.native_skill_state.as_deref())?;
        if let Some(history) = &row.history {
            for version in &history.versions {
                validate(version.native_skill_state.as_deref())?;
            }
            for fork in &history.forks {
                if fork.output.is_none() && fork.output_native_skill_state.is_some() {
                    return Err(invalid());
                }
                validate(fork.output_native_skill_state.as_deref())?;
            }
        }
        Ok(Self { row })
    }

    pub(in crate::entity_doc) fn write_current(&self, doc: &LoroDoc) -> Result<()> {
        write_selected(doc, self.row.native_skill_state.as_deref())
    }

    pub(in crate::entity_doc) fn write_version(&self, doc: &LoroDoc, index: usize) -> Result<()> {
        let version = self
            .row
            .history
            .as_ref()
            .and_then(|history| history.versions.get(index))
            .ok_or_else(invalid)?;
        write_selected(doc, version.native_skill_state.as_deref())
    }

    pub(in crate::entity_doc) fn write_output(&self, doc: &LoroDoc, index: usize) -> Result<()> {
        let fork = self
            .row
            .history
            .as_ref()
            .and_then(|history| history.forks.get(index))
            .ok_or_else(invalid)?;
        if fork.output.is_none() {
            return Err(invalid());
        }
        write_selected(doc, fork.output_native_skill_state.as_deref())
    }
}

/// This raw writer is private to the source-bound selection above. In
/// particular, None deletes inherited state rather than keeping a parent.
fn write_selected(doc: &LoroDoc, selected: Option<&[u8]>) -> Result<()> {
    let LoroValue::Map(roots) = doc.get_value() else {
        return Err(invalid());
    };
    let existing = match roots.get(ROOT) {
        None => None,
        Some(LoroValue::Container(id)) => Some(doc.try_get_map(id).ok_or_else(invalid)?),
        Some(_) => return Err(invalid()),
    };
    match selected {
        Some(bytes) => {
            existing
                .unwrap_or_else(|| doc.get_map(ROOT))
                .insert(CURRENT, bytes)
                .map_err(|_| invalid())?;
        }
        None => {
            if let Some(map) = existing {
                map.delete(CURRENT).map_err(|_| invalid())?;
            }
        }
    }
    let LoroValue::Map(roots) = doc.get_value() else {
        return Err(invalid());
    };
    let actual = match roots.get(ROOT) {
        None => None,
        Some(LoroValue::Container(id)) => {
            let map = doc.try_get_map(id).ok_or_else(invalid)?;
            let current = map.get(CURRENT);
            if map.len() != usize::from(current.is_some()) {
                return Err(invalid());
            }
            match current {
                None => None,
                Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Some(bytes.to_vec()),
                Some(_) => return Err(invalid()),
            }
        }
        Some(_) => return Err(invalid()),
    };
    if actual.as_deref() != selected {
        return Err(invalid());
    }
    Ok(())
}
