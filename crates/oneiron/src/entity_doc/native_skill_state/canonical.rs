//! Exact native values restored only from an owned Store capture.

use std::collections::BTreeSet;

use loro::{Frontiers, LoroDoc, LoroValue, UpdateOptions, ValueOrContainer};

use super::super::{EntityDoc, document::BODY, recovery, storage};
use super::codec::SkillStateFact;
use super::inspect::{NativeMapInventory, inspect};
use super::register::{CURRENT, ROOT};
use crate::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::recovery::StoreCapturedCanonical;
use crate::store::canonical_document::CanonicalEntityDocument;

/// The source owns this exact row. It grants no peer, owner or grant standing.
pub(in crate::entity_doc) struct CanonicalSkillState<'a> {
    row: &'a CanonicalEntityDocument,
}

/// Owns the actual fresh replay, not a caller-supplied document with matching
/// signed values. Its only constructor runs the fixed canonical producer.
pub(in crate::entity_doc) struct CanonicalRebuiltDocument<'a> {
    source: CanonicalSkillState<'a>,
    document: EntityDoc,
    frontiers: Vec<Frontiers>,
    frontier: Vec<u8>,
    inventory: NativeMapInventory,
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

/// Validate the carried values only; this grants no restore source standing.
pub(in crate::entity_doc) fn validate_witnesses(row: &CanonicalEntityDocument) -> Result<()> {
    let entity = EntityId::from_bytes(row.entity_id)?;
    let validate = |bytes: Option<&[u8]>| -> Result<()> {
        if let Some(bytes) = bytes {
            let fact = SkillStateFact::decode(bytes)?;
            if !fact.target_birth_is(entity, row.birth_at) {
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
    Ok(())
}

impl<'a> CanonicalSkillState<'a> {
    pub(in crate::entity_doc) fn from_source(
        row: &'a CanonicalEntityDocument,
        source: &StoreCapturedCanonical,
    ) -> Result<Self> {
        // Full row membership binds the current source slot and every exact
        // carried witness. A witness's own document id is historical: a
        // legitimate SWITCH keeps it while moving the storage slot.
        source.require_entity_document(row)?;
        validate_witnesses(row)?;
        Ok(Self { row })
    }

    pub(in crate::entity_doc) fn rebuild(self) -> Result<CanonicalRebuiltDocument<'a>> {
        let (document, frontiers) = recovery::rebuild_canonical_document(self.row, Some(&self))?;
        let inventory = inspect(&document)?;
        let frontier = document.frontier();
        Ok(CanonicalRebuiltDocument {
            source: self,
            document,
            frontiers,
            frontier,
            inventory,
        })
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

impl<'a> CanonicalRebuiltDocument<'a> {
    /// Own the ordinary fixed replay when it emits no native state at any
    /// retained version. Repair must not reload the damaged old document to
    /// establish what this producer itself wrote.
    pub(in crate::entity_doc) fn ordinary(row: &'a CanonicalEntityDocument) -> Result<Self> {
        if has_witness(row) {
            return Err(invalid());
        }
        let (document, frontiers) = recovery::rebuild_canonical_document(row, None)?;
        let inventory = inspect(&document)?;
        if inventory.current.is_some()
            || inventory
                .floor
                .as_ref()
                .is_some_and(|floor| floor.fact.is_some())
            || !inventory.mutations.is_empty()
        {
            return Err(invalid());
        }
        let frontier = document.frontier();
        Ok(Self {
            source: CanonicalSkillState { row },
            document,
            frontiers,
            frontier,
            inventory,
        })
    }

    pub(in crate::entity_doc) fn document(&self) -> &EntityDoc {
        &self.document
    }

    pub(in crate::entity_doc) fn frontiers(&self) -> &[Frontiers] {
        &self.frontiers
    }

    fn require_unchanged(&self) -> Result<()> {
        // Inspect first: exporting the raw inventory also commits any pending
        // mutation, so the following frontier comparison includes it.
        if inspect(&self.document)? != self.inventory || self.document.frontier() != self.frontier {
            return Err(invalid());
        }
        Ok(())
    }

    pub(in crate::entity_doc) fn require_document(
        &self,
        entity: &EntityId,
        head: &storage::Head,
    ) -> Result<BTreeSet<EntityId>> {
        self.require_unchanged()?;
        let row = self.source.row;
        let field = match &row.field {
            None => storage::TextField::Utf8Body,
            Some(field) => storage::TextField::MapField(field.clone()),
        };
        if *entity.as_bytes() != row.entity_id
            || head.entity != entity.to_hex()
            || head.document != EntityId::from_bytes(row.document_id)?.to_hex()
            || head.field != field
            || self.document.birth().entity != entity.to_hex()
            || self.document.birth().at != row.birth_at
        {
            return Err(invalid());
        }
        self.inventory.writer_tokens()
    }

    /// Rebuild this source's OWN output on its OWN replayed base. No supplied
    /// snapshot or mutation closure can obtain this continuation.
    pub(in crate::entity_doc) fn persist_output_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        index: usize,
    ) -> Result<()> {
        self.require_unchanged()?;
        if *entity.as_bytes() != self.source.row.entity_id {
            return Err(invalid());
        }
        let fork = self
            .source
            .row
            .history
            .as_ref()
            .and_then(|history| history.forks.get(index))
            .ok_or_else(invalid)?;
        let output = fork.output.as_ref().ok_or_else(invalid)?;
        let base = match fork.base {
            Some(index) => self
                .frontiers
                .get(index as usize)
                .ok_or_else(invalid)?
                .encode(),
            None => Frontiers::default().encode(),
        };
        let branch = self.document.fork(&base)?;
        branch
            .doc
            .get_text(BODY)
            .update(output, UpdateOptions::default())
            .map_err(|_| invalid())?;
        EntityDoc::replace_metadata(
            &branch.doc,
            fork.output_metadata.as_ref().ok_or_else(invalid)?,
        )?;
        self.source.write_output(&branch.doc, index)?;
        super::super::document::restate_birth(&branch.doc);
        branch.doc.commit();
        let snapshot = branch.shallow_snapshot(&base)?;
        let replayed = EntityDoc::from_snapshot(&snapshot)?;
        if super::register::current_witness_bytes(&replayed)? != fork.output_native_skill_state {
            return Err(Error::InvariantViolation(
                "replayed native SKILL state output differs",
            ));
        }
        // The fixed producer above owns both the inherited operations and its
        // one selected output write, including a genuine selected None delete.
        // Record uses from the complete resulting history, not just its winner.
        let native_tokens = inspect(&replayed)?.writer_tokens()?;
        if !native_tokens.is_empty() {
            crate::provenance::record_actor_stamp_uses_in_txn(store, txn, entity, native_tokens)?;
        }
        super::super::forks::ENTITY_DOC_FORK_SNAPSHOT.put(
            store,
            txn,
            &EntityId::from_bytes(fork.fork)?.to_hex(),
            &snapshot,
        )?;
        Ok(())
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
