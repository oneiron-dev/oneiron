//! The host-driven fill of the learned rung: find the names that lack a vector of the bound
//! model, embed them outside any transaction, and store each in one write, as the media
//! backfill does ([`Vault::reconcile_media_embeddings`]).
//!
//! A model off this device reads only the names the host's egress gate admits, and never a
//! name a device-local world keeps (FIX 382, DEC-0005): a name gets the privacy treatment its
//! entity's text gets (canon 0013 `#open` Q5), asked right before it leaves.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    LEARNED_VECTOR, LearnedVectorRow, NAMES_PER_ENTITY_CAP, PHONETIC_VECTOR_MAX_DIMENSIONS,
    PhoneticEmbedReport, PhoneticEmbedder, model_key, name_key,
};
use crate::Vault;
use crate::batch::phonetic_codes::names_for_body;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::embed::{
    EgressDecision, EgressPredicate, EmbedderLocality, InputKind, MediaEmbeddingInput,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::settings::ReadDestination;
use crate::store::encode_vector_row_v1;
use crate::vault::entity_revision::{ReadMode, read_entity_revision_in_txn};

/// The records whose names the learned rung embeds: people, organisations and places, the
/// entities canon 0013 resolves by sound.
const NAMED_ENTITY_TYPES: [u8; 3] = [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG, ENTITY_TYPE_PLACE];

/// The media type a name is judged as by the host's egress gate.
const NAME_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// One name a pass owes a vector.
struct PendingName {
    id: EntityId,
    name: String,
    key: [u8; 16],
}

impl Vault {
    /// Embeds up to `max_names` entity names that lack a vector of `embedder`'s model, and
    /// stores one vector per name. The names are those the code rung reads, at the revision it
    /// publishes, at most [`NAMES_PER_ENTITY_CAP`] an entity. A vector of a name the entity no
    /// longer has is dropped; one of another model is replaced as its name is embedded again.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the embedder runs at a third party (this door has no egress
    /// gate), its width is outside 1..=[`PHONETIC_VECTOR_MAX_DIMENSIONS`], or it answers with
    /// another number of vectors; [`Error::DimensionMismatch`] for a vector of another width;
    /// storage and embedder errors otherwise.
    pub fn reconcile_phonetic_embeddings(
        &self,
        embedder: &dyn PhoneticEmbedder,
        max_names: usize,
    ) -> Result<PhoneticEmbedReport> {
        self.reconcile_phonetic_embeddings_admitted(embedder, max_names, None)
    }

    /// [`Self::reconcile_phonetic_embeddings`] with the host's egress gate: an embedder at a
    /// third party, or on the owner's server with a gate, is sent only the names `egress`
    /// allows ([`EgressPredicate::decide_media`], each name as a text document of its entity)
    /// whose entity no device-local world keeps; the rest stay unsent and are counted
    /// [`PhoneticEmbedReport::withheld`].
    ///
    /// # Errors
    ///
    /// As [`Self::reconcile_phonetic_embeddings`]; a third-party embedder with no gate is
    /// refused.
    pub fn reconcile_phonetic_embeddings_admitted(
        &self,
        embedder: &dyn PhoneticEmbedder,
        max_names: usize,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<PhoneticEmbedReport> {
        let egress = phonetic_egress_for(embedder, egress)?;
        let dimensions = embedder.dimensions();
        if !(1..=PHONETIC_VECTOR_MAX_DIMENSIONS).contains(&dimensions) {
            return Err(Error::InvalidConfig(format!(
                "a phonetic embedder's width must be 1..={PHONETIC_VECTOR_MAX_DIMENSIONS}, not \
                 {dimensions}"
            )));
        }
        let model = model_key(embedder.model_id(), dimensions);
        let mut report = PhoneticEmbedReport::default();
        let (pending, dropped) = {
            let rtxn = self.store.env.read_txn()?;
            self.phonetic_backlog_in_txn(&rtxn, model, max_names, &mut report)?
        };
        let pending =
            self.phonetic_names_released(pending, egress, &embedder.endpoint(), &mut report)?;
        if pending.is_empty() && dropped.is_empty() {
            return Ok(report);
        }
        let vectors = embed_checked(embedder, &pending, dimensions)?;
        self.store_phonetic_vectors(model, &pending, vectors, &dropped, &mut report)?;
        Ok(report)
    }

    /// Stores `vectors` for `pending` and drops `dropped` in one write, each only while its
    /// entity still has the name: one that left while the model ran lands no vector and is
    /// counted vanished.
    fn store_phonetic_vectors(
        &self,
        model: [u8; 16],
        pending: &[PendingName],
        vectors: Vec<Vec<f32>>,
        dropped: &[(EntityId, [u8; 16])],
        report: &mut PhoneticEmbedReport,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut current: BTreeMap<EntityId, BTreeSet<[u8; 16]>> = BTreeMap::new();
        for id in pending
            .iter()
            .map(|item| item.id)
            .chain(dropped.iter().map(|(id, _)| *id))
        {
            if let std::collections::btree_map::Entry::Vacant(entry) = current.entry(id) {
                let (names, _) = capped_names(self.phonetic_names_in_txn(&wtxn, &id)?);
                entry.insert(names.iter().map(String::as_str).map(name_key).collect());
            }
        }
        let holds =
            |id: &EntityId, key: &[u8; 16]| current.get(id).is_some_and(|keys| keys.contains(key));
        for (id, key) in dropped {
            if !holds(id, key)
                && LEARNED_VECTOR
                    .get(&self.store, &wtxn, &(*id, *key))?
                    .is_some()
            {
                LEARNED_VECTOR.delete(&self.store, &mut wtxn, &(*id, *key))?;
                report.removed += 1;
            }
        }
        for (item, vector) in pending.iter().zip(vectors) {
            if !holds(&item.id, &item.key) {
                report.vanished += 1;
                continue;
            }
            let key = (item.id, item.key);
            if LEARNED_VECTOR
                .get(&self.store, &wtxn, &key)?
                .is_some_and(|old| old.model != model)
            {
                report.removed += 1;
            }
            let row = LearnedVectorRow {
                model,
                row: encode_vector_row_v1(&vector)?,
            };
            LEARNED_VECTOR.put(&self.store, &mut wtxn, &key, &row)?;
            report.embedded += 1;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Up to `max_names` names of the named entities in `txn` that lack a vector of `model`,
    /// in scan order, and every stored vector of a name its entity no longer has; `report`
    /// counts what the scan read.
    fn phonetic_backlog_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        model: [u8; 16],
        max_names: usize,
        report: &mut PhoneticEmbedReport,
    ) -> Result<(Vec<PendingName>, Vec<(EntityId, [u8; 16])>)> {
        let mut pending = Vec::new();
        let mut dropped = Vec::new();
        for entity_type in NAMED_ENTITY_TYPES {
            for id in self.store.port_entity_ids_by_type(txn, entity_type, None)? {
                if pending.len() >= max_names {
                    return Ok((pending, dropped));
                }
                let id = id?;
                report.scanned += 1;
                let (names, over_cap) = capped_names(self.phonetic_names_in_txn(txn, &id)?);
                report.over_name_cap += over_cap;
                let keys: BTreeSet<[u8; 16]> =
                    names.iter().map(String::as_str).map(name_key).collect();
                let mut held = BTreeMap::new();
                for row in LEARNED_VECTOR.iter_from(&self.store, txn, id.as_bytes())? {
                    let ((_, key), row) = row?;
                    held.insert(key, row.model);
                }
                dropped.extend(
                    held.keys()
                        .filter(|key| !keys.contains(*key))
                        .map(|key| (id, *key)),
                );
                for name in names {
                    let key = name_key(&name);
                    if held.get(&key) == Some(&model) {
                        report.unchanged += 1;
                    } else if pending.len() < max_names {
                        pending.push(PendingName { id, name, key });
                    }
                }
            }
        }
        Ok((pending, dropped))
    }

    /// The names of `id` at the revision the code rung publishes
    /// ([`ReadMode::Indexed`]): none for a record that is gone, withdrawn or unreadable.
    fn phonetic_names_in_txn(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<String>> {
        let Some(raw) = read_entity_revision_in_txn(self, txn, id, ReadMode::Indexed)? else {
            return Ok(Vec::new());
        };
        let (Some(header), Some(body)) = (
            EntityMetadataHeader::parse(&raw),
            raw.get(ENTITY_METADATA_HEADER_LEN..),
        ) else {
            return Ok(Vec::new());
        };
        Ok(names_for_body(header.entity_type, body))
    }

    /// The names of `pending` that may leave toward `destination` now: all of them with no
    /// gate; with one, those it allows whose entity no device-local world keeps, read right
    /// before they go. The rest are counted withheld.
    fn phonetic_names_released(
        &self,
        pending: Vec<PendingName>,
        egress: Option<&dyn EgressPredicate>,
        destination: &ReadDestination,
        report: &mut PhoneticEmbedReport,
    ) -> Result<Vec<PendingName>> {
        let Some(egress) = egress else {
            return Ok(pending);
        };
        let mut entity_may_leave: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut released = Vec::with_capacity(pending.len());
        for item in pending {
            let rows = std::slice::from_ref(&item.id);
            let input = MediaEmbeddingInput {
                entity_id: item.id,
                kind: InputKind::Text,
                media_type: NAME_MEDIA_TYPE,
                bytes: item.name.as_bytes(),
                source_rows: Some(rows),
            };
            let allowed = egress.decide_media(&input) == EgressDecision::Allow
                && match entity_may_leave.get(&item.id) {
                    Some(may_leave) => *may_leave,
                    None => {
                        let may_leave = self.media_rows_may_leave(None, rows, destination)?;
                        entity_may_leave.insert(item.id, may_leave);
                        may_leave
                    }
                };
            if allowed {
                released.push(item);
            } else {
                report.withheld += 1;
            }
        }
        Ok(released)
    }
}

/// The gate a pass with `embedder` reads through: a third-party embedder's must be there, or
/// the pass is refused; one on the owner's server reads through the gate the host gives, or
/// ungated with none (FIX 9830); one on this device reads ungated. As the media backfill's.
fn phonetic_egress_for<'a>(
    embedder: &dyn PhoneticEmbedder,
    egress: Option<&'a dyn EgressPredicate>,
) -> Result<Option<&'a dyn EgressPredicate>> {
    match embedder.locality() {
        EmbedderLocality::OnDevice => Ok(None),
        EmbedderLocality::OwnerServer => Ok(egress),
        EmbedderLocality::ThirdParty => egress.map(Some).ok_or_else(|| {
            Error::InvalidConfig(
                "a third-party phonetic embedder has no egress grant for entity names".into(),
            )
        }),
    }
}

/// The first [`NAMES_PER_ENTITY_CAP`] of `names`, and how many were past it.
fn capped_names(mut names: Vec<String>) -> (Vec<String>, usize) {
    let over_cap = names.len().saturating_sub(NAMES_PER_ENTITY_CAP);
    names.truncate(NAMES_PER_ENTITY_CAP);
    (names, over_cap)
}

/// `embedder`'s vectors for `pending`, one each, of its width and finite.
fn embed_checked(
    embedder: &dyn PhoneticEmbedder,
    pending: &[PendingName],
    dimensions: usize,
) -> Result<Vec<Vec<f32>>> {
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<&str> = pending.iter().map(|item| item.name.as_str()).collect();
    let vectors = embedder.embed_names(&names)?;
    if vectors.len() != names.len() {
        return Err(Error::InvalidConfig(format!(
            "the phonetic embedder returned {} vectors for {} names",
            vectors.len(),
            names.len()
        )));
    }
    for vector in &vectors {
        if vector.len() != dimensions {
            return Err(Error::DimensionMismatch {
                expected: dimensions,
                got: vector.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(vector) {
            return Err(error);
        }
    }
    Ok(vectors)
}
