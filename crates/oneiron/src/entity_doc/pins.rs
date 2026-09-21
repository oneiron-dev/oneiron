//! Causal citation floors, retained quotes and the owner's shallow-purge door.

use super::document::decode_frontier;
use super::{DocAuthorization, EntityDoc, ForkStatus, TextAnchor, invalid, storage};
use crate::error::{ArtifactError, Error, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use heed::RoTxn;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// A citation names the document, causal frontier, cursor span and quote hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitationPin {
    pub citation: String,
    pub entity: String,
    pub document: String,
    pub anchor: TextAnchor,
    pub actor: String,
}

/// Unmappable cursors keep both the quote and the original frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorResolution {
    Live {
        start: usize,
        end: usize,
        quote: String,
    },
    Drifted {
        origin: TextAnchor,
    },
}

/// Durable proof that one explicit owner action discarded only safe history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeReceipt {
    pub receipt: String,
    pub entity: String,
    pub document: String,
    pub actor: String,
    pub requested: Vec<u8>,
    pub applied: Vec<u8>,
    pub at: u64,
    pub live_text_hash: [u8; 32],
}

fn pin_prefix(entity: &EntityId) -> String {
    format!("entity_doc:v1:pin:{}:", entity.to_hex())
}
fn purge_prefix(entity: &EntityId) -> String {
    format!("entity_doc:v1:purge:{}:", entity.to_hex())
}

fn pins(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Vec<CitationPin>> {
    vault
        .store
        .sync_state
        .prefix_iter(txn, &pin_prefix(entity))?
        .map(|row| {
            let (_, bytes) = row?;
            storage::decode(&bytes)
        })
        .collect()
}

impl Vault {
    /// Installs an immutable citation pin. Its quote is checked against its
    /// actual origin version, not just a caller-supplied hash or sequence number.
    pub fn pin_entity_text(
        &self,
        citation: &EntityId,
        entity: &EntityId,
        anchor: &TextAnchor,
        authorization: &DocAuthorization<'_>,
        actor: WriteActor,
    ) -> Result<CitationPin> {
        self.with_write_txn(|txn| {
            super::forks::authorize(self, txn, authorization, entity, actor)?;
            let h = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &h)?;
            let origin = doc.fork(&anchor.frontier)?;
            let (start, end) = super::verbs::resolve(&origin, *entity, anchor)?;
            let quote: String = origin
                .text()
                .chars()
                .skip(start)
                .take(end - start)
                .collect();
            if quote != anchor.quote || blake3::hash(quote.as_bytes()).as_bytes() != &anchor.hash {
                return Err(invalid("citation quote does not match pinned version"));
            }
            let pin = CitationPin {
                citation: citation.to_hex(),
                entity: entity.to_hex(),
                document: h.document,
                anchor: anchor.clone(),
                actor: actor.entity_ref().to_hex(),
            };
            let key = format!("{}{}", pin_prefix(entity), citation.to_hex());
            if let Some(raw) = self.store.sync_state.get(txn, &key)? {
                let prior: CitationPin = storage::decode(&raw)?;
                if prior != pin {
                    return Err(invalid("citation pin is immutable"));
                }
                return Ok(prior);
            }
            self.store
                .sync_state
                .put(txn, &key, &storage::encode(&pin)?)?;
            Ok(pin)
        })
    }

    /// Returns the unique causally oldest citation. Concurrent incomparable
    /// pins have no scalar oldest; callers use `entity_text_pin_floor` instead.
    pub fn oldest_entity_text_pin(&self, entity: &EntityId) -> Result<Option<CitationPin>> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let all = pins(self, &txn, entity)?;
        for candidate in &all {
            let front = decode_frontier(&candidate.anchor.frontier)?;
            if all.iter().all(|other| {
                decode_frontier(&other.anchor.frontier)
                    .ok()
                    .is_some_and(|f| {
                        matches!(
                            doc.doc.cmp_frontiers(&front, &f),
                            Ok(Some(Ordering::Less | Ordering::Equal))
                        )
                    })
            }) {
                return Ok(Some(candidate.clone()));
            }
        }
        if all.is_empty() {
            Ok(None)
        } else {
            Err(invalid(
                "citation pins are causally incomparable; use the floor",
            ))
        }
    }

    /// Computes a causal meet of citations, settlement receipts and live fork
    /// bases. Vector clocks are intersected; encoded frontier bytes are never
    /// sorted as if they were numeric revisions.
    pub fn entity_text_pin_floor(&self, entity: &EntityId) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        floor(self, &txn, entity, &doc, &doc.frontier())
    }

    /// Refuses a requested history drop beyond any pin. An equal frontier is
    /// safe: Loro keeps that frontier's complete state, dropping only predecessors.
    pub fn check_entity_text_purge(&self, entity: &EntityId, requested: &[u8]) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let allowed = floor(self, &txn, entity, &doc, requested)?;
        if decode_frontier(&allowed)? != decode_frontier(requested)? {
            return Err(invalid("history drop crosses a document pin"));
        }
        Ok(())
    }

    /// Resolves a stable cursor against the live document. A purge cannot turn
    /// missing history into an arbitrary new quote or silently move its origin.
    pub fn resolve_entity_text_cursor(
        &self,
        entity: &EntityId,
        anchor: &TextAnchor,
    ) -> Result<CursorResolution> {
        if anchor.entity != entity.to_hex() {
            return Err(invalid("anchor belongs to another entity"));
        }
        self.read_entity_doc(entity, |doc| {
            match super::verbs::resolve(doc, *entity, anchor) {
                Ok((start, end)) => {
                    let quote: String = doc.text().chars().skip(start).take(end - start).collect();
                    if quote == anchor.quote {
                        CursorResolution::Live { start, end, quote }
                    } else {
                        CursorResolution::Drifted {
                            origin: anchor.clone(),
                        }
                    }
                }
                Err(_) => CursorResolution::Drifted {
                    origin: anchor.clone(),
                },
            }
        })
    }

    /// Owner-only history destruction. No policy/standing grant can call this
    /// door. The registry lock excludes concurrent local edits; all durable
    /// state is loaded, clamped, replaced and receipted in ONE write transaction.
    /// Cache entries are invalidated only after that transaction commits.
    pub fn purge_entity_text_history(
        &self,
        entity: &EntityId,
        requested: &[u8],
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<PurgeReceipt> {
        let DocAuthorization::Owner(owner) = authorization else {
            return Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
                "document purge requires the authenticated owner",
            )));
        };
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let receipt = self.with_write_txn(|txn| {
            super::forks::owner_in_txn(self, txn, owner)?;
            let mut h = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &h)?;
            let applied = floor(self, txn, entity, &doc, requested)?;
            let old_state = doc.text();
            let bytes = doc.shallow_snapshot(&applied)?;
            let shallow = EntityDoc::from_snapshot(&bytes)?;
            if shallow.text() != old_state || shallow.doc.oplog_vv() != doc.doc.oplog_vv() {
                return Err(Error::InvariantViolation(
                    "shallow purge changed live state",
                ));
            }
            for pin in pins(self, txn, entity)? {
                let old = doc.fork(&pin.anchor.frontier)?.text();
                if shallow.fork(&pin.anchor.frontier)?.text() != old {
                    return Err(Error::InvariantViolation(
                        "shallow purge changed a pinned version",
                    ));
                }
            }
            storage::persist(self, txn, entity, &mut h, &shallow, None)?;
            self.store.sync_state.put(
                txn,
                &format!("ssv:e:{}", h.document),
                &shallow.doc.shallow_since_vv().encode(),
            )?;
            let receipt = PurgeReceipt {
                receipt: EntityId::now().to_hex(),
                entity: entity.to_hex(),
                document: h.document,
                actor: owner.actor().to_hex(),
                requested: requested.to_vec(),
                applied,
                at,
                live_text_hash: *blake3::hash(old_state.as_bytes()).as_bytes(),
            };
            self.store.sync_state.put(
                txn,
                &format!("{}{}", purge_prefix(entity), receipt.receipt),
                &storage::encode(&receipt)?,
            )?;
            Ok(receipt)
        })?;
        registry.remove(entity);
        Ok(receipt)
    }

    /// Reads the version at a pin, even after an allowed owner purge.
    pub fn entity_text_at(&self, entity: &EntityId, frontier: &[u8]) -> Result<String> {
        self.read_entity_doc(entity, |doc| doc.fork(frontier).map(|fork| fork.text()))?
    }

    /// Lists durable owner-purge receipts for an entity.
    pub fn entity_text_purge_receipts(&self, entity: &EntityId) -> Result<Vec<PurgeReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .sync_state
            .prefix_iter(&txn, &purge_prefix(entity))?
            .map(|row| {
                let (_, bytes) = row?;
                storage::decode(&bytes)
            })
            .collect()
    }
}

fn floor(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    doc: &EntityDoc,
    requested: &[u8],
) -> Result<Vec<u8>> {
    let target = decode_frontier(requested)?;
    let mut allowed = doc
        .doc
        .frontiers_to_vv(&target)
        .ok_or(invalid("purge frontier unavailable"))?;
    let mut protected: Vec<Vec<u8>> = pins(vault, txn, entity)?
        .into_iter()
        .map(|pin| pin.anchor.frontier)
        .collect();
    for receipt in super::forks::receipts(&vault.store, txn, entity)? {
        protected.push(receipt.before);
        protected.push(receipt.after);
    }
    for fork in super::forks::all_forks(&vault.store, txn, entity)? {
        if fork.status == ForkStatus::Pending {
            protected.push(fork.base);
        }
    }
    for row in vault
        .store
        .sync_state
        .prefix_iter(txn, &purge_prefix(entity))?
    {
        let (_, bytes) = row?;
        let receipt: PurgeReceipt = storage::decode(&bytes)?;
        protected.push(receipt.applied);
    }
    for pin in protected {
        let f = decode_frontier(&pin)?;
        let vv = doc
            .doc
            .frontiers_to_vv(&f)
            .ok_or(invalid("pin frontier unavailable"))?;
        allowed = allowed.intersection(&vv);
    }
    let current_floor = doc.doc.shallow_since_vv().to_vv();
    if !allowed.includes_vv(&current_floor) {
        return Err(invalid("pin predates retained document history"));
    }
    let frontier = doc.doc.vv_to_frontiers(&allowed);
    if frontier.is_empty() {
        return Err(invalid("no common retained purge frontier"));
    }
    Ok(frontier.encode())
}
