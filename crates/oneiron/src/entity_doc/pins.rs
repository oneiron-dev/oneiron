//! Causal citation floors, retained quotes and the owner's shallow-purge door.

use super::document::decode_frontier;
use super::side_keys::HexPair;
use super::{DocAuthorization, EntityDoc, ForkStatus, TextAnchor, invalid, storage};
use crate::EdgeActorClass;
use crate::consent::AuthenticatedOwner;
use crate::error::{ArtifactError, Error, Result};
use crate::memory::MemoryResult;
use crate::ports::{DocumentRowStore, DocumentSlot};
use crate::side_table::{self, HexId, Named, SideTable};
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

#[cfg(feature = "sync")]
impl CitationPin {
    /// The quoted entity and the citing record, when the pin is whole: its
    /// ids each in their one spelling, its anchor on its own entity at a
    /// version that decodes, and a nonempty quote its hash proves (FIX 853).
    pub(crate) fn carried_ids(&self) -> Option<(EntityId, EntityId)> {
        let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
        let entity = named(&self.entity)?;
        let citation = named(&self.citation)?;
        named(&self.document)?;
        named(&self.actor)?;
        let anchor = &self.anchor;
        let whole = anchor.entity == self.entity
            && !anchor.quote.is_empty()
            && blake3::hash(anchor.quote.as_bytes()).as_bytes() == &anchor.hash
            && decode_frontier(&anchor.frontier).is_ok()
            && loro::cursor::Cursor::decode(&anchor.start).is_ok()
            && loro::cursor::Cursor::decode(&anchor.end).is_ok();
        whole.then_some((entity, citation))
    }
}

/// What merging one pin a window carried did (FIX 853).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinMerge {
    /// The pin was new here, and is held now.
    Written,
    /// This vault already held the same pin.
    Held,
    /// This vault holds another pin for the same quote, and it stands.
    Conflict,
    /// The pin does not merge here.
    Refused(&'static str),
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

/// Immutable citation pin binding a quoted span to its exact causal frontier,
/// keyed by entity then citation id.
pub(super) const ENTITY_DOC_PIN: SideTable<HexPair, CitationPin, Named> =
    SideTable::new(&side_table::ENTITY_DOC_PIN);
/// Durable proof of one owner-authorized shallow history purge, keyed by
/// entity then receipt id.
pub(super) const ENTITY_DOC_PURGE_RECEIPT: SideTable<HexPair, PurgeReceipt, Named> =
    SideTable::new(&side_table::ENTITY_DOC_PURGE_RECEIPT);

fn pins(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Vec<CitationPin>> {
    Ok(ENTITY_DOC_PIN
        .scan_from(
            &vault.store,
            txn,
            format!("{}:", entity.to_hex()).as_bytes(),
        )?
        .into_iter()
        .map(|(_, pin)| pin)
        .collect())
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
        self.with_write_txn_grouped(|txn| {
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
            let key = HexPair(HexId(*entity), HexId(*citation));
            if let Some(prior) = ENTITY_DOC_PIN.get(&self.store, txn, &key)? {
                if prior != pin {
                    return Err(invalid("citation pin is immutable"));
                }
                return Ok(prior);
            }
            ENTITY_DOC_PIN.put(&self.store, txn, &key, &pin)?;
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

    /// Computes a causal meet of citations (pins and the citation floors of
    /// live citers), settlement receipts and live fork bases. Vector clocks
    /// are intersected; encoded frontier bytes are never sorted as if they
    /// were numeric revisions.
    pub fn entity_text_pin_floor(&self, entity: &EntityId) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        floor(self, &txn, entity, &h.incarnation, &doc, &doc.frontier())
    }

    /// Refuses a requested history drop beyond any pin. An equal frontier is
    /// safe: Loro keeps that frontier's complete state, dropping only predecessors.
    pub fn check_entity_text_purge(&self, entity: &EntityId, requested: &[u8]) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let allowed = floor(self, &txn, entity, &h.incarnation, &doc, requested)?;
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
    /// Cache entries are invalidated only after that transaction commits. A
    /// legal hold on the entity refuses it (OF-470). With two or more live
    /// Owners it runs only through the vault's `erase` veto window
    /// ([`Self::start_text_history_erase`], Docs Q05).
    pub fn purge_entity_text_history(
        &self,
        entity: &EntityId,
        requested: &[u8],
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<PurgeReceipt> {
        self.purge_entity_text_history_for(entity, requested, authorization, at, None)
    }

    /// [`Self::purge_entity_text_history`], claiming the completed `erase`
    /// act `act` in its writer when one admits it.
    pub(crate) fn purge_entity_text_history_for(
        &self,
        entity: &EntityId,
        requested: &[u8],
        authorization: &DocAuthorization<'_>,
        at: u64,
        act: Option<&str>,
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
        let receipt = self.with_write_txn_grouped(|txn| {
            let owner_actor = super::forks::owner_in_txn(self, txn, owner)?;
            // A held record keeps its history, and so does a pad whose world
            // or sealed claim is held (OF-470).
            self.store
                .reject_legal_hold_in_txn(txn, entity.as_bytes())?;
            crate::world_keys::reject_held_pad_world_in_txn(&self.store, txn, &[*entity])?;
            let receipt_id = EntityId::now();
            super::admit_history_erase_in_txn(
                self,
                txn,
                entity,
                Some(requested),
                act,
                &receipt_id,
            )?;
            let mut h = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &h)?;
            let applied = floor(self, txn, entity, &h.incarnation, &doc, requested)?;
            let old_state = doc.text();
            let bytes = doc.shallow_snapshot(&applied)?;
            let shallow = EntityDoc::from_snapshot(&bytes)?;
            if shallow.text() != old_state || shallow.doc.oplog_vv() != doc.doc.oplog_vv() {
                return Err(Error::InvariantViolation(
                    "shallow purge changed live state",
                ));
            }
            let cited =
                super::citation_floor::live_frontiers(&self.store, txn, entity, &h.incarnation)?;
            let pinned = pins(self, txn, entity)?
                .into_iter()
                .map(|pin| pin.anchor.frontier);
            for frontier in pinned.chain(cited) {
                let old = doc.fork(&frontier)?.text();
                if shallow.fork(&frontier)?.text() != old {
                    return Err(Error::InvariantViolation(
                        "shallow purge changed a pinned version",
                    ));
                }
            }
            storage::persist(self, txn, entity, &mut h, &shallow, None)?;
            self.store.port_document_shallow_since_put(
                txn,
                DocumentSlot::from_hex(&h.document)?,
                &shallow.doc.shallow_since_vv().encode(),
            )?;
            let receipt = PurgeReceipt {
                receipt: receipt_id.to_hex(),
                entity: entity.to_hex(),
                document: h.document,
                actor: owner_actor.to_hex(),
                requested: requested.to_vec(),
                applied,
                at,
                live_text_hash: *blake3::hash(old_state.as_bytes()).as_bytes(),
            };
            ENTITY_DOC_PURGE_RECEIPT.put(
                &self.store,
                txn,
                &HexPair(HexId(*entity), HexId(receipt_id)),
                &receipt,
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
        Ok(ENTITY_DOC_PURGE_RECEIPT
            .scan_from(
                &self.store,
                &txn,
                format!("{}:", entity.to_hex()).as_bytes(),
            )?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }

    /// Files one owner history-purge receipt for `entity`. A NOTE's purge
    /// lands here beside the entity-text ones, so one list reads both.
    pub(crate) fn put_text_purge_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        id: EntityId,
        receipt: &PurgeReceipt,
    ) -> Result<()> {
        ENTITY_DOC_PURGE_RECEIPT.put(
            &self.store,
            txn,
            &HexPair(HexId(*entity), HexId(id)),
            receipt,
        )
    }

    /// The owner's "erase history" (ARCH-0038: a purge reads as erase): drops
    /// an entity's text history below its oldest pin, as the authenticated
    /// `owner`; no Grant reaches it. A NOTE goes through
    /// [`crate::memory::Memory::purge_note_history_as`]. Any other entity's
    /// text goes through [`Self::purge_entity_text_history`], which clamps
    /// `through` (the head when absent) to the pin floor. A shared vault with
    /// two or more live Owners refuses it: its erase waits on the `erase`
    /// veto window through [`Self::start_text_history_erase`] (Docs Q05).
    pub fn erase_text_history_as(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        through: Option<&[u8]>,
    ) -> MemoryResult<PurgeReceipt> {
        if entity_type(self, entity)? == Some(crate::registry::ENTITY_TYPE_NOTE) {
            let actor = owner.revalidate(self)?;
            return self
                .memory(actor, EdgeActorClass::Human)
                .purge_note_history_as(owner, *entity, through);
        }
        let through = match through {
            Some(bytes) => bytes.to_vec(),
            None => self.read_entity_doc(entity, EntityDoc::frontier)?,
        };
        Ok(self.purge_entity_text_history(
            entity,
            &through,
            &DocAuthorization::Owner(owner),
            self.now_recorded_at(),
        )?)
    }
}

impl Vault {
    /// Pins a quoted span of a MESSAGE that owns a document, inside the
    /// caller's write transaction: the conversation reply door's quote.
    /// `start..end` is a half-open range of Unicode scalar values, the index
    /// space of the document's text API, so it becomes stable cursors at the
    /// current frontier unconverted and is not kept. The quote is proven
    /// against that version as [`Self::pin_entity_text`] proves one. A quote
    /// adds no text operation, so it asks no edit grant: the reply door has
    /// already admitted `actor` to the message's room.
    pub(crate) fn pin_message_quote_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        citation: &EntityId,
        message: &EntityId,
        start: usize,
        end: usize,
        actor: WriteActor,
    ) -> Result<CitationPin> {
        super::forks::validate_actor(self, txn, actor)?;
        let is_message = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, message)?
            .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_MESSAGE);
        let h = storage::head(&self.store, txn, message)?;
        if !is_message || h.field != super::TextField::MapField("content".to_owned()) {
            return Err(invalid("quote pin requires a MESSAGE document"));
        }
        if start >= end {
            return Err(invalid("quote span is empty"));
        }
        let doc = storage::load(&self.store, txn, &h)?;
        let anchor = super::verbs::make_anchor(&doc, *message, start, end)?;
        let origin = doc.fork(&anchor.frontier)?;
        let (from, to) = super::verbs::resolve(&origin, *message, &anchor)?;
        let quote: String = origin.text().chars().skip(from).take(to - from).collect();
        if quote.is_empty()
            || quote != anchor.quote
            || blake3::hash(quote.as_bytes()).as_bytes() != &anchor.hash
        {
            return Err(invalid("citation quote does not match pinned version"));
        }
        let key = HexPair(HexId(*message), HexId(*citation));
        if ENTITY_DOC_PIN.contains(&self.store, txn, &key)? {
            return Err(invalid("citation pin is immutable"));
        }
        let pin = CitationPin {
            citation: citation.to_hex(),
            entity: message.to_hex(),
            document: h.document,
            anchor,
            actor: actor.entity_ref().to_hex(),
        };
        ENTITY_DOC_PIN.put(&self.store, txn, &key, &pin)?;
        // The pin rides beside the message (FIX 853): the live mirror takes
        // it into the loaded window that carries the message.
        #[cfg(feature = "sync")]
        crate::batch::queue_committed_rows(self, txn, std::iter::once(*message).collect());
        Ok(pin)
    }

    /// The citation pin `citation` holds on `message`, in the caller's snapshot.
    pub(crate) fn message_quote_pin_in_txn(
        &self,
        txn: &RoTxn<'_>,
        message: &EntityId,
        citation: &EntityId,
    ) -> Result<Option<CitationPin>> {
        ENTITY_DOC_PIN.get(
            &self.store,
            txn,
            &HexPair(HexId(*message), HexId(*citation)),
        )
    }

    /// Every citation pin held on `message`, in the caller's snapshot.
    #[cfg(feature = "sync")]
    pub(crate) fn message_quote_pins_in_txn(
        &self,
        txn: &RoTxn<'_>,
        message: &EntityId,
    ) -> Result<Vec<CitationPin>> {
        pins(self, txn, message)
    }

    /// Installs `pin`, which a window brought from another of the owner's
    /// machines, in the caller's write transaction (FIX 853). A pin is
    /// written once: an equal one is held, and a different one for the same
    /// quote leaves the one held here standing. Erase wins: a pin of a
    /// message or reply this vault erased is refused. Where this vault holds
    /// the message's document, the pin must quote it at its version, as
    /// [`Self::pin_entity_text`] proves one. Where it holds none, the pin
    /// stands on its own quote.
    #[cfg(feature = "sync")]
    pub(crate) fn merge_replicated_quote_pin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        pin: &CitationPin,
    ) -> Result<PinMerge> {
        let Some((message, citation)) = pin.carried_ids() else {
            return Ok(PinMerge::Refused("not a whole pin"));
        };
        for id in [message, citation] {
            if crate::ports::removed_in_txn(&self.store, txn, &id)? {
                return Ok(PinMerge::Refused("erased here"));
            }
        }
        let key = HexPair(HexId(message), HexId(citation));
        if let Some(prior) = ENTITY_DOC_PIN.get(&self.store, txn, &key)? {
            return Ok(if prior == *pin {
                PinMerge::Held
            } else {
                PinMerge::Conflict
            });
        }
        let entity_type =
            crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &message)?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .map(|header| header.entity_type);
        if entity_type.is_some_and(|kind| kind != crate::registry::ENTITY_TYPE_MESSAGE) {
            return Ok(PinMerge::Refused("quotes no MESSAGE"));
        }
        if storage::has_record_head(&self.store, txn, &message)?
            && !quotes_document(self, txn, &message, pin)
        {
            return Ok(PinMerge::Refused("does not quote this vault's document"));
        }
        ENTITY_DOC_PIN.put(&self.store, txn, &key, pin)?;
        Ok(PinMerge::Written)
    }
}

/// Whether `pin` quotes `entity`'s document as this vault holds it: the
/// document retains its version, and its span there reads its quote.
#[cfg(feature = "sync")]
fn quotes_document(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId, pin: &CitationPin) -> bool {
    let proven = || -> Result<bool> {
        let h = storage::head(&vault.store, txn, entity)?;
        let doc = storage::load(&vault.store, txn, &h)?;
        let origin = doc.fork(&pin.anchor.frontier)?;
        let (start, end) = super::verbs::resolve(&origin, *entity, &pin.anchor)?;
        let quote: String = origin
            .text()
            .chars()
            .skip(start)
            .take(end - start)
            .collect();
        Ok(quote == pin.anchor.quote)
    };
    proven().unwrap_or(false)
}

pub(super) fn entity_type(vault: &Vault, entity: &EntityId) -> Result<Option<u8>> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, entity)?
            .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
            .map(|header| header.entity_type),
    )
}

fn floor(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    incarnation: &str,
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
    protected.extend(super::citation_floor::live_frontiers(
        &vault.store,
        txn,
        entity,
        incarnation,
    )?);
    for receipt in super::forks::receipts(&vault.store, txn, entity)? {
        protected.push(receipt.before);
        protected.push(receipt.after);
    }
    for fork in super::forks::all_forks(&vault.store, txn, entity)? {
        if fork.status == ForkStatus::Pending {
            protected.push(fork.base);
        }
    }
    for (_, receipt) in ENTITY_DOC_PURGE_RECEIPT.scan_from(
        &vault.store,
        txn,
        format!("{}:", entity.to_hex()).as_bytes(),
    )? {
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
