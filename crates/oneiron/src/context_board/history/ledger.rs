//! Board turn anchors reference one CRDT frontier; facts remain CLAIM rows.

use super::claims::{PREDICATES, decode_value, sets, validate_board_claim, value};
use super::types::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    decode_claim_body,
};
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, LoroDoc, LoroValue, ValueOrContainer};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, BoardHistoryError>;
const DOC: &[u8] = b"board_history:doc:";
const TURN: &[u8] = b"board_history:turn:";
const LAST: &[u8] = b"board_history:last:";
const CLAIM_FRONTIER: &[u8] = b"board_history:claim_frontier:";
const HORIZON: &[u8] = b"board_history:horizon:";

fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}

fn map_bytes(doc: &LoroDoc, map: &str, name: &str) -> Result<Option<Vec<u8>>> {
    match doc.get_map(map).get(name) {
        None => Ok(None),
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Ok(Some(bytes.to_vec())),
        _ => Err(BoardHistoryError::MissingFrontier),
    }
}

fn map_insert(doc: &LoroDoc, map: &str, name: &str, bytes: &[u8]) -> Result<()> {
    doc.get_map(map)
        .insert(name, bytes)
        .map_err(|_| BoardHistoryError::MissingFrontier)?;
    Ok(())
}

fn reference(owner: &EntityId, frontier: &[u8]) -> RevisionRef {
    let mut hash = blake3::Hasher::new();
    hash.update(owner.as_bytes());
    hash.update(frontier);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    RevisionRef(bytes)
}

fn load_doc(vault: &Vault, txn: &RoTxn<'_>, owner: &EntityId) -> Result<LoroDoc> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, &key(DOC, owner))?
        .ok_or(BoardHistoryError::MissingFrontier)?;
    LoroDoc::from_snapshot(&raw).map_err(|_| BoardHistoryError::MissingFrontier)
}

fn claim(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<(ClaimBody, EntityMetadataHeader)> {
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(BoardHistoryError::MissingFrontier)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(BoardHistoryError::MissingFrontier)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(BoardHistoryError::MissingFrontier);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    validate_board_claim(&body)?;
    let (_, writing_frontier) = decode_value(&body.value)?;
    // Unchanged families reuse earlier claims. Authenticate each claim's
    // writing frontier at every read/write door, not the requesting turn.
    if vault
        .store
        .vault_meta
        .get(txn, &key(CLAIM_FRONTIER, id))?
        .as_deref()
        != Some(writing_frontier.0.as_slice())
    {
        return Err(BoardHistoryError::MissingFrontier);
    }
    Ok((body, header))
}

fn id_from(bytes: &[u8]) -> Result<EntityId> {
    EntityId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| BoardHistoryError::MissingFrontier)?,
    )
    .map_err(Into::into)
}

fn selection_hash(items: &std::collections::BTreeSet<EntityId>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    for id in items {
        hash.update(id.as_bytes());
    }
    *hash.finalize().as_bytes()
}

fn validate_selection(selection: &BoardSelection) -> Result<()> {
    if !selection.active.is_subset(&selection.allowed)
        || !selection.default_on.is_subset(&selection.allowed)
    {
        return Err(BoardHistoryError::InvalidSelection(
            "active and default_on must be subsets of allowed",
        ));
    }
    if sets(selection)
        .into_iter()
        .any(|persisted| !persisted.is_disjoint(&selection.index_only))
    {
        return Err(BoardHistoryError::InvalidSelection(
            "index-only activations cannot be persistent",
        ));
    }
    Ok(())
}

impl Vault {
    /// Commits only changed selection families through the reserved claim door.
    /// The TURN extension holds one singular frontier ref, not a snapshot or a
    /// per-turn list of revision ids. Index-only activations are never recorded.
    pub fn record_board_turn(
        &self,
        input: &BoardTurn,
        learned_at: u64,
    ) -> Result<BoardTurnReceipt> {
        validate_selection(&input.selection)?;
        let mut txn = self.store.env.write_txn()?;
        let turn_raw = crate::vault::entity_revision::read_entity_revision_in_txn(
            self,
            &txn,
            &input.turn,
            ReadMode::Live,
        )?
        .ok_or(Error::EntityNotFound)?;
        crate::vault::entity_revision::read_entity_revision_in_txn(
            self,
            &txn,
            &input.owner,
            ReadMode::Live,
        )?
        .ok_or(Error::EntityNotFound)?;
        let turn_header =
            EntityMetadataHeader::parse(&turn_raw).ok_or(Error::CorruptedIndex("turn header"))?;
        if turn_header.entity_type != crate::registry::ENTITY_TYPE_TURN {
            return Err(BoardHistoryError::InvalidSelection(
                "anchor must name a TURN",
            ));
        }
        if self
            .store
            .vault_meta
            .get(&txn, &key(TURN, &input.turn))?
            .is_some()
        {
            return Err(BoardHistoryError::InvalidSelection(
                "turn is already anchored",
            ));
        }
        if let Some(last) = self.store.vault_meta.get(&txn, &key(LAST, &input.owner))? {
            let last: (u64, u64) =
                rmp_serde::from_slice(&last).map_err(|_| BoardHistoryError::MissingFrontier)?;
            if input.at <= last.0 || learned_at < last.1 {
                return Err(BoardHistoryError::InvalidSelection(
                    "turn and learned time must advance monotonically",
                ));
            }
        }
        let doc = if self
            .store
            .vault_meta
            .get(&txn, &key(DOC, &input.owner))?
            .is_some()
        {
            load_doc(self, &txn, &input.owner)?
        } else {
            LoroDoc::new()
        };
        let mut changes = Vec::new();
        for (predicate, selected) in PREDICATES.iter().zip(sets(&input.selection)) {
            let old_id = map_bytes(&doc, "claims", predicate)?
                .map(|raw| id_from(raw.get(..16).ok_or(BoardHistoryError::MissingFrontier)?))
                .transpose()?;
            if let Some(id) = old_id {
                let (body, _) = claim(self, &txn, &id)?;
                if decode_value(&body.value)?.0 == *selected {
                    continue;
                }
            } else if selected.is_empty() {
                continue;
            }
            let next = EntityId::now();
            let mut claim_ref = next.as_bytes().to_vec();
            claim_ref.extend_from_slice(&selection_hash(selected));
            map_insert(&doc, "claims", predicate, &claim_ref)?;
            changes.push((*predicate, selected, old_id, next));
        }
        // Retained document pointers are CRDT map entries, updated only when
        // a text frontier changes. No board bytes or rendered text are stored.
        let all = sets(&input.selection)
            .into_iter()
            .flat_map(|set| set.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        let actor = crate::claim::ScopedReadActorKey::new(input.owner.to_hex())
            .ok_or(BoardHistoryError::InvalidSelection("invalid owner"))?;
        let scoped = self.scoped_read(actor);
        for id in all {
            let live = crate::vault::entity_revision::read_entity_revision_in_txn(
                self,
                &txn,
                &id,
                ReadMode::Live,
            )?
            .ok_or(BoardHistoryError::UnreadableDocument(id))?;
            if live[0] == crate::registry::ENTITY_TYPE_CLAIM
                && !scoped.is_claim_raw_readable_in(&txn, &id, &live)?
            {
                return Err(BoardHistoryError::UnreadableDocument(id));
            }
            let (revision, _) =
                crate::vault::entity_revision::ensure_document(self, &mut txn, &id)?;
            map_insert(&doc, "documents", &id.to_hex(), &revision.0)?;
        }
        doc.commit();
        let frontier = doc.oplog_frontiers().encode();
        let anchor_ref = reference(&input.owner, &frontier);
        let mut changed_claims = Vec::new();
        for (predicate, selected, old, id) in changes {
            if let Some(old) = old {
                let (mut previous, header) = claim(self, &txn, &old)?;
                previous.valid_to = Some(input.at - 1);
                self.put_reserved_claim_in_txn(
                    &mut txn,
                    &old,
                    &previous,
                    TimeRange {
                        start: previous.valid_from.unwrap_or(header.occurred_start),
                        end: input.at - 1,
                    },
                    header.learned_at,
                )?;
            }
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(input.owner),
                value(selected, anchor_ref),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.valid_from = Some(input.at);
            body.source = Some(ClaimSource::Observed);
            self.put_reserved_claim_in_txn(
                &mut txn,
                &id,
                &body,
                TimeRange {
                    start: input.at,
                    end: u64::MAX,
                },
                learned_at,
            )?;
            self.store
                .vault_meta
                .put(&mut txn, &key(CLAIM_FRONTIER, &id), &anchor_ref.0)?;
            changed_claims.push(id);
        }
        let anchor = TurnAnchor {
            owner: input.owner,
            at: input.at,
            learned_at,
            source_revision_ref: anchor_ref,
            frontier,
        };
        write_anchor(self, &mut txn, &input.turn, &anchor)?;
        let snapshot = doc
            .export(ExportMode::Snapshot)
            .map_err(|_| BoardHistoryError::MissingFrontier)?;
        self.store
            .vault_meta
            .put(&mut txn, &key(DOC, &input.owner), &snapshot)?;
        let last = rmp_serde::to_vec(&(input.at, learned_at))
            .map_err(|_| BoardHistoryError::MissingFrontier)?;
        self.store
            .vault_meta
            .put(&mut txn, &key(LAST, &input.owner), &last)?;
        txn.commit()?;
        Ok(BoardTurnReceipt {
            turn: input.turn,
            source_revision_ref: anchor_ref,
            changed_claims,
        })
    }

    /// Folds valid bitemporal claims from the TURN's exact CRDT frontier.
    /// No current-state fallback is permitted, including a missing document.
    pub fn reconstruct_board(&self, turn: &EntityId) -> Result<ReconstructedBoard> {
        let txn = self.store.env.read_txn()?;
        let turn_raw = crate::vault::entity_revision::read_entity_revision_in_txn(
            self,
            &txn,
            turn,
            ReadMode::Live,
        )?
        .ok_or(BoardHistoryError::UnknownTurn(*turn))?;
        let turn_header =
            EntityMetadataHeader::parse(&turn_raw).ok_or(Error::CorruptedIndex("turn header"))?;
        if turn_header.entity_type != crate::registry::ENTITY_TYPE_TURN {
            return Err(BoardHistoryError::UnknownTurn(*turn));
        }
        let bytes = self
            .store
            .vault_meta
            .get(&txn, &key(TURN, turn))?
            .ok_or(BoardHistoryError::UnknownTurn(*turn))?;
        let anchor: TurnAnchor =
            rmp_serde::from_slice(&bytes).map_err(|_| BoardHistoryError::MissingFrontier)?;
        if let Some(raw) = self
            .store
            .vault_meta
            .get(&txn, &key(HORIZON, &anchor.owner))?
        {
            let retained_from = u64::from_be_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| BoardHistoryError::MissingFrontier)?,
            );
            if anchor.at < retained_from {
                return Err(BoardHistoryError::BeyondCompactionHorizon {
                    turn: *turn,
                    retained_from,
                });
            }
        }
        if reference(&anchor.owner, &anchor.frontier) != anchor.source_revision_ref {
            return Err(BoardHistoryError::MissingFrontier);
        }
        let frontier =
            Frontiers::decode(&anchor.frontier).map_err(|_| BoardHistoryError::MissingFrontier)?;
        let doc = load_doc(self, &txn, &anchor.owner)?
            .fork_at(&frontier)
            .map_err(|_| BoardHistoryError::MissingFrontier)?;
        let mut selected = Vec::new();
        for predicate in PREDICATES {
            let items = match map_bytes(&doc, "claims", predicate)? {
                None => Default::default(),
                Some(raw) => {
                    let id = id_from(raw.get(..16).ok_or(BoardHistoryError::MissingFrontier)?)?;
                    let (body, header) = claim(self, &txn, &id)?;
                    let items = decode_value(&body.value)?.0;
                    if raw.get(16..) != Some(selection_hash(&items).as_slice()) {
                        return Err(BoardHistoryError::MissingFrontier);
                    }
                    if body.predicate != predicate
                        || body.subject != ClaimSubject::Entity(anchor.owner)
                        || body.valid_from.is_none_or(|from| from > anchor.at)
                        || body.valid_to.is_some_and(|to| to < anchor.at)
                        || header.learned_at > anchor.learned_at
                        || body.lifecycle != ClaimLifecycleStatus::Active
                    {
                        return Err(BoardHistoryError::MissingFrontier);
                    }
                    items
                }
            };
            selected.push(items);
        }
        let selection = BoardSelection {
            allowed: selected.remove(0),
            default_on: selected.remove(0),
            active: selected.remove(0),
            pinned: selected.remove(0),
            top_snippet: selected.remove(0),
            index_only: Default::default(),
        };
        validate_selection(&selection)?;
        let mut documents = BTreeMap::new();
        let actor = crate::claim::ScopedReadActorKey::new(anchor.owner.to_hex())
            .ok_or(BoardHistoryError::InvalidSelection("invalid owner"))?;
        let scoped = self.scoped_read(actor);
        for id in sets(&selection).into_iter().flat_map(|set| set.iter()) {
            let raw = map_bytes(&doc, "documents", &id.to_hex())?
                .ok_or(BoardHistoryError::MissingFrontier)?;
            let revision = RevisionRef(
                raw.as_slice()
                    .try_into()
                    .map_err(|_| BoardHistoryError::MissingFrontier)?,
            );
            let raw = crate::vault::entity_revision::read_entity_revision_in_txn(
                self,
                &txn,
                id,
                ReadMode::Pinned(revision),
            )?
            .ok_or(BoardHistoryError::MissingFrontier)?;
            if raw[0] == crate::registry::ENTITY_TYPE_CLAIM {
                let live = crate::vault::entity_revision::read_entity_revision_in_txn(
                    self,
                    &txn,
                    id,
                    ReadMode::Live,
                )?
                .ok_or(BoardHistoryError::UnreadableDocument(*id))?;
                if !scoped.is_claim_raw_readable_in(&txn, id, &live)?
                    || !scoped.is_claim_raw_readable_in(&txn, id, &raw)?
                {
                    return Err(BoardHistoryError::UnreadableDocument(*id));
                }
            }
            documents.insert(*id, raw[ENTITY_METADATA_HEADER_LEN..].to_vec());
        }
        Ok(ReconstructedBoard {
            turn: *turn,
            owner: anchor.owner,
            at: anchor.at,
            source_revision_ref: anchor.source_revision_ref,
            selection,
            documents,
        })
    }

    /// Advances the retained window monotonically. Anchors remain as compact
    /// tombstones so a pre-horizon request is distinguishable from an unknown
    /// turn. The Loro history is deliberately not shallow-compacted: citations
    /// and retained turns can still reference its earlier operations.
    pub fn advance_board_compaction_horizon(
        &self,
        owner: &EntityId,
        retained_from: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        if let Some(raw) = self.store.vault_meta.get(&txn, &key(HORIZON, owner))? {
            let current = u64::from_be_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| BoardHistoryError::MissingFrontier)?,
            );
            if retained_from < current {
                return Err(BoardHistoryError::InvalidSelection(
                    "compaction horizon cannot move backward",
                ));
            }
        }
        self.store
            .vault_meta
            .put(&mut txn, &key(HORIZON, owner), &retained_from.to_be_bytes())?;
        txn.commit()?;
        Ok(())
    }
}

fn write_anchor(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turn: &EntityId,
    anchor: &TurnAnchor,
) -> Result<()> {
    let raw = rmp_serde::to_vec_named(anchor).map_err(|_| BoardHistoryError::MissingFrontier)?;
    vault.store.vault_meta.put(txn, &key(TURN, turn), &raw)?;
    Ok(())
}
