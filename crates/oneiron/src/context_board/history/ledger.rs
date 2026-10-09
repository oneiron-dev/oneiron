//! Board turn anchors reference one CRDT frontier; facts remain CLAIM rows.

use super::claims::{PREDICATES, decode_value, sets, validate_board_claim, value};
use super::types::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, ScopedRead,
    ScopedReadActorKey, decode_claim_body,
};
use crate::error::Error;
use crate::side_table::{self, LegacyCompact, Named, Raw, SideTable};
use crate::temporal::TimeRange;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, LoroDoc, LoroValue, ValueOrContainer};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, BoardHistoryError>;

/// Loro CRDT snapshot backing one owner's board-selection/document history.
/// Key: the owner id.
const DOC: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::BOARD_HISTORY_DOC);
/// Turn anchor recording the board-history CRDT frontier and selection
/// snapshot a TURN committed. Key: the turn id.
const TURN: SideTable<EntityId, TurnAnchor, Named> =
    SideTable::new(&side_table::BOARD_HISTORY_TURN);
/// Last committed `(at, learned_at)` monotonic stamp per board-history owner.
/// Key: the owner id.
const LAST: SideTable<EntityId, (u64, u64), LegacyCompact> =
    SideTable::new(&side_table::BOARD_HISTORY_LAST);
/// Revision-ref frontier a board-selection CLAIM was written under,
/// authenticated on every read. Key: the claim id.
const CLAIM_FRONTIER: SideTable<EntityId, [u8; 16], Raw> =
    SideTable::new(&side_table::BOARD_HISTORY_CLAIM_FRONTIER);
/// Monotonic compaction horizon (earliest retained turn time) per
/// board-history owner. Key: the owner id.
const HORIZON: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::BOARD_HISTORY_HORIZON);

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
    let raw = DOC
        .get(&vault.store, txn, owner)?
        .ok_or(BoardHistoryError::MissingFrontier)?;
    LoroDoc::from_snapshot(&raw).map_err(|_| BoardHistoryError::MissingFrontier)
}

fn claim(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<(ClaimBody, EntityMetadataHeader)> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
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
    if CLAIM_FRONTIER.get(&vault.store, txn, id)? != Some(writing_frontier.0) {
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

/// The board owner's own proof-less key: the trusted embedded door's reader.
fn owner_key(owner: &EntityId) -> Result<ScopedReadActorKey> {
    ScopedReadActorKey::new(owner.to_hex())
        .ok_or(BoardHistoryError::InvalidSelection("invalid owner"))
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
        let (txn, receipt) =
            self.stage_board_turn(input.turn, input.owner, &input.selection, None, |_| {
                (input.at, learned_at)
            })?;
        txn.commit()?;
        Ok(receipt)
    }

    /// The per-turn board path: `caller`, the board owner, records the board
    /// `memories` rendered for its own `turn`, at the vault clock. A turn
    /// recorded in the same second as the owner's last one moves one second
    /// past it, so turn order stays strict.
    ///
    /// The TURN must carry `owner` as the author its door stamped, so a
    /// reader of someone else's turn cannot claim its board. Every selected
    /// document, of every type, must be readable under `caller`'s current
    /// scope, and each is recorded at the revision the board served it at.
    ///
    /// `accept` sees the receipt inside the recording transaction, before it
    /// commits: a caller that declines it (a response that no longer fits
    /// its budget with the receipt in it) records nothing, and gets `None`.
    pub fn record_board_turn_now(
        &self,
        turn: EntityId,
        owner: EntityId,
        memories: Option<&crate::context_board::MemoriesSection>,
        caller: &ScopedRead<'_>,
        accept: impl FnOnce(&BoardTurnReceipt) -> bool,
    ) -> Result<Option<BoardTurnReceipt>> {
        let selection =
            memories.map_or_else(BoardSelection::default, BoardSelection::from_memories);
        let served = memories.map_or_else(BTreeMap::new, |memories| {
            selection.served_revisions(memories)
        });
        let now = self.now_recorded_at();
        let (txn, receipt) =
            self.stage_board_turn(turn, owner, &selection, Some((caller, &served)), |last| {
                match last {
                    Some((at, learned_at)) => (now.max(at.saturating_add(1)), now.max(learned_at)),
                    None => (now, now),
                }
            })?;
        if !accept(&receipt) {
            return Ok(None);
        }
        txn.commit()?;
        Ok(Some(receipt))
    }

    /// Writes one turn's board into a transaction the caller commits.
    /// `stamp` picks `(at, learned_at)` from the owner's last committed stamp,
    /// read inside it. Without a `caller` this is the trusted embedded door:
    /// the owner's own key, checking CLAIM documents.
    fn stage_board_turn(
        &self,
        turn: EntityId,
        owner: EntityId,
        selection: &BoardSelection,
        caller: Option<(&ScopedRead<'_>, &BTreeMap<EntityId, RevisionRef>)>,
        stamp: impl FnOnce(Option<(u64, u64)>) -> (u64, u64),
    ) -> Result<(RwTxn<'_>, BoardTurnReceipt)> {
        validate_selection(selection)?;
        let mut txn = self.store.env.write_txn()?;
        let last = LAST.get(&self.store, &txn, &owner)?;
        let (at, learned_at) = stamp(last);
        let input = &BoardTurn {
            turn,
            owner,
            at,
            selection: selection.clone(),
        };
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
        if let Some((caller, _)) = caller {
            if !caller.is_entity_readable_in(&txn, &input.turn)? {
                return Err(BoardHistoryError::UnknownTurn(input.turn));
            }
            // The author the TURN's own door stamped owns its board. An
            // unparsable body or an imported turn names no author.
            let author =
                crate::conversation::record_author(&turn_raw[ENTITY_METADATA_HEADER_LEN..])
                    .ok()
                    .flatten();
            if author != Some(input.owner) {
                return Err(BoardHistoryError::NotTurnAuthor(input.turn));
            }
        }
        if TURN.contains(&self.store, &txn, &input.turn)? {
            return Err(BoardHistoryError::InvalidSelection(
                "turn is already anchored",
            ));
        }
        if let Some(last) = last
            && (input.at <= last.0 || learned_at < last.1)
        {
            return Err(BoardHistoryError::InvalidSelection(
                "turn and learned time must advance monotonically",
            ));
        }
        let doc = if DOC.contains(&self.store, &txn, &input.owner)? {
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
        let owner_read;
        let (scoped, served) = match caller {
            Some((caller, served)) => (caller, Some(served)),
            None => {
                owner_read = self.scoped_read(owner_key(&input.owner)?);
                (&owner_read, None)
            }
        };
        // A caller's scope checks every document; the owner's own key, CLAIMs.
        let gated = |raw: &[u8]| caller.is_some() || raw[0] == crate::registry::ENTITY_TYPE_CLAIM;
        for id in all {
            let live = crate::vault::entity_revision::read_entity_revision_in_txn(
                self,
                &txn,
                &id,
                ReadMode::Live,
            )?
            .ok_or(BoardHistoryError::UnreadableDocument(id))?;
            if gated(&live) && !scoped.is_claim_raw_readable_in(&txn, &id, &live)? {
                return Err(BoardHistoryError::UnreadableDocument(id));
            }
            let (live_revision, _) =
                crate::vault::entity_revision::ensure_document(self, &mut txn, &id)?;
            // The board showed this revision; its history keeps exactly it,
            // never the live text in its place.
            let revision = match served.and_then(|served| served.get(&id)) {
                None => live_revision,
                Some(&revision) => {
                    let owned = crate::vault::entity_revision::entity_owns_revision_in_txn(
                        &self.store,
                        &txn,
                        &id,
                        revision,
                    )?;
                    let raw = if owned {
                        crate::vault::entity_revision::read_entity_revision_in_txn(
                            self,
                            &txn,
                            &id,
                            ReadMode::Pinned(revision),
                        )?
                    } else {
                        None
                    };
                    let raw = raw.ok_or(BoardHistoryError::UnreadableDocument(id))?;
                    if !scoped.is_claim_raw_readable_in(&txn, &id, &raw)? {
                        return Err(BoardHistoryError::UnreadableDocument(id));
                    }
                    revision
                }
            };
            map_insert(&doc, "documents", &id.to_hex(), &revision.0)?;
        }
        let read_receipt = scoped.read_receipt_in(&txn, None, 0)?;
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
            )?;
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
            CLAIM_FRONTIER.put(&self.store, &mut txn, &id, &anchor_ref.0)?;
            changed_claims.push(id);
        }
        let anchor = TurnAnchor {
            owner: input.owner,
            at: input.at,
            learned_at,
            source_revision_ref: anchor_ref,
            frontier,
            folded: false,
        };
        write_anchor(self, &mut txn, &input.turn, &anchor)?;
        let snapshot = doc
            .export(ExportMode::Snapshot)
            .map_err(|_| BoardHistoryError::MissingFrontier)?;
        DOC.put(&self.store, &mut txn, &input.owner, &snapshot)?;
        LAST.put(&self.store, &mut txn, &input.owner, &(input.at, learned_at))?;
        let receipt = BoardTurnReceipt {
            turn: input.turn,
            source_revision_ref: anchor_ref,
            changed_claims,
            read_receipt,
        };
        Ok((txn, receipt))
    }

    /// Folds valid bitemporal claims from the TURN's exact CRDT frontier.
    /// No current-state fallback is permitted, including a missing document.
    /// The trusted embedded door: the owner's own key checks CLAIM documents.
    pub fn reconstruct_board(&self, turn: &EntityId) -> Result<ReconstructedBoard> {
        self.reconstruct_board_with(turn, None)
    }

    /// [`Self::reconstruct_board`] for an authenticated caller. The TURN and
    /// every document, of every type, pass `caller`'s CURRENT read scope at
    /// the pinned revision and live: a past board never re-grants a read the
    /// caller has since lost. An unreadable document refuses the whole board.
    pub fn reconstruct_board_for(
        &self,
        turn: &EntityId,
        caller: &ScopedRead<'_>,
    ) -> Result<ReconstructedBoard> {
        self.reconstruct_board_with(turn, Some(caller))
    }

    fn reconstruct_board_with(
        &self,
        turn: &EntityId,
        caller: Option<&ScopedRead<'_>>,
    ) -> Result<ReconstructedBoard> {
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
        if let Some(caller) = caller
            && !caller.is_entity_readable_in(&txn, turn)?
        {
            return Err(BoardHistoryError::UnknownTurn(*turn));
        }
        let anchor = TURN
            .get(&self.store, &txn, turn)?
            .ok_or(BoardHistoryError::UnknownTurn(*turn))?;
        if anchor.folded {
            return Err(BoardHistoryError::Compacted(*turn));
        }
        if let Some(retained_from) = HORIZON.get(&self.store, &txn, &anchor.owner)?
            && anchor.at < retained_from
        {
            return Err(BoardHistoryError::BeyondCompactionHorizon {
                turn: *turn,
                retained_from,
            });
        }
        if reference(&anchor.owner, &anchor.frontier) != anchor.source_revision_ref {
            return Err(BoardHistoryError::MissingFrontier);
        }
        crate::vault::entity_revision::read_entity_revision_in_txn(
            self,
            &txn,
            &anchor.owner,
            ReadMode::Live,
        )?
        .ok_or(BoardHistoryError::UnknownOwner(anchor.owner))?;
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
        let owner_read;
        let scoped = match caller {
            Some(caller) => caller,
            None => {
                owner_read = self.scoped_read(owner_key(&anchor.owner)?);
                &owner_read
            }
        };
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
            if caller.is_some() || raw[0] == crate::registry::ENTITY_TYPE_CLAIM {
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
        let read_receipt = scoped.read_receipt_in(&txn, None, 0)?;
        Ok(ReconstructedBoard {
            turn: *turn,
            owner: anchor.owner,
            at: anchor.at,
            source_revision_ref: anchor.source_revision_ref,
            selection,
            documents,
            read_receipt,
        })
    }

    /// The owner whose board `turn` anchored, if any: who may read it back.
    pub fn board_turn_owner(&self, turn: &EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(TURN
            .get(&self.store, &txn, turn)?
            .map(|anchor| anchor.owner))
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
        if let Some(current) = HORIZON.get(&self.store, &txn, owner)?
            && retained_from < current
        {
            return Err(BoardHistoryError::InvalidSelection(
                "compaction horizon cannot move backward",
            ));
        }
        HORIZON.put(&self.store, &mut txn, owner, &retained_from)?;
        txn.commit()?;
        Ok(())
    }
}

/// Compaction folded `turns` into a summary: exactly those turns' boards stop
/// reconstructing. Each anchor is marked on its own, so folding one session
/// leaves the owner's boards in every other session whole. A turn with no
/// board anchor marks nothing. Runs inside the compaction's own transaction.
pub(crate) fn fold_board_turns_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turns: impl IntoIterator<Item = EntityId>,
) -> crate::error::Result<()> {
    for turn in turns {
        if let Some(mut anchor) = TURN.get(&vault.store, txn, &turn)?
            && !anchor.folded
        {
            anchor.folded = true;
            TURN.put(&vault.store, txn, &turn, &anchor)?;
        }
    }
    Ok(())
}

fn write_anchor(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turn: &EntityId,
    anchor: &TurnAnchor,
) -> Result<()> {
    TURN.put(&vault.store, txn, turn, anchor)?;
    Ok(())
}
