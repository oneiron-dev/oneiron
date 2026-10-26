//! A row's covers, walked on the heap (rule 5, FIX 9113): a summary's or a
//! claim's covers, each cover's own covers, and so on, however deep. No
//! depth refuses a row; the deepest cover one read reaches is counted
//! against [`EngineScan::AudienceCoverDepth`], scoped to the row asked
//! about, and a crossing raises a check while the read serves.
//!
//! The walk keeps the order the recursive walk had: a row's own rules, then
//! its body's covers, then, for a claim, its merge sources, summary covers
//! and reaction record, each cover read whole before the next, and a claim's
//! relationship last. The first cover that does not read, and the first
//! error, end the read as they did. A cover that covers itself, through any
//! chain, is a malformed source and reads as none, as the old depth cut read
//! it; a cover already proven readable is not walked again.
use super::*;
use std::borrow::Cow;

/// The next group of covers one row on the walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverGroup {
    Body,
    Merge,
    Summary,
    Reaction,
    Relationship,
    Done,
}

/// What one row's next group gives the walk.
enum CoverStep {
    /// Covers to read, in order.
    Covers(Vec<EntityId>),
    /// The row does not read.
    Denied,
    /// Every group read.
    Done,
}

/// One row on the walk: its revision, its depth under the row asked about,
/// the group it reads next and the covers of the current group still to
/// read.
struct CoverFrame<'r> {
    id: EntityId,
    raw: Cow<'r, [u8]>,
    depth: usize,
    next: CoverGroup,
    claim: Option<crate::ClaimBody>,
    covers: std::vec::IntoIter<EntityId>,
}

impl<'r> CoverFrame<'r> {
    fn new(id: EntityId, raw: Cow<'r, [u8]>, depth: usize) -> Self {
        Self {
            id,
            raw,
            depth,
            next: CoverGroup::Body,
            claim: None,
            covers: Vec::new().into_iter(),
        }
    }

    /// The row's next group of covers, past any group that names none.
    fn advance(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        audience: &[EntityId],
    ) -> Result<CoverStep> {
        loop {
            let body = self
                .raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("audience body"))?;
            let covers = match self.next {
                CoverGroup::Body => {
                    let h = EntityMetadataHeader::parse(&self.raw)
                        .ok_or(Error::CorruptedIndex("audience header"))?;
                    self.next = if h.entity_type == ENTITY_TYPE_CLAIM {
                        CoverGroup::Merge
                    } else {
                        CoverGroup::Done
                    };
                    crate::scope_summary::body_covers_in_txn(
                        vault,
                        txn,
                        &self.id,
                        h.entity_type,
                        body,
                    )
                }
                CoverGroup::Merge => {
                    let claim = crate::claim::decode_claim_body(body, true)?;
                    let covers =
                        crate::scope_summary::merge_word_sources_in_txn(vault, txn, &claim);
                    self.claim = Some(claim);
                    self.next = CoverGroup::Summary;
                    covers
                }
                CoverGroup::Done => return Ok(CoverStep::Done),
                group => {
                    let Some(claim) = self.claim.as_ref() else {
                        return Ok(CoverStep::Done);
                    };
                    match group {
                        CoverGroup::Summary => {
                            self.next = CoverGroup::Reaction;
                            conversation_summary_covers(claim)
                        }
                        CoverGroup::Reaction => {
                            self.next = CoverGroup::Relationship;
                            reaction_covers(claim)
                        }
                        _ => {
                            self.next = CoverGroup::Done;
                            if !relationship_readable_in(vault, txn, claim, audience)? {
                                return Ok(CoverStep::Denied);
                            }
                            continue;
                        }
                    }
                }
            };
            match covers {
                Ok(None) => {}
                Ok(Some(covers)) if covers.is_empty() => return Ok(CoverStep::Denied),
                Ok(Some(covers)) => return Ok(CoverStep::Covers(covers)),
                Err(
                    Error::EntityNotFound
                    | Error::Record(
                        RecordError::InvalidScopeSummary(_)
                        | RecordError::InvalidConversationDag(_),
                    ),
                ) => return Ok(CoverStep::Denied),
                Err(error) => return Err(error),
            }
        }
    }
}

impl AudienceCache {
    /// `id`'s live row, `None` when it is not live, archived or unread.
    pub(super) fn live_raw(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<Vec<u8>>> {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            return Ok(None);
        }
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)
    }

    /// Whether `audience` reads `id`'s revision `raw` by its own rules and
    /// every cover its words came from by theirs; see the module doc. A
    /// cover meets its room's windows as the row it covers does, and walks
    /// no private thread turn by turn.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn readable_with_covers(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        audience: &[EntityId],
        current: bool,
        personal: Option<EntityId>,
    ) -> Result<bool> {
        if !self.readable_raw_at_depth(vault, txn, id, raw, audience, current, personal, 0)? {
            return Ok(false);
        }
        let mut stack = vec![CoverFrame::new(id, Cow::Borrowed(raw), 0)];
        let mut active = BTreeSet::from([id]);
        let mut proven = BTreeSet::new();
        let mut deepest = 0;
        let readable = loop {
            let Some(frame) = stack.last_mut() else {
                break true;
            };
            if let Some(cover) = frame.covers.next() {
                let depth = frame.depth + 1;
                if proven.contains(&cover) {
                    continue;
                }
                if active.contains(&cover) {
                    break false;
                }
                let Some(raw) = Self::live_raw(vault, txn, cover)? else {
                    break false;
                };
                if !self.readable_raw_at_depth(
                    vault, txn, cover, &raw, audience, false, personal, depth,
                )? {
                    break false;
                }
                deepest = deepest.max(depth);
                active.insert(cover);
                stack.push(CoverFrame::new(cover, Cow::Owned(raw), depth));
                continue;
            }
            match frame.advance(vault, txn, audience)? {
                CoverStep::Covers(covers) => frame.covers = covers.into_iter(),
                CoverStep::Denied => break false,
                CoverStep::Done => {
                    if let Some(done) = stack.pop() {
                        active.remove(&done.id);
                        if done.depth > 0 {
                            proven.insert(done.id);
                        }
                    }
                }
            }
        };
        if deepest > 0 {
            match ScanCount::start(
                &vault.store,
                txn,
                EngineScan::AudienceCoverDepth,
                id.as_bytes(),
            ) {
                Ok(mut count) => {
                    count.rows(deepest);
                    count.finish(vault);
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "audience cover depth was not counted");
                }
            }
        }
        Ok(readable)
    }
}

/// Whether every member of `audience` takes part in the relationship
/// `claim` is about, when it names one; a relationship that is gone or
/// malformed reads as none.
fn relationship_readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &crate::ClaimBody,
    audience: &[EntityId],
) -> Result<bool> {
    let Some(relationship) = claim.rel else {
        return Ok(true);
    };
    if audience.is_empty() {
        return Ok(false);
    }
    let rel = match require_kind(vault, txn, relationship, ENTITY_TYPE_RELATIONSHIP) {
        Ok(rel) => rel,
        Err(Error::EntityNotFound | Error::Record(RecordError::InvalidConversationBody(_))) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let mut participants = counted_edge_ids(
        &vault.store,
        txn,
        &relationship,
        EdgeKind::ParticipatesIn,
        true,
    )?;
    // Relationship participant ids are a read-path feed, not a
    // replacement for scope/tier authorization or room windows.
    if let Ok(value) = decode::<serde_json::Value>(&rel[ENTITY_METADATA_HEADER_LEN..])
        && let Some(ids) = value.get("participant_ids")
    {
        let body_ids: Vec<EntityId> = serde_json::from_value(ids.clone())
            .map_err(|_| invalid("relationship participants"))?;
        participants.extend(body_ids);
    }
    Ok(!audience.iter().any(|person| !participants.contains(person)))
}
