//! The one receipted point-read entry: ids and short references, each at its
//! own read frontier, answered from one snapshot under one receipt.
use super::access_gate::HeldAuthority;
use super::versions::AdmittedRevision;
use super::{RetrievalFilter, ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::vault::ReadMode;
use crate::{EntityId, Error, HydratedShortIdDeletion, Result, TimeRange};
type EntityParts = (u8, u64, Vec<u8>);

/// What one point read names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTarget<'r> {
    /// An entity id.
    Id(EntityId),
    /// An engine-issued short reference: short id plus content-hash byte.
    ShortRef { short_id: &'r str, content_hash: u8 },
}

impl ScopedRead<'_> {
    /// Recheck a graph-ask source against the current write transaction's
    /// authority, deletion, NOTE privacy and live-body projection. It cannot
    /// turn an earlier scoped read into a permission after grants change.
    pub(crate) fn graph_ask_parts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityParts>> {
        let Some(raw) = self.graph_ask_raw_in_txn(txn, id)? else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("graph ask entity header"))?;
        Ok(Some((
            header.entity_type,
            header.learned_at,
            raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        )))
    }

    /// [`Self::graph_ask_parts_in_txn`]'s whole row, header included, for a
    /// caller that judges the record's Scope as well.
    pub(crate) fn graph_ask_raw_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        Ok(self
            .entity_raw_with_mode_in(txn, &policy, &filter, id, ReadMode::Live)?
            .map(|revision| revision.raw))
    }

    /// Whether this reader may read each of `ids` now, as
    /// [`Self::get_entities_parts_in_txn`] admits it, without taking its
    /// body out: no live projection and no short-reference hash. Every id is
    /// judged in the one snapshot, so the reader's relationship authority is
    /// resolved once for all of them.
    pub(crate) fn entities_readable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: &[EntityId],
    ) -> Result<Vec<bool>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        let authority = HeldAuthority::default();
        ids.iter()
            .map(|id| self.is_entity_readable_held_in(txn, &policy, id, &filter, &authority))
            .collect()
    }

    /// Actor-gated entity bodies at a caller-owned ledger snapshot. A wake
    /// can pass the SAME read transaction to every child accounting step.
    pub(crate) fn get_entities_parts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: &[EntityId],
    ) -> Result<Vec<Option<EntityParts>>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        ids.iter()
            .map(|id| {
                let Some(revision) =
                    self.entity_raw_with_mode_in(txn, &policy, &filter, id, ReadMode::Live)?
                else {
                    return Ok(None);
                };
                let header = EntityMetadataHeader::parse(&revision.raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                Ok(Some((
                    header.entity_type,
                    header.learned_at,
                    revision.raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
                )))
            })
            .collect()
    }
}

/// One read in a [`ScopedRead::read`] slice: its target and its frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointRead<'r> {
    pub target: ReadTarget<'r>,
    pub mode: ReadMode,
}

impl<'r> PointRead<'r> {
    /// The live body of `id`.
    #[must_use]
    pub fn id(id: EntityId) -> Self {
        Self {
            target: ReadTarget::Id(id),
            mode: ReadMode::Live,
        }
    }

    /// The live row behind an engine-issued short reference.
    #[must_use]
    pub fn short(short_id: &'r str, content_hash: u8) -> Self {
        Self {
            target: ReadTarget::ShortRef {
                short_id,
                content_hash,
            },
            mode: ReadMode::Live,
        }
    }

    /// The same target at another frontier (indexed or a pinned revision).
    #[must_use]
    pub fn at(self, mode: ReadMode) -> Self {
        Self { mode, ..self }
    }
}

/// One admitted row.
///
/// An id read admits a row only with its body. A short reference may also
/// resolve to a deleted shell: `body` is then `None` and `deletion` carries the
/// deletion metadata this actor may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRow {
    pub id: EntityId,
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub body: Option<Vec<u8>>,
    pub deletion: Option<HydratedShortIdDeletion>,
    /// The content-hash byte of the stored revision this row was read from,
    /// the byte an engine-issued short reference to that revision carries.
    pub content_hash: u8,
}

impl ReadRow {
    fn from_revision(id: EntityId, revision: AdmittedRevision) -> Result<Self> {
        let header = EntityMetadataHeader::parse(&revision.raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Self {
            id,
            entity_type: header.entity_type,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            body: Some(revision.raw[ENTITY_METADATA_HEADER_LEN..].to_vec()),
            deletion: None,
            content_hash: revision.content_hash,
        })
    }
}

impl ScopedRead<'_> {
    /// Compatibility projection of point rows; policy and body share the read snapshot.
    pub fn get_entity_parts_with_receipt(
        &self,
        id: &EntityId,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<EntityParts>>> {
        self.get_entity_parts_with_mode_with_receipt(id, ReadMode::Live, requested)
    }

    pub fn get_entity_parts_with_mode_with_receipt(
        &self,
        id: &EntityId,
        mode: ReadMode,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<EntityParts>>> {
        let read = self.read(&[PointRead::id(*id).at(mode)], requested)?;
        Ok(ScopedReadResult {
            value: read
                .value
                .into_iter()
                .next()
                .flatten()
                .and_then(|row| row.body.map(|body| (row.entity_type, row.learned_at, body))),
            receipt: read.receipt,
        })
    }

    pub fn get_entities_parts_with_receipt(
        &self,
        ids: &[EntityId],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<EntityParts>>>> {
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let result = self.read(&reads, requested)?;
        Ok(ScopedReadResult {
            value: result
                .value
                .into_iter()
                .map(|row| {
                    row.and_then(|row| row.body.map(|body| (row.entity_type, row.learned_at, body)))
                })
                .collect(),
            receipt: result.receipt,
        })
    }

    /// Reads every target in one snapshot under one policy resolution.
    ///
    /// Each slot answers its read in order; `None` is a missing target or a
    /// withheld row. Missing targets are not policy exclusions: the receipt
    /// counts only existing rows this actor may not read. Mixed frontiers and
    /// mixed id/short-reference slices share the snapshot and the receipt.
    pub fn read(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<ReadRow>>>> {
        self.read_projected(reads, requested, |_, rows| Ok::<_, Error>(rows))
    }

    /// [`Self::read`] under an as-of temporal selection (unix seconds),
    /// applied to each admitted row before any caller composes it.
    ///
    /// The selection is bitemporal at one instant: a row is kept only when
    /// it had both occurred by `as_of` (`occurred.start <= as_of`) and been
    /// learned by the vault by then (`learned_at <= as_of`). A row the
    /// selection drops answers as `None`, exactly like a missing one; it is
    /// the caller's requested instant, not a policy denial, so the receipt
    /// counts no suppression for it. All scope and authority gates of the
    /// underlying point read are unchanged — this only narrows further.
    ///
    /// A kept row carries its live body: retained revision frontiers hold
    /// no per-revision learned-at, so no earlier body can be named for an
    /// instant between two edits of one row.
    pub fn read_as_of(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        as_of: u64,
    ) -> Result<ScopedReadResult<Vec<Option<ReadRow>>>> {
        let result = self.read(reads, requested)?;
        Ok(ScopedReadResult {
            value: result
                .value
                .into_iter()
                .map(|row| {
                    row.filter(|row| row.occurred.start <= as_of && row.learned_at <= as_of)
                })
                .collect(),
            receipt: result.receipt,
        })
    }

    /// Keeps the scoped rows, their receipt and a dependent projection in the
    /// same read transaction. A projection must not open a newer snapshot for
    /// metadata that labels these rows.
    pub(crate) fn read_projected<T, E: From<Error>>(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        project: impl FnOnce(&heed::RoTxn<'_>, Vec<Option<ReadRow>>) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        self.read_projected_opaque(reads, requested, |_, _| Ok(false), project)
    }

    /// [`Self::read_projected`], where `opaque` names, in the read's own
    /// snapshot, an id whose withheld row this reader may not learn of: it
    /// adds no count, as a missing row adds none.
    pub(crate) fn read_projected_opaque<T, E: From<Error>>(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        mut opaque: impl FnMut(&heed::RoTxn<'_>, &EntityId) -> std::result::Result<bool, E>,
        project: impl FnOnce(&heed::RoTxn<'_>, Vec<Option<ReadRow>>) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(reads.len());
        let mut suppressed = 0;
        for read in reads {
            let (row, withheld) = match read.target {
                ReadTarget::Id(id) => {
                    let (row, withheld) = self.id_row_in(&txn, &policy, &filter, id, read.mode)?;
                    if withheld > 0 && opaque(&txn, &id)? {
                        (row, 0)
                    } else {
                        (row, withheld)
                    }
                }
                ReadTarget::ShortRef {
                    short_id,
                    content_hash,
                } => {
                    self.short_ref_in(&txn, &policy, &filter, short_id, content_hash, read.mode)?
                }
            };
            suppressed += withheld;
            value.push(row);
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult {
            value: project(&txn, value)?,
            receipt,
        })
    }

    /// One id at one frontier: the admitted row and whether an existing row
    /// was withheld. Value and denial count come from the same snapshot.
    fn id_row_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        id: EntityId,
        mode: ReadMode,
    ) -> Result<(Option<ReadRow>, usize)> {
        let admitted = self.admit_in(txn, &id, || {
            self.entity_raw_with_mode_in(txn, policy, filter, &id, mode)
        })?;
        let withheld = admitted.suppression();
        let row = admitted
            .into_option()
            .map(|revision| ReadRow::from_revision(id, revision))
            .transpose()?;
        Ok((row, withheld))
    }

    /// One short reference: the admitted row and whether an existing row was withheld.
    fn short_ref_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        short_id: &str,
        content_hash: u8,
        mode: ReadMode,
    ) -> Result<(Option<ReadRow>, usize)> {
        let hydrated = match mode {
            ReadMode::Pinned(revision) => {
                let Some(id) = self.vault.resolve_pinned_entity_reference_in(
                    txn,
                    &format!("{short_id}:{content_hash:02x}"),
                    revision,
                )?
                else {
                    return Ok((None, 0));
                };
                return self.id_row_in(txn, policy, filter, id, mode);
            }
            ReadMode::Live | ReadMode::Indexed => {
                self.vault
                    .hydrate_short_id_in(txn, short_id, content_hash)?
            }
        };
        let Some(hydrated) = hydrated else {
            return Ok((None, 0));
        };
        if hydrated.body.is_some() {
            // Resolve the requested frontier in this same transaction.
            let (row, withheld) = self.id_row_in(txn, policy, filter, hydrated.id, mode)?;
            let deletion = hydrated.deletion;
            return Ok((row.map(|row| ReadRow { deletion, ..row }), withheld));
        }
        // Erased relationship/private bodies cannot prove a scope.
        let revealed = hydrated.deletion.is_some()
            && self.audience_readable_in(txn, &hydrated.id)?
            && hydrated.entity_type != crate::registry::ENTITY_TYPE_NOTE
            && !(self.relationship_gated_in(txn)?
                && matches!(
                    hydrated.entity_type,
                    crate::registry::ENTITY_TYPE_CLAIM
                        | crate::registry::ENTITY_TYPE_MESSAGE
                        | crate::registry::ENTITY_TYPE_SUMMARY
                ))
            && !filter.deny_all
            && filter.read_scope().bands.contains(&hydrated.entity_type)
            // Only authority covering every possible old position may reveal
            // deletion metadata, never a narrow grant.
            && self.credential_allows_id(&hydrated.id)
            && self.facets_allow_shell_in(txn, &hydrated.id)?
            && crate::gate::scoped_read_record_allowed(
                policy,
                &self.actor_key,
                &crate::federation::scope_codec::read_preset(),
            );
        if !revealed {
            // A withheld private NOTE shell counts exactly like a missing row.
            let withheld = self
                .admit_in(txn, &hydrated.id, || Ok(None::<()>))?
                .suppression();
            return Ok((None, withheld));
        }
        let occurred = self
            .entity_record_in(txn, &hydrated.id)?
            .map_or(TimeRange { start: 0, end: 0 }, |record| record.occurred);
        Ok((
            Some(ReadRow {
                id: hydrated.id,
                entity_type: hydrated.entity_type,
                occurred,
                learned_at: hydrated.learned_at,
                body: None,
                deletion: hydrated.deletion,
                content_hash,
            }),
            0,
        ))
    }
}
