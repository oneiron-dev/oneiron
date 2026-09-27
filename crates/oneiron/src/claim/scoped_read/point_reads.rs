//! The one receipted point-read entry: ids and short references, each at its
//! own read frontier, answered from one snapshot under one receipt.
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
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        let Some(raw) = self.entity_raw_with_mode_in(txn, &policy, &filter, id, ReadMode::Live)?
        else {
            return Ok(None);
        };
        let header = EntityMetadataHeader::parse(&raw.raw)
            .ok_or(Error::CorruptedIndex("graph ask entity header"))?;
        Ok(Some((
            header.entity_type,
            header.learned_at,
            raw.raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        )))
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

    /// Keeps the scoped rows, their receipt and a dependent projection in the
    /// same read transaction. A projection must not open a newer snapshot for
    /// metadata that labels these rows.
    pub(crate) fn read_projected<T, E: From<Error>>(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        project: impl FnOnce(&heed::RoTxn<'_>, Vec<Option<ReadRow>>) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(reads.len());
        let mut suppressed = 0;
        for read in reads {
            let row = match read.target {
                ReadTarget::Id(id) => {
                    match self.entity_raw_with_mode_in(&txn, &policy, &filter, &id, read.mode)? {
                        Some(revision) => Some(ReadRow::from_revision(id, revision)?),
                        None => {
                            suppressed += usize::from(self.entity_record_in(&txn, &id)?.is_some());
                            None
                        }
                    }
                }
                ReadTarget::ShortRef {
                    short_id,
                    content_hash,
                } => {
                    let (row, withheld) = self.short_ref_in(
                        &txn,
                        &policy,
                        &filter,
                        short_id,
                        content_hash,
                        read.mode,
                    )?;
                    suppressed += withheld;
                    row
                }
            };
            value.push(row);
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult {
            value: project(&txn, value)?,
            receipt,
        })
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
                return match self.entity_raw_with_mode_in(txn, policy, filter, &id, mode)? {
                    Some(revision) => Ok((Some(ReadRow::from_revision(id, revision)?), 0)),
                    None => Ok((
                        None,
                        usize::from(self.entity_record_in(txn, &id)?.is_some()),
                    )),
                };
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
            return match self.entity_raw_with_mode_in(txn, policy, filter, &hydrated.id, mode)? {
                Some(revision) => Ok((
                    Some(ReadRow {
                        deletion: hydrated.deletion,
                        ..ReadRow::from_revision(hydrated.id, revision)?
                    }),
                    0,
                )),
                None => Ok((
                    None,
                    usize::from(self.entity_record_in(txn, &hydrated.id)?.is_some()),
                )),
            };
        }
        // Erased relationship/private bodies cannot prove a scope.
        let revealed = hydrated.deletion.is_some()
            && self.audience_readable_in(txn, &hydrated.id)?
            && hydrated.entity_type != crate::registry::ENTITY_TYPE_NOTE
            && !(self.actor_key.enforce_access_grants
                && matches!(
                    hydrated.entity_type,
                    crate::registry::ENTITY_TYPE_CLAIM
                        | crate::registry::ENTITY_TYPE_MESSAGE
                        | crate::registry::ENTITY_TYPE_SUMMARY
                ))
            && !filter.deny_all
            && filter
                .entity_types
                .as_ref()
                .is_none_or(|types| types.contains(&hydrated.entity_type))
            // The row's old position cannot be proved. Only authority
            // covering every possible position may reveal deletion
            // metadata, never a narrow grant.
            && self.credential_allows_id(&hydrated.id)
            && crate::gate::scoped_read_record_allowed(
                policy,
                &self.actor_key,
                &crate::federation::scope_codec::read_preset(),
            );
        if !revealed {
            return Ok((
                None,
                usize::from(self.entity_record_in(txn, &hydrated.id)?.is_some()),
            ));
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
