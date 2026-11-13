//! What the side ledgers record each entity row's body was made from, as an
//! Owner's copy judges it before it reads a body (fix list row 15416).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::archive_side_tables::{ArchiveSideFamily, id_at, lent};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::source_audience::ExportJudge;
use crate::store::Store;

/// What the side ledgers record each entity row's body was made from, read
/// once in an Owner's copy's own snapshot (fix list row 15416), through each
/// family's own codec and the codec of each record inside it: the copy judges
/// these before it reads a body, so a body whose words came from a member's
/// mailbox it leaves out stays home though no edge or stamp names that row.
///
/// - each version of a blob artifact's chain (its version and head records)
///   and each stored `blob.version` claim whose subject it is, which a replica
///   holds without the chain and before any `claim_of` edge to it: every row
///   its made_by names is a source of the artifact and of the version's ledger
///   claim, and, with the artifact, of one use of the ASSET its bytes are;
/// - a born-from row: its task, ask or skill source, of its artifact;
/// - an edit settlement: every row its record names, of its artifact;
/// - a code revision's record, integrity fold, stranded proposal (the
///   revision inside it read through the revision's own codec) and promotion:
///   every row they name, its provenance claim among them, of the
///   CODE_ARTIFACT the revision is;
/// - a fork record: its parent session and base revision, of the forked
///   SESSION.
///
/// No other family records a source of a row's body: an LFS, codebase or
/// code-document row names no entity row's source, a code-memory value binds
/// a payload that stands as a row of its own, and a deck's marks, a claimed
/// hash pair, a refcount marker, a high-water mark, a revision's frontier and
/// every index repeat what these records hold.
#[derive(Default)]
pub(crate) struct SideProvenance {
    /// Each row whose body a side ledger records sources of, and every row
    /// those records name beside it: its body goes only when the copy carries
    /// every one. `None` when one of its records does not read.
    owned: BTreeMap<EntityId, Option<BTreeSet<EntityId>>>,
    /// Each content-addressed ASSET a blob version holds, and each recorded
    /// use of its bytes: the version's artifact and every row its made_by
    /// names, `None` when that does not read. Shared bytes go when the copy
    /// carries every row of one use; they stay home only when it carries no
    /// use whole.
    uses: BTreeMap<EntityId, Vec<Option<BTreeSet<EntityId>>>>,
}

impl SideProvenance {
    /// What the side ledgers record each row's body was made from, read in
    /// the snapshot `rtxn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn read_in(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        use crate::code_revision::ArchivedRevisionTable as R;
        use ArchiveSideFamily as F;
        let mut recorded = Self::default();
        for family in [
            F::BlobVersion,
            F::BlobHead,
            F::BlobBornFrom,
            F::BlobSettlement,
            F::CodeRevisionRecord,
            F::CodeRevisionIntegrity,
            F::CodeRevisionProposal,
            F::CodeRevisionPromotion,
            F::CodeRevisionFork,
        ] {
            for (key, value) in lent(family)?.stored_rows(store, rtxn)? {
                // The row a record is of, by its table's own key: a blob
                // row's artifact, a revision's CODE_ARTIFACT, a fork's
                // SESSION.
                let at = if family == F::BlobBornFrom {
                    ENTITY_ID_LEN + 1
                } else {
                    0
                };
                let Some(owner) = id_at(&key, at) else {
                    continue;
                };
                let rows = match family {
                    F::BlobVersion | F::BlobHead => {
                        match crate::blob_artifact::archive_version_source(&value) {
                            Some(version) => {
                                recorded.version(owner, version);
                                continue;
                            }
                            None => None,
                        }
                    }
                    F::BlobBornFrom => crate::blob_artifact::archive_born_from_rows(&key, &value),
                    F::BlobSettlement => crate::edit_settle::archive_settlement_rows(&value),
                    F::CodeRevisionRecord => {
                        crate::code_revision::archive_revision_rows(R::Record, &value)
                    }
                    F::CodeRevisionIntegrity => {
                        crate::code_revision::archive_revision_rows(R::Integrity, &value)
                    }
                    F::CodeRevisionProposal => {
                        crate::code_revision::archive_revision_rows(R::Proposal, &value)
                    }
                    F::CodeRevisionPromotion => {
                        crate::code_revision::archive_revision_rows(R::Promotion, &value)
                    }
                    F::CodeRevisionFork => {
                        crate::code_revision::archive_revision_rows(R::Fork, &value)
                    }
                    _ => continue,
                };
                recorded.record(owner, rows);
            }
        }
        for (artifact, version) in crate::blob_artifact::archive_claimed_versions(store, rtxn)? {
            recorded.version(artifact, version);
        }
        Ok(recorded)
    }

    /// The rows a record of `owner` names as sources of its body (`None`: a
    /// record that does not read), but `owner` itself.
    fn record(&mut self, owner: EntityId, rows: Option<Vec<EntityId>>) {
        let named = self
            .owned
            .entry(owner)
            .or_insert_with(|| Some(BTreeSet::new()));
        match rows {
            Some(rows) => {
                if let Some(named) = named {
                    named.extend(rows.into_iter().filter(|row| *row != owner));
                }
            }
            None => *named = None,
        }
    }

    /// One version of `artifact`: what made its bytes is a source of the
    /// artifact and of the version's ledger claim, and, with the artifact,
    /// one use of the ASSET those bytes are.
    fn version(
        &mut self,
        artifact: EntityId,
        version: crate::blob_artifact::ArchivedVersionSource,
    ) {
        self.record(artifact, version.made_by.clone());
        self.record(version.claim, version.made_by.clone());
        let asset = version.asset;
        let named: Option<BTreeSet<EntityId>> = version.made_by.map(|rows| {
            rows.into_iter()
                .chain([artifact])
                .filter(|row| *row != asset)
                .collect()
        });
        self.uses.entry(asset).or_default().push(named);
    }

    /// The rows the side ledgers record the body of `id` was made from, when
    /// `judge` carries every row its records name and, for bytes a blob
    /// version holds, every row of one recorded use of them: those rows, to
    /// count as carried once the body ships. `None` when the body stays home.
    /// A row no side ledger names goes as its own lineage judges it, with
    /// nothing beside it. Every recorded source is judged, so the copy's
    /// notices name each mailbox one of them is of.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn admitted(
        &self,
        judge: &mut ExportJudge<'_, '_, '_>,
        id: EntityId,
    ) -> Result<Option<Vec<EntityId>>> {
        let mut sources = Vec::new();
        let mut carried = true;
        if let Some(named) = self.owned.get(&id) {
            let named: Option<Vec<EntityId>> =
                named.as_ref().map(|named| named.iter().copied().collect());
            carried &= judge.carries_all(named.as_deref())?;
            sources.extend(named.into_iter().flatten());
        }
        if let Some(uses) = self.uses.get(&id) {
            let mut kept = false;
            for named in uses.iter().flatten() {
                let named: Vec<EntityId> = named.iter().copied().collect();
                if judge.carries_all(Some(named.as_slice()))? {
                    kept = true;
                    sources.extend(named);
                }
            }
            // A use whose made_by does not read is of a source this vault
            // cannot name, and keeps nothing.
            if !kept && uses.iter().any(Option::is_none) {
                judge.carries_all(None)?;
            }
            carried &= kept;
        }
        Ok(carried.then_some(sources))
    }
}
