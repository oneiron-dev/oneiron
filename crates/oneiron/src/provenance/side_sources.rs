//! What the side ledgers and a row's birth record its body was made from:
//! one reader, side-ledger row to its source rows (fix list rows 22344 and
//! 22345; Engine ruling EXPORT-EDGES = C, 2026-11-12).
//!
//! Seven writers record a row's sources only in a side ledger, never as a
//! `DerivedFrom` edge: a blob version's append (its made_by), a born-from row,
//! an edit settlement, a code revision's record, its integrity fold, a
//! retained proposal and a promotion, and a fork record beside them. A row's
//! birth (`ROW_BIRTH`) names the rows its words were made from and what
//! started it. No edge walk sees any of these. An Owner's copy judges them
//! before it reads a body ([`crate::batch::export`]); the sync lineage walk
//! is to read the same ([SYNC-LINEAGE-MISSES-SIDE-LEDGER-SOURCES]).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::batch::export::{ArchiveSideFamily, side_family_key_id, side_family_rows};
use crate::code_revision::ArchivedRevisionTable;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::provenance::made_by::MadeByTrigger;

/// The side-ledger families that record the source rows of a row's body,
/// each read through its own codec.
const RECORDING_FAMILIES: [ArchiveSideFamily; 9] = [
    ArchiveSideFamily::BlobVersion,
    ArchiveSideFamily::BlobHead,
    ArchiveSideFamily::BlobBornFrom,
    ArchiveSideFamily::BlobSettlement,
    ArchiveSideFamily::CodeRevisionRecord,
    ArchiveSideFamily::CodeRevisionIntegrity,
    ArchiveSideFamily::CodeRevisionProposal,
    ArchiveSideFamily::CodeRevisionPromotion,
    ArchiveSideFamily::CodeRevisionFork,
];

/// What the side ledgers record each row's body was made from, read once in
/// one snapshot, through each family's own codec and the codec of each
/// record inside it:
///
/// - each version of a blob artifact's chain (its version and head records)
///   and each stored `blob.version` claim whose subject it is, which a replica
///   holds without the chain and before any `claim_of` edge to it: every row
///   its made_by names is a source of the artifact and of the version's ledger
///   claim, and, with the artifact, of one use of the ASSET its bytes are;
/// - a born-from row: its task, ask or skill source, of its artifact;
/// - an edit settlement: every row its record names, of its artifact;
/// - a code revision's record, integrity fold, retained proposal (the
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
/// every index repeat what these records hold. A row's birth is read per row
/// ([`Self::of`]), since every born row has one.
#[derive(Default)]
pub(crate) struct SideSources {
    /// Each row a side ledger records sources of, and every row those records
    /// name beside it. `None` when one of its records does not read.
    owned: BTreeMap<EntityId, Option<BTreeSet<EntityId>>>,
    /// Each content-addressed ASSET a blob version holds, and each recorded
    /// use of its bytes: the version's artifact and every row its made_by
    /// names, `None` when that does not read.
    uses: BTreeMap<EntityId, Vec<Option<BTreeSet<EntityId>>>>,
}

/// What the side ledgers and its birth record one row's body was made from.
pub(crate) struct RowSources<'s> {
    /// Every row its records and its birth name as a source of its body, but
    /// the row itself: each must go where the body goes. `None` when one of
    /// its records does not read: a source this vault cannot name.
    pub(crate) named: Option<BTreeSet<EntityId>>,
    /// For bytes a blob version holds (an ASSET): each recorded use of them,
    /// `None` for one whose made_by does not read. Shared bytes go where one
    /// use goes whole; empty for any other row.
    pub(crate) uses: &'s [Option<BTreeSet<EntityId>>],
}

impl SideSources {
    /// What the side ledgers record, read in the snapshot `rtxn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn read_in(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        use ArchiveSideFamily as F;
        use ArchivedRevisionTable as R;
        let mut recorded = Self::default();
        for family in RECORDING_FAMILIES {
            for (key, value) in side_family_rows(family, store, rtxn)? {
                // The row a record is of, by its table's own key: a blob
                // row's artifact, a revision's CODE_ARTIFACT, a fork's
                // SESSION.
                let at = if family == F::BlobBornFrom {
                    ENTITY_ID_LEN + 1
                } else {
                    0
                };
                let Some(owner) = side_family_key_id(&key, at) else {
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

    /// What the side ledgers read in [`Self::read_in`] and the row's birth,
    /// read in `rtxn`, record the body of `id` was made from: every input its
    /// birth's made_by names, and the task, ask or skill that started it (a
    /// run's ref names no row; its inputs are the rows it read).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn of(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: EntityId,
    ) -> Result<RowSources<'_>> {
        let mut named = match self.owned.get(&id) {
            Some(Some(rows)) => Some(rows.clone()),
            Some(None) => None,
            None => Some(BTreeSet::new()),
        };
        if let Some(named) = named.as_mut()
            && let Some(birth) = crate::store::birth_record::row_birth_in_txn(store, rtxn, &id)?
        {
            named.extend(birth.made_by.inputs.iter().map(|input| input.row));
            named.extend(
                birth
                    .made_by
                    .trigger
                    .as_ref()
                    .and_then(|trigger| match trigger {
                        MadeByTrigger::Run(_) => None,
                        MadeByTrigger::Task(_)
                        | MadeByTrigger::Ask(_)
                        | MadeByTrigger::Skill(_) => Some(trigger.row()),
                    }),
            );
            named.remove(&id);
        }
        Ok(RowSources {
            named,
            uses: self.uses.get(&id).map_or(&[], Vec::as_slice),
        })
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
}
