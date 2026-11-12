//! A hosted import (ARCH-0027 #hosted-import): an export staged inside the
//! vault's own data directory, landed by a durable job in the vault's own
//! process. This is the job's row. The host stages the bytes, decodes them
//! and runs the job (`oneiron-server`, `commands::history_import::hosted`);
//! each conversation lands through [`Vault::import_history`], with its dedup
//! and its review.
//!
//! One row per import, by its id. The row keeps the second the import lands
//! at from the moment it is made, so every pass and every restart lands into
//! the import's one review ([`history_import_review_id`]). It keeps how many
//! conversations have landed, earliest first: a restart takes the job up at
//! that place. A conversation that landed but whose place was not kept lands
//! again, and the import ledger counts its messages skipped, never twice.

use serde::{Deserialize, Serialize};

use super::{HistoryImportReport, HistorySource, history_import_review_id};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Each hosted import's row, by its id.
const JOBS: SideTable<[u8; 16], HostedImportJob, Named> =
    SideTable::new(&side_table::INGEST_HOSTED_IMPORT);

/// A hosted import's id: a UUIDv7, so ids sort by when they were made. Its
/// staging folder is named by [`Self::to_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostedImportId([u8; 16]);

impl HostedImportId {
    /// A new id.
    #[must_use]
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7().into_bytes())
    }

    /// The id as 32 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        uuid::Uuid::from_bytes(self.0).simple().to_string()
    }

    /// The id that `hex` names: exactly 32 lowercase hex digits, so one id
    /// has one folder name.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        let lowercase_hex = hex.len() == 32
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !lowercase_hex {
            return None;
        }
        uuid::Uuid::try_parse(hex)
            .ok()
            .map(|id| Self(id.into_bytes()))
    }
}

/// Where a hosted import stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostedImportState {
    /// Staged; the job has not landed anything yet.
    Staged,
    /// Landing: [`HostedImportJob::cursor`] conversations have landed.
    Landing,
    /// Every conversation landed. The staging is removed.
    Landed,
    /// The job stopped for good, for this reason; nothing more lands. What
    /// landed before stays in the import's review.
    Failed(String),
}

/// What the stager counted of a staged export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedImportStaged {
    /// The bytes it wrote, counted as it wrote them.
    pub bytes: u64,
    /// Their BLAKE3.
    pub blake3: [u8; 32],
}

/// One hosted import, as a restart finds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedImportJob {
    /// The history source's id ([`HistorySource::source_id`]).
    pub source: String,
    /// The staged export's bytes, as the stager counted them.
    pub staged_bytes: u64,
    /// Their BLAKE3.
    pub staged_blake3: [u8; 32],
    /// The second every row this import lands is learned at, fixed when the
    /// row is made: the import's review is
    /// `history_import_review_id(source, imported_at)`.
    pub imported_at: u64,
    pub state: HostedImportState,
    /// The export's conversations and messages, once the job has decoded it;
    /// 0 before.
    pub conversations: u64,
    pub messages: u64,
    /// How many conversations have landed, earliest first: where a restart
    /// takes the job up.
    pub cursor: u64,
    /// Messages landed new, landed again unchanged, landed as a revision,
    /// refused at the write door, and left by a race with another import for
    /// the next import ([`HistoryImportReport`]), summed over the landed
    /// conversations.
    pub new: u64,
    pub skipped: u64,
    pub changed: u64,
    pub refused: u64,
    pub pending: u64,
    /// When the row was made and last written (vault seconds).
    pub created_at: u64,
    pub updated_at: u64,
}

impl HostedImportJob {
    /// The history source, when its id is one this build reads.
    #[must_use]
    pub fn history_source(&self) -> Option<HistorySource> {
        HistorySource::parse(&self.source)
    }

    /// The review the import's claims wait in.
    #[must_use]
    pub fn review_id(&self) -> Option<String> {
        self.history_source()
            .map(|source| history_import_review_id(source, self.imported_at))
    }

    /// Whether nothing more lands: Landed or Failed.
    #[must_use]
    pub fn ended(&self) -> bool {
        matches!(
            self.state,
            HostedImportState::Landed | HostedImportState::Failed(_)
        )
    }
}

impl Vault {
    /// Makes the row of a staged hosted import of `source`, Staged and
    /// learned at `imported_at`, for the vault's `owner`. When the row
    /// already exists, that row is returned unchanged.
    ///
    /// # Errors
    ///
    /// An owner who no longer holds the vault, or a storage error.
    pub fn hosted_import_create(
        &self,
        owner: &AuthenticatedOwner,
        id: HostedImportId,
        source: HistorySource,
        staged: HostedImportStaged,
        imported_at: u64,
    ) -> Result<HostedImportJob> {
        owner.revalidate(self)?;
        self.with_write_txn(|txn| {
            if let Some(row) = JOBS.get(&self.store, txn, &id.0)? {
                return Ok(row);
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let row = HostedImportJob {
                source: source.source_id().to_owned(),
                staged_bytes: staged.bytes,
                staged_blake3: staged.blake3,
                imported_at,
                state: HostedImportState::Staged,
                conversations: 0,
                messages: 0,
                cursor: 0,
                new: 0,
                skipped: 0,
                changed: 0,
                refused: 0,
                pending: 0,
                created_at: now,
                updated_at: now,
            };
            JOBS.put(&self.store, txn, &id.0, &row)?;
            Ok(row)
        })
    }

    /// One hosted import's row.
    ///
    /// # Errors
    ///
    /// A storage error, or a row that does not decode.
    pub fn hosted_import(&self, id: HostedImportId) -> Result<Option<HostedImportJob>> {
        let txn = self.store.env.read_txn()?;
        JOBS.get(&self.store, &txn, &id.0)
    }

    /// Every hosted import's row, oldest first.
    ///
    /// # Errors
    ///
    /// A storage error, or a row that does not decode.
    pub fn hosted_imports(&self) -> Result<Vec<(HostedImportId, HostedImportJob)>> {
        let txn = self.store.env.read_txn()?;
        Ok(JOBS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(id, row)| (HostedImportId(id), row))
            .collect())
    }

    /// Records what the job decoded the export to. An ended row is left as
    /// it is. `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub fn hosted_import_decoded(
        &self,
        id: HostedImportId,
        conversations: u64,
        messages: u64,
    ) -> Result<Option<HostedImportJob>> {
        self.hosted_import_update(id, |row| {
            row.conversations = conversations;
            row.messages = messages;
        })
    }

    /// Records that conversation `cursor` (counted from 1, earliest first)
    /// landed with `report`: the row is Landing at that place and adds the
    /// report's counts. Only the conversation after the row's place moves it,
    /// so no conversation is counted twice. An ended row is left as it is.
    /// `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub fn hosted_import_landed(
        &self,
        id: HostedImportId,
        cursor: u64,
        report: &HistoryImportReport,
    ) -> Result<Option<HostedImportJob>> {
        self.hosted_import_update(id, |row| {
            if cursor != row.cursor.saturating_add(1) {
                return;
            }
            row.state = HostedImportState::Landing;
            row.cursor = cursor;
            row.new += u64::from(report.new);
            row.skipped += u64::from(report.skipped);
            row.changed += u64::from(report.changed);
            row.refused += u64::from(report.refused);
            row.pending += u64::from(report.pending);
        })
    }

    /// Ends the job as `state`, Landed or Failed. An ended row is left as it
    /// is. `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub fn hosted_import_end(
        &self,
        id: HostedImportId,
        state: HostedImportState,
    ) -> Result<Option<HostedImportJob>> {
        self.hosted_import_update(id, |row| row.state = state)
    }

    /// Changes an unended row in one write. An ended row is returned as it
    /// is, unwritten.
    fn hosted_import_update(
        &self,
        id: HostedImportId,
        change: impl FnOnce(&mut HostedImportJob),
    ) -> Result<Option<HostedImportJob>> {
        self.with_write_txn(|txn| {
            let Some(mut row) = JOBS.get(&self.store, txn, &id.0)? else {
                return Ok(None);
            };
            if row.ended() {
                return Ok(Some(row));
            }
            change(&mut row);
            row.updated_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            JOBS.put(&self.store, txn, &id.0, &row)?;
            Ok(Some(row))
        })
    }
}
