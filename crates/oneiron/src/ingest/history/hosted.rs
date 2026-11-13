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
//!
//! A cancel ([`Vault::hosted_import_cancel`]) marks an unended job
//! Cancelling. The job's worker sees it before the next conversation lands,
//! lands nothing more, surfaces what already landed in the import's review
//! and removes the staging; the job then ends Cancelled.
//!
//! The job's progress ([`HostedImportView`]) reports the canon's five phases
//! apart: upload, parse, searchable, embeddings and review.

use serde::{Deserialize, Serialize};

use super::{HistoryImportReport, HistorySource, history_import_review_id};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};

/// Each hosted import's row, by its id.
const JOBS: SideTable<[u8; 16], HostedImportJob, Named> =
    SideTable::new(&side_table::INGEST_HOSTED_IMPORT);

/// Each TURN a hosted import landed messages into: the import's id, then the
/// TURN's.
const TURNS: SideTable<[u8; 32], (), Raw> = SideTable::new(&side_table::INGEST_HOSTED_IMPORT_TURN);

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

    /// The key of one TURN this import landed messages into.
    fn turn_key(self, turn: EntityId) -> [u8; 32] {
        let mut key = [0; 32];
        key[..16].copy_from_slice(&self.0);
        key[16..].copy_from_slice(turn.as_bytes());
        key
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
    /// A cancel was asked ([`Vault::hosted_import_cancel`]). The job's worker
    /// lands no further conversation and ends the job Cancelled.
    Cancelling,
    /// Cancelled: nothing more lands and the staging is removed. What landed
    /// before stays in the import's review.
    Cancelled,
}

impl HostedImportState {
    /// The state as a job's progress names it.
    #[must_use]
    pub fn status(&self) -> HostedImportStatus {
        match self {
            Self::Staged => HostedImportStatus::Staged,
            Self::Landing => HostedImportStatus::Landing,
            Self::Landed => HostedImportStatus::Landed,
            Self::Failed(_) => HostedImportStatus::Failed,
            Self::Cancelling => HostedImportStatus::Cancelling,
            Self::Cancelled => HostedImportStatus::Cancelled,
        }
    }
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
    /// The Dreamer attempts the job's end queued for what it landed; 0 until
    /// the job ends Landed or Cancelled.
    #[serde(default)]
    pub dreamer_attempts_queued: u64,
    /// Who asked the cancel: the owner's PERSON or the grant holder.
    #[serde(default)]
    pub cancelled_by: Option<EntityId>,
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

    /// Whether nothing more lands: Landed, Failed or Cancelled.
    #[must_use]
    pub fn ended(&self) -> bool {
        matches!(
            self.state,
            HostedImportState::Landed | HostedImportState::Failed(_) | HostedImportState::Cancelled
        )
    }
}

/// Who asks to cancel a hosted import: the owner, by proof, or an actor
/// that may hold the grant a cancel needs.
#[derive(Debug, Clone, Copy)]
pub enum HostedImportCanceller<'a> {
    Owner(&'a AuthenticatedOwner),
    Holder(EntityId),
}

/// A hosted import's state, as its progress names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostedImportStatus {
    Staged,
    Landing,
    Landed,
    Failed,
    Cancelling,
    Cancelled,
}

/// Upload: what the stager wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportUpload {
    /// The staged export's bytes.
    pub bytes: u64,
    /// Their BLAKE3, as 64 lowercase hex digits.
    pub blake3: String,
}

/// Parse: what the job decoded the export to; 0 before it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportParse {
    pub conversations: u64,
    pub messages: u64,
}

/// Searchable: what has landed. A landed message is searchable at once: the
/// write that lands it indexes its words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportSearchable {
    /// Conversations landed, earliest first.
    pub conversations: u64,
    /// Messages landed new, landed again unchanged, landed as a revision,
    /// refused at the write door, and left for the next import by a race
    /// with another import.
    pub new: u64,
    pub skipped: u64,
    pub changed: u64,
    pub refused: u64,
    pub pending: u64,
}

/// Embeddings: the TURNs the import landed messages into, and how many of
/// them still wait for a vector of their text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportEmbeddings {
    /// Whether the vault has an embedding model. A vault with none embeds
    /// nothing, so nothing waits.
    pub embedder: bool,
    pub turns: u64,
    /// Turns still marked for a vector.
    pub pending: u64,
}

/// Review: where the import's claims wait for the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportReview {
    /// The review the owner approves or declines whole (`oneiron runs`);
    /// absent when the job's source is not one this build reads.
    pub review_id: Option<String>,
    /// Claims proposed from the import's words that wait in it now.
    pub waiting: u64,
    /// The Dreamer attempts the job's end queued for what it landed.
    pub dreamer_attempts_queued: u64,
}

/// One hosted import's progress, its five phases apart, because uploaded is
/// not ready (ARCH-0027 #hosted-import): `vault.imports.get`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostedImportView {
    /// The import's id, as 32 lowercase hex digits.
    pub import: String,
    /// The history source's id.
    pub source: String,
    pub state: HostedImportStatus,
    /// Why a Failed job stopped.
    pub failure: Option<String>,
    pub upload: HostedImportUpload,
    pub parse: HostedImportParse,
    pub searchable: HostedImportSearchable,
    pub embeddings: HostedImportEmbeddings,
    pub review: HostedImportReview,
    /// Who asked the cancel, as 32 hex.
    pub cancelled_by: Option<String>,
    /// When the job was made and last written (vault seconds).
    pub created_at: u64,
    pub updated_at: u64,
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
                dreamer_attempts_queued: 0,
                cancelled_by: None,
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
    /// landed with `report`: the row is Landing at that place (a Cancelling
    /// row stays Cancelling), adds the report's counts and keeps the TURNs
    /// the report names, in one write. Only the conversation after the row's
    /// place moves it, so no conversation is counted twice. An ended row is
    /// left as it is. `None` when there is no row.
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
        self.with_write_txn(|txn| {
            let Some(mut row) = JOBS.get(&self.store, txn, &id.0)? else {
                return Ok(None);
            };
            if row.ended() || cursor != row.cursor.saturating_add(1) {
                return Ok(Some(row));
            }
            if row.state != HostedImportState::Cancelling {
                row.state = HostedImportState::Landing;
            }
            row.cursor = cursor;
            row.new += u64::from(report.new);
            row.skipped += u64::from(report.skipped);
            row.changed += u64::from(report.changed);
            row.refused += u64::from(report.refused);
            row.pending += u64::from(report.pending);
            for turn in &report.turns {
                TURNS.put(&self.store, txn, &id.turn_key(*turn), &())?;
            }
            row.updated_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            JOBS.put(&self.store, txn, &id.0, &row)?;
            Ok(Some(row))
        })
    }

    /// Ends the job as `state`, Landed, Failed or Cancelled, with the
    /// Dreamer attempts its end queued. An ended row is left as it is.
    /// `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub fn hosted_import_end(
        &self,
        id: HostedImportId,
        state: HostedImportState,
        dreamer_attempts_queued: u64,
    ) -> Result<Option<HostedImportJob>> {
        self.hosted_import_update(id, |row| {
            row.state = state;
            row.dreamer_attempts_queued = dreamer_attempts_queued;
        })
    }

    /// Whether `canceller` may cancel a hosted import now: the owner by a
    /// proof that still holds, or a holder of a live Steward grant that
    /// names `delete` itself and reaches the whole vault. A grant whose verbs
    /// are left open (an Owner's or an Admin's) does not count, so only a
    /// grant the owner gives admits a holder.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn hosted_import_cancel_allowed(
        &self,
        canceller: HostedImportCanceller<'_>,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .hosted_import_canceller_in_txn(&txn, canceller)?
            .is_some())
    }

    /// Who [`Self::hosted_import_cancel_allowed`] admits in `txn`.
    fn hosted_import_canceller_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        canceller: HostedImportCanceller<'_>,
    ) -> Result<Option<EntityId>> {
        match canceller {
            HostedImportCanceller::Owner(owner) => Ok(owner.revalidate_in_txn(self, txn).ok()),
            HostedImportCanceller::Holder(holder) => Ok(self
                .whole_vault_steward_grant_with_verb_in(
                    txn,
                    holder,
                    crate::federation::grant_scope::STEWARD_DELETE_VERB,
                )?
                .map(|_| holder)),
        }
    }

    /// Asks the job's worker to cancel an unended hosted import: the row is
    /// Cancelling, naming who asked, checked in this write
    /// ([`Self::hosted_import_cancel_allowed`]). A Cancelling or ended row is
    /// returned as it is, unwritten. `None` when there is no row.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `canceller` may not cancel; a storage error.
    pub fn hosted_import_cancel(
        &self,
        canceller: HostedImportCanceller<'_>,
        id: HostedImportId,
    ) -> Result<Option<HostedImportJob>> {
        self.with_write_txn(|txn| {
            let Some(by) = self.hosted_import_canceller_in_txn(&*txn, canceller)? else {
                return Err(Error::InvalidConfig(
                    "cancelling a hosted import needs the owner or a Steward grant naming `delete` \
                     that reaches the whole vault"
                        .into(),
                ));
            };
            let Some(mut row) = JOBS.get(&self.store, txn, &id.0)? else {
                return Ok(None);
            };
            if row.ended() || row.state == HostedImportState::Cancelling {
                return Ok(Some(row));
            }
            row.state = HostedImportState::Cancelling;
            row.cancelled_by = Some(by);
            row.updated_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            JOBS.put(&self.store, txn, &id.0, &row)?;
            Ok(Some(row))
        })
    }

    /// One hosted import's progress under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, a storage error, or a row that does not
    /// decode.
    pub fn hosted_import_view_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        id: HostedImportId,
    ) -> Result<Option<HostedImportView>> {
        owner.revalidate(self)?;
        self.hosted_import_view(id)
    }

    /// One hosted import's progress, its five phases read in one snapshot.
    /// Callers admit the reader first.
    pub(crate) fn hosted_import_view(
        &self,
        id: HostedImportId,
    ) -> Result<Option<HostedImportView>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = JOBS.get(&self.store, &txn, &id.0)? else {
            return Ok(None);
        };
        let mut turns = 0_u64;
        let mut unembedded = 0_u64;
        for key in TURNS.scan_keys(&self.store, &txn, &id.0)? {
            let mut turn = [0; 16];
            turn.copy_from_slice(&key[16..]);
            turns += 1;
            if self
                .store
                .pending_embedding_marker_present(&txn, &EntityId::from_bytes_unchecked(turn))?
            {
                unembedded += 1;
            }
        }
        let review_id = row.review_id();
        let waiting = match &review_id {
            Some(review) => self
                .store
                .pending_gate_consents_for_run_in_txn(&txn, review)?
                .len(),
            None => 0,
        };
        let failure = match &row.state {
            HostedImportState::Failed(reason) => Some(reason.clone()),
            _ => None,
        };
        Ok(Some(HostedImportView {
            import: id.to_hex(),
            source: row.source.clone(),
            state: row.state.status(),
            failure,
            upload: HostedImportUpload {
                bytes: row.staged_bytes,
                blake3: blake3::Hash::from_bytes(row.staged_blake3)
                    .to_hex()
                    .to_string(),
            },
            parse: HostedImportParse {
                conversations: row.conversations,
                messages: row.messages,
            },
            searchable: HostedImportSearchable {
                conversations: row.cursor,
                new: row.new,
                skipped: row.skipped,
                changed: row.changed,
                refused: row.refused,
                pending: row.pending,
            },
            embeddings: HostedImportEmbeddings {
                embedder: self.config.embedding_model.is_some(),
                turns,
                pending: unembedded,
            },
            review: HostedImportReview {
                review_id,
                waiting: u64::try_from(waiting).unwrap_or(u64::MAX),
                dreamer_attempts_queued: row.dreamer_attempts_queued,
            },
            cancelled_by: row.cancelled_by.map(|by| by.to_hex()),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }))
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
