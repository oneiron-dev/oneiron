//! The late-result store of code-mode type feedback (FIX 8277): one row per
//! program step, keyed by its run, step and invocation, on the vault's own
//! storage. The step writes its feedback as it stands when it ends; a check
//! still running then writes its result here once it lands, never into the
//! step's replay record. A diagnostics collection past one reply lives in a
//! body the run owns, released with the run, or with the actor's erase.
//!
//! A pending row belongs to the checker incarnation that admitted it: read
//! under any other (a restart, a restore), it is interrupted, never pending
//! for good and never clean.

use serde::{Deserialize, Serialize};

use super::super::replay::{
    CODE_RUN_REPLAY_HASH_LEN, CodeRunOutputKind, CodeRunOutputPreview, CodeRunRawOutput,
    ResultOccurrence,
};
use super::super::type_diagnostics::{
    DiagnosticCollection, DiagnosticMeasures, ProgramPreparationNote, ProgramStepFeedback,
    ProgramStepIdentity, TYPE_CHECK_INTERRUPTED, TypeCheckFacts, TypeDiagnostic, TypeDiagnostics,
    check_incarnation,
};
use super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS};
use super::routing::ExecutorStorage;
use crate::provenance::body::release_body_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// One step's feedback row. Key: (run, step, invocation).
pub(crate) type StepKey = (EntityId, u64, u64);

/// Step feedback rows.
const ROWS: SideTable<StepKey, StoredStepFeedback, Named> =
    SideTable::new(&side_table::CODE_RUN_TYPE_DIAGNOSTICS);

/// A step's check as a row keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StoredCheckState {
    Complete,
    Pending,
    Failed,
    Unavailable,
}

/// One step's feedback, as its row keeps it: flat, every field the state
/// needs and no other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredStepFeedback {
    /// The actor the run ran as, whose erase takes the row.
    pub(crate) actor: Option<EntityId>,
    /// The checker incarnation a pending check belongs to.
    pub(crate) incarnation: EntityId,
    pub(crate) note: Option<ProgramPreparationNote>,
    pub(crate) state: StoredCheckState,
    pub(crate) check: Option<TypeCheckFacts>,
    pub(crate) failure: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) detail: Option<String>,
    pub(crate) measures: Option<DiagnosticMeasures>,
    pub(crate) inline: Option<Vec<TypeDiagnostic>>,
    /// The run's body holding every diagnostic, for a collection past one
    /// reply.
    body: Option<StoredBody>,
}

/// The descriptor of a run's body a row names, as the row keeps it: every
/// field the run's own descriptor holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredBody {
    handle: String,
    path: String,
    raw_blake3: [u8; CODE_RUN_REPLAY_HASH_LEN],
    raw_len: u64,
    text: bool,
    lines: u64,
    complete: bool,
    preview_codec: String,
    preview_text: String,
    preview_truncated: bool,
}

impl StoredBody {
    fn of(output: &CodeRunRawOutput) -> Self {
        Self {
            handle: output.handle.clone(),
            path: output.path.clone(),
            raw_blake3: output.raw_blake3,
            raw_len: output.raw_len,
            text: output.kind == CodeRunOutputKind::Text,
            lines: output.lines,
            complete: output.complete,
            preview_codec: output.preview.codec.clone(),
            preview_text: output.preview.text.clone(),
            preview_truncated: output.preview.truncated,
        }
    }

    fn output(&self) -> CodeRunRawOutput {
        CodeRunRawOutput {
            handle: self.handle.clone(),
            path: self.path.clone(),
            raw_blake3: self.raw_blake3,
            raw_len: self.raw_len,
            kind: if self.text {
                CodeRunOutputKind::Text
            } else {
                CodeRunOutputKind::Binary
            },
            lines: self.lines,
            complete: self.complete,
            preview: CodeRunOutputPreview {
                codec: self.preview_codec.clone(),
                text: self.preview_text.clone(),
                truncated: self.preview_truncated,
            },
        }
    }
}

impl StoredStepFeedback {
    /// `feedback` as a row keeps it, its stored collection's body `body`.
    pub(crate) fn of(
        actor: Option<EntityId>,
        feedback: &ProgramStepFeedback,
        body: Option<CodeRunRawOutput>,
    ) -> Self {
        let mut row = Self {
            actor,
            incarnation: check_incarnation(),
            note: feedback.preparation_note.clone(),
            state: StoredCheckState::Unavailable,
            check: None,
            failure: None,
            reason: None,
            detail: None,
            measures: None,
            inline: None,
            body: None,
        };
        let collection = match &feedback.type_diagnostics {
            TypeDiagnostics::Complete {
                check,
                measures,
                diagnostics,
            } => {
                row.state = StoredCheckState::Complete;
                row.check = Some(check.clone());
                row.measures = Some(*measures);
                Some(diagnostics)
            }
            TypeDiagnostics::Pending { check } => {
                row.state = StoredCheckState::Pending;
                row.check = Some(check.clone());
                None
            }
            TypeDiagnostics::Failed {
                check,
                failure,
                measures,
                diagnostics,
            } => {
                row.state = StoredCheckState::Failed;
                row.check = Some(check.clone());
                row.failure = Some(failure.clone());
                row.measures = Some(*measures);
                Some(diagnostics)
            }
            TypeDiagnostics::Unavailable { reason, detail } => {
                row.reason = Some(reason.clone());
                row.detail.clone_from(detail);
                None
            }
        };
        match collection {
            Some(DiagnosticCollection::Inline { diagnostics }) => {
                row.inline = Some(diagnostics.clone());
            }
            Some(DiagnosticCollection::Stored { .. }) => {
                row.body = body.as_ref().map(StoredBody::of);
            }
            None => {}
        }
        row
    }

    /// The run's body that holds a stored collection whole.
    pub(crate) fn body(&self) -> Option<CodeRunRawOutput> {
        self.body.as_ref().map(StoredBody::output)
    }

    /// Whether the row's check may still land.
    pub(crate) fn pending(&self) -> bool {
        self.state == StoredCheckState::Pending
    }

    /// The step feedback this row holds for `key`: a pending check of
    /// another incarnation reads as interrupted.
    pub(crate) fn feedback(&self, key: StepKey) -> ProgramStepFeedback {
        let (run, program_seq, invocation) = key;
        let step = ProgramStepIdentity::of(run, program_seq, invocation);
        ProgramStepFeedback::new(step, self.note.clone(), self.type_diagnostics(run))
    }

    fn type_diagnostics(&self, run: EntityId) -> TypeDiagnostics {
        let collection = || match (&self.inline, self.body()) {
            (_, Some(body)) => DiagnosticCollection::Stored {
                handle: body.handle.clone(),
                occurrence: ResultOccurrence::of(Some(run), &body)
                    .map(|occurrence| occurrence.id().to_hex())
                    .unwrap_or_default(),
                byte_len: body.raw_len,
            },
            (inline, None) => DiagnosticCollection::Inline {
                diagnostics: inline.clone().unwrap_or_default(),
            },
        };
        let measures = self
            .measures
            .unwrap_or(DiagnosticMeasures { count: 0, bytes: 0 });
        match (self.state, self.check.clone()) {
            (StoredCheckState::Complete, Some(check)) => TypeDiagnostics::Complete {
                check,
                measures,
                diagnostics: collection(),
            },
            (StoredCheckState::Pending, Some(check)) if self.incarnation == check_incarnation() => {
                TypeDiagnostics::Pending { check }
            }
            (StoredCheckState::Pending, _) => {
                TypeDiagnostics::unavailable(TYPE_CHECK_INTERRUPTED, None)
            }
            (StoredCheckState::Failed, Some(check)) => TypeDiagnostics::Failed {
                check,
                failure: self.failure.clone().unwrap_or_default(),
                measures,
                diagnostics: collection(),
            },
            _ => TypeDiagnostics::Unavailable {
                reason: self.reason.clone().unwrap_or_default(),
                detail: self.detail.clone(),
            },
        }
    }
}

impl Vault {
    /// One step's feedback row.
    ///
    /// # Errors
    ///
    /// Storage errors, and a row that does not decode.
    pub(crate) fn type_diagnostics_row(&self, key: StepKey) -> Result<Option<StoredStepFeedback>> {
        let rtxn = self.store.env.read_txn()?;
        ROWS.get(&self.store, &rtxn, &key)
    }

    /// Every step feedback row of `run`, in step order.
    ///
    /// # Errors
    ///
    /// Storage errors, and a row that does not decode.
    pub(crate) fn type_diagnostics_rows(
        &self,
        run: EntityId,
    ) -> Result<Vec<(StepKey, StoredStepFeedback)>> {
        let rtxn = self.store.env.read_txn()?;
        ROWS.scan_from(&self.store, &rtxn, run.as_bytes())
    }

    /// The bodies `run`'s stored diagnostics collections are kept in, for
    /// the readers of its results: read under the run's own checks, as any
    /// result of it is. A row that cannot be read keeps none back; no read
    /// that answers today is refused for it.
    pub(crate) fn type_diagnostics_bodies(&self, run: EntityId) -> Vec<CodeRunRawOutput> {
        self.type_diagnostics_rows(run)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, row)| row.body())
            .collect()
    }

    /// Writes a step's feedback as the step ended: a pending row never
    /// takes the place of a check that has already landed.
    ///
    /// # Errors
    ///
    /// Storage errors; the side-row wall's refusal.
    pub(crate) fn put_type_diagnostics(
        &self,
        key: StepKey,
        row: &StoredStepFeedback,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if row.pending()
            && ROWS
                .get(&self.store, &wtxn, &key)?
                .is_some_and(|held| !held.pending())
        {
            return Ok(());
        }
        ROWS.put(self, &mut wtxn, &key, row)?;
        Ok(wtxn.commit()?)
    }
}

/// The program steps' type feedback of each of `runs`, as it stands, read
/// in `txn` on the vault's own rows: a wait's settled children's (FIX 8277).
/// A row that cannot be read gives none; nothing waits on a check.
pub(crate) fn runs_program_steps_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    runs: &[EntityId],
) -> Vec<ProgramStepFeedback> {
    runs.iter()
        .flat_map(|run| {
            ROWS.scan_from(store, txn, run.as_bytes())
                .unwrap_or_default()
        })
        .map(|(key, row)| row.feedback(key))
        .collect()
}

/// [`runs_program_steps_in_txn`] on a run's storage: none on a session's
/// route, whose steps keep their feedback with their run.
pub(crate) fn runs_program_steps(
    storage: &ExecutorStorage<'_>,
    runs: &[EntityId],
) -> Vec<ProgramStepFeedback> {
    let ExecutorStorage::Canonical(vault) = storage else {
        return Vec::new();
    };
    vault.store.env.read_txn().map_or_else(
        |_| Vec::new(),
        |rtxn| runs_program_steps_in_txn(&vault.store, &rtxn, runs),
    )
}

/// An erased actor's step feedback goes (FIX 8277): each row of a run that
/// ran as `actor`, and its run's occurrence of a stored collection, with
/// that occurrence's own marks.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_type_diagnostics_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let owned: Vec<(StepKey, StoredStepFeedback)> = ROWS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.actor.as_ref() == Some(actor))
        .collect();
    for ((run, program_seq, invocation), row) in owned {
        if let Some(body) = row.body() {
            let occurrence = ResultOccurrence::of(Some(run), &body)?;
            let marks = occurrence.mark_key(&body.handle);
            RAW_OUTPUT_TAINTS.delete(&vault.store, wtxn, &marks)?;
            RAW_OUTPUT_SECRETS.delete(&vault.store, wtxn, &marks)?;
            release_body_in_txn(&vault.store, wtxn, &run, &occurrence.id())?;
        }
        ROWS.delete(&vault.store, wtxn, &(run, program_seq, invocation))?;
    }
    Ok(())
}
