//! The typed per-model code-run heal count door (DOOR-093). It projects the
//! durable tally the executor already keeps, `Vault::code_run_model_heal_count`:
//! how many durable turns of this vault each model needed wire healing for.
//! It is not a correction receipt. The tally stores no run, turn,
//! checkpoint, repair flag or retry outcome, so the door answers none.
//!
//! Authority is the owner's live proof alone (`Memory::code_run_owner`). The
//! tally spans every run of the vault and names no caller, so no run handle
//! or run caller reads it.
//!
//! The typed type-feedback door (FIX 8277) reads one program step's type
//! feedback by its check reference, as the owner: the late result of a
//! check its run never waited on, without running anything again. A step
//! of a session-bound run is read on the session the request names, bound
//! for the owner (FIX 10389).
//!
//! The typed corrections door (CODE-RUNTIME-02 slice 1: FIX 4411, 4412,
//! 4413) reads one canonical run's durable correction records, one per
//! model response its live REPL normalized, with the repair policy they ran
//! under. It is the owner's read, by the same live proof.
//!
//! The typed step-evidence door (CODE-RUNTIME-02 slice 2: FIX 4414) reads
//! one canonical run's steps, each with the program it ran, the JavaScript
//! a TypeScript program ran as, its observation, the console a finished
//! program printed, and its correction records. Each body is the run's own,
//! read under the run's checks. The session heal count door (FIX 4415)
//! reads one model's tally as one live off-record session the owner is in
//! reads it: the canonical tally plus that session's own delta. Both are
//! the owner's reads, by the same live proof.

mod types;

pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::code_run::{
    CODE_RUN_CORRECTION_POLICY, ProgramStepFeedbackRelease, parse_check_ref,
    session_model_heal_count, session_type_diagnostics_row,
};
use crate::consent::AuthenticatedOwner;
use crate::engine_executor::step_evidence_page;
use crate::entity_id::EntityId;
use oneiron_model::llm::ModelId;

impl Memory<'_> {
    /// The CALL behind who reads the tally: the owner alone, by the
    /// caller's own proof. The proof must be live on this vault and name
    /// this handle's own human actor. The tally is an aggregate over every
    /// run, keyed by model alone, so no narrower caller can be filtered to
    /// its own share of it.
    fn code_run_owner(&self, owner: &AuthenticatedOwner, read: &str) -> MemoryResult<()> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{read} is read as the authenticated owner"),
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// `vault.code.model_heal_count`: the owner reads this vault's own
    /// healed-turn tally for one model, zero when it holds none.
    ///
    /// The CALL behind the scope: the canonical tally of this vault alone,
    /// as the executor commits it with each durable turn. No off-record
    /// session overlay, other node or other vault is summed in.
    pub fn code_run_model_heal_count_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunModelHealCountRequest,
    ) -> MemoryResult<CodeRunModelHealCountView> {
        self.code_run_owner(owner, "the model heal count")?;
        let model = heal_count_model(input.model_id)?;
        let count = self.vault.code_run_model_heal_count(&model)?;
        Ok(CodeRunModelHealCountView {
            model_id: count.model_id,
            healed_turns: count.healed_turns,
        })
    }

    /// `vault.code.session_model_heal_count`: the owner reads one model's
    /// healed-turn tally as one live off-record session reads it (FIX
    /// 4415): the vault's canonical tally, the session's own delta, and the
    /// two summed with checked arithmetic.
    ///
    /// The CALL behind the scope: the session the request names, bound for
    /// the owner as the owner manages it, a room's only for a member. A
    /// session that is unknown, closing or gone is refused as such, never
    /// read as the canonical tally alone. No other session is summed in.
    pub fn code_run_session_model_heal_count_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunSessionModelHealCountRequest,
    ) -> MemoryResult<CodeRunSessionModelHealCountView> {
        self.code_run_owner(owner, "a session's model heal count")?;
        let model = heal_count_model(input.model_id)?;
        let session = self
            .vault
            .off_record_session_vault()
            .bind_for(&input.session_ref, self.actor)?;
        let count = session_model_heal_count(&session, &model)?;
        Ok(CodeRunSessionModelHealCountView {
            session_ref: input.session_ref,
            model_id: count.model_id,
            canonical_healed_turns: count.canonical_healed_turns,
            session_healed_turns: count.session_healed_turns,
            healed_turns: count.healed_turns,
        })
    }
}

impl Memory<'_> {
    /// `vault.code.type_diagnostics`: the owner reads one program step's
    /// type feedback by its `check_ref`, as it stands now: a check that
    /// landed after its step answers under the step's identity, a pending
    /// one of a checker that is gone answers interrupted. Nothing runs again.
    /// `None` for a reference no step's feedback was kept under. It answers
    /// the feedback released whole; an MCP answer whose own release check
    /// holds it for its destination gives it withheld (FIX 10390).
    ///
    /// The CALL behind the scope (FIX 10389, CALLS "session feedback lives
    /// on the session route only"): with no `session_ref`, the canonical
    /// rows of this vault. With one, the owner's proof first, then the
    /// session it names, bound for the owner as the owner manages it, and
    /// the rows its runs keep on its route; a session that is gone or
    /// closing is refused as such, never read again on the vault's rows.
    ///
    /// A foreign program's or a pack script's run keeps no result store, so
    /// its row holds its whole collection: this read gives every diagnostic
    /// of it, with no replay record (CALLS "foreign feedback late read scope
    /// = run owner"). The reader is the owner by this proof, never the
    /// caller who ran the program for that alone.
    pub fn code_run_type_diagnostics_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunTypeDiagnosticsRequest,
    ) -> MemoryResult<Option<ProgramStepFeedbackRelease>> {
        self.code_run_owner(owner, "a step's type feedback")?;
        let key = parse_check_ref(&input.check_ref).ok_or_else(|| {
            MemoryError::bad_request(
                "check_ref is not a step check reference \
                 (type_diagnostics:<run>:<step>:<invocation>)",
            )
        })?;
        let row = match input.session_ref.as_deref() {
            None => self.vault.type_diagnostics_row(key)?,
            Some(session_ref) => {
                let session = self
                    .vault
                    .off_record_session_vault()
                    .bind_for(session_ref, self.actor)?;
                session_type_diagnostics_row(&session, key)?
            }
        };
        Ok(row.map(|row| ProgramStepFeedbackRelease::Released(row.feedback(key))))
    }
}

impl Memory<'_> {
    /// `vault.code.corrections`: the owner reads one page of a code run's
    /// correction records, oldest first, with the repair policy the executor
    /// runs. Each record names the run, step, attempt, configured model,
    /// repairs, outcome and, for a committed step, its checkpoint. A run
    /// with no records in the page answers an empty page, never not found.
    ///
    /// The CALL behind the scope: the canonical rows of this vault alone. A
    /// private session's records stay on that session's route and are not
    /// read here.
    pub fn code_run_corrections_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunCorrectionsRequest,
    ) -> MemoryResult<CodeRunCorrectionsView> {
        self.code_run_owner(owner, "a run's correction records")?;
        let run = code_run_id(&input.run_ref)?;
        let steps = step_page_limit(input.limit)?;
        let page = self
            .vault
            .code_run_corrections(run, input.after_step, steps)?;
        Ok(CodeRunCorrectionsView {
            run_ref: run.to_hex(),
            policy: CODE_RUN_CORRECTION_POLICY,
            records: page.records,
            next_after_step: page.next_after_step,
        })
    }

    /// `vault.code.step_evidence`: the owner reads one page of a canonical
    /// code run's steps, oldest first, paged as its correction records are
    /// (FIX 4414). Each step that committed a checkpoint gives the program
    /// the normalization left, the JavaScript a TypeScript program ran as,
    /// the observation it committed and the console a finished program
    /// printed beside its answer; each step gives its correction records.
    /// `None` for a run this vault holds no replay of.
    ///
    /// The CALL behind the scope: the canonical rows of this vault alone, as
    /// the corrections door reads. Each body is the run's own stored body,
    /// read as model context reads it: withheld while the secret scan marked
    /// it or it is under taint for the run, a program's known custody values
    /// masked, and past one reply's bytes its head and the line naming the
    /// whole body. Every row the run's answers, folds and epochs derive from
    /// must read on this handle's credential and locality, and is listed as
    /// a producer, so the answer is released by them for its destination. A
    /// page step whose derived fold or epoch was withdrawn refuses. The
    /// guest's own result reads admit no more paths than before.
    pub fn code_run_step_evidence_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunStepEvidenceRequest,
    ) -> MemoryResult<Option<CodeRunStepEvidenceView>> {
        self.code_run_owner(owner, "a run's step evidence")?;
        let run = code_run_id(&input.run_ref)?;
        let steps = step_page_limit(input.limit)?;
        let Some(page) = step_evidence_page(self.vault, run, input.after_step, steps)? else {
            return Ok(None);
        };
        for source in &page.sources {
            if self.get_entity(&source.to_hex())?.value.is_none() {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a run step evidence source is no longer readable",
                    &[],
                ));
            }
        }
        Ok(Some(CodeRunStepEvidenceView {
            run_ref: run.to_hex(),
            completed_steps: page.completed_steps,
            policy: CODE_RUN_CORRECTION_POLICY,
            steps: page.steps,
            next_after_step: page.next_after_step,
        }))
    }
}

/// The code run a door request's `run_ref` names: 32 hex, outer whitespace
/// aside.
fn code_run_id(run_ref: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(run_ref.trim())
        .map_err(|_| MemoryError::bad_request("run_ref must be a 32-hex code-run id"))
}

/// The steps one page of a run's correction records or step evidence
/// reads: [`CODE_RUN_CORRECTIONS_DEFAULT_STEPS`] when the request names no
/// limit, at most [`CODE_RUN_CORRECTIONS_MAX_STEPS`]; a zero limit is
/// refused.
fn step_page_limit(limit: Option<u32>) -> MemoryResult<u32> {
    match limit {
        Some(0) => Err(MemoryError::bad_request("limit must be positive")),
        Some(limit) => Ok(limit.min(CODE_RUN_CORRECTIONS_MAX_STEPS)),
        None => Ok(CODE_RUN_CORRECTIONS_DEFAULT_STEPS),
    }
}

/// The CALL behind the model a tally is read for: the exact
/// `provider/name@revision` grammar of `ModelId`, as given. Nothing is
/// trimmed, no latest revision is looked up and no provider wire label is
/// mapped to a configured model. A valid id with no tally reads as zero
/// (`Vault::code_run_model_heal_count`), never as not found.
fn heal_count_model(model_id: String) -> MemoryResult<ModelId> {
    ModelId::new(model_id).map_err(|error| {
        MemoryError::bad_request(format!(
            "model_id is not a provider/name@revision model id: {error}"
        ))
    })
}
