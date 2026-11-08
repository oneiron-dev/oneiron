//! The credential-bound host projection of the typed per-model code-run heal
//! count door (DOOR-093). HTTP, SDK, MCP and code mode all take the owner's
//! proof here, through the gate `door_admits` runs before any hook; the
//! engine door revalidates it before the model id is read. The tally is a
//! model-keyed side row with no entity, so the credential's collector lists
//! every row its reads touched beside it (`host_door_lists`): a complete
//! list, empty when the read named no entity row.
//!
//! The type-feedback door (FIX 8277) takes the same owner proof and reads
//! one program step's type feedback by its check reference.
//!
//! The corrections door (FIX 4411, 4412, 4413) takes the same owner proof
//! and reads one canonical run's correction records, with the repair policy
//! they ran under.
//!
//! The step-evidence door (FIX 4414) takes the same owner proof and reads
//! one canonical run's steps: each program, executed JavaScript,
//! observation and finished console as the run stored them, with the
//! step's correction records. Its answer lists the rows the run's answers
//! derive from, so it is released by them for the caller's destination.
//!
//! The session heal count door (FIX 4415) takes the same owner proof and
//! reads one model's tally as one live off-record session reads it.
use std::sync::Arc;

use oneiron::code_run::ProgramStepFeedbackRelease;
use oneiron::memory::code_run_doors::{
    CodeRunCorrectionsRequest, CodeRunCorrectionsView, CodeRunModelHealCountRequest,
    CodeRunModelHealCountView, CodeRunSessionModelHealCountRequest,
    CodeRunSessionModelHealCountView, CodeRunStepEvidenceRequest, CodeRunStepEvidenceView,
    CodeRunTypeDiagnosticsRequest,
};

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The CALL behind the door's public spelling (DOOR-093): a count read
/// beside the other code doors, never named a correction receipt.
const MODEL_HEAL_COUNT_VERB: &str = "vault.code.model_heal_count";

pub(crate) async fn vault_code_model_heal_count(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunModelHealCountRequest,
) -> Listed<CodeRunModelHealCountView> {
    let owner = match owner_proof(auth, server, MODEL_HEAL_COUNT_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        MODEL_HEAL_COUNT_VERB,
        move |_, _, memory| memory.code_run_model_heal_count_as(&owner, input),
    )
    .await
}

/// The CALL behind the corrections door's public spelling (FIX 4411): a run
/// read beside the other code doors, by the run's `run_ref`.
const CORRECTIONS_VERB: &str = "vault.code.corrections";

pub(crate) async fn vault_code_corrections(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunCorrectionsRequest,
) -> Listed<CodeRunCorrectionsView> {
    let owner = match owner_proof(auth, server, CORRECTIONS_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        CORRECTIONS_VERB,
        move |_, _, memory| memory.code_run_corrections_as(&owner, input),
    )
    .await
}

/// The CALL behind the session heal count door's public spelling (FIX
/// 4415): a sibling of the canonical count, which keeps its meaning, by the
/// session's `session_ref`.
const SESSION_MODEL_HEAL_COUNT_VERB: &str = "vault.code.session_model_heal_count";

pub(crate) async fn vault_code_session_model_heal_count(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunSessionModelHealCountRequest,
) -> Listed<CodeRunSessionModelHealCountView> {
    let owner = match owner_proof(auth, server, SESSION_MODEL_HEAL_COUNT_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        SESSION_MODEL_HEAL_COUNT_VERB,
        move |_, _, memory| memory.code_run_session_model_heal_count_as(&owner, input),
    )
    .await
}

/// The CALL behind the step-evidence door's public spelling (FIX 4414): a
/// run read beside the corrections door, by the run's `run_ref`.
const STEP_EVIDENCE_VERB: &str = "vault.code.step_evidence";

pub(crate) async fn vault_code_step_evidence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunStepEvidenceRequest,
) -> Listed<Option<CodeRunStepEvidenceView>> {
    let owner = match owner_proof(auth, server, STEP_EVIDENCE_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        STEP_EVIDENCE_VERB,
        move |_, _, memory| memory.code_run_step_evidence_as(&owner, input),
    )
    .await
}

/// The CALL behind the type-feedback door's public spelling (FIX 8277): a
/// read beside the other code doors, by the step's `check_ref`.
const TYPE_DIAGNOSTICS_VERB: &str = "vault.code.type_diagnostics";

pub(crate) async fn vault_code_type_diagnostics(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunTypeDiagnosticsRequest,
) -> Listed<Option<ProgramStepFeedbackRelease>> {
    let owner = match owner_proof(auth, server, TYPE_DIAGNOSTICS_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        TYPE_DIAGNOSTICS_VERB,
        move |_, _, memory| memory.code_run_type_diagnostics_as(&owner, input),
    )
    .await
}
