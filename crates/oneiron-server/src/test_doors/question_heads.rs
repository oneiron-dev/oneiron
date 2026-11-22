//! Doors for `tests/question_head_host.rs` (FIX 23586, 23587; FIX 3864): the
//! Local slot fronted by the owner's question heads over a test seat, the
//! heads it holds loaded and its prunes, and a question head's trial over a
//! ladder with a test seat on one rung.

use std::sync::Arc;
use std::time::Duration;

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{DecisionProvider, DecisionRung, ProviderPin};
use oneiron::training_pack::QuestionHeadTrial;
use oneiron::{EntityId, Result};

use crate::server::SyncServer;

/// `server` with `seat` in its ladder's `rung` slot, where a configured seat
/// of that rung sits.
///
/// # Errors
///
/// The Human rung: it is the owner's ask queue, never a seat.
pub fn with_seat(
    mut server: SyncServer,
    rung: DecisionRung,
    seat: Arc<dyn DecisionProvider>,
) -> Result<SyncServer> {
    server.decisions = server.decisions.clone().with_test_seat(rung, seat)?;
    Ok(server)
}

/// `server` with the owner's question heads in front of whatever its Local
/// slot holds, as a server attached with a `[models]` config has them.
pub fn with_question_heads(mut server: SyncServer) -> SyncServer {
    let vault = Arc::clone(server.vault());
    server.decisions = server.decisions.clone().with_test_question_heads(&vault);
    server
}

/// The typed question and version of each head the Local slot holds loaded;
/// none when no question heads front it.
pub fn loaded_question_heads(server: &SyncServer) -> Vec<(EntityId, u32)> {
    match server.decisions.test_question_heads() {
        Some(heads) => heads.loaded_questions(),
        None => Vec::new(),
    }
}

/// What the owner's bind and unbind doors do once the binding is written:
/// the Local slot drops each loaded head no binding names any more.
pub fn forget_unbound_question_heads(server: &SyncServer) {
    server.decisions.forget_unbound_question_heads();
}

/// Moves the Local slot's last prune back by `by`, as if that much time had
/// passed since it.
pub fn backdate_question_head_prune(server: &SyncServer, by: Duration) {
    if let Some(heads) = server.decisions.test_question_heads() {
        heads.backdate_prune(by);
    }
}

/// The pin of every rung the server's ladder holds, in rung order: the
/// answerer a trial is paired with.
pub fn answerer_pins(server: &SyncServer) -> Vec<ProviderPin> {
    crate::ai_host::training_pack::answerer_pins(server)
}

/// The owner's trial of question run `run`'s head against typed question
/// `question` at `question_version`, as the owner's trial door runs it:
/// open, read every held-out row, record.
///
/// # Errors
///
/// As the trial door: the engine's refusals, a malformed held-out file, a
/// head that cannot load, or storage errors.
pub fn run_question_head_trial(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    run: &EntityId,
    question: EntityId,
    question_version: u32,
) -> Result<QuestionHeadTrial> {
    crate::ai_host::training_pack::run_question_head_trial(
        server,
        owner,
        run,
        question,
        question_version,
    )
}
