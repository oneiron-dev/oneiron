//! OF-493's role-holder doors (Q3 by role) as SDK verbs: a person or a bound
//! agent that holds the role a decision ask is at lists those asks, answers
//! one, or passes one up its chain. List and answer are the calls
//! `GET /v1/core/decisions/asks` and `POST /v1/core/decisions/asks/answer`
//! make (`decision_role_asks`); the climb is new here. The owner's own doors
//! stay under `/v1/owner/decisions/asks`. The generated facade handler and
//! the MCP dispatcher both call these through `host_doors`.
//!
//! Each acts as the caller: the slip's principal with its declared class,
//! human or agent. No holder, role or kind comes from the request, and an
//! owner-grade credential that names no principal holds no role here. The
//! vault verifies the writer and reads the role's holders again in the
//! snapshot it writes in. Every call goes through the host's one
//! `DecisionAsks`, so an answer wakes the ladder waiting on it.
use std::sync::Arc;

use oneiron::llm::decision::{DecisionAsk, ResolvedRole};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{DecisionAskAnswerRequest, DecisionAskClimbRequest};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.decisions.asks.answer`: the caller's answer to one ask, as a
/// holder of the role the ask is at now. An e-signature or a payment takes
/// only a person. The same answer again returns the ask as it stands; a
/// different one to an answered ask is refused.
pub(crate) async fn vault_decisions_asks_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionAskAnswerRequest,
) -> MemoryResult<DecisionAsk> {
    const VERB: &str = "vault.decisions.asks.answer";
    let holder = holder(auth, VERB)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<DecisionAsk> {
        Ok(server
            .decision_host()
            .asks()
            .answer_as(&holder, input.seq, input.answer)?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.decisions.asks.climb`: one open ask moved to the next role on its
/// chain with a live holder, up to its ceiling, by a holder of the role it
/// is at, the principal it is for, or a live owner. The role it moved to;
/// none, and the ask stays where it is, when no such role is left.
pub(crate) async fn vault_decisions_asks_climb(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionAskClimbRequest,
) -> MemoryResult<Option<ResolvedRole>> {
    const VERB: &str = "vault.decisions.asks.climb";
    let climber = holder(auth, VERB)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Option<ResolvedRole>> {
        Ok(server
            .decision_host()
            .asks()
            .climb_as(&climber, input.seq)?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `self.decisions.asks`: the open asks at a role the caller holds now,
/// oldest first, as `GET /v1/core/decisions/asks` lists them.
pub(crate) async fn self_decisions_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<DecisionAsk>> {
    const VERB: &str = "self.decisions.asks";
    let holder = holder(auth, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Vec<DecisionAsk>> {
        Ok(server.vault().decision_asks_held_by(holder)?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// Where the owner's credential does what `verb` does for a role holder: a
/// held launch resumes through `vault.fanout.resume`, and an ask is answered
/// through the owner's decision routes.
fn owner_path(verb: &str) -> &'static str {
    match verb {
        "vault.fanout.resume_as" => {
            "The owner's credential resumes a held launch through vault.fanout.resume."
        }
        _ => "The owner's credential answers through /v1/owner/decisions/asks.",
    }
}

/// The role holder `verb` acts as: the slip's principal with its declared
/// class, a person (`human`) or a bound agent (`agent`). The writer is made
/// here, never read from the request.
pub(super) fn holder(auth: &CoreAuth, verb: &str) -> MemoryResult<WriteActor> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} acts for a person or a bound agent that holds a role"),
            &[
                "Present a slip that names its principal with actor class human or agent.",
                owner_path(verb),
            ],
        )
    };
    let principal = auth
        .principal_ref()
        .and_then(|reference| EntityId::from_hex(reference).ok())
        .ok_or_else(refused)?;
    let class = match auth.actor_class() {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        _ => return Err(refused()),
    };
    Ok(WriteActor::new(principal, class))
}
