//! OF-493's role-holder doors (Q3 by role): a person or a bound agent that
//! holds the role a decision ask is at answers it, passes it up its chain, or
//! lists the open asks put to it. The owner's own doors stay under
//! `/v1/owner/decisions/asks`. The generated HTTP facade handler and the MCP
//! dispatcher both call these through `host_doors`.
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
use oneiron::receipt::{DecisionAskAnswerRequest, DecisionAskClimbRequest, DecisionAskListRequest};
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

/// `self.decisions.asks`: a page of the open asks put to the caller, oldest
/// first: those whose role's holders, as the ask was queued or last climbed,
/// name the caller.
pub(crate) async fn self_decisions_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionAskListRequest,
) -> MemoryResult<Vec<DecisionAsk>> {
    const VERB: &str = "self.decisions.asks";
    let holder = holder(auth, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Vec<DecisionAsk>> {
        Ok(server
            .decision_host()
            .asks()
            .open_for(holder, input.after, input.page_limit())?)
    })
    .await
    .map_err(|_| internal(VERB))?
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
                "The owner's credential answers through /v1/owner/decisions/asks.",
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
