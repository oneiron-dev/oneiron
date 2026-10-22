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
//!
//! Each lists its rows (`host_door_lists`). An ask lives in the decision
//! queue's side table, its question as the ladder that queued it framed it:
//! it lists the principal it is for, the evidence it carries and the work it
//! decides. A role's holders are the roster's, read to admit, and a climb
//! lists none.
use std::sync::Arc;

use oneiron::llm::decision::{DecisionAsk, ResolvedRole};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{DecisionAskAnswerRequest, DecisionAskClimbRequest};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::decision_role_asks::decision_ask_refs;
use super::host_doors::support::{Listed, internal, naming};
use crate::api::scoped_auth::lane_reads_each;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.decisions.asks.answer`: the caller's answer to one ask, as a
/// holder of the role the ask is at now. An e-signature or a payment takes
/// only a person. The same answer again returns the ask as it stands; a
/// different one to an answered ask is refused.
async fn vault_decisions_asks_answer_answer(
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

/// [`vault_decisions_asks_answer_answer`], listing the rows its ask stands on.
pub(crate) async fn vault_decisions_asks_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionAskAnswerRequest,
) -> Listed<DecisionAsk> {
    naming(
        vault_decisions_asks_answer_answer(server, auth, input).await,
        |ask| ask_rows(ask).collect(),
    )
}

/// `vault.decisions.asks.climb`: one open ask moved to the next role on its
/// chain with a live holder, up to its ceiling, by a holder of the role it
/// is at, the principal it is for, or a live owner. The role it moved to;
/// none, and the ask stays where it is, when no such role is left.
async fn vault_decisions_asks_climb_answer(
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

/// [`vault_decisions_asks_climb_answer`], listing no row.
pub(crate) async fn vault_decisions_asks_climb(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionAskClimbRequest,
) -> Listed<Option<ResolvedRole>> {
    naming(
        vault_decisions_asks_climb_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

/// `self.decisions.asks`: the open asks at a role the caller holds now,
/// oldest first, as `GET /v1/core/decisions/asks` lists them.
async fn self_decisions_asks_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<DecisionAsk>> {
    const VERB: &str = "self.decisions.asks";
    let holder = holder(auth, VERB)?.entity_ref();
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || -> MemoryResult<Vec<DecisionAsk>> {
        let asks = server.vault().decision_asks_held_by(holder)?;
        // FIX 8174: the asks the caller's own lane reads whole, as
        // `GET /v1/core/decisions/asks` lists them.
        lane_reads_each(server.vault(), &auth, asks, decision_ask_refs)
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error())
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// [`self_decisions_asks_answer`], listing the rows each ask stands on.
pub(crate) async fn self_decisions_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<DecisionAsk>> {
    naming(
        self_decisions_asks_answer(server, auth, input).await,
        |asks| asks.iter().flat_map(ask_rows).collect(),
    )
}

/// The rows an ask stands on: the principal it is for (none once erased),
/// its evidence and the work it decides.
fn ask_rows(ask: &DecisionAsk) -> impl Iterator<Item = EntityId> + '_ {
    ask.principal
        .id()
        .into_iter()
        .chain(ask.evidence.iter().copied())
        .chain(ask.correlation)
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
