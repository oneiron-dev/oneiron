//! A code-mode durable run's self-brief port (FIX 17594, delivery slice
//! D5), the code-mode twin of a pumped run's
//! (`server/run_host_door/self_brief_port.rs`). One `execute_code` call
//! lends it to the native host, which installs the run's brief under the
//! run's single flight, binds it on the run's executor and closes it when
//! the run completes.
//!
//! The brief is installed in the server's custody under the agent the
//! call's credential stands for and the run's trusted id
//! ([`crate::api::code_mode_brief_key`]), resolved by the connection's own
//! preparation with the run's facts: no run ceiling, the run as its replay
//! run, its credential ceiling and comm reach from the call's verified slip
//! and connector, and its budget from the run's code-mode line where the
//! host holds one. An entry installs it afresh when none is installed, else
//! again at the epoch it holds, so a resumed run's birth carries the
//! delivered prefix and its source rows again, rendered nowhere (Engine
//! call RESUME C). Every committed fold batch is a boundary (Engine call
//! FOLD B): the state is resolved afresh, installed as the next epoch, and
//! its prefix staged. The backend's successful answer is the delivery
//! (Engine call DELIVERED C). A brief that does not prepare keeps the run's
//! request as it was: the prefix last handed out goes again, and nothing is
//! staged.
//!
//! The executor calls the port on the run's worker thread. Each call runs
//! on one of the server runtime's blocking threads, which blocks on that
//! runtime, and the worker waits for it. No standard mutex is held across
//! that wait.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::EntityId;
use oneiron::engine_executor::{
    BriefBoundary, BriefCandidateToken, BriefPrefix, FoldBoundary, SelfBriefPort,
};

use super::{McpCallContext, McpGatewayError};
use crate::api::ConnectionBriefReads;
use crate::server::SyncServer;
use crate::server::self_brief_custody::{
    BriefAcknowledgment, BriefCandidate, BriefKey, BriefOwner, BriefPreparation, on_server,
};

/// The port one `execute_code` call lends the native host for its durable
/// run: the call's connector, the run, and the installation the entry made
/// or installed again.
pub(crate) struct CodeModeSelfBrief {
    server: Arc<SyncServer>,
    actor: McpCallContext,
    run_id: EntityId,
    key: BriefKey,
    /// The server runtime the call arrived on.
    runtime: tokio::runtime::Handle,
    /// The installation this entry prepares and acknowledges through; `None`
    /// until [`McpCodeRunSelfBrief::install`] installed it.
    owner: Mutex<Option<BriefOwner>>,
    /// The newest candidate a preparation staged, which a delivery of its
    /// token acknowledges; `None` while the prefix the run carries needs no
    /// acknowledgment or no prefix was prepared.
    staged: Mutex<Option<StagedCandidate>>,
    /// The prefix last handed out, sent again when a later boundary's brief
    /// does not prepare.
    last: Mutex<Option<(String, Vec<EntityId>)>>,
    /// The token the next prepared prefix is named by.
    next_token: AtomicU64,
}

/// A staged candidate and the token its prefix went to the executor with.
struct StagedCandidate {
    token: BriefCandidateToken,
    candidate: BriefCandidate,
}

/// One prepared prefix: its text and source rows, and the candidate a
/// delivery acknowledges, `None` for a prefix already delivered.
struct PreparedPrefix {
    text: String,
    sources: Vec<EntityId>,
    candidate: Option<BriefCandidate>,
}

impl CodeModeSelfBrief {
    /// The port for durable run `run_id`, the id `mcp_code_run_id` derived
    /// for `actor`'s call, on the server runtime the call arrived on.
    pub(crate) fn new(server: &Arc<SyncServer>, actor: &McpCallContext, run_id: EntityId) -> Self {
        Self {
            server: Arc::clone(server),
            actor: actor.clone(),
            run_id,
            key: crate::api::code_mode_brief_key(actor, run_id),
            runtime: tokio::runtime::Handle::current(),
            owner: Mutex::new(None),
            staged: Mutex::new(None),
            last: Mutex::new(None),
            next_token: AtomicU64::default(),
        }
    }
}

impl crate::mcp::McpCodeRunSelfBrief for CodeModeSelfBrief {
    fn install(&self) -> bool {
        let (server, actor, key, run_id) = (
            Arc::clone(&self.server),
            self.actor.clone(),
            self.key.clone(),
            self.run_id,
        );
        let installed = on_server(&self.runtime, move |handle| {
            handle.block_on(install_brief(&server, &actor, key, run_id))
        })
        .and_then(|installed| installed);
        match installed {
            Ok(owner) => {
                *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner);
                true
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    run = %self.run_id.to_hex(),
                    "a code-mode run's self brief did not install; the entry runs without one"
                );
                false
            }
        }
    }

    /// Closes whatever is installed under the run's key: the host calls it
    /// under the run's single flight, so no other entry of the run holds the
    /// key then.
    fn close(&self) {
        let (server, key) = (Arc::clone(&self.server), self.key.clone());
        let closed = on_server(&self.runtime, move |handle| {
            handle.block_on(async move {
                server
                    .self_brief_sessions
                    .lock()
                    .await
                    .close_any_owner(&key);
            });
        });
        if let Err(error) = closed {
            tracing::warn!(
                kind = ?error.kind(),
                run = %self.run_id.to_hex(),
                "a completed code-mode run's self brief did not close"
            );
        }
    }
}

impl SelfBriefPort for CodeModeSelfBrief {
    /// A birth stages turn one from the state the entry installed, or
    /// carries the delivered prefix of the installed epoch again. A fold
    /// batch resolves the state afresh and installs it as the next epoch
    /// first. `None` when the installation no longer holds the key.
    fn prepare(&self, boundary: BriefBoundary) -> oneiron::Result<Option<BriefPrefix>> {
        let Some(owner) = *self.owner.lock().unwrap_or_else(PoisonError::into_inner) else {
            return Ok(None);
        };
        let fold = matches!(boundary, BriefBoundary::Fold(_));
        let (server, actor, key, run_id) = (
            Arc::clone(&self.server),
            self.actor.clone(),
            self.key.clone(),
            self.run_id,
        );
        let prepared = on_server(&self.runtime, move |handle| {
            handle.block_on(prepare_prefix(&server, &actor, &key, run_id, owner, fold))
        })
        .and_then(|prepared| prepared);
        let mut staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let token = BriefCandidateToken(self.next_token.fetch_add(1, Ordering::Relaxed));
        match prepared {
            Ok(Some(PreparedPrefix {
                text,
                sources,
                candidate,
            })) => {
                *staged = candidate.map(|candidate| StagedCandidate { token, candidate });
                *last = Some((text.clone(), sources.clone()));
                Ok(Some(BriefPrefix {
                    text,
                    sources,
                    token,
                }))
            }
            Ok(None) => {
                *staged = None;
                *last = None;
                Ok(None)
            }
            // A brief that does not prepare never fails the run's request,
            // which ran before it carried a brief: the prefix last handed out
            // goes again unchanged (none before the first), and nothing is
            // staged to acknowledge.
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    ?boundary,
                    run = %self.run_id.to_hex(),
                    "a code-mode run's self brief did not prepare; its request keeps the last prefix"
                );
                *staged = None;
                Ok(last.clone().map(|(text, sources)| BriefPrefix {
                    text,
                    sources,
                    token,
                }))
            }
        }
    }

    /// Acknowledges the staged candidate `token` names. A prefix with no
    /// staged candidate, a delivered one carried again, changes nothing. A
    /// stale answer changes nothing either, and is logged.
    /// Moves the installed brief to its next epoch as the fold batch lands,
    /// so the boundary outlives an entry that ends before its next request
    /// (a full window, a wait): the next entry's birth stages that epoch,
    /// not the prefix delivered before the fold. A miss is logged and
    /// changes nothing.
    fn folded(&self, boundary: &FoldBoundary) {
        let Some(owner) = *self.owner.lock().unwrap_or_else(PoisonError::into_inner) else {
            return;
        };
        let (server, actor, key, run_id) = (
            Arc::clone(&self.server),
            self.actor.clone(),
            self.key.clone(),
            self.run_id,
        );
        let advanced = on_server(&self.runtime, move |handle| {
            handle.block_on(advance_brief(&server, &actor, &key, run_id, owner))
        })
        .and_then(|advanced| advanced);
        match advanced {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                ?boundary,
                run = %self.run_id.to_hex(),
                "a code-mode run's self brief is no longer held; its fold did not move it"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                ?boundary,
                run = %self.run_id.to_hex(),
                "a code-mode run's self brief did not move past a fold"
            ),
        }
    }

    fn delivered(&self, token: BriefCandidateToken) {
        let candidate = {
            let mut staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
            match staged.take() {
                Some(held) if held.token == token => Some(held.candidate),
                other => {
                    *staged = other;
                    None
                }
            }
        };
        let Some(candidate) = candidate else {
            return;
        };
        let boundary = candidate.boundary();
        let server = Arc::clone(&self.server);
        let acknowledged = on_server(&self.runtime, move |handle| {
            handle.block_on(async move {
                server
                    .self_brief_sessions
                    .lock()
                    .await
                    .acknowledge(candidate)
            })
        });
        match acknowledged {
            Ok(BriefAcknowledgment::Committed) => {}
            Ok(BriefAcknowledgment::Stale) => tracing::warn!(
                ?boundary,
                run = %self.run_id.to_hex(),
                "a code-mode run's delivered self brief was stale; its custody did not move"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                run = %self.run_id.to_hex(),
                "a code-mode run's delivered self brief was not acknowledged"
            ),
        }
    }
}

/// [`crate::mcp::McpCodeRunSelfBrief::install`] on the server's runtime:
/// the run's state as it resolves now, installed afresh, or again at the
/// epoch the installation under `key` holds.
async fn install_brief(
    server: &SyncServer,
    actor: &McpCallContext,
    key: BriefKey,
    run_id: EntityId,
) -> oneiron::Result<BriefOwner> {
    let reads = super::mcp_session_reads(server, actor).await;
    let line = super::code_mode_line(server, run_id);
    let state =
        crate::api::connection_brief_state(server, actor, &reads, Some(run_id), line.as_ref())
            .map_err(unresolved)?;
    server
        .self_brief_sessions
        .lock()
        .await
        .install_or_restate(key, state)
}

/// The port's `prepare` on the server's runtime: on a `fold`, the state
/// resolved afresh and installed as the next epoch of `owner`'s
/// installation; then the prefix of the boundary the installation has yet
/// to deliver, staged from its installed state over the connection's
/// session reads and the PEOPLE its credential reads, laid out under the
/// `people` share of the agent's live board layout; or, with the installed
/// epoch delivered, that prefix's bytes and rows as they stand.
async fn advance_brief(
    server: &SyncServer,
    actor: &McpCallContext,
    key: &BriefKey,
    run_id: EntityId,
    owner: BriefOwner,
) -> oneiron::Result<bool> {
    let reads = super::mcp_session_reads(server, actor).await;
    let line = super::code_mode_line(server, run_id);
    let state =
        crate::api::connection_brief_state(server, actor, &reads, Some(run_id), line.as_ref())
            .map_err(unresolved)?;
    server
        .self_brief_sessions
        .lock()
        .await
        .advance(key, owner, state)
}

async fn prepare_prefix(
    server: &SyncServer,
    actor: &McpCallContext,
    key: &BriefKey,
    run_id: EntityId,
    owner: BriefOwner,
    fold: bool,
) -> oneiron::Result<Option<PreparedPrefix>> {
    let ConnectionBriefReads { reads, people } = crate::api::connection_brief_reads(server, actor)
        .await
        .map_err(unresolved)?;
    let people_budget_tok =
        super::board_setup::mcp_brief_people_budget(server, actor.actor_ref, false)?;
    let state = if fold {
        let line = super::code_mode_line(server, run_id);
        Some(
            crate::api::connection_brief_state(server, actor, &reads, Some(run_id), line.as_ref())
                .map_err(unresolved)?,
        )
    } else {
        None
    };
    // The fold's epoch moved as the batch landed (`folded`); a fold here
    // only restates what the run holds now at that epoch.
    let mut briefs = server.self_brief_sessions.lock().await;
    let held = match state {
        Some(state) => briefs.holds(key, owner) && briefs.restate(key, state)?,
        None => briefs.holds(key, owner),
    };
    if !held {
        return Ok(None);
    }
    let preparation =
        briefs.prepare(key, &server.vault, &reads, Some(&people), people_budget_tok)?;
    Ok(preparation.map(|preparation| match preparation {
        BriefPreparation::Staged { candidate, .. } => PreparedPrefix {
            text: candidate.prefix().to_owned(),
            sources: candidate.sources().to_vec(),
            candidate: Some(candidate),
        },
        BriefPreparation::Emitted { prefix, sources } => PreparedPrefix {
            text: prefix.to_owned(),
            sources: sources.to_vec(),
            candidate: None,
        },
    }))
}

/// A brief state or read that failed, as the port's error. Its kind is
/// logged; its message, which can quote the vault, is not.
fn unresolved(error: McpGatewayError) -> oneiron::Error {
    tracing::warn!(
        kind = error.kind,
        "a code-mode run's self brief did not resolve"
    );
    oneiron::Error::InvariantViolation("a code-mode run's self brief did not resolve")
}
