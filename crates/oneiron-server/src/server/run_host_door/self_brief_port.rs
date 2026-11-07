//! A pumped run's self-brief port (FIX 17594, delivery slice D3): its
//! native executor asks the port for the run's brief prefix at the run's
//! birth in each entry and past each fold batch the run commits, and tells
//! it once the backend answered a request that carried the prefix.
//!
//! The brief is installed in the server's one custody owner under the agent
//! and the run's own board connection, `run:<run id>`, which is how the
//! run's door names that connection and its `describe(self)` finds it. A
//! live run's first entry installs it afresh and each later entry installs
//! it again at the epoch it holds; the installation lives with the live run
//! and closes as that run retires, never with the door (Engine call RESUME
//! C). A birth whose installation holds a delivered prefix for its epoch, a
//! resume after a wait, carries exactly those bytes and their source rows
//! again, rendered nowhere. Every committed fold batch is a boundary (Engine
//! call FOLD B): the run's state is resolved afresh with what the door holds
//! now, installed as the next epoch, and its prefix staged. Several
//! boundaries before one request each stage; the newest candidate is the
//! one a delivery acknowledges. The backend's successful answer is the
//! delivery (Engine call DELIVERED C), and the executor sends the same
//! candidate on each retry until then.
//!
//! The executor calls the port on the run's own thread. Each call runs on
//! one of the server runtime's blocking threads, which blocks on that
//! runtime, and the run's thread waits for it, as the door's rows do. No
//! standard mutex is held across that wait.

use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::engine_executor::{
    BriefBoundary, BriefCandidateToken, BriefPrefix, FoldBoundary, SelfBriefPort,
};

use super::{
    Arc, BriefHostFacts, EntityId, MemoryError, Mutex, PoisonError, RunAdmission, RunHostDoor,
    StreamConnectionId, SyncServer, WriteActor,
};
use crate::server::self_brief_custody::{
    BriefAcknowledgment, BriefCandidate, BriefKey, BriefOwner, BriefPreparation, on_server,
};

/// The port one entry of a pumped run lends its executor: the run's door,
/// for what it holds and its runtime, and the installation of the run's
/// brief the entry made or installed again.
pub(crate) struct ResidentSelfBrief {
    door: Arc<RunHostDoor>,
    key: BriefKey,
    owner: BriefOwner,
    /// The newest candidate a preparation staged, which a delivery of its
    /// token acknowledges; `None` while the prefix the run carries needs no
    /// acknowledgment or no prefix was prepared.
    staged: Mutex<Option<StagedCandidate>>,
    /// The prefix last handed out, sent again when a later boundary's
    /// brief does not prepare.
    last: Mutex<Option<(String, Vec<EntityId>)>>,
    /// The token the next prepared prefix is named by.
    next_token: AtomicU64,
}

/// A staged candidate and the token its prefix went to the executor with.
struct StagedCandidate {
    token: BriefCandidateToken,
    candidate: BriefCandidate,
}

/// What the run's door holds for its brief now: the line its entry spends
/// on and the facts its `describe(self)` is resolved with.
struct DoorFacts {
    line: Option<RunAdmission>,
    host: BriefHostFacts,
}

/// One prepared prefix: its text and source rows, and the candidate a
/// delivery acknowledges, `None` for a prefix already delivered.
struct PreparedPrefix {
    text: String,
    sources: Vec<EntityId>,
    candidate: Option<BriefCandidate>,
}

impl RunHostDoor {
    /// Installs the run's self brief for the entry about to run, resolved
    /// from what the door holds now (its entry's line, run ceiling and pins)
    /// and the run's own session reads, and answers the port the entry's
    /// executor carries the brief through. A live run's first entry (`held`
    /// is `None`) installs afresh, replacing whatever an earlier live run of
    /// the same run left under the key; a later entry installs again at the
    /// epoch `held`'s installation holds, its delivered prefix kept. `None`
    /// when `held` no longer holds the key: the entry's requests carry no
    /// brief. Blocking: call it on the run's thread.
    ///
    /// # Errors
    ///
    /// The brief's state did not resolve or install, or the server's runtime
    /// did not answer.
    pub(crate) fn install_self_brief(
        self: &Arc<Self>,
        held: Option<BriefOwner>,
    ) -> oneiron::Result<Option<ResidentSelfBrief>> {
        let facts = self.self_brief_facts();
        let server = Arc::clone(&self.server);
        let (actor, board) = (self.actor, self.board.clone());
        let installed = on_server(&self.runtime, move |handle| {
            handle.block_on(install_brief(&server, actor, &board, held, facts))
        })??;
        if installed.is_none() {
            tracing::warn!(
                run = %self.run_id.to_hex(),
                "a newer installation holds a pumped run's self brief; this entry carries none"
            );
        }
        Ok(installed.map(|owner| ResidentSelfBrief {
            door: Arc::clone(self),
            key: brief_key(self.actor, &self.board),
            owner,
            staged: Mutex::new(None),
            last: Mutex::new(None),
            next_token: AtomicU64::default(),
        }))
    }

    /// What the door holds for the run's brief now.
    fn self_brief_facts(&self) -> DoorFacts {
        DoorFacts {
            line: self
                .line
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            host: self.brief_host_facts(),
        }
    }
}

impl ResidentSelfBrief {
    /// The installation this port prepares and acknowledges through: the
    /// key and its owner, which the run's live run closes as it retires.
    pub(crate) fn installation(&self) -> (BriefKey, BriefOwner) {
        (self.key.clone(), self.owner)
    }
}

impl SelfBriefPort for ResidentSelfBrief {
    /// A birth stages the installed epoch (turn one, or a fold that moved it
    /// and was not yet delivered), or carries the delivered prefix of the
    /// installed epoch again. A fold restates what the door holds now at the
    /// epoch `folded` moved to, and stages it. `None` when the installation
    /// no longer holds the key.
    fn prepare(&self, boundary: BriefBoundary) -> oneiron::Result<Option<BriefPrefix>> {
        let fold = matches!(boundary, BriefBoundary::Fold(_)).then(|| self.door.self_brief_facts());
        let server = Arc::clone(&self.door.server);
        let (actor, board, owner) = (self.door.actor, self.door.board.clone(), self.owner);
        let prepared = on_server(&self.door.runtime, move |handle| {
            handle.block_on(prepare_prefix(&server, actor, &board, owner, fold))
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
                    run = %self.door.run_id.to_hex(),
                    "a pumped run's self brief did not prepare; its request keeps the last prefix"
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

    /// Moves the installed brief to its next epoch as the fold batch lands,
    /// from what the door holds now, so the boundary outlives an entry that
    /// ends before its next request: the next entry's birth stages that
    /// epoch, not the prefix delivered before the fold. A miss is logged and
    /// changes nothing.
    fn folded(&self, boundary: &FoldBoundary) {
        let facts = self.door.self_brief_facts();
        let server = Arc::clone(&self.door.server);
        let (actor, board, owner) = (self.door.actor, self.door.board.clone(), self.owner);
        let advanced = on_server(&self.door.runtime, move |handle| {
            handle.block_on(advance_brief(&server, actor, &board, owner, facts))
        })
        .and_then(|advanced| advanced);
        match advanced {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                ?boundary,
                run = %self.door.run_id.to_hex(),
                "a pumped run's self brief is no longer held; its fold did not move it"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                ?boundary,
                run = %self.door.run_id.to_hex(),
                "a pumped run's self brief did not move past a fold"
            ),
        }
    }

    /// Acknowledges the staged candidate `token` names. A prefix with no
    /// staged candidate, a delivered one carried again, changes nothing. A
    /// stale answer changes nothing either, and is logged.
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
        let server = Arc::clone(&self.door.server);
        let acknowledged = on_server(&self.door.runtime, move |handle| {
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
                run = %self.door.run_id.to_hex(),
                "a pumped run's delivered self brief was stale; its custody did not move"
            ),
            Err(error) => tracing::warn!(
                %error,
                run = %self.door.run_id.to_hex(),
                "a pumped run's delivered self brief was not acknowledged"
            ),
        }
    }
}

/// [`RunHostDoor::install_self_brief`] on the server's runtime: the run's
/// state as it resolves now, installed afresh with no `held` installation,
/// else again at `held`'s epoch while it holds the key.
async fn advance_brief(
    server: &SyncServer,
    actor: WriteActor,
    board: &StreamConnectionId,
    owner: BriefOwner,
    facts: DoorFacts,
) -> oneiron::Result<bool> {
    let reads = crate::api::run_session_reads(server, actor, board).await;
    let state =
        crate::api::run_brief_state(server, actor, facts.line.as_ref(), &reads, &facts.host)
            .map_err(unresolved)?;
    let key = brief_key(actor, board);
    server
        .self_brief_sessions
        .lock()
        .await
        .advance(&key, owner, state)
}

async fn install_brief(
    server: &SyncServer,
    actor: WriteActor,
    board: &StreamConnectionId,
    held: Option<BriefOwner>,
    facts: DoorFacts,
) -> oneiron::Result<Option<BriefOwner>> {
    let reads = crate::api::run_session_reads(server, actor, board).await;
    let state =
        crate::api::run_brief_state(server, actor, facts.line.as_ref(), &reads, &facts.host)
            .map_err(unresolved)?;
    let key = brief_key(actor, board);
    let mut briefs = server.self_brief_sessions.lock().await;
    match held {
        None => briefs.install_fresh(key, state).map(Some),
        Some(owner) => {
            Ok((briefs.holds(&key, owner) && briefs.restate(&key, state)?).then_some(owner))
        }
    }
}

/// The port's `prepare` on the server's runtime: with `fold`'s
/// facts, the state resolved afresh and installed as the next epoch of
/// `owner`'s installation; then the prefix of the boundary the installation
/// has yet to deliver, staged from its installed state over the run's own
/// session reads and the PEOPLE its agent's lane reads, laid out under the
/// `people` share of the agent's layout; or, with the installed epoch
/// delivered, that prefix's bytes and rows as they stand.
async fn prepare_prefix(
    server: &SyncServer,
    actor: WriteActor,
    board: &StreamConnectionId,
    owner: BriefOwner,
    fold: Option<DoorFacts>,
) -> oneiron::Result<Option<PreparedPrefix>> {
    let reads = crate::api::run_session_reads(server, actor, board).await;
    let people = crate::api::run_brief_people(server, actor).map_err(unresolved)?;
    let people_budget_tok = crate::api::run_brief_people_budget(server, actor.entity_ref())?;
    let state = fold
        .map(|facts| {
            crate::api::run_brief_state(server, actor, facts.line.as_ref(), &reads, &facts.host)
        })
        .transpose()
        .map_err(unresolved)?;
    let key = brief_key(actor, board);
    let mut briefs = server.self_brief_sessions.lock().await;
    // The fold's epoch moved as the batch landed (`folded`); a fold here
    // only restates what the door holds now at that epoch.
    let held = match state {
        Some(state) => briefs.holds(&key, owner) && briefs.restate(&key, state)?,
        None => briefs.holds(&key, owner),
    };
    if !held {
        return Ok(None);
    }
    let preparation = briefs.prepare(
        &key,
        &server.vault,
        &reads,
        Some(&people),
        people_budget_tok,
    )?;
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

/// The key a run's brief is installed under: its agent and its own board
/// connection.
fn brief_key(actor: WriteActor, board: &StreamConnectionId) -> BriefKey {
    (actor.entity_ref(), board.0.clone())
}

/// A brief state or PEOPLE read that failed, as the port's error. Its code
/// is logged; its text, which can quote the vault, is not.
fn unresolved(error: MemoryError) -> oneiron::Error {
    tracing::warn!(code = %error.code, "a pumped run's self brief did not resolve");
    oneiron::Error::InvariantViolation("a pumped run's self brief did not resolve")
}
