//! The engine door that continues an outside session on this node (census
//! L10-17): from the hand-off commit the local CLI pushed to a custody repo
//! this node serves, plus a read-only check of the same.
//!
//! Canon (owner ruling 2026-10-19, CROSS-ARCH-0024 #continue-in-cloud):
//! "Continue in Oneiron Cloud ... works for outside agents too, such as a
//! local Claude Code. The memory is already in the vault. The workspace
//! travels through repo custody. The agent resumes with the user's own
//! login, within the provider's terms." Steal row CLR-001 (adopted): "Check
//! the destination's model and login first ... Build it on the existing
//! session, attempt, workspace artifact, queue and host adapter. Vault
//! identity and grants stay stable; the destination gets its own narrower
//! authority, never a copied home directory. Test a lost upload ... Never
//! promise process or memory migration."
//!
//! WHO = B (Engine ruling Sat 14 Nov 20:57): the owner may start a
//! continue, and so may an outside agent whose live Grant names
//! `vault.runners.continue`, checked live in the door's own transaction.
//!
//! The hand-over is a NEW vendor session primed from the vault's memory and
//! the pushed workspace; no process, home directory or session file moves.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::LlmBackend;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::authority::OwnerActKind;
use crate::checkout::lease::transactions::claim_in_txn;
use crate::checkout::{CheckoutClaimRequest, CheckoutError, CheckoutId, CheckoutTaskClass};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{CodeError, Error};
use crate::git_wire::{GitRefName, GitWire};
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::origin::smart_http::origin_repo_dir;

use super::staged_input::persist_staged_input_in_txn;
use super::work_binding::{
    BindRunnerWork, RunnerSeatChoice, RunnerSeatSearch, RunnerWorkBindingId, RunnerWorkBound,
    head_hop,
};
use super::{
    ByoEndpointBackendFactory, ByoEndpointSpec, ByoaDispatcher, ByoaEgressLease, ByoaEgressPort,
    ByoaError, ByoaResult, ProviderAdapterRegistry, RunnerSeat, RunnerSeatPolicy,
    SkippedRunnerSeat, SkippedRunnerSeatView, StagedJob,
};

/// The step key the hand-over binds its runner work under.
const CONTINUE_STEP_KEY: &str = "byoa.runner.continue";

/// The domain a hand-over id is derived under.
const HAND_OVER_DOMAIN: &str = "oneiron.byoa.runner-continue.v1";

/// The domain a hand-over checkout id is derived under.
const HAND_OVER_CHECKOUT_DOMAIN: &str = "oneiron.byoa.runner-continue-checkout.v1";

/// The longest hand-over note the door carries, in bytes.
const CONTINUE_NOTE_MAX_BYTES: usize = 4096;

/// The hand-over job's kind.
const HAND_OVER_JOB_KIND: &str = "oneiron.runner.continue.v1";

/// A request that names no repository.
const ERR_CONTINUE_REPO_EMPTY: &str = "the continue request names no repository";

/// A request whose ref is not a full branch ref.
const ERR_CONTINUE_REF: &str = "the continue request names no refs/heads/ ref";

/// A request whose commit is not a 40 lower-hex commit.
const ERR_CONTINUE_COMMIT: &str = "the continue request names no 40 lower-hex commit";

/// A request whose conversation is not an entity id.
const ERR_CONTINUE_CONVERSATION: &str = "the continue request names no conversation id";

/// A request that names no runner.
const ERR_CONTINUE_RUNNER_EMPTY: &str = "the continue request names no runner";

/// A request whose note is past the door's budget.
const ERR_CONTINUE_NOTE_LONG: &str = "the continue note is past 4096 bytes";

/// A commit that is not the tip of the pushed ref.
const ERR_CONTINUE_NOT_TIP: &str = "the commit is not the tip of the pushed ref: the hand-off did not land, and nothing was started";

/// A conversation the vault does not hold.
const ERR_CONTINUE_CONVERSATION_MISSING: &str =
    "the conversation is not in this vault: nothing was started";

/// A seat search whose seat moved before the bind.
const ERR_CONTINUE_SEAT_MOVED: &str = "the continue seat moved between the search and the bind";

/// A checkout the claim door refused.
const ERR_CONTINUE_CLAIM: &str = "the continue checkout did not claim";

/// A derived checkout id no checkout has.
const ERR_CONTINUE_CHECKOUT_ID: &str = "the continue checkout id did not derive";

/// A continued work whose attempt names no TASK.
const ERR_CONTINUE_TASK_MISSING: &str = "the continued work names no TASK";

/// A continued work whose repeat bind did not answer it as bound.
const ERR_CONTINUE_EXISTING_UNBOUND: &str = "the continued work did not answer as bound";

/// A hand-over job that did not encode.
const ERR_CONTINUE_JOB_ENCODE: &str = "the continue hand-over job did not encode";

/// The owner's or agent's start of a continued outside session.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContinueOutsideWorkRequest {
    /// The served repo name, as the push URL's `{repo}`.
    pub repo: String,
    /// The full ref the hand-off commit was pushed to, `refs/heads/...`.
    pub git_ref: String,
    /// The hand-off commit, 40 lower hex.
    pub commit: String,
    /// The imported conversation entity id, hex.
    pub conversation: String,
    /// The runner that continues the session, e.g. `"claude-code"`.
    pub runner: String,
    /// A note the hand-over job carries to the runner.
    #[serde(default)]
    pub note: Option<String>,
}

/// The read-only check of the same: whether this node would take the work.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContinueOutsideWorkCheckRequest {
    /// The served repo name, as the push URL's `{repo}`.
    pub repo: String,
    /// The runner that would continue the session.
    pub runner: String,
}

/// Where starting a continued outside session left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ContinueOutsideWorkView {
    /// The work is bound and its attempt dispatched. `existing` when the
    /// same hand-off already did, and then `seat` and `attempt` are where
    /// the work stands now; the TASK and checkout are the hand-over's. Ids
    /// are lower hex.
    Bound {
        binding: String,
        seat: usize,
        attempt: String,
        task: String,
        checkout: String,
        existing: bool,
    },
    /// No seat in this node's policy names the runner.
    NoRunnerSeat { runner: String },
    /// No seat this runtime may run is left: each one tried is named with
    /// why.
    NoSeat { skipped: Vec<SkippedRunnerSeatView> },
    /// Every seat this runtime may run is spent. `back_at` is the first time
    /// one is back; none waits for the owner. Each seat passed over is named
    /// with why.
    Exhausted {
        back_at: Option<u64>,
        skipped: Vec<SkippedRunnerSeatView>,
    },
}

/// Where the read-only check left it. It writes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ContinueOutsideWorkCheckView {
    /// This node would take the work on `seat`.
    Ready { seat: usize, runner: String },
    /// No seat in this node's policy names the runner.
    NoRunnerSeat { runner: String },
    /// No seat this runtime may run is left: each one tried is named with
    /// why.
    NoSeat { skipped: Vec<SkippedRunnerSeatView> },
    /// Every seat this runtime may run is spent. `back_at` is the first time
    /// one is back; none waits for the owner. Each seat passed over is named
    /// with why.
    Exhausted {
        back_at: Option<u64>,
        skipped: Vec<SkippedRunnerSeatView>,
    },
}

/// The caller's proof: the owner's, or an agent whose live Grant names
/// `vault.runners.continue`. Both are checked again in the door's own
/// transaction.
#[derive(Debug, Clone, Copy)]
pub enum RunnerContinueCaller<'a> {
    /// The owner's own proof.
    Owner(&'a AuthenticatedOwner),
    /// An agent whose live Grant names the verb.
    GrantedAgent(EntityId),
}

/// A continue reaches no endpoint: the door mints rows; no endpoint is
/// reached and no egress is leased.
struct ContinueEndpoints;

impl ByoEndpointBackendFactory for ContinueEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend(
            "the continue door serves no endpoint connector".to_owned(),
        ))
    }
}

/// A continue takes no egress lease: it mints a row, and no traffic moves.
struct ContinueEgress;

impl ByoaEgressPort for ContinueEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the continue door leases no egress".to_owned(),
        })
    }
}

/// The hand-over job the runner is handed, as JSON.
#[derive(Serialize)]
struct HandOverJob<'r> {
    kind: &'static str,
    conversation: &'r str,
    repo: &'r str,
    git_ref: &'r str,
    commit: &'r str,
    note: Option<&'r str>,
    instruction: String,
}

/// The wire views of the seats a search passed over, in the policy's order.
fn skipped_views(skipped: &[SkippedRunnerSeat]) -> Vec<SkippedRunnerSeatView> {
    skipped
        .iter()
        .map(|skip| SkippedRunnerSeatView {
            seat: skip.seat,
            runner: skip.runner.clone(),
            reason: skip.reason.to_string(),
        })
        .collect()
}

/// A continue door's refusal as a memory door's: a store failure keeps its
/// own code.
fn refusal(error: ByoaError) -> MemoryError {
    match error {
        ByoaError::Store(error) => MemoryError::from(error),
        other => MemoryError::bad_request(other.to_string()),
    }
}

/// A checkout claim's refusal as a memory door's: a store failure keeps its
/// own code.
fn claim_refusal(error: CheckoutError) -> MemoryError {
    match error {
        CheckoutError::Store(error) => MemoryError::from(error),
        _ => MemoryError::bad_request(ERR_CONTINUE_CLAIM),
    }
}

/// The hand-over id: the work's parent id, derived from the conversation and
/// the pushed coordinates. No attempt row answers to it; a runner work's
/// parent is only bytes in its id and its child's payload. The same request
/// twice derives the same binding
/// ([`RunnerWorkBindingId::of`] under [`CONTINUE_STEP_KEY`]).
///
/// # Errors
///
/// A derived id the attempt queue refuses.
fn hand_over_id(
    repo: &str,
    git_ref: &str,
    commit: &str,
    conversation: EntityId,
) -> ByoaResult<AttemptId> {
    let mut hasher = blake3::Hasher::new_derive_key(HAND_OVER_DOMAIN);
    hasher.update(conversation.as_bytes());
    for part in [repo, git_ref, commit] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[0] = 1;
    }
    Ok(AttemptId::from_bytes(&bytes)?)
}

/// The checkout a hand-over runs against, derived from the hand-over id.
///
/// # Errors
///
/// A derived id the checkout door refuses; a store failure.
fn hand_over_checkout(hand_over: AttemptId) -> ByoaResult<CheckoutId> {
    let mut hasher = blake3::Hasher::new_derive_key(HAND_OVER_CHECKOUT_DOMAIN);
    hasher.update(hand_over.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[0] = 1;
    }
    CheckoutId::from_bytes(bytes).map_err(|_| super::error::invalid(ERR_CONTINUE_CHECKOUT_ID))
}

/// The hand-over job's bytes: the conversation, the pushed coordinates and
/// the instruction to recall the session through memory first.
///
/// # Errors
///
/// A job that does not encode.
fn hand_over_job(request: &ContinueOutsideWorkRequest) -> MemoryResult<Vec<u8>> {
    let conversation = request.conversation.as_str();
    let repo = request.repo.as_str();
    let git_ref = request.git_ref.as_str();
    let commit = request.commit.as_str();
    let job = HandOverJob {
        kind: HAND_OVER_JOB_KIND,
        conversation,
        repo,
        git_ref,
        commit,
        note: request.note.as_deref(),
        instruction: format!(
            "Recall this session through Oneiron memory first: conversation \
             {conversation}. Then go on with its work in this checkout, which \
             holds commit {commit} of {git_ref}."
        ),
    };
    serde_json::to_vec(&job).map_err(|_| MemoryError::bad_request(ERR_CONTINUE_JOB_ENCODE))
}

/// The served store of `repo`: the directory this node serves it from.
///
/// # Errors
///
/// A repository this node serves nothing under; a store failure.
fn served_store(vault: &Vault, repo: &str) -> MemoryResult<PathBuf> {
    match origin_repo_dir(vault, repo) {
        Ok(store) => Ok(store),
        Err(Error::Code(
            CodeError::GitHttpRepoNotFound { .. } | CodeError::GitHttpInvalidRepoName(_),
        )) => Err(MemoryError::not_found(format!(
            "this node serves no repository named {repo:?}"
        ))),
        Err(error) => Err(MemoryError::from(error)),
    }
}

/// The commit `git_ref` names now in the served `store`, peeled to a commit:
/// the pin the door reads the hand-off at. `None` for a ref that is not
/// there. The repo opens pinned at `commit`, the claimed tip: the proof
/// needs a commit the store holds, so a hand-off that never landed its
/// commit refuses here rather than reading no store at all.
///
/// # Errors
///
/// A ref that does not parse; a store that does not read; a store failure.
fn pushed_tip(
    vault: &Vault,
    store: &Path,
    git_ref: &str,
    commit: &str,
) -> MemoryResult<Option<String>> {
    let name =
        GitRefName::parse_full(git_ref).map_err(|_| MemoryError::bad_request(ERR_CONTINUE_REF))?;
    let wire = GitWire::new(vault).map_err(MemoryError::from)?;
    let repo = wire
        .open_repo(
            RepoRef::LocalFolder {
                path: store.to_string_lossy().into_owned(),
                commit: commit.to_owned(),
            },
            store,
        )
        .map_err(MemoryError::from)?;
    let named = wire.read_ref(&repo, &name).map_err(MemoryError::from)?;
    let Some(named) = named else {
        return Ok(None);
    };
    let tip = wire
        .resolve_commit(&repo, named.as_str())
        .map_err(MemoryError::from)?;
    Ok(Some(tip.as_str().to_owned()))
}

/// Whether `commit` is a 40 lower-hex commit.
fn commit_shaped(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The request, checked: a served repo name, a full branch ref, a 40
/// lower-hex commit, a conversation id, a runner and a bounded note. Answers
/// the conversation.
///
/// # Errors
///
/// A request that fails any check; each refusal names its own check.
fn validated_conversation(request: &ContinueOutsideWorkRequest) -> MemoryResult<EntityId> {
    if request.repo.is_empty() {
        return Err(MemoryError::bad_request(ERR_CONTINUE_REPO_EMPTY));
    }
    if GitRefName::parse_full(request.git_ref.as_str()).is_err()
        || !request.git_ref.starts_with("refs/heads/")
    {
        return Err(MemoryError::bad_request(ERR_CONTINUE_REF));
    }
    if !commit_shaped(&request.commit) {
        return Err(MemoryError::bad_request(ERR_CONTINUE_COMMIT));
    }
    let conversation = EntityId::from_hex(&request.conversation)
        .map_err(|_| MemoryError::bad_request(ERR_CONTINUE_CONVERSATION))?;
    if request.runner.is_empty() {
        return Err(MemoryError::bad_request(ERR_CONTINUE_RUNNER_EMPTY));
    }
    if request
        .note
        .as_deref()
        .is_some_and(|note| note.len() > CONTINUE_NOTE_MAX_BYTES)
    {
        return Err(MemoryError::bad_request(ERR_CONTINUE_NOTE_LONG));
    }
    Ok(conversation)
}

/// The seats of the owner's policy that name the runner a continue asks
/// for. A continue searches only these, so a seat passed over as spent or
/// as one this runtime may not run never hands the work to another
/// vendor's runner; each seat keeps its quota and placement checks.
struct RunnerSeats {
    /// Those seats as a policy of their own, in the owner's order, under
    /// the owner's spend rule.
    policy: RunnerSeatPolicy,
    /// Each seat's index in the owner's policy.
    indices: Vec<usize>,
}

impl RunnerSeats {
    /// The seats of `policy` that name `runner`; `None` when no seat does.
    fn of(policy: &RunnerSeatPolicy, runner: &str) -> Option<Self> {
        let (indices, seats): (Vec<usize>, Vec<RunnerSeat>) = policy
            .seats
            .iter()
            .enumerate()
            .filter(|(_, seat)| seat.runner == runner)
            .map(|(index, seat)| (index, seat.clone()))
            .unzip();
        if seats.is_empty() {
            return None;
        }
        Some(Self {
            policy: RunnerSeatPolicy {
                seats,
                on_spent: policy.on_spent,
            },
            indices,
        })
    }

    /// The seat search over these seats from the first, read in `txn`, its
    /// seat indices put back in the owner's order.
    ///
    /// # Errors
    ///
    /// Every refusal the search has.
    fn search_in_txn(
        &self,
        dispatcher: &ByoaDispatcher<'_, ContinueEndpoints, ContinueEgress>,
        txn: &heed::RoTxn<'_>,
        registry: &ProviderAdapterRegistry,
        work: &BindRunnerWork,
    ) -> ByoaResult<RunnerSeatSearch> {
        let found = dispatcher.search_runner_seat_in_txn(txn, registry, &self.policy, work)?;
        Ok(match found {
            RunnerSeatSearch::Found {
                seat,
                connector,
                context,
                task_source,
            } => RunnerSeatSearch::Found {
                seat: self.owner_index(seat),
                connector,
                context,
                task_source,
            },
            RunnerSeatSearch::NoSeat { skipped } => RunnerSeatSearch::NoSeat {
                skipped: self.owner_skipped(skipped),
            },
            RunnerSeatSearch::Exhausted { back_at, skipped } => RunnerSeatSearch::Exhausted {
                back_at,
                skipped: self.owner_skipped(skipped),
            },
        })
    }

    /// Seat `index` of these seats as its index in the owner's policy. A
    /// search over these seats answers only their own indices.
    fn owner_index(&self, index: usize) -> usize {
        self.indices[index]
    }

    /// `skipped` with each seat named by its index in the owner's policy.
    fn owner_skipped(&self, skipped: Vec<SkippedRunnerSeat>) -> Vec<SkippedRunnerSeat> {
        skipped
            .into_iter()
            .map(|skip| SkippedRunnerSeat {
                seat: self.owner_index(skip.seat),
                ..skip
            })
            .collect()
    }
}

/// The owner whose will the caller's act carries, checked live in `txn`:
/// the owner's proof revalidated, or the agent's standing Grant naming the
/// verb.
///
/// # Errors
///
/// A proof that no longer holds; an agent with no live Grant naming the
/// verb; a store failure.
fn caller_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: &RunnerContinueCaller<'_>,
) -> crate::error::Result<EntityId> {
    match caller {
        RunnerContinueCaller::Owner(owner) => owner.revalidate_in_txn(vault, txn),
        RunnerContinueCaller::GrantedAgent(agent) => {
            vault.agent_act_owner_in_txn(txn, *agent, OwnerActKind::RunnerContinue)
        }
    }
}

/// [`caller_owner_in_txn`] in a read snapshot of its own: a door judges the
/// caller before the served store or a pushed ref answers anything, so a
/// refused caller learns neither which repos this node serves nor which
/// commit a ref names.
///
/// # Errors
///
/// Every refusal [`caller_owner_in_txn`] has.
fn caller_owner(vault: &Vault, caller: &RunnerContinueCaller<'_>) -> MemoryResult<EntityId> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    caller_owner_in_txn(vault, &rtxn, caller).map_err(MemoryError::from)
}

impl Vault {
    /// Starts the outside session the local CLI pushed as `input.commit` on
    /// `input.git_ref` of the custody repo `input.repo`: the same request
    /// twice binds the same work and answers it again, with no second write.
    ///
    /// The caller is judged first, in a read snapshot, before the served
    /// store or the pushed ref answers anything, and again inside the
    /// writer, so a refused caller learns neither the repo nor the policy.
    /// The commit must be the tip of the pushed ref before any writer opens
    /// (a lost upload starts nothing, CLR-001); refs live on disk, so this
    /// read is outside the writer, and the checkout is pinned at the commit,
    /// so a later ref move cannot change what runs.
    ///
    /// The work runs only on a seat of `policy` that names `input.runner`:
    /// the first such seat in the owner's order that this runtime may run
    /// and whose quota is not spent. `registry` is the one the node's own
    /// seat settings build, so an official seat's adapter and its login
    /// machine ride the work.
    ///
    /// # Errors
    ///
    /// A request that fails its checks; a commit that is not the tip; a
    /// caller the door refuses; a conversation the vault does not hold; a
    /// checkout the claim door refuses; every refusal a dispatch has; a
    /// store failure.
    pub fn continue_outside_work(
        &self,
        caller: RunnerContinueCaller<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        input: &ContinueOutsideWorkRequest,
    ) -> MemoryResult<ContinueOutsideWorkView> {
        let conversation = validated_conversation(input)?;
        caller_owner(self, &caller)?;
        let store = served_store(self, &input.repo)?;
        let tip = pushed_tip(self, &store, &input.git_ref, &input.commit)?;
        if tip.as_deref() != Some(input.commit.as_str()) {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                ERR_CONTINUE_NOT_TIP,
                &["Push the hand-off commit, then call again."],
            ));
        }
        let hand_over = hand_over_id(&input.repo, &input.git_ref, &input.commit, conversation)
            .map_err(refusal)?;
        let binding = RunnerWorkBindingId::of(hand_over, CONTINUE_STEP_KEY).map_err(refusal)?;
        let checkout = hand_over_checkout(hand_over).map_err(refusal)?;
        let job = hand_over_job(input)?;
        let staged = StagedJob::new(&job);
        let pointer = staged.pointer();
        let hand_over_hex = bytes_to_hex_lower(hand_over.as_bytes());
        let run_id = format!("runner.continue:{hand_over_hex}");
        let conversation_hex = conversation.to_hex();
        let dispatcher = ByoaDispatcher::new(self, ContinueEndpoints, ContinueEgress);
        self.try_with_write_txn_grouped(|wtxn| -> MemoryResult<ContinueOutsideWorkView> {
            let owner = caller_owner_in_txn(self, wtxn, &caller)?;
            let Some(seats) = RunnerSeats::of(policy, &input.runner) else {
                return Ok(ContinueOutsideWorkView::NoRunnerSeat {
                    runner: input.runner.clone(),
                });
            };
            let now = self.instant_in_txn(wtxn)?.secs();
            let mut work = BindRunnerWork {
                parent_attempt_id: hand_over,
                step_key: CONTINUE_STEP_KEY.to_owned(),
                task: pointer,
                staged_input: None,
                checkout_id: checkout,
                task_ref: None,
                run_id: Some(run_id.clone()),
                // The search over the runner's own seats starts at their
                // first; a bound work answers where it stands.
                choice: RunnerSeatChoice::NextSeat { from: 0 },
                now,
            };
            if head_hop(self, wtxn, binding).map_err(refusal)?.is_some() {
                let bound = dispatcher
                    .bind_runner_work_in_txn(wtxn, registry, policy, work)
                    .map_err(refusal)?;
                let RunnerWorkBound::Bound {
                    binding,
                    seat,
                    attempt,
                    existing: _,
                } = bound
                else {
                    return Err(refusal(ByoaError::Store(Error::InvariantViolation(
                        ERR_CONTINUE_EXISTING_UNBOUND,
                    ))));
                };
                let record = AttemptQueue::new(self)
                    .get_in_txn(wtxn, attempt)?
                    .ok_or_else(|| {
                        refusal(ByoaError::Store(Error::InvariantViolation(
                            ERR_CONTINUE_TASK_MISSING,
                        )))
                    })?;
                let task = record
                    .task_ref
                    .as_deref()
                    .and_then(|task| EntityId::from_hex(task).ok())
                    .map(|task| task.to_hex());
                let Some(task) = task else {
                    return Err(refusal(ByoaError::Store(Error::InvariantViolation(
                        ERR_CONTINUE_TASK_MISSING,
                    ))));
                };
                let attempt_hex = bytes_to_hex_lower(attempt.as_bytes());
                let checkout_hex = bytes_to_hex_lower(checkout.as_bytes());
                return Ok(ContinueOutsideWorkView::Bound {
                    binding: binding.to_hex(),
                    seat,
                    attempt: attempt_hex,
                    task,
                    checkout: checkout_hex,
                    existing: true,
                });
            }
            let found = seats
                .search_in_txn(&dispatcher, wtxn, registry, &work)
                .map_err(refusal)?;
            let seat = match found {
                RunnerSeatSearch::Found { seat, .. } => seat,
                RunnerSeatSearch::NoSeat { skipped } => {
                    return Ok(ContinueOutsideWorkView::NoSeat {
                        skipped: skipped_views(&skipped),
                    });
                }
                RunnerSeatSearch::Exhausted { back_at, skipped } => {
                    return Ok(ContinueOutsideWorkView::Exhausted {
                        back_at,
                        skipped: skipped_views(&skipped),
                    });
                }
            };
            if !crate::ports::EntityStoreRead::port_entity_present(
                &self.store,
                wtxn,
                &conversation,
            )? {
                return Err(MemoryError::not_found(ERR_CONTINUE_CONVERSATION_MISSING));
            }
            let mut runner_continue = vec![
                (
                    rmpv::Value::from("conversation"),
                    rmpv::Value::from(conversation_hex.clone()),
                ),
                (
                    rmpv::Value::from("repo"),
                    rmpv::Value::from(input.repo.clone()),
                ),
                (
                    rmpv::Value::from("git_ref"),
                    rmpv::Value::from(input.git_ref.clone()),
                ),
                (
                    rmpv::Value::from("commit"),
                    rmpv::Value::from(input.commit.clone()),
                ),
            ];
            if let Some(note) = input.note.as_deref() {
                runner_continue.push((rmpv::Value::from("note"), rmpv::Value::from(note)));
            }
            let spec = rmpv::Value::Map(vec![(
                rmpv::Value::from("runner_continue"),
                rmpv::Value::Map(runner_continue),
            )]);
            let mut provenance_entries = vec![
                (
                    rmpv::Value::from("source"),
                    rmpv::Value::from(CONTINUE_STEP_KEY),
                ),
                (
                    rmpv::Value::from("conversation"),
                    rmpv::Value::from(conversation_hex.clone()),
                ),
                (
                    rmpv::Value::from("commit"),
                    rmpv::Value::from(input.commit.clone()),
                ),
            ];
            if let RunnerContinueCaller::GrantedAgent(agent) = caller {
                provenance_entries.push((
                    rmpv::Value::from("requested_by"),
                    rmpv::Value::from(agent.to_hex()),
                ));
            }
            let provenance = rmpv::Value::Map(provenance_entries);
            let label = format!("continue:{conversation_hex}");
            let task =
                self.mint_runner_continue_task_in_txn(wtxn, owner, label, spec, &provenance, now)?;
            let holder = format!("{CONTINUE_STEP_KEY}:{}", binding.to_hex());
            claim_in_txn(
                self,
                wtxn,
                CheckoutClaimRequest {
                    checkout_id: checkout,
                    task_ref: task,
                    repo_ref: RepoRef::LocalFolder {
                        path: store.to_string_lossy().into_owned(),
                        commit: input.commit.clone(),
                    },
                    holder_ref: holder,
                    task_class: CheckoutTaskClass::Edit,
                    ttl_secs: None,
                    now,
                },
            )
            .map_err(claim_refusal)?;
            let pin =
                persist_staged_input_in_txn(self, wtxn, &staged, &run_id, now).map_err(refusal)?;
            work.staged_input = Some(pin);
            work.task_ref = Some(task);
            // The bind takes the seat the search found, by its index in the
            // owner's policy, so the binding names it there.
            work.choice = RunnerSeatChoice::Seat(seat);
            let bound = dispatcher
                .bind_runner_work_in_txn(wtxn, registry, policy, work)
                .map_err(refusal)?;
            let RunnerWorkBound::Bound {
                binding,
                seat,
                attempt,
                existing: false,
            } = bound
            else {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    ERR_CONTINUE_SEAT_MOVED,
                    &["Call again: the search runs anew."],
                ));
            };
            let attempt_hex = bytes_to_hex_lower(attempt.as_bytes());
            let checkout_hex = bytes_to_hex_lower(checkout.as_bytes());
            Ok(ContinueOutsideWorkView::Bound {
                binding: binding.to_hex(),
                seat,
                attempt: attempt_hex,
                task: task.to_hex(),
                checkout: checkout_hex,
                existing: false,
            })
        })
    }

    /// Checks whether this node would take the outside session the local CLI
    /// would push to the custody repo `input.repo` for `input.runner`: the
    /// caller holds, the repo is in custody here, and the search
    /// [`Self::continue_outside_work`] runs over the seats of `policy` that
    /// name `input.runner`, under `registry`, lands. One read snapshot; it
    /// writes nothing. The caller is judged first, so a refused caller
    /// learns nothing of the repo.
    ///
    /// # Errors
    ///
    /// A request that fails its checks; a caller the door refuses; a store
    /// failure.
    pub fn continue_outside_work_check(
        &self,
        caller: RunnerContinueCaller<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        input: &ContinueOutsideWorkCheckRequest,
    ) -> MemoryResult<ContinueOutsideWorkCheckView> {
        if input.repo.is_empty() {
            return Err(MemoryError::bad_request(ERR_CONTINUE_REPO_EMPTY));
        }
        if input.runner.is_empty() {
            return Err(MemoryError::bad_request(ERR_CONTINUE_RUNNER_EMPTY));
        }
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        caller_owner_in_txn(self, &rtxn, &caller)?;
        served_store(self, &input.repo)?;
        // The pointer a run is handed has one shape whatever its job, so a
        // placeholder job searches the same seats; its hand-over id derives
        // from this check request with an all-zero conversation, which the
        // search never reads.
        let placeholder = b"{}";
        let staged = StagedJob::new(placeholder);
        let pointer = staged.pointer();
        let hand_over = hand_over_id(&input.repo, "", "", EntityId::from_bytes_unchecked([0; 16]))
            .map_err(refusal)?;
        let checkout = hand_over_checkout(hand_over).map_err(refusal)?;
        let dispatcher = ByoaDispatcher::new(self, ContinueEndpoints, ContinueEgress);
        let Some(seats) = RunnerSeats::of(policy, &input.runner) else {
            return Ok(ContinueOutsideWorkCheckView::NoRunnerSeat {
                runner: input.runner.clone(),
            });
        };
        let now = self.instant_in_txn(&rtxn)?.secs();
        let work = BindRunnerWork {
            parent_attempt_id: hand_over,
            step_key: CONTINUE_STEP_KEY.to_owned(),
            task: pointer,
            staged_input: None,
            checkout_id: checkout,
            task_ref: None,
            run_id: None,
            choice: RunnerSeatChoice::NextSeat { from: 0 },
            now,
        };
        let found = seats
            .search_in_txn(&dispatcher, &rtxn, registry, &work)
            .map_err(refusal)?;
        Ok(match found {
            RunnerSeatSearch::Found { seat, .. } => ContinueOutsideWorkCheckView::Ready {
                seat,
                runner: input.runner.clone(),
            },
            RunnerSeatSearch::NoSeat { skipped } => ContinueOutsideWorkCheckView::NoSeat {
                skipped: skipped_views(&skipped),
            },
            RunnerSeatSearch::Exhausted { back_at, skipped } => {
                ContinueOutsideWorkCheckView::Exhausted {
                    back_at,
                    skipped: skipped_views(&skipped),
                }
            }
        })
    }
}
