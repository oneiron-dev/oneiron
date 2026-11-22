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

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::authority::OwnerActKind;
use crate::checkout::lease::transactions::claim_in_txn;
use crate::checkout::{CheckoutClaimRequest, CheckoutError, CheckoutTaskClass};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::git_wire::GitRefName;
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};

use super::staged_input::persist_staged_input_in_txn;
use super::work_binding::{
    BindRunnerWork, RunnerSeatChoice, RunnerSeatSearch, RunnerWorkBindingId, RunnerWorkBound,
    head_hop,
};
use super::{
    ByoaDispatcher, ByoaError, ProviderAdapterRegistry, RunnerSeatPolicy, SkippedRunnerSeatView,
    StagedJob,
};

mod hand_over;
mod seats;

use self::hand_over::{
    ContinueEgress, ContinueEndpoints, commit_shaped, hand_over_checkout, hand_over_id,
    hand_over_job, pushed_tip, served_store,
};
use self::seats::{RunnerSeats, skipped_views};

/// The step key the hand-over binds its runner work under: the bind keeps
/// a work bound under it to its first seat's runner on every later hop.
pub(super) const CONTINUE_STEP_KEY: &str = "byoa.runner.continue";

/// The domain a hand-over id is derived under.
const HAND_OVER_DOMAIN: &[u8] = b"oneiron.byoa.runner-continue.v1";

/// The domain a hand-over checkout id is derived under.
const HAND_OVER_CHECKOUT_DOMAIN: &[u8] = b"oneiron.byoa.runner-continue-checkout.v1";

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
    /// The doors' admission of `caller` to `vault.runners.continue` and
    /// `vault.runners.continue.check`, before any verb hook sees the call:
    /// the owner's proof revalidated, or the agent's live Grant naming the
    /// act, in a read snapshot of its own. [`Self::continue_outside_work`]
    /// and [`Self::continue_outside_work_check`] judge the caller again.
    ///
    /// # Errors
    ///
    /// A caller the doors refuse.
    pub fn admit_runner_continue_caller(
        &self,
        caller: RunnerContinueCaller<'_>,
    ) -> MemoryResult<()> {
        caller_owner(self, &caller).map(drop)
    }

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
    /// so a later ref move cannot change what runs. The checkout is the
    /// owner's: the owner holds it and takes the TASK, as the claim door's
    /// claimer does, so the owner reads and releases it through the checkout
    /// doors.
    ///
    /// The work runs only on a seat of `policy` that names `input.runner`:
    /// the first such seat in the owner's order that this runtime may run,
    /// whose quota is not spent and whose connector is a CLI one, the only
    /// shape a host runner claims. Every later hop keeps to it: a spent
    /// seat's work is handed on, or resumed, only on a CLI seat naming the
    /// runner, and parks when none is left. `registry` is the one the node's
    /// own seat settings build, so an official seat's adapter and its login
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
        let hand_over = hand_over_id(
            &input.repo,
            &input.git_ref,
            &input.commit,
            &input.runner,
            conversation,
        )
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
            // The owner claims the checkout as the claim door's claimer
            // does: the holder is the owner's id and the owner takes the
            // TASK, so the shipped checkout doors read, settle and tear it
            // down under the owner's own credential. The runner's narrower
            // authority is the attempt's reservation of this epoch, never
            // the holder. No ttl, as before: an expired lease would turn a
            // long run's capture stale.
            let act = claim_in_txn(
                self,
                wtxn,
                CheckoutClaimRequest {
                    checkout_id: checkout,
                    task_ref: task,
                    repo_ref: RepoRef::LocalFolder {
                        path: store.to_string_lossy().into_owned(),
                        commit: input.commit.clone(),
                    },
                    holder_ref: owner.to_hex(),
                    task_class: CheckoutTaskClass::Edit,
                    ttl_secs: None,
                    now,
                },
            )
            .map_err(claim_refusal)?;
            self.memory(owner, EdgeActorClass::Human)
                .checkout_started_in(wtxn, &act, now)?;
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
        let hand_over = hand_over_id(
            &input.repo,
            "",
            "",
            &input.runner,
            EntityId::from_bytes_unchecked([0; 16]),
        )
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
