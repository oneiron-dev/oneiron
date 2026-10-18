//! Who pays for a model call that a room's spend scope bounds (OF-531, FIX
//! 805).
//!
//! A call spending under a scope whose root carries a payer's consent bills
//! that PERSON's own billing account. The host binds it before the run starts,
//! so every permit and usage row the run makes carries it. One hook,
//! `billing_account`, maps a PERSON to an account: a live Owner of the vault
//! bills the vault's own account, with no ask. When it maps none, the
//! call holds on a typed payer-needed ask to the vault's owners, who may
//! approve billing the vault for that launch. A workflow step or an agent run
//! held so parks as it is ([`park_for_payer`]) and is taken up as the same
//! try once its payer can be billed ([`resume_payer_parks`]). Nothing here
//! falls back to the vault owner silently: a scope that cannot be read, or a
//! room-bound call whose root names no payer, is a typed error. A call no
//! room pays for keeps the owner default.

use std::fmt;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId, decode_agent_dispatch_input};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::dreamer_runner::{
    DreamerParkCause, ParkDreamerAttempt, decode_dreamer_attempt_payload,
};
use oneiron::llm::decision::catalogue::PAYER_NEEDED;
use oneiron::llm::decision::{
    AnswerContract, AskTo, DecisionAnswer, DecisionRung, HumanAskReason, HumanDecisionRequest,
    ProviderPin,
};
use oneiron::llm::run_admission::{PayerAccount, PayerPerson};
use oneiron::workspace_roster::RoomSpend;
use oneiron::{DreamerRunnerStore, EntityId, Vault};

/// The host-issued queue identity of a payer-needed ask.
const PAYER_NEEDED_QUEUE: &str = "spend.payer_needed";
const PAYER_NEEDED_QUEUE_VERSION: &str = "v1";
/// The reason a payer park carries, ahead of its fault: it marks the park as
/// a payer hold among its owner's signal parks.
const PAYER_PARK_REASON: &str = "payer-needed hold: ";

/// Why a scope-funded call has no account to bill yet. Neither refuses the
/// call for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PayerFault {
    /// No payer could be read for the call: its scope or an ancestor is
    /// missing, or a room-bound call's root names none (`scope` is `None`
    /// when a room-bound call spends under no scope).
    Missing { scope: Option<SpendScopeId> },
    /// The payer PERSON's own billing account is not one this host can
    /// resolve: the call holds on the owners' payer-needed ask `ask`, and
    /// once they say yes it bills the vault. `None` when the ask could not be
    /// queued; the next read queues it.
    Needed { person: EntityId, ask: Option<u64> },
}

impl PayerFault {
    /// The fault's stable reason code.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "payer_missing",
            Self::Needed { .. } => "payer_needed",
        }
    }
}

impl fmt::Display for PayerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { scope } => write!(
                f,
                "payer_missing: no payer could be read for spend scope {}",
                scope.as_ref().map_or("(none)", SpendScopeId::as_str)
            ),
            Self::Needed { person, ask } => {
                write!(
                    f,
                    "payer_needed: payer {} has no billing account this host can resolve; ",
                    person.to_hex()
                )?;
                match ask {
                    Some(ask) => write!(f, "the call holds on the owners' payer-needed ask {ask}"),
                    None => f.write_str("its payer-needed ask is queued on the next try"),
                }
            }
        }
    }
}

/// The host's PERSON-to-billing-account map, the one hook (CALLS, FIX 805
/// resolver). A live Owner of the vault bills the vault's own account, the
/// one owner spend bills: that is the Owner's own account, not a fallback.
/// Neither canon nor a root's payer consent maps any other PERSON to an
/// account, so their room-paid calls hold on a payer-needed ask until a host
/// maps them here. An owner check that fails to read maps none, so the call
/// holds rather than bills the vault unasked.
fn billing_account(vault: &Vault, person: EntityId) -> Option<PayerAccount> {
    match vault.is_live_owner_person(&person) {
        Ok(true) => Some(PayerAccount::VaultOwner),
        Ok(false) => None,
        Err(error) => {
            tracing::warn!(%error, "a payer's owner standing could not be read");
            None
        }
    }
}

/// How a call that spends under `scope` is funded: `None` for a call no room
/// pays for (it spends under no scope, or its root carries no payer), which
/// keeps the vault owner's default; else the payer PERSON, its root scope and
/// the account the call bills. `room` says the caller knows the call is
/// room-bound, so its root must name a payer.
pub(crate) fn scope_funding(
    vault: &Vault,
    scope: Option<&SpendScopeId>,
    room: bool,
) -> Result<Option<PayerPerson>, PayerFault> {
    let missing = || PayerFault::Missing {
        scope: scope.cloned(),
    };
    let Some(scope) = scope else {
        return if room { Err(missing()) } else { Ok(None) };
    };
    let (root, payer) = match AgentDispatcher::new(vault).root_payer(scope) {
        Ok(Some(found)) => found,
        Ok(None) if !room => return Ok(None),
        Ok(None) => return Err(missing()),
        Err(error) => {
            tracing::warn!(%error, %scope, "a spend scope's payer could not be read");
            return Err(missing());
        }
    };
    let account = match billing_account(vault, payer.party) {
        Some(account) => account,
        None => PayerAccount::VaultApproved {
            ask: approved_ask(vault, &root, payer.party)?,
        },
    };
    Ok(Some(PayerPerson {
        person: payer.party,
        root_scope: root,
        account,
    }))
}

/// How a launch that `agent` answers in `room`, or its thread `branch`, for
/// `requester` is funded (FIX 805): a chat or voice turn, or a queued
/// Continue or Retry. This is the one place that says which launch is
/// room-bound (CALLS, FIX 805 room-bound predicate).
///
/// Its payer is the PERSON whose consent on the agent's Ready join funds the
/// place (L02's join receipt, re-proved live), read through that consent's
/// scope as [`scope_funding`] reads a room-bound call's. A join that
/// launches no paid work, or that no longer covers the place (or cannot be
/// read), is no funding consent: the launch holds on
/// [`PayerFault::Missing`], never the vault owner's default, unless a live
/// Owner of the vault is the turn's subject, the requester or the PERSON a
/// person-anchored agent's join speaks for (Engine, 10-18). An Owner's turn
/// bills the vault account, as it did before rooms were funded. An agent
/// with no Ready join filed there answers no room launch but the owner's own
/// conversation, which keeps the vault owner's default.
pub(crate) fn room_launch_funding(
    vault: &Vault,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    requester: EntityId,
) -> Result<Option<PayerPerson>, PayerFault> {
    let (person, spend) = match vault.room_funding(room, branch, agent) {
        Ok(funding) => (funding.person, funding.spend),
        Err(error) => {
            tracing::warn!(%error, room = %room.to_hex(), "a room launch's join could not be read");
            (None, RoomSpend::Lapsed)
        }
    };
    match spend {
        RoomSpend::Paid { scope, .. } => scope_funding(vault, Some(&scope), true),
        RoomSpend::NotJoined => Ok(None),
        RoomSpend::NoPaidWork | RoomSpend::Lapsed => {
            let owner = |person: EntityId| {
                matches!(
                    billing_account(vault, person),
                    Some(PayerAccount::VaultOwner)
                )
            };
            if owner(requester) || person.is_some_and(owner) {
                Ok(None)
            } else {
                Err(PayerFault::Missing { scope: None })
            }
        }
    }
}

/// The owners' yes to billing the vault for the launch under `root`, whose
/// payer `person` has no account this host resolves: the payer-needed ask's
/// number once they approved it. An open ask, or one answered otherwise,
/// holds the call; with none yet, one is queued, and queueing the same open
/// ask again is that ask.
fn approved_ask(vault: &Vault, root: &SpendScopeId, person: EntityId) -> Result<u64, PayerFault> {
    let held = |ask: Option<u64>| PayerFault::Needed { person, ask };
    let request = match payer_needed_ask(root, person) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "a payer-needed ask could not be built");
            return Err(held(None));
        }
    };
    let asked = vault.decision_ask_for(
        &request.question,
        request.principal,
        &request.evidence,
        &request.to,
        request.correlation,
    );
    match asked {
        Ok(Some(ask)) => {
            let yes = ask
                .answer
                .as_ref()
                .is_some_and(|answer| answer.answer == DecisionAnswer::Noul(true));
            if yes {
                Ok(ask.seq)
            } else {
                Err(held(Some(ask.seq)))
            }
        }
        Ok(None) => match vault.queue_decision_ask(&request) {
            Ok(seq) => Err(held(Some(seq))),
            Err(error) => {
                tracing::warn!(%error, "a payer-needed ask could not be queued");
                Err(held(None))
            }
        },
        Err(error) => {
            tracing::warn!(%error, "a payer-needed ask could not be read");
            Err(held(None))
        }
    }
}

/// The owners' payer-needed ask about the launch under `root`, keyed by its
/// payer and root: one ask per room-paid launch, put to the owners.
fn payer_needed_ask(
    root: &SpendScopeId,
    person: EntityId,
) -> oneiron::Result<HumanDecisionRequest> {
    let text = format!(
        "A room-paid launch (root spend scope {root}) is paid for by PERSON {person}, whose own \
         billing account this host cannot resolve, so its model calls are held. Bill this vault \
         for that launch's calls instead? Its payer's cap still bounds them. Answering no keeps \
         them held until the payer's own account resolves.",
        person = person.to_hex(),
    );
    let question = PAYER_NEEDED.question(
        &[person.as_bytes().as_slice(), root.as_str().as_bytes()],
        text,
        AnswerContract::Noul,
    )?;
    Ok(HumanDecisionRequest {
        question,
        principal: person,
        evidence: vec![person],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: PAYER_NEEDED_QUEUE.to_owned(),
            version: PAYER_NEEDED_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: None,
    })
}

/// Parks `attempt`, leased by `owner`, on its payer (FIX 805): a workflow
/// step or an agent run whose payer waits on the owners' payer-needed ask
/// neither fails nor spends a try on its failure ladder. It keeps its lease
/// and its spend scope, and [`resume_payer_parks`] takes it up once the
/// payer can be billed. The owners' ask is the hold's notice; the park's
/// reason names the payer and the ask, never a spend cap.
pub(crate) fn park_for_payer(
    vault: &Vault,
    attempt: AttemptId,
    owner: &str,
    fault: &PayerFault,
    now: u64,
) -> oneiron::Result<()> {
    DreamerRunnerStore::new(vault).park_attempt(ParkDreamerAttempt {
        attempt_id: attempt,
        reason: format!("{PAYER_PARK_REASON}{fault}"),
        cause: DreamerParkCause::Signal,
        park_owner: owner.to_owned(),
        now,
    })?;
    Ok(())
}

/// Takes up every attempt `owner` parked on its payer whose funding no
/// longer waits on the owners: they said yes to its payer-needed ask, or its
/// funding now reads otherwise. Each is released to the queue as the same
/// try and admitted again from the start; a funding that now fails another
/// way fails it there. One whose payer still waits stays parked, unwritten.
/// Returns how many were taken up. It runs on each pump pass: an answer's
/// write wakes the pumps, and their timed recheck catches the rest.
pub(crate) fn resume_payer_parks(vault: &Vault, owner: &str, now: u64) -> usize {
    let rows = match AttemptQueue::new(vault).list() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "payer parks could not be listed");
            return 0;
        }
    };
    let runner = DreamerRunnerStore::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    let mut resumed = 0;
    for row in rows
        .iter()
        .filter(|row| matches!(row.state, AttemptState::Leased))
    {
        let Ok(Some(park)) = runner.parked_attempt(row.id) else {
            continue;
        };
        if park.park_owner != owner
            || park.cause != DreamerParkCause::Signal
            || !park.reason.starts_with(PAYER_PARK_REASON)
        {
            continue;
        }
        let room = decode_dreamer_attempt_payload(&row.payload)
            .and_then(|payload| decode_agent_dispatch_input(&payload.input))
            .map(|input| input.room.is_some());
        let waits = match (dispatcher.spend_scope_for_attempt(row.id), room) {
            (Ok(scope), Ok(room)) => matches!(
                scope_funding(vault, scope.as_ref(), room),
                Err(PayerFault::Needed { .. })
            ),
            (Err(error), _) | (_, Err(error)) => {
                tracing::warn!(%error, attempt = ?row.id, "a payer park's funding could not be read; it stays parked");
                true
            }
        };
        if waits {
            continue;
        }
        match runner.resume_parked(row.id, owner, now) {
            Ok(Some(_)) => resumed += 1,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, attempt = ?row.id, "a payer park was not resumed");
            }
        }
    }
    if resumed > 0 {
        tracing::info!(resumed, owner, "attempts parked on their payer resume");
    }
    resumed
}
