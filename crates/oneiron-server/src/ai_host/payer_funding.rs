//! Who pays for a model call that a room's spend scope bounds (OF-531, FIX
//! 805).
//!
//! A call spending under a scope whose root carries a payer's consent bills
//! that PERSON's own billing account. The host binds it before the run starts,
//! so every permit and usage row the run makes carries it. One hook,
//! `billing_account`, maps a PERSON to an account. When it maps none, the
//! call holds on a typed payer-needed ask to the vault's owners, who may
//! approve billing the vault for that launch. Nothing here falls back to the
//! vault owner silently: a scope that cannot be read, or a room-bound call
//! whose root names no payer, is a typed error. A call no room pays for keeps
//! the owner default.

use std::fmt;

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::llm::decision::catalogue::PAYER_NEEDED;
use oneiron::llm::decision::{
    AnswerContract, AskTo, DecisionAnswer, DecisionRung, HumanAskReason, HumanDecisionRequest,
    ProviderPin,
};
use oneiron::llm::run_admission::{PayerAccount, PayerPerson};
use oneiron::{EntityId, Vault};

/// The host-issued queue identity of a payer-needed ask.
const PAYER_NEEDED_QUEUE: &str = "spend.payer_needed";
const PAYER_NEEDED_QUEUE_VERSION: &str = "v1";

/// Why a scope-funded call has no account to bill yet. Neither refuses the
/// call for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PayerFault {
    /// No payer could be read for the call: its scope or an ancestor is
    /// missing, or a room-bound call's root names none (`scope` is `None`
    /// when a room-bound call spends under no scope).
    Missing { scope: Option<SpendScopeId> },
    /// The payer PERSON's own billing account is not one this host can
    /// resolve: the call holds on the owners' payer-needed ask `ask`, and a
    /// try after their yes bills the vault. `None` when the ask could not be
    /// queued; the next try queues it.
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
/// resolver). Neither canon nor a root's payer consent maps a PERSON to an
/// account, so it maps none yet: every room-paid call holds on a payer-needed
/// ask until a host maps its payers here.
fn billing_account(_vault: &Vault, _person: EntityId) -> Option<String> {
    None
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
        Some(account) => PayerAccount::Person { account },
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
