//! The owner's ruling on an answer under `always ask` (FIX 3837, 3842): the
//! ask raised or reused for exactly one frozen answer, the wait for its
//! ruling within the round's live lease, and its withdrawal once nothing is
//! left to send it to (FIX 9160). The ruling is the owner's authenticated
//! press the call's row keeps (FIX 8808), never the ask's raw answer; the
//! press mints at the owner answer route ([`press_owner_consent`]).

use oneiron::consent::AuthenticatedOwner;
use oneiron::genui::ConsentConfirmOutcome;
use oneiron::llm::decision::{DecisionAnswer, DecisionAsks};

use super::*;
use crate::owner::OwnerResult;

/// The owner's authenticated press on decision ask `seq` at the owner
/// answer route, before its answer lands (FIX 8808): a connector
/// elicitation's decisive ask mints the owner's consent through the consent
/// doors; every other ask is left as it is.
///
/// # Errors
///
/// What the consent doors refuse, typed; the route records the answer
/// either way.
pub(crate) fn press_owner_consent(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    seq: u64,
    answer: &DecisionAnswer,
) -> OwnerResult<()> {
    Ok(server
        .vault()
        .press_connector_elicitation_consent(owner, seq, answer)?)
}

/// Asks the owner about exactly `frozen`, or reads the ask the same answer
/// to this round already raised, and waits for the ruling within the
/// round's live lease. Past the lease the ask stands, kept with the round,
/// so the same answer given again reads it (FIX 3837); an ask another
/// answer superseded is withdrawn. The linked parts of a long ask are
/// withdrawn once it is decided (FIX 3842).
pub(super) fn owner_rules(
    server: &SyncServer,
    claim: &Claim<'_>,
    call_ref: &EntityId,
    authority: &ConnectorElicitationBinding,
    answer: &ConnectorElicitationAnswer<'_>,
) -> OwnerRuling {
    let asks = server.decision_host().asks();
    let kept = match &claim.owner_ask {
        Some((digest, asked)) if *digest == answer.digest => Some(asked.clone()),
        Some((_, superseded)) => {
            drop(asks.withdraw(superseded.seq));
            for part in &superseded.parts {
                drop(asks.withdraw(*part));
            }
            None
        }
        None => None,
    };
    let asked = match kept {
        Some(asked) => asked,
        None => match server
            .vault()
            .queue_connector_elicitation_owner_ask(call_ref, authority, answer)
        {
            Ok(asked) => asked,
            Err(error) => {
                tracing::warn!(%error, "connector elicitation owner ask not queued");
                return OwnerRuling::Unasked;
            }
        },
    };
    let ruling = match owner_answer(asks, asked.seq, claim.lease) {
        Some(given) => pressed_ruling(server.vault(), call_ref, answer, &given),
        None => OwnerRuling::Pending,
    };
    let registry = &server.connector_elicitations;
    if matches!(ruling, OwnerRuling::Pending) {
        // A round whose worker already ended keeps no ask (FIX 9160).
        if !registry.keep_owner_ask(
            &claim.handle,
            claim.generation,
            Some((answer.digest, asked.clone())),
        ) {
            withdraw_owner_ask(server.vault(), &asked);
        }
        return ruling;
    }
    registry.keep_owner_ask(&claim.handle, claim.generation, None);
    for part in asked.parts {
        drop(asks.withdraw(part));
    }
    ruling
}

/// What the owner's answer `given` to the consent ask about `answer` rules
/// (FIX 8808): only the authenticated press the call `call_ref`'s row keeps
/// approves or denies, never the raw choice. An abstain, a withdrawn or a
/// vanished ask declines; an answer with no press on the row leaves the ask
/// standing, and nothing goes.
fn pressed_ruling(
    vault: &oneiron::Vault,
    call_ref: &EntityId,
    answer: &ConnectorElicitationAnswer<'_>,
    given: &DecisionAnswer,
) -> OwnerRuling {
    if matches!(given, DecisionAnswer::Abstain) {
        return OwnerRuling::No;
    }
    match vault.connector_elicitation_consent(
        call_ref,
        answer.handle,
        answer.generation,
        &answer.digest,
    ) {
        Ok(Some(ConsentConfirmOutcome::Deny)) => OwnerRuling::No,
        Ok(Some(_)) => OwnerRuling::Yes,
        Ok(None) => OwnerRuling::Pending,
        Err(error) => {
            tracing::warn!(%error, "connector elicitation owner consent not read");
            OwnerRuling::Pending
        }
    }
}

/// Spends the once mark the owner's approving press left on `answer`, as
/// it goes (FIX 8808); `false`, logged, when there is none to spend.
pub(super) fn spend_owner_consent(
    vault: &oneiron::Vault,
    call_ref: &EntityId,
    answer: &ConnectorElicitationAnswer<'_>,
) -> bool {
    match vault.consume_connector_elicitation_consent(
        call_ref,
        answer.handle,
        answer.generation,
        &answer.digest,
    ) {
        Ok(spent) => spent,
        Err(error) => {
            tracing::warn!(%error, "connector elicitation owner consent not spent");
            false
        }
    }
}

/// Withdraws the owner ask `asked` and each part quoting it from the
/// owner's queue; one that cannot be withdrawn is logged (FIX 9160).
pub(super) fn withdraw_owner_ask(vault: &oneiron::Vault, asked: &ConnectorElicitationOwnerAsk) {
    for seq in std::iter::once(asked.seq).chain(asked.parts.iter().copied()) {
        if let Err(error) = vault.withdraw_decision_ask(seq) {
            tracing::warn!(%error, seq, "connector elicitation owner ask not withdrawn");
        }
    }
}

/// The owner's ruling on ask `seq` as it stands: `None` while it is open; a
/// withdrawn or vanished ask abstains.
fn ruling_now(asks: &DecisionAsks, seq: u64) -> Option<oneiron::Result<DecisionAnswer>> {
    match asks.get(seq) {
        Ok(Some(ask)) if ask.withdrawn_at.is_some() => Some(Ok(DecisionAnswer::Abstain)),
        Ok(Some(ask)) => ask.answer.map(|answer| Ok(answer.answer)),
        Ok(None) => Some(Ok(DecisionAnswer::Abstain)),
        Err(error) => Some(Err(error)),
    }
}

/// Waits for the owner's answer to ask `seq` until `lease`; past it the ask
/// is read once and, still open, stands (FIX 3837): `None`. A withdrawn or
/// vanished ask, or one whose wait failed, abstains.
fn owner_answer(asks: &DecisionAsks, seq: u64, lease: Instant) -> Option<DecisionAnswer> {
    let runtime = tokio::runtime::Handle::try_current().ok();
    loop {
        let left = lease.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return match ruling_now(asks, seq) {
                None | Some(Err(_)) => None,
                Some(Ok(given)) => Some(given),
            };
        }
        let wait = left.min(OWNER_ASK_POLL);
        let answered = match &runtime {
            Some(runtime) => match runtime.block_on(tokio::time::timeout(wait, asks.answered(seq)))
            {
                Ok(answered) => Some(answered.map(|answer| answer.answer)),
                Err(_) => None,
            },
            None => {
                std::thread::sleep(wait);
                ruling_now(asks, seq)
            }
        };
        match answered {
            None => {}
            Some(Ok(given)) => return Some(given),
            Some(Err(_)) => return Some(DecisionAnswer::Abstain),
        }
    }
}
