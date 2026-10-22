//! The owner's ruling on an answer under `always ask` (FIX 3837, 3842): the
//! ask raised or reused for exactly one frozen answer, the wait for its
//! ruling within the round's live lease, and its withdrawal once nothing is
//! left to send it to (FIX 9160).

use oneiron::llm::decision::{DecisionAnswer, DecisionAsks};
use oneiron::outbound_consent::ConnectorElicitationAnswer;

use super::*;

/// Asks the owner about exactly `frozen`, or reads the ask the same answer
/// to this round already raised, and waits for the ruling within the
/// round's live lease. Past the lease the ask stands, kept with the round,
/// so the same answer given again reads it (FIX 3837); an ask another
/// answer superseded is withdrawn. The linked parts of a long ask are
/// withdrawn once it is decided (FIX 3842).
pub(super) fn owner_rules(
    server: &SyncServer,
    claim: &Claim<'_>,
    authority: &ConnectorElicitationBinding,
    frozen: &FrozenAnswer,
) -> OwnerRuling {
    let asks = server.decision_host().asks();
    let kept = match &claim.owner_ask {
        Some((digest, asked)) if *digest == frozen.digest => Some(asked.clone()),
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
        None => {
            let answer = ConnectorElicitationAnswer {
                handle: &claim.handle,
                generation: claim.generation,
                questions: &claim.questions,
                answers: &frozen.text,
                digest: frozen.digest,
            };
            match server
                .vault()
                .queue_connector_elicitation_owner_ask(authority, &answer)
            {
                Ok(asked) => asked,
                Err(error) => {
                    tracing::warn!(%error, "connector elicitation owner ask not queued");
                    return OwnerRuling::Unasked;
                }
            }
        }
    };
    let ruling = owner_ruling(asks, asked.seq, claim.lease);
    let registry = &server.connector_elicitations;
    if matches!(ruling, OwnerRuling::Pending) {
        // A round whose worker already ended keeps no ask (FIX 9160).
        if !registry.keep_owner_ask(
            &claim.handle,
            claim.generation,
            Some((frozen.digest, asked.clone())),
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

/// Waits for the owner's ruling on ask `seq` until `lease`; past it the ask
/// is read once and, still open, stands (FIX 3837).
fn owner_ruling(asks: &DecisionAsks, seq: u64, lease: Instant) -> OwnerRuling {
    let runtime = tokio::runtime::Handle::try_current().ok();
    loop {
        let left = lease.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return match ruling_now(asks, seq) {
                None | Some(Err(_)) => OwnerRuling::Pending,
                Some(Ok(DecisionAnswer::Noul(true))) => OwnerRuling::Yes,
                Some(Ok(_)) => OwnerRuling::No,
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
            Some(Ok(DecisionAnswer::Noul(true))) => return OwnerRuling::Yes,
            // A no, an abstain or a withdrawn ask declines.
            Some(_) => return OwnerRuling::No,
        }
    }
}
