//! The held sign act's worker (OF-415, ARCH-0064 D6, ARCH-0076
//! #roles-everywhere): every tick it asks each new hold up its role chain
//! and settles each answered one. The question starts at the person rung:
//! no rule or model rung answers whether a signature lands, because
//! decide() advises and never grants. The ask goes first to the person the
//! agent signs for (or the document's sender) and climbs to the vault
//! owners; it is an e-signature act, so at every rung it resolves only to a
//! natural person holding the role, who answers on the decision-ask door.
//! An ask its person leaves unanswered for `esign.ask.climb_hours` climbs to
//! the next role. A hold that fails a tick stays as it was for the next,
//! never dropped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::blob_artifact::esign::{
    HOLD_ALLOW, HOLD_DECLINE, HeldSigning, HeldSigningAnswer, HeldSigningState,
};
use oneiron::llm::decision::{
    AskAct, AskTo, DecisionAnswer, DecisionRung, Reversibility, RoleRank,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, Error, Result};
use serde_json::json;

use crate::server::SyncServer;

const TICK: Duration = Duration::from_secs(15);
/// The clock one hold's ask runs under.
const ASK_BUDGET: Duration = Duration::from_secs(30);

/// Starts the hold worker on the server's runtime.
pub(crate) fn spawn(server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(&server);
    drop(server);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            match tokio::task::spawn_blocking(move || tick(&server)).await {
                Ok(Err(error)) => {
                    tracing::warn!(%error, "esign hold pass failed; it runs again next tick");
                }
                Err(error) => tracing::warn!(%error, "esign hold pass stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}

/// One pass over the open holds.
fn tick(server: &SyncServer) -> Result<()> {
    let open = server.vault().esign_held_signings(true)?;
    if open.is_empty() {
        return Ok(());
    }
    let owner = server
        .vault()
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("no owner principal: {error}")))?;
    for held in open {
        let passed = match held.state {
            HeldSigningState::Held => ask(server, owner, &held),
            HeldSigningState::Asked { .. } => settle(server, owner, &held),
            _ => Ok(()),
        };
        if let Err(error) = passed {
            tracing::warn!(
                %error,
                document = %held.document,
                recipient = %held.recipient,
                "esign hold stays held for the next tick"
            );
        }
    }
    Ok(())
}

/// Puts one hold's question in its first role's ask queue. The ladder call
/// stays the owner's, so [`settle`] finds the answer whoever on the chain
/// gave it.
fn ask(server: &SyncServer, owner: EntityId, held: &HeldSigning) -> Result<()> {
    let host = server.decision_host();
    let question = held.question()?;
    let mut dial = host.dial(DecisionRung::Human);
    dial.first = DecisionRung::Human;
    // An e-signature goes to a natural person holding each role, never to a
    // board or a bound agent that holds it too.
    let signer = AskTo {
        role: held.first_role(server.vault())?,
        ceiling: RoleRank::Owner,
        act: AskAct::ESignature,
    };
    let mut ladder = host.ladder().ladder();
    ladder.ask_to = Some(&signer);
    let state = json!({
        "document": held.document,
        "title": held.title,
        "recipient": held.recipient,
        "principal_ref": held.principal_ref,
        "next": held.next,
        "held_at": held.held_at,
        "calls": held.calls,
    });
    ladder.run(
        &question,
        owner,
        &[],
        &state,
        dial,
        &host.bands(),
        Reversibility::OutboundEffect,
        &RetrievalDeadline::hard(Instant::now(), ASK_BUDGET),
    )?;
    server
        .vault()
        .esign_hold_asked(&held.document, &held.recipient, held.held_at, question.id)
}

/// Settles one asked hold once a holder of its role answered it, and climbs
/// an ask left unanswered past its wait.
fn settle(server: &SyncServer, owner: EntityId, held: &HeldSigning) -> Result<()> {
    let Some(ask) = server
        .decision_host()
        .asks()
        .latest(&held.question()?, owner)?
    else {
        return Ok(());
    };
    if ask.answer.is_none() {
        if server.vault().climb_stale_esign_ask(held, &ask)? {
            tracing::info!(
                document = %held.document,
                recipient = %held.recipient,
                "esign hold's unanswered ask climbed its role chain"
            );
        }
        return Ok(());
    }
    let Some(answer) = ask.answer else {
        return Ok(());
    };
    let answer = match answer.answer {
        DecisionAnswer::Choice(label) if label == HOLD_ALLOW => HeldSigningAnswer::Allow {
            by: answer.by,
            role: answer.role.rank(),
        },
        DecisionAnswer::Choice(label) if label == HOLD_DECLINE => HeldSigningAnswer::Decline,
        _ => return Ok(()),
    };
    let settled =
        server
            .vault()
            .settle_esign_hold(&held.document, &held.recipient, held.held_at, answer)?;
    tracing::info!(
        document = %settled.document,
        recipient = %settled.recipient,
        state = ?settled.state,
        "esign hold settled by its role's answer"
    );
    Ok(())
}
