//! The held sign act's worker (OF-415, ARCH-0064 D6, ARCH-0076
//! #roles-everywhere): every tick it asks the vault owner role about each
//! new hold and settles each answered one. The question starts at the owner
//! role's rung: no rule or model rung answers whether a signature lands,
//! because decide() advises and never grants. The owner answers on the
//! decision-ask door. A hold that fails a tick stays as it was for the
//! next, never dropped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::blob_artifact::esign::{
    HOLD_ALLOW, HOLD_DECLINE, HeldSigning, HeldSigningAnswer, HeldSigningState,
};
use oneiron::llm::decision::{DecisionAnswer, DecisionRung, Reversibility};
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

/// Puts one hold's question in the owner role's ask queue.
fn ask(server: &SyncServer, owner: EntityId, held: &HeldSigning) -> Result<()> {
    let host = server.decision_host();
    let question = held.question()?;
    let mut dial = host.dial(DecisionRung::Human);
    dial.first = DecisionRung::Human;
    let state = json!({
        "document": held.document,
        "title": held.title,
        "recipient": held.recipient,
        "principal_ref": held.principal_ref,
        "next": held.next,
        "held_at": held.held_at,
        "calls": held.calls,
    });
    host.ladder().ladder().run(
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

/// Settles one asked hold once the owner role answered it.
fn settle(server: &SyncServer, owner: EntityId, held: &HeldSigning) -> Result<()> {
    let Some(ask) = server
        .decision_host()
        .asks()
        .latest(&held.question()?, owner)?
    else {
        return Ok(());
    };
    let Some(answer) = ask.answer else {
        return Ok(());
    };
    let answer = match answer.answer {
        DecisionAnswer::Choice(label) if label == HOLD_ALLOW => HeldSigningAnswer::Allow,
        DecisionAnswer::Choice(label) if label == HOLD_DECLINE => HeldSigningAnswer::Decline,
        _ => return Ok(()),
    };
    let settled = server.vault().settle_esign_hold(
        &held.document,
        &held.recipient,
        held.held_at,
        answer,
    )?;
    tracing::info!(
        document = %settled.document,
        recipient = %settled.recipient,
        state = ?settled.state,
        "esign hold settled by the vault owner role"
    );
    Ok(())
}
