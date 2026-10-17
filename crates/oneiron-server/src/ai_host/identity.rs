//! Identity decisions (OF-123, ask rule B): the host side of the Dreamer's
//! identity re-check. Each round asks the open identity asks on the host's
//! decision ladder, act-now ones first, as one Choice over the candidates
//! and someone new. The dial stops at the Big rung: an abstention goes to
//! the person through the ask's own inbox notification and choice card, not
//! the generic owner ask queue, so the person sees one question in one
//! place. A slower beat sends each waiting ask again in the conversation
//! that mentions its name since.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::dreamer_runner::maintenance::identity::{IdentityDecisions, IdentityRuling};
use oneiron::llm::decision::DecisionRung;
use oneiron::retrieval_depth::RetrievalDeadline;

use crate::server::SyncServer;

/// The host's wording of the identity question; the options carry the
/// candidates and the state their names and the words around the mention.
const WORDING: &str = "Which candidate is the person this mention names? \
    Choose someone_new when it is none of them.";
const TICK: Duration = Duration::from_secs(2);
/// Asks one round decides.
const ROUND: usize = 4;
/// Rounds between two passes that send waiting asks again.
const RESURFACE_EVERY: u32 = 30;
/// One decision's budget.
const DECIDE_BUDGET: Duration = Duration::from_secs(20);

/// Starts the worker. Each round runs on a blocking thread: the ladder's
/// model rungs block on the server's runtime.
pub(crate) fn spawn(server: &Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut beat: u32 = 0;
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let resurface = beat % RESURFACE_EVERY == 0;
            beat = beat.wrapping_add(1);
            match tokio::task::spawn_blocking(move || round(&server, resurface)).await {
                // By kind only: an engine error can quote the vault.
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "identity asks wait for the next round");
                }
                Err(error) => tracing::warn!(%error, "identity round stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}

fn round(server: &SyncServer, resurface: bool) -> oneiron::Result<()> {
    let vault = server.vault();
    let now = vault.now_recorded_at();
    let due = vault.identity_asks_due(now, ROUND)?;
    if !due.is_empty() {
        let principal = vault.ensure_embedded_owner_actor().map_err(|error| {
            oneiron::Error::InvalidConfig(format!("no owner principal: {error}"))
        })?;
        let host = server.decision_host();
        for ask in due {
            let deadline = RetrievalDeadline::hard(Instant::now(), DECIDE_BUDGET);
            let decisions = IdentityDecisions {
                ladder: host.ladder().ladder(),
                principal,
                dial: host.dial(DecisionRung::Big),
                bands: host.bands(),
                wording: WORDING.to_owned(),
                deadline: &deadline,
            };
            match vault.decide_identity_ask(&decisions, &ask, now) {
                Ok(IdentityRuling::Retry) => {
                    tracing::debug!("an identity decision failed; it is asked again later");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "an identity ask was not decided");
                }
            }
        }
    }
    if resurface {
        vault.resurface_identity_asks(now)?;
    }
    Ok(())
}
