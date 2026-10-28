//! The served connector-event responder (OF-519): what a Dreamer pass runs
//! when a subscribed Slack or LINE message wakes the agent it addressed.
//!
//! The pass only hands the reply off (FIX 2405): it queues one durable
//! reply job for the agent and event and settles at once, so no model call
//! or send holds the pass. The reply worker ([`worker`]) runs the job: the
//! agent answers on the chat role, on its own budget line, with its stored
//! instructions as the system message; the sender's words reach it as
//! labelled foreign data, never as instructions. No text is invented here.
//! The words it writes are kept in the vault before the reply is named, so
//! a rerun sends them again instead of asking the model twice, and the
//! reply leaves through the ordinary recorded dispatch (gate, consent,
//! budget, window, ledger, receipt) on the served sink.
use std::sync::Arc;

use oneiron::attempt_queue::AttemptId;
use oneiron::connector_key::events::ConnectorEvent;
use oneiron::dreamer_runner::connector_event::{
    ConnectorEventReplyHandoff, ConnectorEventResponder, ConnectorEventWake,
};
use oneiron::outbound::ConnectorReplyJob;
use oneiron::surface_event::{SurfaceConnectorPayload, SurfaceEventDispatchRoute};
use oneiron::{EntityId, Vault};

use super::dreamer::QuestionTimer;
use crate::models::ModelRuntime;

mod worker;

pub(crate) use self::worker::run_connector_reply_job;

/// The channels the served sink answers on.
const SERVED_REPLY_CHANNELS: [&str; 2] = [
    oneiron::channel_identity_provider::SLACK_CHANNEL,
    oneiron::channel_identity_provider::LINE_CHANNEL,
];

/// The pass-facing half of the served reply: the hand-off. The model
/// runtime, the chat budget and the LINE plan are read live by the reply
/// worker for each job, so nothing handed in at installation is kept.
pub(super) struct ServedConnectorResponder;

impl ServedConnectorResponder {
    pub(super) fn new(
        _vault: Arc<Vault>,
        _runtime: Arc<ModelRuntime>,
        _serve: tokio::runtime::Handle,
        _server: QuestionTimer,
    ) -> Self {
        Self
    }
}

impl ConnectorEventResponder for ServedConnectorResponder {
    fn handoff(
        &mut self,
        vault: &Vault,
        wake: &ConnectorEventWake,
        parent: AttemptId,
        now: u64,
    ) -> oneiron::Result<ConnectorEventReplyHandoff> {
        if answerable_origin(&wake.event, wake.agent)?.is_none() {
            return Ok(ConnectorEventReplyHandoff::NoReply);
        }
        let job = ConnectorReplyJob {
            agent: wake.agent,
            event: wake.event.clone(),
            parent_attempt: parent,
        };
        let job = vault.enqueue_connector_reply_job(&job, now)?;
        Ok(ConnectorEventReplyHandoff::Queued { job })
    }
}

/// The origin of an event `agent` answers here. Only a surface-born message
/// the agent itself was addressed by has a sender to answer: a tap, an
/// intake copy or another actor's message is the agent's to read, not to
/// answer here.
fn answerable_origin(
    event: &ConnectorEvent,
    agent: EntityId,
) -> oneiron::Result<Option<SurfaceConnectorPayload>> {
    let Ok(origin) = SurfaceConnectorPayload::from_connector_event(event) else {
        return Ok(None);
    };
    if origin.route != SurfaceEventDispatchRoute::ActorSelf
        || !SERVED_REPLY_CHANNELS.contains(&origin.channel.as_str())
        || origin.actor()? != agent
    {
        return Ok(None);
    }
    Ok(Some(origin))
}
