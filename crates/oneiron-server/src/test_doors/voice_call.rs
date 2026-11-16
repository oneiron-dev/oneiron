//! Doors for `tests/voice_self_epoch.rs` (UNBUILT-02 PR 2): the brain of an
//! owner's own standalone call on this device, its record resolved as a
//! call's boot resolves it, and one of its turns driven from the person's
//! final transcript to its stop, with what the turn keeps written.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::interlocutor::InterlocutorSet;
use oneiron::voice_cascade::{Brain, BrainEvent, BrainRequest, RetrievalContext};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use tokio::sync::mpsc;

use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;
use crate::voice_host::{ChatBrain, ChatBrainBindings, VoiceBrainOut, standalone_call_record};

/// The seeded agent a call answers with, as the call's boot reads it.
const DEFAULT_AGENT: &str = "sys.default";
/// The cascade session the door's generation tokens name.
const CASCADE_SESSION: u128 = 0x0e11_ca11;
/// How long a turn may take to stop and keep what it keeps.
const TURN_PATIENCE: Duration = Duration::from_secs(60);

/// An owner's own standalone call, held open by its brain.
pub struct StandaloneCall {
    brain: ChatBrain,
    out: mpsc::Receiver<VoiceBrainOut>,
    session_ref: String,
    agent: EntityId,
}

impl StandaloneCall {
    /// `person`'s standalone call on this device with the seeded default
    /// agent, paid and written as `person`. Refused when the call would
    /// keep no turn.
    ///
    /// # Errors
    ///
    /// No default agent, no record, or no chat seat.
    pub fn open(server: &Arc<SyncServer>, person: EntityId) -> anyhow::Result<Self> {
        let vault = server.vault();
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)?
            .ok_or_else(|| anyhow::anyhow!("no default agent"))?;
        let payer = WriteActor::new(person, EdgeActorClass::Human);
        let record = standalone_call_record(
            server,
            person,
            agent,
            payer,
            PeerMachine::Unknown,
            CallerLocality::OnDevice,
        )
        .ok_or_else(|| anyhow::anyhow!("an on-device standalone call keeps no turn"))?;
        let (out, receiver) = mpsc::channel(64);
        let brain = ChatBrain::new(ChatBrainBindings {
            ai: server.ai.clone(),
            vault: Arc::clone(vault),
            // Read only for a turn's retrieved memories or its room; the
            // door's turns carry neither.
            auth: CoreAuth::from_oauth_relay(
                person.to_hex(),
                BTreeSet::from([CoreScope::Read, CoreScope::Write]),
            ),
            phone: None,
            room: None,
            instructions: None,
            agent,
            payer,
            funding: None,
            out,
            record: Some(record),
        })
        .map_err(|error| anyhow::anyhow!("voice brain: {error:?}"))?;
        Ok(Self {
            brain,
            out: receiver,
            session_ref: format!("voice-call:{}", EntityId::now().to_hex()),
            agent,
        })
    }

    /// The agent answering the call.
    #[must_use]
    pub fn agent(&self) -> EntityId {
        self.agent
    }

    /// One turn: `transcript` as the person's final at `generation`, its
    /// answer streamed to its stop, then until the brain is at rest, so
    /// whatever the turn keeps has landed.
    ///
    /// # Errors
    ///
    /// The turn did not start, its answer did not stop, or it did not
    /// settle in time.
    pub async fn say(&mut self, generation: u64, transcript: &str) -> anyhow::Result<()> {
        let request = BrainRequest {
            generation: oneiron::test_doors::voice_generation_epoch::generation_epoch(
                CASCADE_SESSION,
                generation,
            ),
            transcript: transcript.to_owned(),
            retrieval: RetrievalContext {
                result_refs: Vec::new(),
                promoted: false,
                run_id: None,
                partial: false,
            },
            session_ref: self.session_ref.clone(),
            tools_enabled: false,
            interlocutors: InterlocutorSet::owner_alone(),
            audience_revision: 0,
            tool_events: Vec::new(),
            externally_tainted: false,
        };
        self.brain.start(&request)?;
        tokio::time::timeout(TURN_PATIENCE, async {
            loop {
                let Some(out) = self.out.recv().await else {
                    anyhow::bail!("the brain stopped sending");
                };
                match out.event {
                    BrainEvent::Done => break,
                    BrainEvent::Incomplete => anyhow::bail!("the answer did not stop"),
                    BrainEvent::Error(error) => anyhow::bail!("the turn failed: {error}"),
                    BrainEvent::TextDelta(_) | BrainEvent::Tool(_) => {}
                }
            }
            // What the turn keeps lands on its own task after its stop.
            while !self.brain.at_rest() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("the turn did not settle in time"))?
    }
}
