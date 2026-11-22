//! Doors for `tests/voice_room_turn_off_record.rs` (row
//! VOICE-ROOM-TURN-SOURCED-OFF-RECORD): the brain of a call heard in a room,
//! and one of its turns driven from the person's final transcript to its
//! stop. A room call keeps no standalone record, so the brain holds none;
//! each turn still proves the room under the member's credential, the slip
//! the call's hello admitted.

use std::sync::Arc;
use std::time::Duration;

use oneiron::claim::CallerLocality;
use oneiron::interlocutor::InterlocutorSet;
use oneiron::voice_cascade::{Brain, BrainEvent, BrainRequest, RetrievalContext};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use tokio::sync::mpsc;

use crate::auth::{BindingProof, CoreAuth};
use crate::server::SyncServer;
use crate::voice_host::{ChatBrain, ChatBrainBindings, VoiceBrainOut};

use super::{CASCADE_SESSION, DEFAULT_AGENT, TURN_PATIENCE};

/// The holder-bound slip a call's hello carries, with the fresh binding
/// proof the caller's device signs over it.
pub struct HelloSlip {
    /// The slip's token.
    pub token: String,
    /// The proof's timestamp, on the vault's clock.
    pub timestamp: u64,
    /// The proof's nonce.
    pub nonce: String,
    /// Hex of the holder's signature over the slip's binding transcript.
    pub signature: String,
}

/// A call heard in a room, held open by its brain.
pub struct RoomTurnCall {
    brain: ChatBrain,
    out: mpsc::Receiver<VoiceBrainOut>,
    session_ref: String,
    agent: EntityId,
}

impl RoomTurnCall {
    /// `person`'s call heard in `room` on this device with the seeded default
    /// agent, paid as `person`. The brain keeps no standalone record, as a
    /// call heard in a room keeps none; it proves the room on every turn
    /// under `person`'s credential, so `person` must read the room. The
    /// credential is `hello`, admitted as a call's hello admits it: the slip
    /// with its fresh binding proof, once, on this device.
    ///
    /// # Errors
    ///
    /// No default agent, a hello slip the vault refuses, or no chat seat.
    pub fn open(
        server: &Arc<SyncServer>,
        person: EntityId,
        room: EntityId,
        hello: &HelloSlip,
    ) -> anyhow::Result<Self> {
        let vault = server.vault();
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)?
            .ok_or_else(|| anyhow::anyhow!("no default agent"))?;
        let binding = BindingProof {
            timestamp: hello.timestamp,
            nonce: hello.nonce.clone(),
            signature: hello.signature.clone(),
        };
        let auth = CoreAuth::bind_transport_once(&hello.token, &binding, vault.as_ref())
            .map_err(|error| anyhow::anyhow!("hello slip refused: {error:?}"))?
            .at(CallerLocality::OnDevice);
        let (out, receiver) = mpsc::channel(64);
        let brain = ChatBrain::new(ChatBrainBindings {
            ai: server.ai.clone(),
            vault: Arc::clone(vault),
            // The member's own credential: each turn proves the room under
            // it, and would read its retrieved memories under it too. The
            // door's turns carry no retrieval.
            auth,
            phone: None,
            room: Some(room),
            instructions: None,
            agent,
            payer: WriteActor::new(person, EdgeActorClass::Human),
            funding: None,
            out,
            // A call heard in a room keeps no standalone record.
            record: None,
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
    /// whatever the turn settles has landed.
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
            // What the turn settles lands on its own task after its stop.
            while !self.brain.at_rest() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("the turn did not settle in time"))?
    }
}
