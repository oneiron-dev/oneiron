//! Doors for `tests/voice_self_epoch.rs` (UNBUILT-02 PR 2),
//! `tests/voice_phone_transcript.rs` (PR 3),
//! `tests/voice_call_announcement.rs` (PR 3B) and
//! `tests/voice_room_call.rs` (PR 4): the brain of an owner's own
//! standalone call on this device, of a phone call its line agent
//! answered, or of a room call heard in a room, its record and opening line
//! resolved as the call's boot resolves them, the opening line spoken as the
//! call's loop opens it, and one of its turns driven from the speaker's
//! final transcript to its stop, with what the turn keeps written.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::interlocutor::InterlocutorSet;
use oneiron::voice_cascade::{
    Brain, BrainEvent, BrainRequest, RetrievalContext, VoiceCascadeSession,
};
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use tokio::sync::mpsc;

use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;
use crate::voice_host::{
    ChatBrain, ChatBrainBindings, VoiceBrainOut, phone_call_opening, phone_call_record,
    phone_call_session, room_call_record, standalone_call_record,
};

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
        drive_turn(
            &mut self.brain,
            &mut self.out,
            &self.session_ref,
            generation,
            transcript,
            None,
        )
        .await
    }
}

/// A phone call the line agent answered, held open by its brain. Its line
/// agent is the seeded default agent; the call's phone read fence is not
/// the door's subject, so the brain holds none.
pub struct PhoneCall {
    brain: ChatBrain,
    out: mpsc::Receiver<VoiceBrainOut>,
    vault: Arc<Vault>,
    session_ref: String,
    agent: EntityId,
    conversation: EntityId,
    /// The line the call opens with, until it is spoken.
    opening: Option<String>,
}

impl PhoneCall {
    /// A phone call from `caller` (the arrival's caller text; `None` when
    /// withheld), answered by the seeded default agent: its record and its
    /// opening line resolved as the phone call's boot resolves them, so its
    /// start row is written.
    ///
    /// # Errors
    ///
    /// No default agent, no record, or no chat seat.
    pub fn answer(server: &Arc<SyncServer>, caller: Option<&str>) -> anyhow::Result<Self> {
        let vault = server.vault();
        let (agent, definition) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)?
            .ok_or_else(|| anyhow::anyhow!("no default agent"))?;
        let opening = phone_call_opening(vault, &definition);
        let session_ref = format!("voice-call:{}", EntityId::now().to_hex());
        let record = phone_call_record(vault, agent, caller, &session_ref)
            .ok_or_else(|| anyhow::anyhow!("the phone call keeps nothing"))?;
        let conversation = record.conversation;
        let (out, receiver) = mpsc::channel(64);
        let brain = ChatBrain::new(ChatBrainBindings {
            ai: server.ai.clone(),
            vault: Arc::clone(vault),
            auth: CoreAuth::from_oauth_relay(
                agent.to_hex(),
                BTreeSet::from([CoreScope::Read, CoreScope::Write]),
            ),
            phone: None,
            room: None,
            instructions: None,
            agent,
            payer: WriteActor::new(agent, EdgeActorClass::Agent),
            funding: None,
            out,
            record: Some(record),
        })
        .map_err(|error| anyhow::anyhow!("voice brain: {error:?}"))?;
        Ok(Self {
            brain,
            out: receiver,
            vault: Arc::clone(vault),
            session_ref,
            agent,
            conversation,
            opening,
        })
    }

    /// The call opens as its loop opens it: its opening line, when the owner's
    /// announcement is on, opened by the call's voice session as a
    /// generation with no caller's words before it, and spoken by the brain
    /// to its end, with what it keeps written. What the brain handed to
    /// speech; `None` when the call opens silent.
    ///
    /// # Errors
    ///
    /// The session refused the generation, the brain did not speak the line
    /// to its end, or it did not settle in time.
    pub async fn open(&mut self) -> anyhow::Result<Option<String>> {
        let Some(line) = self.opening.take() else {
            return Ok(None);
        };
        let mut session = VoiceCascadeSession::new(
            Arc::clone(&self.vault),
            phone_call_session(&self.session_ref, self.agent),
        )?;
        let request = session.open_announcement(line)?;
        self.brain.announce(&request)?;
        let brain = &self.brain;
        let events = &mut self.out;
        tokio::time::timeout(TURN_PATIENCE, async {
            let mut said = String::new();
            loop {
                let Some(out) = events.recv().await else {
                    anyhow::bail!("the brain stopped sending");
                };
                match out.event {
                    BrainEvent::TextDelta(text) => said.push_str(&text),
                    BrainEvent::Done => break,
                    other => anyhow::bail!("the announcement did not end whole: {other:?}"),
                }
            }
            while !brain.at_rest() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(Some(said))
        })
        .await
        .map_err(|_| anyhow::anyhow!("the announcement did not settle in time"))?
    }

    /// The line agent answering the call.
    #[must_use]
    pub fn agent(&self) -> EntityId {
        self.agent
    }

    /// The call's thread.
    #[must_use]
    pub fn conversation(&self) -> EntityId {
        self.conversation
    }

    /// One turn: `transcript` as the caller's final at `generation`, as
    /// [`StandaloneCall::say`] drives it.
    ///
    /// # Errors
    ///
    /// As [`StandaloneCall::say`].
    pub async fn say(&mut self, generation: u64, transcript: &str) -> anyhow::Result<()> {
        drive_turn(
            &mut self.brain,
            &mut self.out,
            &self.session_ref,
            generation,
            transcript,
            None,
        )
        .await
    }

    /// The caller hangs up: the brain drops, which writes the call's end
    /// row before this returns.
    pub fn hang_up(self) {
        drop(self.brain);
    }
}

/// A room call heard in a room, held open by its brain. Its answering agent
/// is the seeded default agent; the call's room read fence is not the door's
/// subject, so the brain holds none.
pub struct RoomCall {
    brain: ChatBrain,
    out: mpsc::Receiver<VoiceBrainOut>,
    session_ref: String,
    agent: EntityId,
    conversation: EntityId,
}

impl RoomCall {
    /// `person`'s room call heard in `room`, on this device, with the call's
    /// speakers matched under `roster` when named: its record resolved as
    /// the call's boot resolves it, so its start row is written. Refused
    /// when the call keeps no turn.
    ///
    /// # Errors
    ///
    /// No default agent, no record, no room read, or no chat seat.
    pub fn open(
        server: &Arc<SyncServer>,
        person: EntityId,
        room: EntityId,
        roster: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::open_at(server, person, room, None, roster)?
            .ok_or_else(|| anyhow::anyhow!("a room call that keeps no turn"))
    }

    /// `person`'s room call heard at `place`, a room or one of its threads by
    /// any TURN of it: the place resolved as the call's boot resolves it.
    /// `Ok(None)` when the call keeps no turn yet, as in a thread or a
    /// project room.
    ///
    /// # Errors
    ///
    /// No default agent, no room read, or no chat seat.
    pub fn open_in(
        server: &Arc<SyncServer>,
        person: EntityId,
        place: EntityId,
        roster: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let work = crate::api::ai::room_place::call_place(server.vault(), place)
            .map_err(|error| anyhow::anyhow!("the call's place does not resolve: {error:?}"))?;
        Self::open_at(server, person, work.room, work.branch, roster)
    }

    /// A room call in `room`, in `branch` when the call named a thread: its
    /// members read as the call's boot reads them, its record resolved, and
    /// its brain. `Ok(None)` when the record is none.
    fn open_at(
        server: &Arc<SyncServer>,
        person: EntityId,
        room: EntityId,
        branch: Option<EntityId>,
        roster: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let vault = server.vault();
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)?
            .ok_or_else(|| anyhow::anyhow!("no default agent"))?;
        let auth = CoreAuth::from_oauth_relay(
            person.to_hex(),
            BTreeSet::from([CoreScope::Read, CoreScope::Write]),
        );
        let members = {
            let read = crate::api::scoped_read_for_core_auth(vault, &auth)
                .map_err(|error| anyhow::anyhow!("the room does not read: {error:?}"))?;
            vault
                .room_audience_members_under(&read, room, Some(person))
                .map_err(|error| anyhow::anyhow!("the room does not read: {error:?}"))?
        };
        let payer = WriteActor::new(person, EdgeActorClass::Human);
        let session_ref = format!("voice-call:{}", EntityId::now().to_hex());
        let Some(record) = room_call_record(
            server,
            payer,
            PeerMachine::Unknown,
            CallerLocality::OnDevice,
            room,
            branch,
            &members,
            roster.map(str::to_owned),
            &session_ref,
        ) else {
            return Ok(None);
        };
        let conversation = record.conversation;
        let (out, receiver) = mpsc::channel(64);
        let brain = ChatBrain::new(ChatBrainBindings {
            ai: server.ai.clone(),
            vault: Arc::clone(vault),
            auth,
            phone: None,
            room: Some(room),
            instructions: None,
            agent,
            payer,
            funding: None,
            out,
            record: Some(record),
        })
        .map_err(|error| anyhow::anyhow!("voice brain: {error:?}"))?;
        Ok(Some(Self {
            brain,
            out: receiver,
            session_ref,
            agent,
            conversation,
        }))
    }

    /// The agent answering the call.
    #[must_use]
    pub fn agent(&self) -> EntityId {
        self.agent
    }

    /// The room the call is heard in.
    #[must_use]
    pub fn conversation(&self) -> EntityId {
        self.conversation
    }

    /// One turn: `transcript` as the speaker's final at `generation`, heard
    /// under `speaker` when the host route's final named one, as
    /// [`StandaloneCall::say`] drives it.
    ///
    /// # Errors
    ///
    /// As [`StandaloneCall::say`].
    pub async fn say(
        &mut self,
        generation: u64,
        transcript: &str,
        speaker: Option<&str>,
    ) -> anyhow::Result<()> {
        drive_turn(
            &mut self.brain,
            &mut self.out,
            &self.session_ref,
            generation,
            transcript,
            speaker,
        )
        .await
    }

    /// The call ends: the brain drops, which writes the call's end row
    /// before this returns.
    pub fn hang_up(self) {
        drop(self.brain);
    }
}

/// One turn of `brain`'s call: `transcript` as the speaker's final at
/// `generation`, heard under `speaker` when the host route's final named
/// one, its answer streamed to its stop, then until the brain is at rest, so
/// whatever the turn keeps has landed.
async fn drive_turn(
    brain: &mut ChatBrain,
    events: &mut mpsc::Receiver<VoiceBrainOut>,
    session_ref: &str,
    generation: u64,
    transcript: &str,
    speaker: Option<&str>,
) -> anyhow::Result<()> {
    let epoch =
        oneiron::test_doors::voice_generation_epoch::generation_epoch(CASCADE_SESSION, generation);
    let request = BrainRequest {
        generation: epoch,
        transcript: transcript.to_owned(),
        retrieval: RetrievalContext {
            result_refs: Vec::new(),
            promoted: false,
            run_id: None,
            partial: false,
        },
        session_ref: session_ref.to_owned(),
        tools_enabled: false,
        interlocutors: InterlocutorSet::owner_alone(),
        audience_revision: 0,
        tool_events: Vec::new(),
        externally_tainted: false,
    };
    brain.final_speaker(epoch, speaker);
    brain.start(&request)?;
    tokio::time::timeout(TURN_PATIENCE, async {
        loop {
            let Some(out) = events.recv().await else {
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
        while !brain.at_rest() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("the turn did not settle in time"))?
}
