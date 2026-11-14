//! `say` (L8-25; agent-runtime-v1 #d6, ARCH-0067 tasks table, ARCH-0079
//! #channels): one message to a destination the caller names, as a room, a
//! person or agent by its people handle, or a TASK, meaning the agent or
//! person that holds it. Each route is a door the caller can already call by
//! name (`vault.rooms.speak`, `self.message`), under its own read and grant,
//! so a caller that may not message someone may not `say` to them either.
//! `kind` marks the message a note or an ask: metadata only, which no
//! authority rides. `refs` are the records it cites, admitted under the
//! caller's read by the row's OF-063 check and carried as the turn's cited
//! assertions. A code run's plain `say(text)` speaks where the run speaks,
//! as `self.speak` does; the run's bridge answers it, so this door never sees
//! it.

use serde::{Deserialize, Serialize};

use super::{
    Memory, MemoryError, MemoryResult, MessagePersonRequest, WitnessAssertions, WitnessAuthor,
    WitnessMessage, WitnessReceipt, WitnessTurn,
};
use crate::EdgeActorClass;

/// A `say` that names no destination, outside the one case a code run
/// answers itself: a plain `say(text)`.
pub const SAY_NEEDS_A_DESTINATION: &str = "say_needs_a_destination";
/// A `to` that names no room, person, agent or TASK this caller can read.
pub const SAY_UNKNOWN_DESTINATION: &str = "say_unknown_destination";
/// A `to` that names a TASK no agent or person holds open.
pub const SAY_TASK_UNASSIGNED: &str = "say_task_unassigned";

/// What a message asks of its reader (canon's closed pair). Neither carries
/// authority: a note is advice, an ask a cheap question while work goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SayKind {
    /// Advice, with no authority.
    Note,
    /// A cheap question; work goes on while it waits.
    Ask,
}

impl SayKind {
    /// The message metadata that marks this kind.
    fn metadata(self) -> serde_json::Value {
        let kind = match self {
            Self::Note => "note",
            Self::Ask => "ask",
        };
        serde_json::json!({ "say_kind": kind })
    }
}

/// `say`'s input: the message, where it goes, its kind and the records it
/// cites.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SayRequest {
    /// The message's words. A code run's `say(text)` sends them here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A result of the calling code run, by its name, handle or card
    /// (`say(r7)`), spoken as its typed-result bubble.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Where the message goes: a room (CONVERSATION short id or id), a
    /// person or agent by its people handle (`pr<n>`), or a TASK (short id
    /// or id), meaning the agent or person that holds it. A code run's plain
    /// `say(text)` with none speaks where the run speaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// `note` (advice) or `ask` (a question while work goes on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SayKind>,
    /// Records the message cites, each one the caller can read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
}

/// `say`'s receipt: the room the message landed in and its witness receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SayReceipt {
    /// The room's id, hex.
    pub room: String,
    pub receipt: WitnessReceipt,
}

/// What a message carries beside its words: its metadata and the records
/// its turn asserts.
#[derive(Debug, Clone, Default)]
pub(crate) struct MessageMarks {
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) assertions: WitnessAssertions,
}

/// Where one `say` goes, resolved under the caller's own read.
enum SayDestination {
    /// A person or agent, by its people handle.
    Person(String),
    /// A room.
    Room(crate::EntityId),
}

impl Memory<'_> {
    /// `say`: one message to the destination `to` names.
    ///
    /// # Errors
    /// [`SAY_NEEDS_A_DESTINATION`] with no `to` or with a result body (a
    /// result is a code run's own, spoken where it speaks);
    /// [`SAY_UNKNOWN_DESTINATION`] and [`SAY_TASK_UNASSIGNED`] before any
    /// write; then every refusal of the door the destination takes.
    pub fn say(&self, input: &SayRequest) -> MemoryResult<SayReceipt> {
        let (Some(to), Some(text), None) = (
            input
                .to
                .as_deref()
                .map(str::trim)
                .filter(|to| !to.is_empty()),
            input.text.as_deref(),
            input.result.as_ref(),
        ) else {
            return Err(MemoryError::new(
                SAY_NEEDS_A_DESTINATION,
                "say names its `to`: only a code run's plain say(text) speaks where the run speaks",
                &["Name `to`: a room, a person's handle (pr<n>) or a task."],
            ));
        };
        let marks = MessageMarks {
            metadata: input.kind.map(SayKind::metadata),
            assertions: WitnessAssertions {
                cited: self.cited_refs(&input.refs)?,
                created: Vec::new(),
            },
        };
        match self.say_destination(to)? {
            SayDestination::Person(pr) => {
                let request = MessagePersonRequest {
                    pr,
                    text: text.to_owned(),
                    mention: None,
                    from_project: None,
                    to_project: None,
                };
                let landed =
                    self.message_person_linked(&request, marks, |_| Ok(()), |_, _| Ok(()))?;
                Ok(SayReceipt {
                    room: landed.room,
                    receipt: landed.receipt,
                })
            }
            SayDestination::Room(room) => {
                let text = text.trim();
                if text.is_empty() {
                    return Err(MemoryError::bad_request("message text is empty"));
                }
                let author = if self.actor_class == EdgeActorClass::Agent {
                    WitnessAuthor::Companion
                } else {
                    WitnessAuthor::User
                };
                let receipt = self.rooms_speak(&WitnessTurn {
                    conversation_ref: room.to_hex(),
                    turn_ref: None,
                    thread_audience: None,
                    messages: vec![WitnessMessage {
                        id: None,
                        author,
                        message_type: "text".to_owned(),
                        content: text.to_owned(),
                        parts: None,
                        metadata: marks.metadata,
                        is_visible: true,
                        order: 0,
                        quote: None,
                    }],
                    occurred_at: unix_seconds(),
                    assertions: marks.assertions,
                })?;
                Ok(SayReceipt {
                    room: room.to_hex(),
                    receipt,
                })
            }
        }
    }

    /// The destination `to` names, read through this caller's own read: a
    /// people handle first, then a room, a TASK's holder or a person by id.
    /// A record the caller cannot read names no destination.
    fn say_destination(&self, to: &str) -> MemoryResult<SayDestination> {
        let unknown = || {
            MemoryError::new(
                SAY_UNKNOWN_DESTINATION,
                "`to` names no room, person, agent or task you can read",
                &["Name a room, a person's handle (pr<n>) from vault.people.list, or a task."],
            )
        };
        let people = self.people_roster()?;
        if people.by_handle(to).is_some() {
            return Ok(SayDestination::Person(to.to_owned()));
        }
        let Ok(id) = super::resolve_entity_ref(self.vault, to) else {
            return Err(unknown());
        };
        // A record this caller may not read refuses as one that is not there.
        let Some(view) = self
            .get_entity(&id.to_hex())
            .ok()
            .and_then(|read| read.value)
        else {
            return Err(unknown());
        };
        let person = match view.kind.as_str() {
            "CONVERSATION" => return Ok(SayDestination::Room(id)),
            "TASK" => {
                let txn = self
                    .vault
                    .store
                    .env
                    .read_txn()
                    .map_err(crate::error::Error::from)?;
                let holder = crate::task_verb::open_thread_task_holder_in(
                    self.vault,
                    &txn,
                    id,
                    crate::gate::TaskHolderFallback::AssigneeOnly,
                )
                .map_err(|_| unknown())?;
                holder.ok_or_else(|| {
                    MemoryError::new(
                        SAY_TASK_UNASSIGNED,
                        "the task has no open assignee to speak to",
                        &["Speak to the task's room, or to a person by handle."],
                    )
                })?
            }
            _ => id,
        };
        people
            .get(person)
            .map(|row| SayDestination::Person(row.handle.clone()))
            .ok_or_else(unknown)
    }

    /// Each cited ref as the turn names it. The row's OF-063 check has
    /// already admitted every one under this caller's read; this read gives
    /// each its kind and label.
    fn cited_refs(&self, refs: &[String]) -> MemoryResult<Vec<crate::lens::RecordRef>> {
        let mut cited = Vec::with_capacity(refs.len());
        for reference in refs {
            let view = self.get_entity(reference)?.value.ok_or_else(|| {
                MemoryError::bad_request("a cited record does not resolve for this writer")
            })?;
            cited.push(crate::lens::RecordRef::from_view(&view));
        }
        Ok(cited)
    }
}

/// Now, in unix seconds.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
