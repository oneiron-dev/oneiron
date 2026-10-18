//! PEOPLE verbs (owner ruling, ARCH-0067): `vault.people.list`,
//! `vault.people.get`, `self.message` and `self.grants.ask`.
//!
//! Every verb names persons by their `pr` handle and reads the roster through
//! the caller's own read: a person the caller does not read is not there.

use serde::{Deserialize, Serialize};

use super::{
    Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn,
};
use crate::access_grant::{AccessGrant, AccessGrantScope, AccessGrantStatus};
use crate::agent_dispatch::{
    AddressDecision, AddressRefusal, AgentDispatchInput, CommReach, SenderDispatch,
};
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimReadStatus;
use crate::context_board::{People, PersonKind, PersonRow};
use crate::conversation::{ConversationBody, ConversationKind};
use crate::{EdgeActorClass, EntityId, WriteActor};

/// Rows on one `vault.people.list` page.
pub const PEOPLE_PAGE_SIZE: usize = 50;

/// Derivation domain of the one Direct room two persons share.
const DIRECT_ROOM_DOMAIN: &[u8] = b"oneiron.people.direct-room.v1";

/// Derivation domain of a leader message's room: one per leadership tenure,
/// keyed by both projects and the actors leading them, so a new leader gets
/// a new room and the old one stops admitting turns (FIX 1380; CALLS C6).
const LEADER_DIRECT_ROOM_DOMAIN: &[u8] = b"oneiron.people.leader-room.v1";

/// Policy hook (CALLS "FIX 3899 unslipped transport sender", open): the comm
/// ceiling of a caller whose credential is no capability slip (a host
/// secret, a managed login, an ask guest's task grant), which carries no
/// signed reach. None: it reads as before FIX 3899, by its run's reach, or
/// C5's when unbound.
const UNSLIPPED_TRANSPORT_COMM: Option<CommReach> = None;

/// `vault.people.list`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeopleListRequest {
    /// The vault tag the board's `<people vault=…>` names; this vault when
    /// absent.
    #[serde(default)]
    pub vault: Option<String>,
    /// Zero-based page of [`PEOPLE_PAGE_SIZE`] rows.
    #[serde(default)]
    pub page: Option<u32>,
}

/// One page of the people the caller reads, in handle order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeoplePage {
    pub vault: String,
    pub page: u32,
    pub people: Vec<PersonRow>,
    /// Rows on later pages.
    pub more: usize,
}

/// `vault.people.get`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonRequest {
    /// `pr<n>`.
    pub pr: String,
}

/// `self.message`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessagePersonRequest {
    pub pr: String,
    pub text: String,
    /// The saved mention `pr` came from, when the agent named the person
    /// (OF-123): the message refuses while that mention is unsettled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention: Option<crate::outbound::MentionProvenance>,
    /// When the sender leads several projects and sends from no run that
    /// names one: the project (entity hex) it speaks for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_project: Option<String>,
    /// When the person leads several projects: the project (entity hex) the
    /// message addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_project: Option<String>,
}

/// Where an admitted message lands (FIX 1380).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageRoute {
    /// The leader chat of two projects' leaders, projects in id order.
    Leader {
        room: EntityId,
        projects: [EntityId; 2],
    },
    /// The Direct room two persons share, persons in id order.
    Plain { room: EntityId, pair: [EntityId; 2] },
}

impl MessageRoute {
    const fn room(self) -> EntityId {
        match self {
            Self::Leader { room, .. } | Self::Plain { room, .. } => room,
        }
    }
}

/// A message the comm dial refused: why, and the run it was sent from.
#[derive(Debug, Clone, Copy)]
struct AddressRefused {
    refusal: AddressRefusal,
    child: Option<AttemptId>,
}

/// The "ask" when the leader pair is not fixed (Engine 10-18; CALLS C9): a
/// bad request naming every candidate, answered by the request's selector.
fn ask_for_project(who: &str, field: &str, candidates: &[EntityId]) -> MemoryError {
    let names: Vec<String> = candidates.iter().map(EntityId::to_hex).collect();
    MemoryError::bad_request(format!(
        "{who} several projects; name one with {field}: {}",
        names.join(", ")
    ))
}

/// The led project the sender speaks for: a bound run's own project when
/// the sender leads it, else none (Engine 10-18: the project the dispatch
/// names); unbound, its one led project, or among several the one
/// `from_project` names, else the ask.
fn sender_project(
    led: &[EntityId],
    run: Option<&AgentDispatchInput>,
    from: Option<EntityId>,
) -> MemoryResult<Option<EntityId>> {
    if let Some(project) = from
        && !led.contains(&project)
    {
        return Err(MemoryError::bad_request(format!(
            "you do not lead project {}",
            project.to_hex()
        )));
    }
    match run {
        Some(run) => {
            let named = run.project_ref.filter(|project| led.contains(project));
            if from.is_some() && from != named {
                return Err(MemoryError::bad_request(
                    "from_project is not the led project this run works in",
                ));
            }
            Ok(named)
        }
        None => match (led, from) {
            ([], _) => Ok(None),
            ([one], _) => Ok(Some(*one)),
            (_, Some(project)) => Ok(Some(project)),
            (several, None) => Err(ask_for_project("you lead", "from_project", several)),
        },
    }
}

/// The Direct room the message landed in, and its witness receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePersonReceipt {
    pub room: String,
    pub receipt: WitnessReceipt,
}

/// What `self.grants.ask` asks for. A space is a conversation or
/// relationship id, in hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantAskScope {
    Messages {
        space_ref: String,
    },
    Summaries {
        space_ref: String,
    },
    RelationshipClaims {
        space_ref: String,
    },
    /// The asked person's companion profile, optionally one facet of it.
    CompanionProfile {
        #[serde(default)]
        facet_ref: Option<String>,
    },
}

/// `self.grants.ask`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantAskRequest {
    pub pr: String,
    pub scope: GrantAskScope,
}

/// The pending access request. Asking grants nothing; the vault owner
/// answers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAskReceipt {
    pub request: String,
    pub asked: String,
    pub status: String,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn hex_ref(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} is not an entity id")))
}

fn hex_opt(field: &str, value: Option<&str>) -> MemoryResult<Option<EntityId>> {
    value.map(|value| hex_ref(field, value)).transpose()
}

impl Memory<'_> {
    /// The people the caller reads, each with the `about` line of the
    /// highest band its read admits.
    fn people_roster(&self) -> MemoryResult<People> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let mut people = People::load(self.vault, unix_ms(), &mut |person| {
            read.is_entity_readable(&person)
        })?;
        let applied = read.read_receipt(None, 0)?.applied;
        let ceiling = (!applied.deny_all).then_some(applied.max_sensitivity_band);
        people.set_about(&mut |person| self.vault.person_about(person, ceiling))?;
        Ok(people)
    }

    fn person_by_handle<'p>(people: &'p People, pr: &str) -> MemoryResult<&'p PersonRow> {
        people
            .by_handle(pr.trim())
            .ok_or_else(|| MemoryError::not_found(format!("no person {pr}")))
    }

    /// `vault.people.list`: one page of the people the caller reads.
    pub fn people_list(&self, input: &PeopleListRequest) -> MemoryResult<PeoplePage> {
        let people = self.people_roster()?;
        if let Some(vault) = input.vault.as_deref()
            && vault != people.vault()
        {
            return Err(MemoryError::not_found(format!(
                "this vault is {}, not {vault}",
                people.vault()
            )));
        }
        let page = input.page.unwrap_or(0);
        let (rows, more) = people.page(page as usize, PEOPLE_PAGE_SIZE);
        Ok(PeoplePage {
            vault: people.vault().to_owned(),
            page,
            people: rows.to_vec(),
            more,
        })
    }

    /// `vault.people.get`: one person by `pr` handle.
    pub fn people_get(&self, input: &PersonRequest) -> MemoryResult<PersonRow> {
        let people = self.people_roster()?;
        Ok(Self::person_by_handle(&people, &input.pr)?.clone())
    }

    /// `self.message`: one message to a person. Two leaders speak in the
    /// leader chat of the projects they lead; anyone else in the Direct room
    /// the two persons share. The room is made on first use, in the message's
    /// own write.
    ///
    /// FIX 1380: the comm dial admits the address first. ARCH-0067 :53-56:
    /// "An explorer hears only from its parent, through its comm dial."
    /// ARCH-0067 :449: "Any two leaders in one vault may open a direct
    /// chat", "Each speaks under its own project's scope", and a shared
    /// ancestor's rule "narrows the default, stricter wins". One read
    /// snapshot decides the route; the write decides again and lands the
    /// message only on the same route.
    pub fn message_person(
        &self,
        input: &MessagePersonRequest,
    ) -> MemoryResult<MessagePersonReceipt> {
        let text = input.text.trim();
        if text.is_empty() {
            return Err(MemoryError::bad_request("message text is empty"));
        }
        // OF-123 act-now guard: a person taken from a saved mention waits
        // until that mention is settled.
        if let Some(mention) = input.mention.as_ref() {
            let unsettled = {
                let txn = self
                    .vault
                    .store
                    .env
                    .read_txn()
                    .map_err(crate::error::Error::from)?;
                crate::dreamer_runner::maintenance::identity::mention_unsettled_in_txn(
                    self.vault, &txn, mention,
                )?
            };
            if let Some(name) = unsettled {
                return Err(crate::error::Error::Record(
                    crate::error::RecordError::IdentityUnsettled { name },
                )
                .into());
            }
        }
        let people = self.people_roster()?;
        let target = Self::person_by_handle(&people, &input.pr)?;
        let me = people
            .get(self.actor)
            .ok_or_else(|| MemoryError::bad_request("the caller is not a person in this vault"))?
            .person;
        if me == target.person {
            return Err(MemoryError::bad_request("a person cannot message itself"));
        }
        let decided = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            self.message_route_in_txn(&txn, me, target, input)?
        };
        let route = match decided {
            Ok(route) => route,
            Err(refused) => return Err(self.address_refused(target, refused)),
        };
        let room = route.room();
        let now_ms = unix_ms();
        let author = if self.actor_class == EdgeActorClass::Agent {
            WitnessAuthor::Companion
        } else {
            WitnessAuthor::User
        };
        let refused_in_write = std::cell::Cell::new(None);
        let landed = self.witness_with_room_birth(
            &WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author,
                    message_type: "text".to_owned(),
                    content: text.to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: now_ms / 1_000,
                assertions: Default::default(),
            },
            |wtxn| {
                if let Some(mention) = input.mention.as_ref()
                    && let Some(name) =
                        crate::dreamer_runner::maintenance::identity::mention_unsettled_in_txn(
                            self.vault, wtxn, mention,
                        )?
                {
                    return Err(crate::error::Error::Record(
                        crate::error::RecordError::IdentityUnsettled { name },
                    )
                    .into());
                }
                match self.message_route_in_txn(wtxn, me, target, input)? {
                    Err(refused) => {
                        refused_in_write.set(Some(refused));
                        Err(Self::address_refusal(target, refused.refusal))
                    }
                    Ok(again) if again != route => Err(MemoryError::new(
                        super::MEMORY_CODE_INVALID_STATE,
                        "who leads or who hears changed while the message was sent",
                        &["Send the message again."],
                    )),
                    Ok(MessageRoute::Leader { room, projects }) => {
                        self.vault.ensure_leader_chat_in_txn(
                            wtxn,
                            room,
                            projects,
                            WriteActor::new(self.actor, self.actor_class),
                            now_ms / 1_000,
                        )?;
                        Ok(())
                    }
                    Ok(MessageRoute::Plain { room, pair }) => {
                        if matches!(
                            crate::vault::live_entity_row_in_txn(&self.vault.store, wtxn, &room)?,
                            crate::vault::LiveEntityRow::Absent
                        ) {
                            let at = now_ms / 1_000;
                            crate::conversation::create_in_txn(
                                self.vault,
                                wtxn,
                                room,
                                &ConversationBody {
                                    kind: ConversationKind::Direct,
                                    member_ids: pair.to_vec(),
                                    ..Default::default()
                                },
                                WriteActor::new(self.actor, self.actor_class),
                                crate::TimeRange { start: at, end: at },
                                at,
                                &[],
                            )?;
                        }
                        Ok(())
                    }
                }
            },
        );
        // A refusal the write found is answered once the write has unwound.
        if landed.is_err()
            && let Some(refused) = refused_in_write.take()
        {
            return Err(self.address_refused(target, refused));
        }
        Ok(MessagePersonReceipt {
            room: room.to_hex(),
            receipt: landed?,
        })
    }

    /// Steps 2-4 of `self.message`, in one snapshot: who sends and from which
    /// run, whether the two persons' leaders speak for two projects, and
    /// whether the comm dial admits the address. `Err` inside `Ok` is the
    /// dial's refusal; anything else that refuses is the outer `Err`.
    fn message_route_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        me: EntityId,
        target: &PersonRow,
        input: &MessagePersonRequest,
    ) -> MemoryResult<Result<MessageRoute, AddressRefused>> {
        let vault = self.vault;
        let run = crate::task_verb::message_dispatch_in_txn(self, txn)?;
        // The credential's reach caps the sender, bound run or none (FIX
        // 3899), read again in this snapshot.
        let ceiling = self.message_comm_in_txn(txn)?;
        let sender = match &run {
            Some((attempt, input)) => SenderDispatch::Bound {
                attempt,
                input,
                ceiling,
            },
            None => SenderDispatch::Unbound {
                actor: self.actor,
                ceiling,
            },
        };
        let child = run.as_ref().map(|(attempt, _)| attempt.id);
        // The roster was read in its own snapshots: re-prove both persons'
        // actors in this one.
        if !crate::workspace_roster::speaks_as_in_txn(vault, txn, self.actor, me)? {
            return Err(MemoryError::bad_request(
                "the caller is not a person in this vault",
            ));
        }
        let mut actors = Vec::new();
        for actor in &target.actors {
            if crate::workspace_roster::speaks_as_in_txn(vault, txn, *actor, target.person)? {
                actors.push(*actor);
            }
        }
        if actors.is_empty() {
            return Err(MemoryError::not_found(format!(
                "no person {}",
                target.handle
            )));
        }
        let mine = sender_project(
            &crate::workspace_roster::projects_led_in_txn(vault, txn, self.actor)?,
            run.as_ref().map(|(_, input)| input),
            hex_opt("from_project", input.from_project.as_deref())?,
        )?;
        let theirs = Self::target_project_in_txn(
            vault,
            txn,
            target,
            &actors,
            hex_opt("to_project", input.to_project.as_deref())?,
        )?;
        if let (Some(mine), Some((theirs, their_leader))) = (mine, theirs) {
            // Leaders address each other vault-wide unless a shared ancestor
            // narrows it (CALLS C8); every actor of the person must still
            // hear the sender.
            for actor in &actors {
                if let AddressDecision::Refuse(refusal) =
                    crate::agent_dispatch::target_admits_in_txn(vault, txn, &sender, *actor)?
                {
                    return Ok(Err(AddressRefused { refusal, child }));
                }
            }
            crate::workspace_roster::leader_chat_allowed(vault, txn, [mine, theirs])?;
            let (projects, leaders) = if mine < theirs {
                ([mine, theirs], [self.actor, their_leader])
            } else {
                ([theirs, mine], [their_leader, self.actor])
            };
            let room = EntityId::derive(
                LEADER_DIRECT_ROOM_DOMAIN,
                &[
                    projects[0].as_bytes(),
                    leaders[0].as_bytes(),
                    projects[1].as_bytes(),
                    leaders[1].as_bytes(),
                ],
            )?;
            return Ok(Ok(MessageRoute::Leader { room, projects }));
        }
        // A plain message must reach every actor of the person (CALLS C7).
        for actor in &actors {
            if let AddressDecision::Refuse(refusal) =
                crate::agent_dispatch::may_address_in_txn(vault, txn, &sender, *actor)?
            {
                return Ok(Err(AddressRefused { refusal, child }));
            }
        }
        let pair = if me < target.person {
            [me, target.person]
        } else {
            [target.person, me]
        };
        let room = EntityId::derive(
            DIRECT_ROOM_DOMAIN,
            &[pair[0].as_bytes(), pair[1].as_bytes()],
        )?;
        Ok(Ok(MessageRoute::Plain { room, pair }))
    }

    /// The led project a message addresses, with the actor leading it: the
    /// person's one led project; among several, the one `to_project` names,
    /// else the one project its live runs work in, else the ask.
    fn target_project_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        target: &PersonRow,
        actors: &[EntityId],
        to: Option<EntityId>,
    ) -> MemoryResult<Option<(EntityId, EntityId)>> {
        let mut led = Vec::new();
        for actor in actors {
            for project in crate::workspace_roster::projects_led_in_txn(vault, txn, *actor)? {
                led.push((project, *actor));
            }
        }
        if let Some(project) = to
            && !led.iter().any(|(led, _)| *led == project)
        {
            return Err(MemoryError::bad_request(format!(
                "{} does not lead project {}",
                target.handle,
                project.to_hex()
            )));
        }
        Ok(match (led.as_slice(), to) {
            ([], _) => None,
            ([one], _) => Some(*one),
            (_, Some(project)) => led.iter().copied().find(|(led, _)| *led == project),
            (several, None) => {
                let mut named = std::collections::BTreeSet::new();
                for actor in actors {
                    for project in
                        crate::agent_dispatch::live_dispatch_projects_in_txn(vault, txn, *actor)?
                    {
                        if let Some(row) = several
                            .iter()
                            .find(|(led, leader)| *led == project && leader == actor)
                        {
                            named.insert(*row);
                        }
                    }
                }
                if named.len() != 1 {
                    let candidates: Vec<EntityId> = several.iter().map(|(led, _)| *led).collect();
                    return Err(ask_for_project(
                        &format!("{} leads", target.handle),
                        "to_project",
                        &candidates,
                    ));
                }
                named.into_iter().next()
            }
        })
    }

    /// The typed refusal for a dial refusal: `gate.deny.message_address`,
    /// the dial's reason in its text (FIX 1380).
    fn address_refusal(target: &PersonRow, refusal: AddressRefusal) -> MemoryError {
        let (reason, suggestion) = match refusal {
            AddressRefusal::OutboundReach { reach, needed } => (
                format!(
                    "{}: {} is outside this run's comm reach ({}); it needs {}",
                    refusal.as_str(),
                    target.handle,
                    reach.as_str(),
                    needed.as_str()
                ),
                "Ask the run's parent to widen its comm reach, then send again.",
            ),
            // The owner's mint-time ceiling: no parent widen lifts it (FIX
            // 3899), so the remedy names the Grant, never a run or a place.
            AddressRefusal::CredentialReach { reach, needed } => (
                format!(
                    "{}: {} is outside the comm reach the owner set on this credential ({}); it needs {}",
                    refusal.as_str(),
                    target.handle,
                    reach.as_str(),
                    needed.as_str()
                ),
                "Ask the owner to re-mint this credential with a wider comm reach, then send again.",
            ),
            AddressRefusal::TargetHearsParentOnly => (
                format!(
                    "{}: {} hears only from its parent and its own children",
                    refusal.as_str(),
                    target.handle
                ),
                "Reach it through its parent.",
            ),
        };
        crate::gate::message_address_refusal(&reason, suggestion)
    }

    /// FIX 3899: the comm reach the credential this request was admitted on
    /// carries, read in `txn`. The slip its host kept is verified again,
    /// every caveat met, and its signed reach caps the sender. With no kept
    /// slip, the verified proof the host bound for reads answers. A surface
    /// no slip bounds has no ceiling: the in-process host's own (its native
    /// marker), or a caller whose credential is no slip
    /// ([`UNSLIPPED_TRANSPORT_COMM`]). A kept slip that no longer verifies
    /// refuses: a transport sender whose proof fails reaches no one.
    fn message_comm_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<Option<CommReach>> {
        if let Some(binding) = self.invocation_slip() {
            return match self.vault.invocation_slip_in_txn(txn, binding) {
                Ok(slip) => Ok(Some(slip.comm())),
                Err(_) => Err(crate::gate::message_address_refusal(
                    "credential_unverified: the credential this request was admitted on no longer verifies, so it reaches no one",
                    "Ask the owner to re-mint this credential, then send again.",
                )),
            };
        }
        if let Some(proof) = &self.read_proof {
            return Ok(Some(proof.comm()));
        }
        if self.native_invocation() {
            return Ok(None);
        }
        Ok(UNSLIPPED_TRANSPORT_COMM)
    }

    /// The one place a dial refusal leaves `self.message`, after any write it
    /// stopped has unwound. A run refused for reach raises the one widen ask
    /// to its parent (ARCH-0028 :611 "Widening is one signal to the parent,
    /// approve-and-stop-asking"), and the refusal names it: in its text, and
    /// as its typed denial's `ask_ref` (FIX 1380).
    fn address_refused(&self, target: &PersonRow, refused: AddressRefused) -> MemoryError {
        let mut error = Self::address_refusal(target, refused.refusal);
        let (Some(child), Some(needed)) = (refused.child, refused.refusal.needed_reach()) else {
            return error;
        };
        match self.raise_comm_widen(child, needed) {
            Ok(view) => {
                error.message = format!("{}; {}", error.message, view.describe());
                error.suggestions = vec![view.suggestion().to_owned()];
                if let Some(denial) = error.gate_denial.as_deref_mut() {
                    denial.ask_ref = view.ask_ref();
                }
            }
            Err(raise) => {
                error.message = format!(
                    "{}; the widen ask could not be raised ({}); the request is kept and the next refused send resumes it",
                    error.message, raise.message
                );
            }
        }
        error
    }

    /// `self.grants.ask`: asks a person for access, on behalf of the caller.
    /// The request grants nothing until the vault owner approves it.
    pub fn grants_ask(&self, input: &GrantAskRequest) -> MemoryResult<GrantAskReceipt> {
        super::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let people = self.people_roster()?;
        let asked = Self::person_by_handle(&people, &input.pr)?;
        if asked.kind != PersonKind::Human {
            return Err(MemoryError::bad_request(format!(
                "{} is an agent; only a human grants access",
                asked.handle
            )));
        }
        let scope = match &input.scope {
            GrantAskScope::Messages { space_ref } => AccessGrantScope::Messages {
                space_ref: hex_ref("space_ref", space_ref)?,
            },
            GrantAskScope::Summaries { space_ref } => AccessGrantScope::Summaries {
                space_ref: hex_ref("space_ref", space_ref)?,
            },
            GrantAskScope::RelationshipClaims { space_ref } => {
                AccessGrantScope::RelationshipClaims {
                    space_ref: hex_ref("space_ref", space_ref)?,
                }
            }
            GrantAskScope::CompanionProfile { facet_ref } => AccessGrantScope::CompanionProfile {
                person_ref: asked.person,
                facet_ref: facet_ref
                    .as_deref()
                    .map(|facet| hex_ref("facet_ref", facet))
                    .transpose()?,
            },
        };
        let request = self.vault.new_entity_id()?;
        self.vault.request_access(
            request,
            AccessGrant {
                authority_scope: crate::federation::Scope::top(),
                principal_ref: self.actor,
                capability: scope.required_capability(),
                scope,
                status: AccessGrantStatus::Active,
                created_at: unix_ms() / 1_000,
                revoked_at: None,
                expires_at: None,
            },
        )?;
        Ok(GrantAskReceipt {
            request: request.to_hex(),
            asked: asked.handle.clone(),
            status: "pending".to_owned(),
        })
    }
}
