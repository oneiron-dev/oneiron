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
use crate::claim::ClaimReadStatus;
use crate::context_board::{People, PersonKind, PersonRow};
use crate::conversation::{ConversationBody, ConversationKind};
use crate::ports::EntityStoreRead;
use crate::{EdgeActorClass, EntityId, WriteActor};

/// Rows on one `vault.people.list` page.
pub const PEOPLE_PAGE_SIZE: usize = 50;

/// Derivation domain of the one Direct room two persons share.
const DIRECT_ROOM_DOMAIN: &[u8] = b"oneiron.people.direct-room.v1";

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

    /// `self.message`: one message to a person, in the Direct room the
    /// caller's person and theirs share. The room is made on first use.
    pub fn message_person(
        &self,
        input: &MessagePersonRequest,
    ) -> MemoryResult<MessagePersonReceipt> {
        let text = input.text.trim();
        if text.is_empty() {
            return Err(MemoryError::bad_request("message text is empty"));
        }
        let people = self.people_roster()?;
        let target = Self::person_by_handle(&people, &input.pr)?.person;
        let me = people
            .get(self.actor)
            .ok_or_else(|| MemoryError::bad_request("the caller is not a person in this vault"))?
            .person;
        if me == target {
            return Err(MemoryError::bad_request("a person cannot message itself"));
        }
        let pair = if me < target {
            [me, target]
        } else {
            [target, me]
        };
        let room = EntityId::derive(
            DIRECT_ROOM_DOMAIN,
            &[pair[0].as_bytes(), pair[1].as_bytes()],
        )?;
        let now_ms = unix_ms();
        let exists = |vault: &crate::Vault| -> MemoryResult<bool> {
            let txn = vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            Ok(vault.store.port_entity_record(&txn, &room)?.is_some())
        };
        if !exists(self.vault)? {
            let body = ConversationBody {
                kind: ConversationKind::Direct,
                member_ids: pair.to_vec(),
                ..Default::default()
            };
            let made = self.vault.create_conversation(
                room,
                &body,
                WriteActor::new(self.actor, self.actor_class),
                now_ms / 1_000,
            );
            // A message racing this one may have made the room first.
            if let Err(error) = made
                && !exists(self.vault)?
            {
                return Err(error.into());
            }
        }
        let author = if self.actor_class == EdgeActorClass::Agent {
            WitnessAuthor::Companion
        } else {
            WitnessAuthor::User
        };
        let receipt = self.witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: now_ms / 1_000,
        })?;
        Ok(MessagePersonReceipt {
            room: room.to_hex(),
            receipt,
        })
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
