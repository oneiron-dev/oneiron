//! Typed pages over the existing identity lens and Dreamer consent groups.
//! These are distinct from delivered NOTIFICATION pages (`self.inbox.list`).
use super::{AgentInboxItemKind, AgentInboxLensItem, AgentInboxLensQuery, InboxImpact};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxLensRequest {
    #[serde(default)]
    pub identity: Option<String>,
    /// Owner view only; an ordinary reader always gets its own slice.
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub before_impact: Option<u16>,
    #[serde(default)]
    pub before_at: Option<u64>,
    #[serde(default)]
    pub before_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensPage {
    pub items: Vec<InboxLensRow>,
    pub concern_groups: Vec<InboxConcernGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxConcernGroup {
    pub agent: String,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboxLensKind {
    Conversation,
    WaitingOnYou,
    CoordinationUpdate,
    Concern,
    /// A digest addressed to the reader alone (FIX 1261).
    Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboxLensPile {
    Conversations,
    WaitingOnYou,
    Updates,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensRow {
    pub item_id: String,
    pub kind: InboxLensKind,
    pub pile: InboxLensPile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_ref: Option<String>,
    /// The receiving identity; absent on a row the vault itself sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facet: Option<String>,
    pub participants: Vec<InboxLensParticipant>,
    pub impact: u16,
    pub occurred_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concern: Option<InboxLensConcern>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diary_review: Option<InboxLensDiaryReview>,
    /// Who the row is from, as 32 hex: the author of its newest inbound
    /// message with admitted provenance (FIX 9745); absent where none has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// The widening a comm widen ask asks for (FIX 3901).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widening: Option<crate::context_board::ConsultWidening>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensParticipant {
    /// The receiving identity; absent on a row the vault itself sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensConcern {
    pub agent: String,
    pub signal: String,
    pub tone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensDiaryReview {
    pub request: String,
    pub reader: String,
    pub reader_class: String,
    pub reason: String,
}

impl From<AgentInboxLensItem> for InboxLensRow {
    fn from(item: AgentInboxLensItem) -> Self {
        Self {
            item_id: item.item_id,
            kind: match item.kind {
                AgentInboxItemKind::Conversation => InboxLensKind::Conversation,
                AgentInboxItemKind::ApprovalRequired => InboxLensKind::WaitingOnYou,
                AgentInboxItemKind::CoordinationUpdate => InboxLensKind::CoordinationUpdate,
                AgentInboxItemKind::Concern => InboxLensKind::Concern,
                AgentInboxItemKind::Digest => InboxLensKind::Digest,
            },
            pile: match item.kind {
                AgentInboxItemKind::Conversation => InboxLensPile::Conversations,
                AgentInboxItemKind::ApprovalRequired | AgentInboxItemKind::Concern => {
                    InboxLensPile::WaitingOnYou
                }
                AgentInboxItemKind::CoordinationUpdate | AgentInboxItemKind::Digest => {
                    InboxLensPile::Updates
                }
            },
            thread_ref: item.thread_ref,
            identity: item.identity_ref.map(|id| id.to_hex()),
            actor: item.actor_ref.to_hex(),
            facet: item.facet_ref.map(|id| id.to_hex()),
            participants: item
                .participants
                .into_iter()
                .map(|p| InboxLensParticipant {
                    identity: p.identity_ref.map(|id| id.to_hex()),
                    actor: p.actor_ref.to_hex(),
                })
                .collect(),
            impact: item.impact.0,
            occurred_at: item.occurred_at,
            receipt_ref: item.receipt_ref,
            payload_ref: item.payload_ref,
            concern: item.concern.map(|c| InboxLensConcern {
                agent: c.subject.to_hex(),
                signal: c.signal.as_str().to_owned(),
                tone: c.tone.as_str().to_owned(),
            }),
            diary_review: item.diary_review.map(|r| InboxLensDiaryReview {
                request: r.request.to_hex(),
                reader: r.reader.to_hex(),
                reader_class: r.reader_class,
                reason: r.reason,
            }),
            sender: item.sender.map(|id| id.to_hex()),
            widening: item.widening,
        }
    }
}

fn entity(reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| MemoryError::bad_request("inbox filters name 32-hex entity ids"))
}

/// One lens page. `reader` reads the page: an actor's digests join only the
/// slice of the actor that reads it.
fn page(
    vault: &Vault,
    input: &InboxLensRequest,
    actor: Option<EntityId>,
    reader: EntityId,
) -> MemoryResult<InboxLensPage> {
    let before = match (input.before_impact, input.before_at, &input.before_id) {
        (Some(impact), Some(at), Some(id)) => Some((InboxImpact(impact), at, id.clone())),
        (None, None, None) => None,
        _ => {
            return Err(MemoryError::bad_request(
                "before_impact, before_at and before_id go together",
            ));
        }
    };
    let identity = input.identity.as_deref().map(entity).transpose()?;
    let limit = input.limit.unwrap_or(50).min(200);
    let items = match actor {
        Some(actor) => {
            vault.agent_identity_inbox_slice(actor, identity, limit, before, actor == reader)?
        }
        None => vault.agent_inbox_lens(AgentInboxLensQuery {
            identity_ref: identity,
            limit,
            before,
        })?,
    };
    let items: Vec<InboxLensRow> = items.into_iter().map(InboxLensRow::from).collect();
    let mut concern_groups: Vec<InboxConcernGroup> = Vec::new();
    for row in &items {
        let Some(concern) = &row.concern else {
            continue;
        };
        match concern_groups
            .iter_mut()
            .find(|group| group.agent == concern.agent)
        {
            Some(group) => group.items.push(row.item_id.clone()),
            None => concern_groups.push(InboxConcernGroup {
                agent: concern.agent.clone(),
                items: vec![row.item_id.clone()],
            }),
        }
    }
    Ok(InboxLensPage {
        items,
        concern_groups,
    })
}

impl Memory<'_> {
    /// A credential reads only its own actor's slice, optionally narrowed to
    /// one of its identities. Filtering happens before page truncation.
    pub fn inbox_lens(&self, input: &InboxLensRequest) -> MemoryResult<InboxLensPage> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if input
            .agent
            .as_deref()
            .map(entity)
            .transpose()?
            .is_some_and(|id| id != self.actor())
        {
            return Err(MemoryError::bad_request(
                "an inbox reader cannot select another actor",
            ));
        }
        page(self.vault(), input, Some(self.actor()), self.actor())
    }

    /// The owner's existing cross-identity lens, including an optional
    /// agent filter. Owning the vault never reads another actor's digests.
    pub fn inbox_lens_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &InboxLensRequest,
    ) -> MemoryResult<InboxLensPage> {
        self.inbox_owner(owner)?;
        if input.identity.is_some() && input.agent.is_some() {
            return Err(MemoryError::bad_request(
                "filter by identity or by agent, not both",
            ));
        }
        page(
            self.vault(),
            input,
            input.agent.as_deref().map(entity).transpose()?,
            self.actor(),
        )
    }

    fn inbox_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        if self.actor_class() != EdgeActorClass::Human
            || owner.revalidate(self.vault())? != self.actor()
        {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "the owner inbox requires the owner's own credential handle",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// The canon consent-group projection over real gate-held Dreamer
    /// proposals, including its per-member receipts and exception classes:
    /// one page of complete groups, and where the next page resumes (FIX
    /// 9873).
    pub fn inbox_run_groups(
        &self,
        owner: &AuthenticatedOwner,
        input: &InboxRunGroupsRequest,
    ) -> MemoryResult<crate::inbox::InboxGroupPage> {
        self.inbox_owner(owner)?;
        let after = input
            .after
            .as_deref()
            .map(|token| {
                crate::inbox::InboxGroupCursor::parse(token).ok_or_else(|| {
                    MemoryError::bad_request("after is not the next cursor of a groups page")
                })
            })
            .transpose()?;
        Ok(self.vault().inbox_groups(
            crate::inbox::InboxQuery::at(
                self.vault().now_recorded_at(),
                input.limit.unwrap_or(50).min(200),
            )
            .after(after),
        )?)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxRunGroupsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    /// A previous page's `next`: this page resumes after the groups that
    /// page served.
    #[serde(default)]
    pub after: Option<String>,
}
