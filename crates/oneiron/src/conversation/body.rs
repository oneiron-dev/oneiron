//! Forward-compatible room body codec and the all-writer membership guard.
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    #[default]
    Direct,
    Agent,
    Group,
    Channel,
    Mirror,
}
impl ConversationKind {
    pub const fn history_default(self) -> bool {
        matches!(self, Self::Group | Self::Channel | Self::Mirror)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConversationBody {
    pub v: Option<u8>,
    pub kind: ConversationKind,
    pub member_ids: Vec<EntityId>,
    pub external_id: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub history_visible: Option<bool>,
    pub relationship: Option<EntityId>,
    pub is_default: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, rmpv::Value>,
}
impl ConversationBody {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // A live header-only legacy room has no pinned fields. It is distinct
        // from a deleted shell (checked by the owning read door).
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let mut cursor = std::io::Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("body decode"))?;
        let rmpv::Value::Map(entries) = value else {
            return Err(invalid("body must be a map"));
        };
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid("trailing body bytes"));
        }
        let mut seen = BTreeSet::new();
        for (key, _) in entries {
            let key = key
                .as_str()
                .ok_or(invalid("body keys must be strings"))?
                .to_owned();
            if !seen.insert(key) {
                return Err(invalid("duplicate body key"));
            }
        }
        let body: Self = decode(bytes)?;
        body.validate()?;
        Ok(body)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self)
    }
    pub fn shares_history(&self) -> bool {
        self.history_visible.unwrap_or(self.kind.history_default())
    }
    fn validate(&self) -> Result<()> {
        if self.member_ids.len() > 10_000 {
            return Err(invalid("too many conversation members"));
        }
        if self.v.is_some_and(|v| v != 1) {
            return Err(invalid("unsupported version"));
        }
        if self.kind == ConversationKind::Mirror
            && self
                .external_id
                .as_ref()
                .is_none_or(|s| s.trim().is_empty())
        {
            return Err(invalid("mirror requires external_id"));
        }
        if self
            .member_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != self.member_ids.len()
        {
            return Err(invalid("duplicate member"));
        }
        Ok(())
    }
}

pub(crate) fn validate_put_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    bytes: &[u8],
    replicated: bool,
) -> Result<()> {
    let body = ConversationBody::from_bytes(bytes)?;
    let chat_field = crate::workspace_roster::LEADER_CHAT_FIELD;
    if let Some(value) = body.extra.get(chat_field) {
        let encoded = rmp_serde::to_vec_named(value).map_err(|_| invalid("leader chat binding"))?;
        let chat: crate::workspace_roster::LeaderChat =
            rmp_serde::from_slice(&encoded).map_err(|_| invalid("leader chat binding"))?;
        if body.kind != ConversationKind::Direct
            || body.member_ids != chat.persons
            || chat.projects[0] == chat.projects[1]
            || chat.actors[0] == chat.actors[1]
            || chat.persons[0] == chat.persons[1]
        {
            return Err(invalid("leader chat binding"));
        }
        if !replicated
            && store.entities.get(txn, id.as_bytes())?.is_none()
            && store
                .vault_meta
                .get(
                    txn,
                    &[b"project.leader_chat.v1/".as_slice(), id.as_bytes()].concat(),
                )?
                .as_deref()
                != Some(encoded.as_slice())
        {
            return Err(denied());
        }
    }
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && raw.len() >= ENTITY_METADATA_HEADER_LEN
    {
        let previous = ConversationBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if previous.extra.get(chat_field) != body.extra.get(chat_field) {
            return Err(state("leader chat binding is immutable"));
        }
    }
    // A replica carries structurally valid body metadata, not local membership
    // authority. PERSON rows may arrive later; only the local ledger grants reads.
    if !replicated {
        for person in &body.member_ids {
            let raw = store
                .entities
                .get(txn, person.as_bytes())?
                .ok_or(invalid("member must be a PERSON"))?;
            if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_PERSON)
            {
                return Err(invalid("member must be a PERSON"));
            }
        }
        let rows = membership::rows_in(store, txn, id)?;
        let members = membership::members_at_rows(&rows, u64::MAX);
        if members != body.member_ids.iter().copied().collect() {
            return Err(state("membership changes require the membership door"));
        }
    }
    Ok(())
}
impl Vault {
    pub fn conversation_body(&self, id: EntityId) -> Result<ConversationBody> {
        let txn = self.store.env.read_txn()?;
        body_in(self, &txn, id)
    }
    pub fn create_conversation(
        &self,
        id: EntityId,
        body: &ConversationBody,
        actor: WriteActor,
        at: u64,
    ) -> Result<()> {
        self.create_conversation_with_text(
            id,
            body,
            actor,
            crate::TimeRange { start: at, end: at },
            at,
            &[],
        )
    }
    /// Creates a room, membership ledger and text index in one transaction,
    /// preserving the caller's occurrence interval and learned timestamp.
    pub fn create_conversation_with_text(
        &self,
        id: EntityId,
        body: &ConversationBody,
        actor: WriteActor,
        occurred: crate::TimeRange,
        learned_at: u64,
        text: &[(&str, &str)],
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            create_in_txn(self, txn, id, body, actor, occurred, learned_at, text)
        })
    }

    /// Filter the type-index page. The cursor is the last *scanned* id, not a
    /// matching id, so sparse filters cannot skip or repeat rooms.
    pub fn conversations_page(
        &self,
        kind: Option<ConversationKind>,
        external_id: Option<&str>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<(Vec<EntityId>, Option<EntityId>)> {
        let mut cursor = after.copied();
        let mut result = Vec::new();
        if limit == 0 {
            return Ok((result, cursor));
        }
        loop {
            let page =
                self.entities_by_type_page(ENTITY_TYPE_CONVERSATION, cursor.as_ref(), 256)?;
            if page.is_empty() {
                return Ok((result, None));
            }
            for id in page.iter().copied() {
                cursor = Some(id);
                if self.is_deleted_shell(&id)? {
                    continue;
                }
                let body = self.conversation_body(id)?;
                if kind.is_none_or(|k| k == body.kind)
                    && external_id.is_none_or(|e| body.external_id.as_deref() == Some(e))
                {
                    result.push(id);
                    if result.len() == limit {
                        return Ok((result, cursor));
                    }
                }
            }
            if page.len() < 256 {
                return Ok((result, None));
            }
        }
    }
}
pub(crate) fn body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<ConversationBody> {
    let raw = require_kind(vault, txn, id, ENTITY_TYPE_CONVERSATION)?;
    ConversationBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])
}

/// Shared atomic create door for ordinary conversations and project-leader chats.
#[expect(
    clippy::too_many_arguments,
    reason = "the atomic conversation create carries its original caller fields into one transaction"
)]
pub(crate) fn create_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ConversationBody,
    actor: WriteActor,
    occurred: crate::TimeRange,
    learned_at: u64,
    text: &[(&str, &str)],
) -> Result<()> {
    authorize(vault, txn, actor)?;
    if crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?
        != crate::vault::LiveEntityRow::Absent
    {
        return Err(state("conversation already exists"));
    }
    for person in &body.member_ids {
        require_kind(vault, txn, *person, ENTITY_TYPE_PERSON)?;
        membership::append_row(
            vault,
            txn,
            id,
            &MembershipRow {
                v: 1,
                person: *person,
                action: MembershipAction::Join,
                at: occurred.start,
                actor: actor.entity_ref(),
                visible_from: Some(if body.shares_history() {
                    0
                } else {
                    occurred.start
                }),
            },
        )?;
    }
    let mut batch = vault.batch_in().put(
        &id,
        ENTITY_TYPE_CONVERSATION,
        occurred,
        learned_at,
        &body.to_bytes()?,
    );
    if !text.is_empty() {
        batch = batch.text(&id, text);
    }
    batch.apply(txn)
}
