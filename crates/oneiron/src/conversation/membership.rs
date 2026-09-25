//! Append-only membership ledger. Body and ledger commit in the same transaction.
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
const PREFIX: &[u8] = b"conversation_membership:v1:";
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChoice {
    #[default]
    Inherit,
    Share,
    None,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAction {
    Join,
    Leave,
    History,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRow {
    pub v: u8,
    pub person: EntityId,
    pub action: MembershipAction,
    pub at: u64,
    pub actor: EntityId,
    pub visible_from: Option<u64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipWindow {
    pub joined_at: u64,
    pub from: u64,
    pub to: Option<u64>,
}
impl MembershipWindow {
    pub fn contains(&self, at: u64) -> bool {
        self.from <= at && self.to.is_none_or(|end| at < end)
    }
}

pub(super) fn revision_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
) -> Result<u64> {
    let revision = store
        .vault_meta
        .get(txn, &key(b"conversation_membership:seq:v1:", conversation))?
        .map(|bytes| {
            bytes
                .as_ref()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::CorruptedIndex("membership revision"))
        })
        .transpose()?;
    if revision.unwrap_or(0) == 0
        && store
            .vault_meta
            .prefix_iter(txn, &key(PREFIX, conversation))?
            .next()
            .transpose()?
            .is_some()
    {
        return Err(Error::CorruptedIndex("membership rows without revision"));
    }
    Ok(revision.unwrap_or(0))
}

pub(super) fn rows_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
) -> Result<Vec<MembershipRow>> {
    let prefix = key(PREFIX, conversation);
    let mut rows = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (k, v) = row?;
        if k.len() != prefix.len() + 8 {
            return Err(Error::CorruptedIndex("membership key"));
        }
        let row: MembershipRow = decode(&v)?;
        if row.v != 1
            || rows
                .last()
                .is_some_and(|last: &MembershipRow| last.at > row.at)
        {
            return Err(Error::CorruptedIndex("membership ledger order"));
        }
        rows.push(row);
    }
    if revision_in(store, txn, conversation)? != rows.len() as u64 {
        return Err(Error::CorruptedIndex(
            "membership revision does not match rows",
        ));
    }
    Ok(rows)
}
pub(super) fn append_row(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    row: &MembershipRow,
) -> Result<()> {
    let rows = rows_in(&vault.store, txn, conversation)?;
    if rows.last().is_some_and(|last| row.at < last.at) {
        return Err(state("membership time cannot rewind"));
    }
    let mut k = key(PREFIX, conversation);
    k.extend_from_slice(&(rows.len() as u64).to_be_bytes());
    vault.store.vault_meta.put(txn, &k, &encode(row)?)?;
    vault.store.vault_meta.put(
        txn,
        &key(b"conversation_membership:seq:v1:", conversation),
        &((rows.len() + 1) as u64).to_be_bytes(),
    )?;
    Ok(())
}
pub(super) fn members_at_rows(rows: &[MembershipRow], at: u64) -> BTreeSet<EntityId> {
    let mut members = BTreeSet::new();
    for row in rows.iter().take_while(|r| r.at <= at) {
        match row.action {
            MembershipAction::Join => {
                members.insert(row.person);
            }
            MembershipAction::Leave => {
                members.remove(&row.person);
            }
            MembershipAction::History => {}
        }
    }
    members
}
pub(super) fn windows_rows(
    rows: &[MembershipRow],
    person: EntityId,
) -> Result<Vec<MembershipWindow>> {
    let mut windows: Vec<MembershipWindow> = Vec::new();
    for row in rows.iter().filter(|r| r.person == person) {
        match row.action {
            MembershipAction::Join => {
                if windows.last().is_some_and(|w| w.to.is_none()) {
                    return Err(Error::CorruptedIndex("duplicate membership join"));
                }
                windows.push(MembershipWindow {
                    joined_at: row.at,
                    from: row
                        .visible_from
                        .ok_or(Error::CorruptedIndex("membership visibility"))?,
                    to: None,
                });
            }
            MembershipAction::Leave => {
                let current = windows
                    .last_mut()
                    .filter(|w| w.to.is_none())
                    .ok_or(Error::CorruptedIndex("membership leave without join"))?;
                current.to = Some(row.at);
            }
            MembershipAction::History => {
                let current = windows
                    .last_mut()
                    .filter(|w| w.to.is_none())
                    .ok_or(Error::CorruptedIndex("history without membership"))?;
                let from = row
                    .visible_from
                    .ok_or(Error::CorruptedIndex("membership visibility"))?;
                if from != 0 && from != current.joined_at {
                    return Err(Error::CorruptedIndex("invalid history boundary"));
                }
                current.from = from;
            }
        }
    }
    Ok(windows)
}
impl Vault {
    pub fn membership_ledger(&self, conversation: EntityId) -> Result<Vec<MembershipRow>> {
        let txn = self.store.env.read_txn()?;
        body::body_in(self, &txn, conversation)?;
        rows_in(&self.store, &txn, conversation)
    }
    pub fn membership_at(&self, conversation: EntityId, at: u64) -> Result<Vec<EntityId>> {
        Ok(members_at_rows(&self.membership_ledger(conversation)?, at)
            .into_iter()
            .collect())
    }
    pub fn members(&self, conversation: EntityId) -> Result<Vec<EntityId>> {
        self.membership_at(conversation, u64::MAX)
    }
    pub fn windows(
        &self,
        conversation: EntityId,
        person: EntityId,
    ) -> Result<Vec<MembershipWindow>> {
        windows_rows(&self.membership_ledger(conversation)?, person)
    }
    pub fn join_member(
        &self,
        conversation: EntityId,
        person: EntityId,
        actor: WriteActor,
        at: u64,
        history: HistoryChoice,
    ) -> Result<()> {
        self.change_membership(
            conversation,
            person,
            actor,
            at,
            MembershipAction::Join,
            Some(history),
            None,
        )
    }
    pub fn leave_member(
        &self,
        conversation: EntityId,
        person: EntityId,
        actor: WriteActor,
        at: u64,
    ) -> Result<()> {
        self.change_membership(
            conversation,
            person,
            actor,
            at,
            MembershipAction::Leave,
            None,
            None,
        )
    }
    pub fn set_history_visibility(
        &self,
        conversation: EntityId,
        person: EntityId,
        actor: WriteActor,
        at: u64,
        from: u64,
    ) -> Result<()> {
        self.change_membership(
            conversation,
            person,
            actor,
            at,
            MembershipAction::History,
            None,
            Some(from),
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "atomic membership operation with audit and visibility axes"
    )]
    fn change_membership(
        &self,
        conversation: EntityId,
        person: EntityId,
        actor: WriteActor,
        at: u64,
        action: MembershipAction,
        history: Option<HistoryChoice>,
        from: Option<u64>,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            authorize(self, txn, actor)?;
            require_kind(self, txn, person, ENTITY_TYPE_PERSON)?;
            let mut body = body::body_in(self, txn, conversation)?;
            let rows = rows_in(&self.store, txn, conversation)?;
            let mut members = members_at_rows(&rows, u64::MAX);
            let visible_from = match action {
                MembershipAction::Join => {
                    if !members.insert(person) {
                        return Err(state("member already joined"));
                    }
                    Some(match history.unwrap_or_default() {
                        HistoryChoice::Share => 0,
                        HistoryChoice::None => at,
                        HistoryChoice::Inherit => {
                            if body.shares_history() {
                                0
                            } else {
                                at
                            }
                        }
                    })
                }
                MembershipAction::Leave => {
                    if !members.remove(&person) {
                        return Err(state("not a member"));
                    }
                    None
                }
                MembershipAction::History => {
                    let windows = windows_rows(&rows, person)?;
                    let window = windows
                        .last()
                        .filter(|w| w.to.is_none())
                        .ok_or(state("not a current member"))?;
                    if from != Some(0) && from != Some(window.joined_at) {
                        return Err(state("history edge must be origin or join time"));
                    }
                    from
                }
            };
            append_row(
                self,
                txn,
                conversation,
                &MembershipRow {
                    v: 1,
                    person,
                    action,
                    at,
                    actor: actor.entity_ref(),
                    visible_from,
                },
            )?;
            body.member_ids = members.into_iter().collect();
            let raw = require_kind(self, txn, conversation, ENTITY_TYPE_CONVERSATION)?;
            let h = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("conversation header"))?;
            self.batch_in()
                .put(
                    &conversation,
                    ENTITY_TYPE_CONVERSATION,
                    crate::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                    &body.to_bytes()?,
                )
                .apply(txn)
        })
    }
}
