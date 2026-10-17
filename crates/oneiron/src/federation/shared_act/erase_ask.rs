//! Erase asks (ARCH-0043 "Who may archive, delete and erase", 2026-10-09): in
//! a shared vault a Member requests an erase and an Admin proposes one, while
//! only an Owner erases, by hand, through the erase doors and their veto
//! window. An ask erases nothing, starts no window and lifts no hold. It is
//! one durable record, an inbox ask to every live Owner, and the asker's own
//! view of it; an Owner closes it once they have erased the record or decided
//! not to.
use super::{Role, check_vault, decode, encode, invalid, key};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::{EntityId, Vault};

const ASK_PREFIX: &[u8] = b"shared-act:erase-ask:v1:";
/// The inbox producer of an erase ask; its event is `<ask id>:<owner id>`.
pub const NOTIFICATION_PRODUCER_ERASE_ASK: &str = "shared_vault.erase_ask";
/// The act name an Owner's erase runs under, which a closing answer names.
const ERASE_ACT: &str = "erase";

/// Who asked: a Member requests, an Admin proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseAskKind {
    Request,
    Proposal,
}

/// Where an ask stands. Only an Owner closes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseAskStatus {
    Open,
    /// The Owner `by` erased the record; `act` names the `erase` act it
    /// started where the veto window applied.
    Erased {
        by: String,
        act: Option<String>,
    },
    Declined {
        by: String,
    },
}

/// One Member's request or Admin's proposal to erase a record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAsk {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    pub kind: EraseAskKind,
    /// The asker's PERSON id, hex.
    pub asker: String,
    /// The record the asker wants erased, entity id hex.
    pub record: String,
    pub asked_at: u64,
    pub status: EraseAskStatus,
    pub closed_at: Option<u64>,
}

impl Vault {
    fn erase_asks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<SharedEraseAsk>> {
        let mut asks = Vec::new();
        for row in self.store.vault_meta.prefix_iter(txn, ASK_PREFIX)? {
            let (_, raw) = row?;
            let ask: SharedEraseAsk = decode(&raw)?;
            if ask.vault_id == vault_id {
                asks.push(ask);
            }
        }
        Ok(asks)
    }

    /// Ask the Owners to erase `record`, a live record of this vault: a live
    /// Member requests it and a live Admin proposes it, each through their
    /// grant's `write` verb. Every live Owner gets an inbox ask naming the
    /// record. Asking again while the asker's ask for the record is open
    /// answers that ask.
    pub fn ask_shared_erase(
        &self,
        asker: &AuthenticatedOwner,
        vault_id: u64,
        record: EntityId,
    ) -> Result<SharedEraseAsk> {
        let mut txn = self.store.env.write_txn()?;
        // Person tier; the role is read from the live roster below.
        let actor = asker.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        let kind = holders
            .iter()
            .find(|holder| holder.member == actor)
            .and_then(|holder| match holder.role {
                Role::Member if holder.can(&[Role::Member], "write") => Some(EraseAskKind::Request),
                Role::Admin if holder.can(&[Role::Admin], "write") => Some(EraseAskKind::Proposal),
                _ => None,
            })
            .ok_or_else(invalid)?;
        if !crate::vault::live_entity_row_in_txn(&self.store, &txn, &record)?.is_live() {
            return Err(invalid());
        }
        let (asker_hex, record_hex) = (actor.to_hex(), record.to_hex());
        if let Some(open) = self
            .erase_asks_in_txn(&txn, vault_id)?
            .into_iter()
            .find(|ask| {
                ask.status == EraseAskStatus::Open
                    && ask.asker == asker_hex
                    && ask.record == record_hex
            })
        {
            return Ok(open);
        }
        let ask = SharedEraseAsk {
            id: self.store.clock.entity_id()?.to_hex(),
            vault_id,
            kind,
            asker: asker_hex,
            record: record_hex,
            asked_at: now,
            status: EraseAskStatus::Open,
            closed_at: None,
        };
        self.store
            .vault_meta
            .put(&mut txn, &key(ASK_PREFIX, &ask.id), &encode(&ask)?)?;
        for owner in super::live_owners(&holders, None) {
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_ERASE_ASK.to_owned(),
                        event: format!("{}:{}", ask.id, owner.to_hex()),
                        result: Some(ask.id.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![record],
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        txn.commit()?;
        Ok(ask)
    }

    /// The erase asks `reader` may see in `vault_id`: every ask for a live
    /// Owner, the reader's own asks for anyone else.
    pub fn shared_erase_asks(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedEraseAsk>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: an Owner reads every ask, an asker their own.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let holders = self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
        let owner = super::live_owners(&holders, None).contains(&reader);
        let reader = reader.to_hex();
        Ok(self
            .erase_asks_in_txn(&txn, vault_id)?
            .into_iter()
            .filter(|ask| owner || ask.asker == reader)
            .collect())
    }

    /// A live Owner closes open ask `ask_id`: `erased` when they erased its
    /// record, naming with `act` the `erase` act they started where the veto
    /// window applied, else declined. Closing erases nothing.
    pub fn close_shared_erase_ask(
        &self,
        owner: &AuthenticatedOwner,
        ask_id: &str,
        erased: bool,
        act: Option<&str>,
    ) -> Result<SharedEraseAsk> {
        let ask_key = key(ASK_PREFIX, &EntityId::from_hex(ask_id)?.to_hex());
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_person_in_txn(self, &txn)?;
        let raw = self
            .store
            .vault_meta
            .get(&txn, &ask_key)?
            .ok_or_else(invalid)?;
        let mut ask: SharedEraseAsk = decode(&raw)?;
        check_vault(self, &txn, ask.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, ask.vault_id, now)?;
        if ask.status != EraseAskStatus::Open
            || !super::live_owners(&holders, None).contains(&actor)
            || (!erased && act.is_some())
        {
            return Err(invalid());
        }
        let act = match act {
            Some(id) => {
                let started = self
                    .pending_authority_act_in_txn(&txn, id)?
                    .ok_or_else(invalid)?;
                if started.act != ERASE_ACT || started.vault_id != ask.vault_id {
                    return Err(invalid());
                }
                Some(started.id)
            }
            None => None,
        };
        let by = actor.to_hex();
        ask.status = if erased {
            EraseAskStatus::Erased { by, act }
        } else {
            EraseAskStatus::Declined { by }
        };
        ask.closed_at = Some(now);
        self.store
            .vault_meta
            .put(&mut txn, &ask_key, &encode(&ask)?)?;
        txn.commit()?;
        Ok(ask)
    }
}
