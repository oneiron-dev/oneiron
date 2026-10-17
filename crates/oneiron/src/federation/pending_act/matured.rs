//! The matured-act notice: the housekeeping pass that tells the Owners when a
//! waiting shared act's window has passed, and each Owner's read of their own
//! notices. The pass is effect-free; executing the act stays an Owner's door.
use super::{
    ACT_PREFIX, PendingAuthorityAct, Role, check_vault, decode, encode, invalid, key, reconcile,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;

const MATURED_PREFIX: &[u8] = b"shared-act:matured:v1:";

/// Waiting acts beside their row keys.
type WaitingActs = Vec<(Vec<u8>, PendingAuthorityAct)>;

/// Durable, recipient-specific notice that a waiting act has matured: its
/// window passed on the store clock with no live objection, so a live Owner
/// may now execute it. A zero-wait act was told at its start instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActMatured {
    pub act_id: String,
    pub vault_id: u64,
    pub act: String,
    pub recipient: String,
    pub deadline: u64,
    /// The store-clock time the housekeeping pass saw the act matured.
    pub noticed_at: u64,
}

impl Vault {
    /// The housekeeping pass over waiting shared acts. Each act no door has
    /// executed whose window has passed on the store clock with no live
    /// objection is persisted completed, and every live Owner who may execute
    /// it gets one durable [`PendingActMatured`] notice. Answers the number of
    /// notices written; running it again writes none, and an Owner who joins
    /// after an act matured is told on the next pass.
    ///
    /// A read pass goes first: a vault with no waiting act whose deadline has
    /// come on the store clock opens no writer. The same pass drops each
    /// export-first removal archive past its retention (OF-150).
    pub fn notify_matured_shared_acts(&self) -> Result<usize> {
        self.drop_expired_removal_exports()?;
        {
            let txn = self.store.env.read_txn()?;
            let now = self.store.clock.now_recorded_at();
            let due = self
                .waiting_shared_acts_in_txn(&txn)?
                .is_some_and(|(_, waiting)| {
                    waiting.iter().any(|(_, record)| record.deadline <= now)
                });
            if !due {
                return Ok(0);
            }
        }
        let mut txn = self.store.env.write_txn()?;
        let Some((vault_id, waiting)) = self.waiting_shared_acts_in_txn(&txn)? else {
            return Ok(0);
        };
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        let mut written = 0;
        for (k, mut record) in waiting {
            if !record.completed {
                reconcile(&mut record, &holders, now);
                if !record.completed {
                    continue;
                }
                self.store.vault_meta.put(&mut txn, &k, &encode(&record)?)?;
            }
            if now < record.deadline {
                continue;
            }
            for holder in &holders {
                if !holder.can(&[Role::Owner], &record.required_verb) {
                    continue;
                }
                let notice_key = key(
                    MATURED_PREFIX,
                    &format!("{}:{}", holder.member.to_hex(), record.id),
                );
                if self.store.vault_meta.get(&txn, &notice_key)?.is_some() {
                    continue;
                }
                let notice = PendingActMatured {
                    act_id: record.id.clone(),
                    vault_id: record.vault_id,
                    act: record.act.clone(),
                    recipient: holder.member.to_hex(),
                    deadline: record.deadline,
                    noticed_at: now,
                };
                self.store
                    .vault_meta
                    .put(&mut txn, &notice_key, &encode(&notice)?)?;
                written += 1;
            }
        }
        txn.commit()?;
        Ok(written)
    }

    /// The shared vault's id and its waiting acts (unexecuted, with a window)
    /// with their row keys; `None` outside a live shared vault or when none
    /// waits.
    fn waiting_shared_acts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<(u64, WaitingActs)>> {
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(None);
        };
        if self.shared_vault_deletion_in_txn(txn)?.is_some() {
            return Ok(None);
        }
        let mut waiting = Vec::new();
        for row in self.store.vault_meta.prefix_iter(txn, ACT_PREFIX)? {
            let (k, raw) = row?;
            let record: PendingAuthorityAct = decode(&raw)?;
            if record.execution.is_none()
                && record.deadline > record.started_at
                && record.vault_id == creation.vault_id
            {
                waiting.push((k.to_vec(), record));
            }
        }
        Ok((!waiting.is_empty()).then_some((creation.vault_id, waiting)))
    }
    /// The reader's own matured-act notices for `vault_id`.
    pub fn pending_act_matured_events(
        &self,
        holder: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<PendingActMatured>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a live holder reads their own notices.
        let holder_actor = holder.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        if !self
            .live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?
            .iter()
            .any(|entry| entry.member == holder_actor)
        {
            return Err(invalid());
        }
        let prefix = key(MATURED_PREFIX, &format!("{}:", holder_actor.to_hex()));
        let mut events = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, bytes) = entry?;
            let event: PendingActMatured = decode(&bytes)?;
            if event.vault_id == vault_id {
                events.push(event);
            }
        }
        Ok(events)
    }
}
