//! Steward member asks (untangle 6.3d; ARCH-0043 Steward, S63-4): a Steward
//! looks after a shared vault's memory, but it can only suggest who joins,
//! who leaves or what role a member holds. Its add, remove or assign-role
//! writes one durable ask and changes nothing; every live Owner and Admin
//! gets an inbox ask. A live Admin or Owner applies it through the same
//! membership door they use for a change of their own, so every check of
//! that door holds, and in that writer the ask closes and the receipt names
//! the Steward as `proposer` beside the applier as `actor`. Or they decline
//! it. Modelled on erase asks. The verbs come after slice 4.2.
use super::{
    OUTCOME_PREFIX, RECEIPT_PREFIX, Role, SharedActExecutionReceipt, SharedActOutcome, check_vault,
    encode, invalid, key, non_root,
};
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// The inbox producer of a member ask; its event is `<ask id>:<recipient id>`.
pub const NOTIFICATION_PRODUCER_MEMBER_ASK: &str = "shared_vault.member_ask";

/// Every member ask, by ask id.
const MEMBER_ASK: SideTable<EntityId, SharedMemberAsk, Named> =
    SideTable::new(&side_table::SHARED_ACT_MEMBER_ASK);

/// The member change a Steward suggests. Ids are PERSON hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberAskChange {
    /// Invite `member` at `role`, or at the vault preset's default member
    /// role when `None`, as [`Vault::add_shared_member`] does.
    Add {
        member: String,
        role: Option<Role>,
    },
    Remove {
        member: String,
    },
    AssignRole {
        member: String,
        role: Role,
    },
}

impl MemberAskChange {
    fn member(&self) -> Result<EntityId> {
        let (Self::Add { member, .. } | Self::Remove { member } | Self::AssignRole { member, .. }) =
            self;
        EntityId::from_hex(member)
    }
}

/// Where an ask stands. Only a live Admin or Owner closes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MemberAskStatus {
    Open,
    /// The Admin or Owner `by` applied it; `receipt` is the membership
    /// change's receipt, which names the Steward as its proposer.
    Applied {
        by: String,
        receipt: String,
    },
    Declined {
        by: String,
    },
}

/// One Steward's suggested member change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberAsk {
    pub id: String,
    #[serde(with = "crate::federation::vault_id_decimal")]
    pub vault_id: u64,
    /// The Steward's PERSON id, hex.
    pub steward: String,
    pub change: MemberAskChange,
    pub asked_at: u64,
    pub status: MemberAskStatus,
    pub closed_at: Option<u64>,
}

/// What a member change did: applied at once for an Admin or Owner, or an
/// ask for a Steward.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedMemberChange {
    Applied(SharedActExecutionReceipt),
    Asked(SharedMemberAsk),
}

/// Who may apply or decline an ask: the live Owners and Admins.
fn appliers(holders: &[super::LiveActHolder]) -> BTreeSet<EntityId> {
    holders
        .iter()
        .filter(|holder| matches!(holder.role, Role::Owner | Role::Admin))
        .map(|holder| holder.member)
        .collect()
}

fn is_steward(holders: &[super::LiveActHolder], actor: EntityId) -> bool {
    holders
        .iter()
        .any(|holder| holder.member == actor && holder.role == Role::Steward)
}

impl Vault {
    /// The member-ask table's actor scrub (review of #6915, round 2): a hard
    /// erase of `actor` deletes every ask that names it, open or closed, as
    /// its Steward, as the member the change is about, or as the Admin or
    /// Owner who closed it. A deleted ask can be neither applied nor
    /// declined, so no pending change outlives the person it names. An id is
    /// matched as written and by the id it decodes to: an ask holds the
    /// member's hex as its filer wrote it.
    pub(crate) fn erase_member_ask_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, txn, actor)? {
            return Ok(());
        }
        let written = actor.to_hex();
        let names = |hex: &String| {
            *hex == written || EntityId::from_hex(hex).is_ok_and(|named| named == *actor)
        };
        for (id, ask) in MEMBER_ASK.scan(&self.store, txn)? {
            let (MemberAskChange::Add { member, .. }
            | MemberAskChange::Remove { member }
            | MemberAskChange::AssignRole { member, .. }) = &ask.change;
            let closed_by = match &ask.status {
                MemberAskStatus::Open => false,
                MemberAskStatus::Applied { by, .. } | MemberAskStatus::Declined { by } => names(by),
            };
            if names(&ask.steward) || names(member) || closed_by {
                MEMBER_ASK.delete(&self.store, txn, &id)?;
            }
        }
        Ok(())
    }

    /// A member change on shared vault `vault_id` by `actor`: a live
    /// Steward's change becomes an ask ([`Self::ask_shared_member_change`]);
    /// anyone else goes through the membership door itself
    /// ([`Self::add_shared_member`], [`Self::remove_shared_member`],
    /// [`Self::change_shared_member_role`]), which judges them.
    pub fn shared_member_change(
        &self,
        actor: &AuthenticatedOwner,
        vault_id: u64,
        change: MemberAskChange,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedMemberChange> {
        let steward = {
            let txn = self.store.env.read_txn()?;
            let actor = actor.revalidate_person_in_txn(self, &txn)?;
            check_vault(self, &txn, vault_id)?;
            let holders =
                self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
            is_steward(&holders, actor)
        };
        if steward {
            return self
                .ask_shared_member_change(actor, vault_id, change)
                .map(SharedMemberChange::Asked);
        }
        let member = change.member()?;
        let receipt = match change {
            MemberAskChange::Add { role, .. } => {
                self.add_shared_member(actor, vault_id, member, role)?
            }
            MemberAskChange::Remove { .. } => {
                self.remove_shared_member(actor, vault_id, member, slips)?
            }
            MemberAskChange::AssignRole { role, .. } => {
                self.change_shared_member_role(actor, vault_id, member, role, slips)?
            }
        };
        Ok(SharedMemberChange::Applied(receipt))
    }

    /// A live Steward suggests `change`: one durable ask, an inbox ask to
    /// every live Owner and Admin, and nothing else changes. The change must
    /// be one the membership door could apply now, and never the Steward's
    /// own membership (it leaves through the leave door). Asking again while
    /// the Steward's ask for the same change is open answers that ask.
    pub fn ask_shared_member_change(
        &self,
        steward: &AuthenticatedOwner,
        vault_id: u64,
        change: MemberAskChange,
    ) -> Result<SharedMemberAsk> {
        let mut txn = self.store.env.write_txn()?;
        // Person tier; the role is read from the live roster below.
        let actor = steward.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        if !is_steward(&holders, actor) {
            return Err(invalid());
        }
        let member = change.member()?;
        if member == actor {
            return Err(invalid());
        }
        let current = self.member_role_in_txn(&txn, vault_id, member)?;
        let doable = match &change {
            MemberAskChange::Add { role, .. } => {
                non_root(*role)?;
                // The add effect refuses a second open invitation, so the
                // ask is refused here, at filing.
                current.is_none()
                    && crate::consent::person_is_live_in_txn(self, &txn, &member)?
                    && !self.open_invitation_stands_in_txn(&txn, vault_id, member, now)?
            }
            MemberAskChange::Remove { .. } => current.is_some_and(|from| from != Role::Owner),
            MemberAskChange::AssignRole { role, .. } => {
                non_root(Some(*role))?;
                current.is_some_and(|from| from != Role::Owner && from != *role)
            }
        };
        if !doable {
            return Err(invalid());
        }
        let steward_hex = actor.to_hex();
        if let Some((_, open)) = MEMBER_ASK
            .scan(&self.store, &txn)?
            .into_iter()
            .find(|(_, ask)| {
                ask.vault_id == vault_id
                    && ask.status == MemberAskStatus::Open
                    && ask.steward == steward_hex
                    && ask.change == change
            })
        {
            return Ok(open);
        }
        let id = self.store.clock.entity_id()?;
        let ask = SharedMemberAsk {
            id: id.to_hex(),
            vault_id,
            steward: steward_hex,
            change,
            asked_at: now,
            status: MemberAskStatus::Open,
            closed_at: None,
        };
        MEMBER_ASK.put(&self.store, &mut txn, &id, &ask)?;
        for recipient in appliers(&holders) {
            self.record_notification_in_txn(
                &mut txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_MEMBER_ASK.to_owned(),
                        event: format!("{}:{}", ask.id, recipient.to_hex()),
                        result: Some(ask.id.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![member],
                    recipient: Some(recipient),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        txn.commit()?;
        Ok(ask)
    }

    /// The member asks `reader` may see in `vault_id`: every ask for a live
    /// Owner or Admin, the reader's own asks for a Steward.
    pub fn shared_member_asks(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedMemberAsk>> {
        let txn = self.store.env.read_txn()?;
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let holders = self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
        let applier = appliers(&holders).contains(&reader);
        let reader = reader.to_hex();
        Ok(MEMBER_ASK
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, ask)| ask)
            .filter(|ask| ask.vault_id == vault_id && (applier || ask.steward == reader))
            .collect())
    }

    /// A live Admin or Owner applies open ask `ask_id` through the
    /// membership door its change names, under their own authority: the
    /// door's checks all hold, and its receipt names the Steward as
    /// `proposer`. The Steward also gets the change's outcome notice.
    pub fn apply_shared_member_ask(
        &self,
        applier: &AuthenticatedOwner,
        ask_id: &str,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecutionReceipt> {
        let id = EntityId::from_hex(ask_id)?;
        let ask = {
            let txn = self.store.env.read_txn()?;
            MEMBER_ASK
                .get(&self.store, &txn, &id)?
                .ok_or_else(invalid)?
        };
        if ask.status != MemberAskStatus::Open {
            return Err(invalid());
        }
        let member = ask.change.member()?;
        let ask_ref = Some(ask.id.as_str());
        match ask.change {
            MemberAskChange::Add { role, .. } => {
                self.add_shared_member_for_ask(applier, ask.vault_id, member, role, ask_ref, None)
            }
            MemberAskChange::Remove { .. } => self.remove_shared_member_for_ask(
                applier,
                ask.vault_id,
                member,
                slips,
                ask_ref,
                None,
            ),
            MemberAskChange::AssignRole { role, .. } => self.change_shared_member_role_for_ask(
                applier,
                ask.vault_id,
                member,
                role,
                slips,
                ask_ref,
                None,
            ),
        }
    }

    /// In the membership door's writer, before the change: refuses ask
    /// `ask` unless the Steward who filed it is still a live Steward of
    /// `vault_id` (review of #6915). An ask outlived its Steward: after an
    /// Admin removed them, another Admin's apply still landed the change in
    /// their name and wrote them its outcome notice, which a person outside
    /// the vault then read with the receipt. The applier declines such an
    /// ask, or makes the change as their own.
    pub(super) fn member_ask_steward_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &str,
        vault_id: u64,
        holders: &[super::LiveActHolder],
    ) -> Result<()> {
        let id = EntityId::from_hex(ask)?;
        let ask = MEMBER_ASK.get(&self.store, txn, &id)?.ok_or_else(invalid)?;
        if ask.vault_id != vault_id || !is_steward(holders, EntityId::from_hex(&ask.steward)?) {
            return Err(invalid());
        }
        Ok(())
    }

    /// In the membership door's writer, after its receipt: close ask `ask`
    /// as applied by `applier`, name its Steward in the receipt, and tell
    /// the Steward. The ask must still be open, for this vault.
    pub(super) fn apply_member_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ask: &str,
        applier: EntityId,
        receipt: &mut SharedActExecutionReceipt,
        now: u64,
    ) -> Result<()> {
        let id = EntityId::from_hex(ask)?;
        let mut ask = MEMBER_ASK
            .get(&self.store, &*txn, &id)?
            .ok_or_else(invalid)?;
        if ask.status != MemberAskStatus::Open || ask.vault_id != receipt.vault_id {
            return Err(invalid());
        }
        receipt.proposer = Some(ask.steward.clone());
        self.store
            .vault_meta
            .put(txn, &key(RECEIPT_PREFIX, &receipt.id), &encode(&*receipt)?)?;
        let notice = key(OUTCOME_PREFIX, &format!("{}:{}", ask.steward, receipt.id));
        if self.store.vault_meta.get(&*txn, &notice)?.is_none() {
            let outcome = SharedActOutcome {
                receipt_id: receipt.id.clone(),
                act_id: receipt.act_id.clone(),
                vault_id: receipt.vault_id,
                recipient: ask.steward.clone(),
                change: receipt.change.clone(),
                completed_at: now,
            };
            self.store
                .vault_meta
                .put(txn, &notice, &encode(&outcome)?)?;
        }
        ask.status = MemberAskStatus::Applied {
            by: applier.to_hex(),
            receipt: receipt.id.clone(),
        };
        ask.closed_at = Some(now);
        MEMBER_ASK.put(&self.store, txn, &id, &ask)
    }

    /// A live Admin or Owner declines open ask `ask_id`. Declining changes no
    /// membership.
    pub fn decline_shared_member_ask(
        &self,
        applier: &AuthenticatedOwner,
        ask_id: &str,
    ) -> Result<SharedMemberAsk> {
        let id = EntityId::from_hex(ask_id)?;
        let mut txn = self.store.env.write_txn()?;
        let actor = applier.revalidate_person_in_txn(self, &txn)?;
        let mut ask = MEMBER_ASK
            .get(&self.store, &txn, &id)?
            .ok_or_else(invalid)?;
        check_vault(self, &txn, ask.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, ask.vault_id, now)?;
        if ask.status != MemberAskStatus::Open || !appliers(&holders).contains(&actor) {
            return Err(invalid());
        }
        ask.status = MemberAskStatus::Declined { by: actor.to_hex() };
        ask.closed_at = Some(now);
        MEMBER_ASK.put(&self.store, &mut txn, &id, &ask)?;
        txn.commit()?;
        Ok(ask)
    }
}

#[cfg(test)]
mod tests;
