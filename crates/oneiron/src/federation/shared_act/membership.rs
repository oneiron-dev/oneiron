//! Membership effects: Owner additions and handovers, and the
//! ordinary member changes an Admin's named power makes at once. Each rewrites
//! or deletes FEDERATION_GRANT records in the caller's writer and revokes the
//! capability slips of whoever lost a role, using the supplied issuer or this
//! install's own live host issuer. A change no issuer signs keeps its effects
//! and a pending intent of its signed record, which this install carries
//! when it can (`pending_execution`, FIX 12335).
//! Removal is access revocation, never a group rekey. A new member joins only
//! by accepting an invitation (`invitation`).
//!
//! The add, move and remove doors check in first, in their own writer
//! (ROLES-CHECKIN 2i; P24-SHAPE Q3 to Q6 = A): an Owner's and an Admin's act
//! goes, a Deputy's add and a Member's raise to Admin go on the person's own
//! judgment, and a Deputy's other moves and removes wait for an Owner's
//! answer. The receipt records the decision.
mod invitation;
mod owner_recovery;
mod pending_execution;

pub use invitation::{SHARED_INVITATION_TTL_SECS, SharedInvitation, SharedInvitationState};
pub use owner_recovery::OwnerRecoveryAuthorization;

pub(super) use pending_execution::UnsignedExecution;

use super::{
    ChangeRecord, DetachOutcome, DetachReport, Effect, RECEIPT_PREFIX, RemoveOwnerPlan,
    SharedActExecutionReceipt, SharedActKind, SharedVaultChange, decode, encode, invalid, key,
    live_owners, non_root,
};
use crate::authority::{
    CapabilitySlip, HostSlipIssuer, MembershipExecutionCause, OwnerHandover, OwnerHandoverCause,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::check_in::{ActClass, CheckInScope, DoorAct, DoorCheckIn, RolePreset};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::federation::record_scope::ScopedRecord;
use crate::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, OrgAdminPower, Scope,
    ScopeAxis, SharedVaultWrite, decode_federation_grant_body, encode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

/// What one membership move wrote (FIX 5765): every grant id it rewrote,
/// minted, deleted or retired, as the receipt lists them; the own-device
/// grant ids it retired, which `grants` lists too; the slips it revoked; and
/// the detach report, when a genuine leave released bound Connect grants.
/// the Grants an owner's signed mint made that it deleted with no signed
/// withdrawal, for want of an issuer (FIX 12335).
pub(super) struct MemberMove {
    pub(super) grants: Vec<EntityId>,
    pub(super) retired_own_device: Vec<EntityId>,
    pub(super) revoked_slips: Vec<[u8; 32]>,
    pub(super) detach: Option<DetachReport>,
    pub(super) unsigned_withdrawals: Vec<EntityId>,
}

impl MemberMove {
    /// The handover's signed id lists: the grants it wrote, apart from the
    /// own-device grants it retired, and those retired grants, each
    /// canonical.
    pub(super) fn handover_ids(&self) -> (Vec<EntityId>, Vec<EntityId>) {
        let retired =
            crate::authority::canonical_handover_ids(self.retired_own_device.iter().copied());
        let affected = crate::authority::canonical_handover_ids(
            self.grants
                .iter()
                .copied()
                .filter(|id| retired.binary_search(id).is_err()),
        );
        (affected, retired)
    }
}

/// A genuine membership departure (FIX 12555): the closed token the
/// guest-revoke detach entry consumes. It carries the actual writer borrow,
/// so the detach runs in the same transaction as the authorized membership
/// transition — never a frozen proof, a caller bool or raw ids alone. No
/// clone, default or serde escape: it is built in one place and consumed by
/// value in the same writer.
pub(crate) struct SharedMemberDeparture<'writer, 'env> {
    txn: &'writer mut heed::RwTxn<'env>,
    vault_id: u64,
    leaver: EntityId,
}

impl<'writer, 'env> SharedMemberDeparture<'writer, 'env> {
    /// The one construction: [`Vault::move_member_in_txn`] builds it after
    /// its authorized transition to no role. Private, so no other module can
    /// forge a departure; recovery's genuine leave arrives through the same
    /// move and is included automatically.
    fn for_genuine_leave(
        txn: &'writer mut heed::RwTxn<'env>,
        vault_id: u64,
        leaver: EntityId,
    ) -> Self {
        Self {
            txn,
            vault_id,
            leaver,
        }
    }

    /// Consumed by value at the guest-revoke detach entry.
    pub(crate) fn into_parts(self) -> (&'writer mut heed::RwTxn<'env>, u64, EntityId) {
        (self.txn, self.vault_id, self.leaver)
    }
}

/// The member ladder: higher ranks hold more, and a change to a lower rank
/// revokes held slips. A Deputy sits above Admin: a move from Deputy to Admin
/// drops its delegated Owner powers. Steward is a named grant preset, not a
/// rung (ARCH-0043; lead 10 Nov 06:5x), so it has no rank.
const fn rank(role: Role) -> Option<u8> {
    match role {
        Role::Owner => Some(6),
        Role::Deputy => Some(5),
        Role::Admin => Some(4),
        Role::Member => Some(2),
        Role::Viewer => Some(1),
        Role::Delegate | Role::Guest => Some(0),
        Role::Steward => None,
    }
}

/// Whether moving a member from `from` to `to` (`None` leaves the vault)
/// revokes the slips they hold: a lower rank on the ladder, or any move
/// into or out of Steward. A Steward's verbs (read, derive, archive,
/// delete) are neither a subset nor a superset of a Member's (read, write)
/// or an Admin's, so a slip minted under one never stands under the other.
fn move_revokes_slips(from: Role, to: Option<Role>) -> bool {
    to.is_none_or(|to| match (rank(from), rank(to)) {
        (Some(from), Some(to)) => to < from,
        _ => to != from,
    })
}

impl Vault {
    /// Every live grant record over `vault_id`, delegates included.
    pub(crate) fn vault_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<(EntityId, FederationGrant)>> {
        let mut grants = Vec::new();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            let raw = self.get_raw_in(txn, &id)?.ok_or_else(invalid)?;
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
            {
                return Err(invalid());
            }
            if raw.len() == ENTITY_METADATA_HEADER_LEN
                || !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                continue;
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope == FederationGrantScope::vault(vault_id) {
                grants.push((id, grant));
            }
        }
        Ok(grants)
    }
    /// Every live membership grant record over `vault_id`, delegates
    /// included: [`Self::vault_grants_in_txn`] without the rows that were
    /// never minted as a membership. A base agent's Steward grant is the
    /// engine's actor's reach (untangle 6.3; review of #6913): the host
    /// mints it by default, and only the owner moves it, through its own
    /// door, which shows what breaks and waits for his confirm. An owner's
    /// `engine.controls` grant to a principal that is no Steward member is
    /// his grant to that principal (6.6), taken back through its own door.
    /// So no membership door reads either as a role, lists it on the
    /// roster, re-roles it or drops it.
    fn member_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<(EntityId, FederationGrant)>> {
        let mut grants = self.vault_grants_in_txn(txn, vault_id)?;
        grants.retain(|(_, grant)| !crate::federation::holds_system_agent_grant(grant.member_ref));
        // An owner's `engine.controls` grant goes with a Steward's
        // membership and is none on its own (ruling on FIX
        // ENGINE-CONTROLS-GRANT-READS-AS-MEMBERSHIP, Engine 11 Nov): beside
        // a Steward membership row it is read with it, so a demotion or a
        // removal takes it too; for anyone else it is skipped.
        let stewards: BTreeSet<EntityId> = grants
            .iter()
            .filter(|(_, grant)| {
                grant.role == Role::Steward && !crate::federation::is_engine_controls_grant(grant)
            })
            .map(|(_, grant)| grant.member_ref)
            .collect();
        grants.retain(|(_, grant)| {
            !crate::federation::is_engine_controls_grant(grant)
                || stewards.contains(&grant.member_ref)
        });
        Ok(grants)
    }
    /// Steward and Deputy are the owner's to give: a role change or an
    /// invitation that names either needs an Owner of the vault, and an
    /// Admin's AssignRole and AddMember powers never reach them. Steward:
    /// ARCH-0043, an Admin "cannot self-grant blanket access" (lead 10 Nov
    /// 06:5x). Deputy: Admin plus the delegated Owner Grant (ARCH-0082),
    /// which the house door already refuses an Admin (Engine ruling
    /// C1-DEPUTY-GIVER, 13 Nov).
    fn reserved_role_given_by_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        giver: EntityId,
        role: Role,
    ) -> Result<()> {
        if matches!(role, Role::Steward | Role::Deputy)
            && self.member_role_in_txn(txn, vault_id, giver)? != Some(Role::Owner)
        {
            return Err(crate::error::Error::Claim(
                crate::error::ClaimError::ActorLacksClaimAuthority {
                    reason: "only an owner of the vault gives the Steward or Deputy role",
                },
            ));
        }
        Ok(())
    }
    /// `member`'s one membership role in the vault, delegate grants aside.
    /// Check-in reads an agent's role from it (P24-SHAPE Q1 = A).
    pub(crate) fn member_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        member: EntityId,
    ) -> Result<Option<Role>> {
        let mut roles = self
            .member_grants_in_txn(txn, vault_id)?
            .into_iter()
            .filter(|(_, grant)| grant.member_ref == member && grant.role != Role::Delegate)
            .map(|(_, grant)| grant.role);
        let role = roles.next();
        if roles.any(|other| Some(other) != role) {
            return Err(invalid());
        }
        Ok(role)
    }
    /// `member`'s membership grant row in the vault and its role, delegate
    /// and `engine.controls` grants aside: the grant a person's pending
    /// check-in climbs the ladder from.
    fn member_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        member: EntityId,
    ) -> Result<Option<(EntityId, Role)>> {
        Ok(self
            .member_grants_in_txn(txn, vault_id)?
            .into_iter()
            .find(|(_, grant)| {
                grant.member_ref == member
                    && grant.role != Role::Delegate
                    && !crate::federation::is_engine_controls_grant(grant)
            })
            .map(|(id, grant)| (id, grant.role)))
    }
    /// Judges `effect`, which `actor` asks, in the door's writer `txn` (2i;
    /// P24-SHAPE Q3 to Q6 = A): the act class from the typed change
    /// ([`member_move_act`] for a role change), `actor`'s membership role,
    /// and the digest of the exact change. A change the door could never
    /// apply is refused here, before any ask opens; the door's own checks
    /// run again when it applies.
    fn member_effect_check_in_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        actor: EntityId,
        effect: &MemberEffect,
        now: u64,
    ) -> Result<DoorCheckIn> {
        let (verb, act, member, from, to) = match effect.change {
            MemberChange::Add { member, role } => {
                let preset = self
                    .shared_vault_creation_in_txn(txn)?
                    .and_then(|row| row.preset);
                let role = role
                    .or_else(|| {
                        preset.map(crate::federation::SharedVaultPreset::default_member_role)
                    })
                    .unwrap_or(Role::Member);
                non_root(Some(role))?;
                if !crate::consent::person_is_live_in_txn(self, txn, &member)?
                    || self.member_role_in_txn(txn, vault_id, member)?.is_some()
                {
                    return Err(invalid());
                }
                (
                    MEMBERS_ADD_VERB,
                    ActClass::MemberAdd,
                    member,
                    None,
                    Some(role),
                )
            }
            MemberChange::Change { member, to } => {
                non_root(Some(to))?;
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner || from == to {
                    return Err(invalid());
                }
                let act = member_move_act(from, to);
                (MEMBERS_CHANGE_VERB, act, member, Some(from), Some(to))
            }
            MemberChange::Remove { member } => {
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner {
                    return Err(invalid());
                }
                let act = ActClass::MemberRemove;
                (MEMBERS_REMOVE_VERB, act, member, Some(from), None)
            }
        };
        let (grant, role) = self
            .member_grant_in_txn(txn, vault_id, actor)?
            .ok_or_else(invalid)?;
        let door_act = DoorAct {
            person: actor,
            role: RolePreset::of_grant_role(role),
            grant,
            verb,
            act,
            scope: CheckInScope::default(),
            effect_digest: member_effect_digest(vault_id, actor, verb, member, from, to),
        };
        crate::check_in::person_door_check_in_in_txn(
            self,
            txn,
            &door_act,
            effect.check_in_ref.as_ref(),
            now,
        )
    }
    /// Every member of shared vault `vault_id` at their role, delegates and
    /// guests aside: the roster a vault shape reads (ARCH-0070).
    pub(crate) fn shared_members_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<(EntityId, Role)>> {
        let mut members = std::collections::BTreeMap::new();
        for (_, grant) in self.member_grants_in_txn(txn, vault_id)? {
            if !matches!(grant.role, Role::Delegate | Role::Guest) {
                members.insert(grant.member_ref, grant.role);
            }
        }
        Ok(members.into_iter().collect())
    }
    fn apply_grant_ops(&self, txn: &mut heed::RwTxn<'_>, ops: Vec<BatchOp>) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
    /// Give `member` `role`: rewrite each of its membership grants in place,
    /// or mint one when it holds none. Default authority is resolved in this
    /// writer, as at creation.
    fn set_member_role_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        member: EntityId,
        role: Role,
        now: u64,
    ) -> Result<Vec<EntityId>> {
        // A base agent's grant is no membership: no role is set on it here.
        if crate::federation::holds_system_agent_grant(member) {
            return Err(invalid());
        }
        let mut ids: Vec<EntityId> = self
            .member_grants_in_txn(txn, vault_id)?
            .into_iter()
            .filter(|(_, grant)| grant.member_ref == member && grant.role != Role::Delegate)
            .map(|(id, _)| id)
            .collect();
        if ids.is_empty() {
            ids.push(self.store.clock.entity_id()?);
        }
        let mut grant = FederationGrant::new(
            FederationGrantScope::vault(vault_id),
            member,
            role,
            crate::federation::shared_creation::role_preset(role)?,
        );
        grant.authority_scope = self.grant_default_scope_in_txn(txn, role, vault_id, member)?;
        let data = encode_federation_grant_body(&grant)?;
        let ops = ids
            .iter()
            .map(|id| BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                row_version: None,
                data: data.clone(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            })
            .collect();
        self.apply_grant_ops(txn, ops)?;
        // FIX 3393: a member who becomes an Owner holds the own-device grant
        // pairing would have minted, so the devices they paired before it
        // reach residence at their next renewal.
        if role == Role::Owner {
            self.own_device_grant_for_holder_in_txn(txn, &member.to_hex(), None, now)?;
        }
        Ok(ids)
    }
    /// Delete the grants that conferred `member`'s standing: its own grants
    /// when `leaves`, and the delegate grants it minted either way. With
    /// `slips`, each deleted Grant an owner's signed mint made (a GitPush
    /// grant or an owner's agent grant) gets the host's signed withdrawal in
    /// this writer (FIX 7135), so the authority audit pairs its mint with a
    /// revoke this membership change made, never one an owner signed. The
    /// deleted ids, then each such Grant no host signed a withdrawal of,
    /// which the change's pending record names (FIX 12335).
    fn drop_member_grants_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        member: EntityId,
        leaves: bool,
        slips: Option<&HostSlipIssuer>,
        receipt: &str,
    ) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
        let dropped: Vec<(EntityId, bool)> = self
            .member_grants_in_txn(txn, vault_id)?
            .into_iter()
            .filter(|(_, grant)| {
                (leaves && grant.member_ref == member) || grant.delegated_by == Some(member)
            })
            .map(|(id, grant)| (id, grant.is_git_push() || grant.owner_agent))
            .collect();
        // Each withdrawal stays known here and reaches its peers, in this
        // writer (FIX-LIST 5107, 10772).
        let mut unsigned = Vec::new();
        for (id, signed_mint) in &dropped {
            crate::authority::withdraw_grant_row_in_txn(&self.store, txn, *id)?;
            if !*signed_mint {
                continue;
            }
            let signed = match slips {
                Some(issuer) => {
                    self.log_membership_grant_withdrawal_in_txn(txn, issuer, *id, receipt)?
                }
                None => false,
            };
            if !signed {
                unsigned.push(*id);
            }
        }
        let ids: Vec<EntityId> = dropped.into_iter().map(|(id, _)| id).collect();
        self.apply_grant_ops(
            txn,
            ids.iter().map(|id| BatchOp::Delete { id: *id }).collect(),
        )?;
        Ok((ids, unsigned))
    }
    /// Move `member` from `from` to `to` (`None` leaves the vault), dropping
    /// the delegates it can no longer parent, the own-device grant a former
    /// Owner held (FIX 3294) and, with `slips`, its slips.
    #[allow(clippy::too_many_arguments)]
    fn move_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        member: EntityId,
        from: Role,
        to: Option<Role>,
        slips: Option<&HostSlipIssuer>,
        receipt: &str,
        now: u64,
    ) -> Result<MemberMove> {
        // An agent's membership is a house mind's link to the org it runs
        // (HOUSE-BIND = A): it moves only through the house doors, which keep
        // its receipts, never through a person's membership move.
        if self.get_entity_type_in_txn(txn, &member)?
            == Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        {
            return Err(crate::error::Error::InvalidConfig(
                "a house mind's org role moves only through set_house_role and clear_house_role"
                    .into(),
            ));
        }
        let mut grants = Vec::new();
        if let Some(role) = to {
            grants.extend(self.set_member_role_in_txn(txn, vault_id, member, role, now)?);
        }
        let mut unsigned_withdrawals = Vec::new();
        if to.is_none_or(|role| !role.is_admin()) {
            let (dropped, unsigned) = self.drop_member_grants_in_txn(
                txn,
                vault_id,
                member,
                to.is_none(),
                slips,
                receipt,
            )?;
            grants.extend(dropped);
            unsigned_withdrawals = unsigned;
        }
        let mut retired_own_device = Vec::new();
        if crate::federation::own_device::own_device_grant_retires(from, to) {
            retired_own_device = self.retire_own_device_grants_in_txn(txn, member)?;
            grants.extend(retired_own_device.iter().copied());
        }
        let mut revoked_slips = match slips {
            Some(issuer) if move_revokes_slips(from, to) => {
                self.revoke_held_capability_slips_in_txn(txn, issuer, &member.to_hex(), None)?
            }
            _ => Vec::new(),
        };
        let mut detach = None;
        if to.is_none() {
            // A genuine leave: the departure is built here, after the
            // authorized transition, and consumed in this same writer. A
            // downgrade never arrives here; recovery's genuine leave does.
            // The seat's inquiry route ends with it (INQUIRE-1 PR 4).
            crate::inquiry::end_inquiry_route_in_txn(&self.store, txn, vault_id, member)?;
            let departure = SharedMemberDeparture::for_genuine_leave(&mut *txn, vault_id, member);
            let DetachOutcome {
                withdrawn,
                revoked_slips: detached_slips,
                report,
            } = self.detach_owner_connect_grants_in_txn(slips, departure)?;
            grants.extend(withdrawn);
            revoked_slips.extend(detached_slips);
            detach = report;
        }
        Ok(MemberMove {
            grants,
            retired_own_device,
            revoked_slips,
            detach,
            unsigned_withdrawals,
        })
    }

    /// Add one Owner without moving or revoking any existing Owner's grants.
    pub(super) fn add_owner_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        owners: &BTreeSet<EntityId>,
        starter: EntityId,
        owner: EntityId,
        now: u64,
    ) -> Result<MemberMove> {
        self.check_add_owner_in_txn(txn, owners, starter, owner)?;
        Ok(MemberMove {
            grants: self.set_member_role_in_txn(txn, vault_id, owner, Role::Owner, now)?,
            retired_own_device: Vec::new(),
            revoked_slips: Vec::new(),
            detach: None,
            unsigned_withdrawals: Vec::new(),
        })
    }

    /// The handover both Owner acts apply, revalidated at execution: `loser`
    /// stops being an Owner and keeps `keeps` (or leaves), `gainer` becomes
    /// one, and at least one live Owner remains.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn hand_over_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        owners: &BTreeSet<EntityId>,
        loser: EntityId,
        keeps: Option<Role>,
        gainer: Option<EntityId>,
        slips: Option<&HostSlipIssuer>,
        receipt: &str,
        now: u64,
    ) -> Result<MemberMove> {
        self.check_handover_in_txn(txn, owners.clone(), loser, keeps, gainer)?;
        let mut grants = Vec::new();
        if let Some(gainer) = gainer {
            grants.extend(self.set_member_role_in_txn(txn, vault_id, gainer, Role::Owner, now)?);
        }
        let mut moved = self.move_member_in_txn(
            txn,
            vault_id,
            loser,
            Role::Owner,
            keeps,
            slips,
            receipt,
            now,
        )?;
        grants.append(&mut moved.grants);
        moved.grants = grants;
        Ok(moved)
    }

    /// For an unexecuted export-first `remove_owner` act, the export of what
    /// its target could read: every axis their Owner grant reads, at the
    /// export verb. Taken before the act's writer opens, as the export door
    /// reads its own snapshot, and only once `executor` and the starter
    /// stand as live Owners holding the act's verb and its window has
    /// passed, so a refused caller builds nothing (FIX 3217); the writer
    /// checks them again.
    pub(super) fn removal_export(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
    ) -> Result<Option<(EntityId, Vec<ScopedRecord>)>> {
        let (target, mut reads) = {
            let txn = self.store.env.read_txn()?;
            let actor = executor.revalidate_person_in_txn(self, &txn)?;
            let Some(act) = self.pending_authority_act_in_txn(&txn, act_id)? else {
                return Ok(None);
            };
            if act.execution.is_some()
                || SharedActKind::parse(&act.act) != Some(SharedActKind::RemoveOwner)
            {
                return Ok(None);
            }
            let plan: RemoveOwnerPlan = decode(&act.payload)?;
            if !plan.export_first {
                return Ok(None);
            }
            super::check_vault(self, &txn, act.vault_id)?;
            let now = self.store.clock.now_recorded_at();
            self.act_executors_in_txn(&txn, &act, actor, now)?;
            if now < act.deadline {
                return Err(crate::error::Error::ConcurrentWrite(
                    "authority act not completed",
                ));
            }
            let target = EntityId::from_hex(&plan.target)?;
            let reads = self
                .vault_grants_in_txn(&txn, act.vault_id)?
                .into_iter()
                .find(|(_, grant)| grant.member_ref == target && grant.role == Role::Owner)
                .map(|(_, grant)| grant.authority_scope)
                .ok_or_else(invalid)?;
            (target, reads)
        };
        reads.verbs = ScopeAxis::All;
        let records = self.export_records_in_scope(&Scope::top(), &reads, &Scope::top())?;
        Ok(Some((target, records)))
    }

    /// One no-wait membership change: authorize `actor` (by `power`, or as
    /// themselves when `None`), apply it, then record its receipt and notices.
    fn change_shared_membership(
        &self,
        actor: &AuthenticatedOwner,
        vault_id: u64,
        power: Option<OrgAdminPower>,
        apply: impl FnOnce(&mut heed::RwTxn<'_>, EntityId, u64) -> Result<Effect>,
    ) -> Result<SharedActExecutionReceipt> {
        self.move_shared_member(actor, vault_id, power, |txn, actor, now, _receipt| {
            Ok((apply(txn, actor, now)?, None))
        })
    }

    /// [`Self::change_shared_membership`] for a change whose `apply` may
    /// leave a half no issuer signed: that half is kept pending under the
    /// receipt in the same writer and signed by this install's carrier when
    /// it can, and the receipt says which (FIX 12335).
    fn move_shared_member(
        &self,
        actor: &AuthenticatedOwner,
        vault_id: u64,
        power: Option<OrgAdminPower>,
        apply: impl FnOnce(
            &mut heed::RwTxn<'_>,
            EntityId,
            u64,
            &str,
        ) -> Result<(Effect, Option<UnsignedExecution>)>,
    ) -> Result<SharedActExecutionReceipt> {
        self.move_shared_member_for_ask(actor, vault_id, power, None, None, apply)
    }

    /// [`Self::move_shared_member`] applying a Steward's member ask `ask`
    /// when one is named (untangle 6.3d): in the same writer the ask closes
    /// as applied, and the receipt names its Steward as `proposer` beside
    /// the applier as `actor`.
    ///
    /// A door that names its typed `effect` is judged by check-in first, in
    /// this writer, after the authority checks (2i; P24-SHAPE Q3 and Q4 =
    /// A). Go: the change applies and the receipt records the decision. An
    /// act that waits commits the pending check-in alone, applies nothing
    /// and refuses with [`Error::CheckInPending`] naming it; a re-call that
    /// names it as `check_in_ref` spends it here once it is eligible.
    fn move_shared_member_for_ask(
        &self,
        actor: &AuthenticatedOwner,
        vault_id: u64,
        power: Option<OrgAdminPower>,
        effect: Option<MemberEffect>,
        ask: Option<&str>,
        apply: impl FnOnce(
            &mut heed::RwTxn<'_>,
            EntityId,
            u64,
            &str,
        ) -> Result<(Effect, Option<UnsignedExecution>)>,
    ) -> Result<SharedActExecutionReceipt> {
        let mut txn = self.store.env.write_txn()?;
        // Person tier; the named power is checked against the live roster.
        let actor_id = actor.revalidate_person_in_txn(self, &txn)?;
        super::check_vault(self, &txn, vault_id)?;
        if let Some(power) = power {
            self.authorize_shared_vault_write_in_txn(
                &txn,
                vault_id,
                &WriteActor::new(actor_id, EdgeActorClass::Human),
                &SharedVaultWrite::Admin(power),
            )?;
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let holders = self.live_act_holders(&txn, vault_id, now)?;
        // An ask stands while its Steward does: judged in this writer,
        // before the change.
        if let Some(ask) = ask {
            self.member_ask_steward_stands_in_txn(&txn, ask, vault_id, &holders)?;
        }
        let decision = match effect {
            Some(effect) => {
                match self
                    .member_effect_check_in_in_txn(&mut txn, vault_id, actor_id, &effect, now)?
                {
                    DoorCheckIn::Go(decision) => Some(decision),
                    DoorCheckIn::Wait(check_in) => {
                        txn.commit()?;
                        return Err(Error::CheckInPending(check_in.to_hex()));
                    }
                }
            }
            None => None,
        };
        let owners = live_owners(&holders, None);
        let id = self.store.clock.entity_id()?.to_hex();
        let (effect, unsigned) = apply(&mut txn, actor_id, now, &id)?;
        let record = match unsigned {
            Some(unsigned) => self.file_membership_execution_in_txn(
                &mut txn, vault_id, &id, actor_id, now, unsigned,
            )?,
            None => ChangeRecord::Unnamed,
        };
        let mut receipt = self.record_shared_change_in_txn(
            &mut txn, id, vault_id, None, actor_id, owners, effect, None, record, None, now,
        )?;
        if decision.is_some() {
            receipt.check_in = decision;
            self.store.vault_meta.put(
                &mut txn,
                &key(RECEIPT_PREFIX, &receipt.id),
                &encode(&receipt)?,
            )?;
        }
        if let Some(ask) = ask {
            self.apply_member_ask_in_txn(&mut txn, ask, actor_id, &mut receipt, now)?;
        }
        txn.commit()?;
        self.store.notify_credential_revocations();
        Ok(receipt)
    }

    /// One founding member's invitation (OF-531), in the initializer's
    /// writer: the vault's creator invites `member`, a live person, at
    /// `role`, Owner included (a co-owned vault, OF-150), and the receipt
    /// tells them through their own outcome notice. They join only on
    /// acceptance, as any invitee does.
    pub(crate) fn invite_founding_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        creator: EntityId,
        member: EntityId,
        role: Role,
        now: u64,
    ) -> Result<SharedActExecutionReceipt> {
        if role != Role::Owner {
            non_root(Some(role))?;
        }
        if !crate::consent::person_is_live_in_txn(self, txn, &member)? {
            return Err(invalid());
        }
        let effect =
            self.issue_invitation_in_txn(txn, vault_id, creator, member, role, true, now)?;
        let id = self.store.clock.entity_id()?.to_hex();
        self.record_shared_change_in_txn(
            txn,
            id,
            vault_id,
            None,
            creator,
            BTreeSet::from([creator]),
            effect,
            None,
            ChangeRecord::Unnamed,
            None,
            now,
        )
    }

    /// Invite `member`, a live person with no membership here, at a non-root
    /// role, or the creation preset's default member role when `None`. No
    /// grant is written until they accept ([`Vault::accept_shared_invitation`]);
    /// the receipt's `MemberInvited` names the invitation. The `add_member`
    /// power only creates or withdraws invitations: it names no key, and the
    /// invitee binds their own ([`Vault::mint_invitation_slip`], FIX 8745).
    pub fn add_shared_member(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Option<Role>,
    ) -> Result<SharedActExecutionReceipt> {
        self.add_shared_member_with_check_in(admin, vault_id, member, role, None)
    }
    /// [`Self::add_shared_member`], spending `check_in_ref`, the settled
    /// check-in an earlier call's `CHECK_IN_PENDING` named, when the act
    /// waits on one (2i).
    ///
    /// # Errors
    /// As [`Self::add_shared_member`]; [`Error::CheckInPending`] when the
    /// act waits.
    pub fn add_shared_member_with_check_in(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Option<Role>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        self.add_shared_member_for_ask(admin, vault_id, member, role, None, check_in_ref)
    }
    pub(super) fn add_shared_member_for_ask(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Option<Role>,
        ask: Option<&str>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        self.move_shared_member_for_ask(
            admin,
            vault_id,
            Some(OrgAdminPower::AddMember),
            Some(MemberEffect {
                change: MemberChange::Add { member, role },
                check_in_ref,
            }),
            ask,
            |txn, inviter, now, _receipt| {
                let preset = self
                    .shared_vault_creation_in_txn(txn)?
                    .and_then(|row| row.preset);
                let role = role
                    .or_else(|| {
                        preset.map(crate::federation::SharedVaultPreset::default_member_role)
                    })
                    .unwrap_or(Role::Member);
                non_root(Some(role))?;
                self.reserved_role_given_by_owner_in_txn(txn, vault_id, inviter, role)?;
                if !crate::consent::person_is_live_in_txn(self, txn, &member)?
                    || self.member_role_in_txn(txn, vault_id, member)?.is_some()
                {
                    return Err(invalid());
                }
                let effect =
                    self.issue_invitation_in_txn(txn, vault_id, inviter, member, role, false, now)?;
                Ok((effect, None))
            },
        )
    }
    /// Assign `member` another non-root role. An Owner's role changes only
    /// through the `transfer_ownership` and `remove_owner` acts.
    pub fn change_shared_member_role(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Role,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecutionReceipt> {
        self.change_shared_member_role_with_check_in(admin, vault_id, member, role, slips, None)
    }
    /// [`Self::change_shared_member_role`], spending `check_in_ref` when the
    /// act waits on one (2i).
    ///
    /// # Errors
    /// As [`Self::change_shared_member_role`]; [`Error::CheckInPending`]
    /// when the act waits.
    pub fn change_shared_member_role_with_check_in(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Role,
        slips: Option<&HostSlipIssuer>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        self.change_shared_member_role_for_ask(
            admin,
            vault_id,
            member,
            role,
            slips,
            None,
            check_in_ref,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "one role change: the applier's proof, the vault, the member, the role, the slip issuer, the Steward's ask and the check-in it spends"
    )]
    pub(super) fn change_shared_member_role_for_ask(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Role,
        slips: Option<&HostSlipIssuer>,
        ask: Option<&str>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        let own_issuer = self.membership_issuer(slips);
        self.move_shared_member_for_ask(
            admin,
            vault_id,
            Some(OrgAdminPower::AssignRole),
            Some(MemberEffect {
                change: MemberChange::Change { member, to: role },
                check_in_ref,
            }),
            ask,
            |txn, giver, now, receipt| {
                non_root(Some(role))?;
                self.reserved_role_given_by_owner_in_txn(txn, vault_id, giver, role)?;
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner || from == role {
                    return Err(invalid());
                }
                let own_issuer = self.executing_host_issuer_in_txn(txn, own_issuer)?;
                let slips = slips.or(own_issuer.as_ref());
                let MemberMove {
                    grants,
                    revoked_slips,
                    detach,
                    unsigned_withdrawals,
                    ..
                } = self.move_member_in_txn(
                    txn,
                    vault_id,
                    member,
                    from,
                    Some(role),
                    slips,
                    receipt,
                    now,
                )?;
                let effect = Effect {
                    change: SharedVaultChange::MemberRoleChanged {
                        member: member.to_hex(),
                        from,
                        to: role,
                    },
                    grants,
                    revoked_slips,
                    detach,
                    notify: BTreeSet::from([member]),
                };
                Ok((
                    effect,
                    member_execution(
                        MembershipExecutionCause::AssignRole,
                        member,
                        unsigned_withdrawals,
                    ),
                ))
            },
        )
    }
    /// Remove `member`, who is not an Owner, from the vault at once.
    pub fn remove_shared_member(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecutionReceipt> {
        self.remove_shared_member_with_check_in(admin, vault_id, member, slips, None)
    }
    /// [`Self::remove_shared_member`], spending `check_in_ref` when the act
    /// waits on one (2i): a Deputy's remove always asks an Owner.
    ///
    /// # Errors
    /// As [`Self::remove_shared_member`]; [`Error::CheckInPending`] when the
    /// act waits.
    pub fn remove_shared_member_with_check_in(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        slips: Option<&HostSlipIssuer>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        self.remove_shared_member_for_ask(admin, vault_id, member, slips, None, check_in_ref)
    }
    pub(super) fn remove_shared_member_for_ask(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        slips: Option<&HostSlipIssuer>,
        ask: Option<&str>,
        check_in_ref: Option<EntityId>,
    ) -> Result<SharedActExecutionReceipt> {
        let own_issuer = self.membership_issuer(slips);
        self.move_shared_member_for_ask(
            admin,
            vault_id,
            Some(OrgAdminPower::RemoveMember),
            Some(MemberEffect {
                change: MemberChange::Remove { member },
                check_in_ref,
            }),
            ask,
            |txn, _, now, receipt| {
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner {
                    return Err(invalid());
                }
                let own_issuer = self.executing_host_issuer_in_txn(txn, own_issuer)?;
                let slips = slips.or(own_issuer.as_ref());
                let MemberMove {
                    grants,
                    revoked_slips,
                    detach,
                    unsigned_withdrawals,
                    ..
                } = self
                    .move_member_in_txn(txn, vault_id, member, from, None, slips, receipt, now)?;
                let effect = Effect {
                    change: SharedVaultChange::MemberRemoved {
                        member: member.to_hex(),
                    },
                    grants,
                    revoked_slips,
                    detach,
                    notify: BTreeSet::from([member]),
                };
                Ok((
                    effect,
                    member_execution(
                        MembershipExecutionCause::RemoveMember,
                        member,
                        unsigned_withdrawals,
                    ),
                ))
            },
        )
    }
    /// Proof-of-control recovery (ARCH-0043): a shared vault with no live
    /// Owner left takes `claimant` as its Owner, on `authorization` (FIX
    /// 1812): a managed vault's attested account owner, a self-hosted
    /// vault's live host root, or a stopped self-hosted vault's own host,
    /// judged again in this writer. The host signs the handover with
    /// `issuer`. The engine checks what it holds: no live Owner remains,
    /// `from` still holds the Owner role here, and `claimant` is a live
    /// person. `from` leaves with its slips revoked, the claimant takes the
    /// Owner role, and the host's `OwnerHandover` (cause `proof_of_control`)
    /// lands in the authority log in the same writer as the receipt and its
    /// notices, keeping the BLAKE3 of the authorization's note (never the
    /// note), so the log records what the recovery rested on.
    pub fn recover_shared_owner_authorized(
        &self,
        issuer: &HostSlipIssuer,
        vault_id: u64,
        from: EntityId,
        claimant: EntityId,
        authorization: &OwnerRecoveryAuthorization,
    ) -> Result<SharedActExecutionReceipt> {
        let proof = Some(authorization.note());
        let authorizer = authorization.authorizer();
        let mut txn = self.store.env.write_txn()?;
        super::check_vault(self, &txn, vault_id)?;
        authorization.holds_in(self, &txn)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let owners = live_owners(&self.live_act_holders(&txn, vault_id, now)?, None);
        if !owners.is_empty()
            || claimant == from
            || !crate::consent::person_is_live_in_txn(self, &txn, &claimant)?
            || self.member_role_in_txn(&txn, vault_id, from)? != Some(Role::Owner)
        {
            return Err(invalid());
        }
        let id = self.store.clock.entity_id()?.to_hex();
        let mut grants =
            self.set_member_role_in_txn(&mut txn, vault_id, claimant, Role::Owner, now)?;
        let mut moved = self.move_member_in_txn(
            &mut txn,
            vault_id,
            from,
            Role::Owner,
            None,
            Some(issuer),
            &id,
            now,
        )?;
        grants.append(&mut moved.grants);
        moved.grants = grants;
        let (affected_grants, retired_own_device_grants) = moved.handover_ids();
        let MemberMove {
            grants,
            revoked_slips,
            detach,
            ..
        } = moved;
        let authority_entry = self.append_owner_handover_in_txn(
            &mut txn,
            issuer,
            OwnerHandover {
                shared_vault: vault_id,
                cause: OwnerHandoverCause::ProofOfControl,
                from,
                to: Some(claimant),
                from_keeps: None,
                act: None,
                proof: proof.map(|digest| crate::entity_id::bytes_to_hex_lower(&digest)),
                authorizer,
                receipt: id.clone(),
                affected_grants,
                retired_own_device_grants,
            },
        )?;
        let receipt = self.record_shared_change_in_txn(
            &mut txn,
            id,
            vault_id,
            None,
            claimant,
            owners,
            Effect {
                change: SharedVaultChange::OwnerRecovered {
                    from: from.to_hex(),
                    to: claimant.to_hex(),
                },
                grants,
                revoked_slips,
                detach,
                notify: BTreeSet::from([from]),
            },
            None,
            ChangeRecord::Signed(authority_entry),
            authorizer,
            now,
        )?;
        txn.commit()?;
        self.store.notify_credential_revocations();
        Ok(receipt)
    }

    /// Leave the vault. Leave covers access only: the personal vault goes
    /// with the person and company-scoped claims stay. An Owner leaves
    /// through the `remove_owner` act, naming a successor when last.
    pub fn leave_shared_vault(
        &self,
        member: &AuthenticatedOwner,
        vault_id: u64,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<SharedActExecutionReceipt> {
        let own_issuer = self.membership_issuer(slips);
        self.move_shared_member(member, vault_id, None, |txn, actor, now, receipt| {
            let from = self
                .member_role_in_txn(txn, vault_id, actor)?
                .ok_or_else(invalid)?;
            if from == Role::Owner {
                return Err(invalid());
            }
            let own_issuer = self.executing_host_issuer_in_txn(txn, own_issuer)?;
            let slips = slips.or(own_issuer.as_ref());
            let MemberMove {
                grants,
                revoked_slips,
                detach,
                unsigned_withdrawals,
                ..
            } = self.move_member_in_txn(txn, vault_id, actor, from, None, slips, receipt, now)?;
            let effect = Effect {
                change: SharedVaultChange::MemberLeft {
                    member: actor.to_hex(),
                },
                grants,
                revoked_slips,
                detach,
                notify: BTreeSet::new(),
            };
            Ok((
                effect,
                member_execution(MembershipExecutionCause::Leave, actor, unsigned_withdrawals),
            ))
        })
    }

    /// This install's own host issuer for a membership change given no
    /// `slips` (FIX 5898), read before the change's writer opens; `None`
    /// with `slips`. With no `slips`, this install's key is loaded too, so
    /// the writer can sign the record of a change no issuer signs (FIX
    /// 12335).
    pub(super) fn membership_issuer(
        &self,
        slips: Option<&HostSlipIssuer>,
    ) -> Option<HostSlipIssuer> {
        if slips.is_some() {
            return None;
        }
        self.load_membership_carrier();
        self.load_host_slip_issuer().ok()
    }
}

/// A member change's half no issuer signed: the signed-mint Grants it
/// deleted with no signed withdrawal; `None` when there are none.
fn member_execution(
    cause: MembershipExecutionCause,
    member: EntityId,
    unsigned_withdrawals: Vec<EntityId>,
) -> Option<UnsignedExecution> {
    (!unsigned_withdrawals.is_empty()).then_some(UnsignedExecution {
        cause,
        member,
        act: None,
        withdrawn_grants: unsigned_withdrawals,
        handover: None,
    })
}

/// The saved verbs whose typed effects the membership doors judge by
/// check-in. An applied Steward ask names the verb of the change it applies,
/// so a direct call and an applied ask over the same effect are one ask.
const MEMBERS_ADD_VERB: &str = "vault.members.add";
const MEMBERS_CHANGE_VERB: &str = "vault.members.change";
const MEMBERS_REMOVE_VERB: &str = "vault.members.remove";

/// A membership door's typed effect, which check-in judges in the door's
/// writer before it applies (P24-SHAPE Q3 to Q6 = A).
pub(super) struct MemberEffect {
    pub(super) change: MemberChange,
    /// The settled check-in a re-call names: the act spends it.
    pub(super) check_in_ref: Option<EntityId>,
}

/// One member change a door runs.
#[derive(Clone, Copy)]
pub(super) enum MemberChange {
    /// Invite `member` at `role`, or at the preset's default member role.
    Add {
        member: EntityId,
        role: Option<Role>,
    },
    /// Move `member` to `to`.
    Change { member: EntityId, to: Role },
    /// Remove `member`.
    Remove { member: EntityId },
}

/// The act class of moving a member from `from` to `to` (P24-SHAPE Q5 = A):
/// roles have no order, so the table is explicit. Member to Admin raises
/// (`member_add`); every other move, Admin to Member and any move into or
/// out of Steward among them, is `member_remove`, which a Deputy always
/// asks.
const fn member_move_act(from: Role, to: Role) -> ActClass {
    match (from, to) {
        (Role::Member, Role::Admin) => ActClass::MemberAdd,
        _ => ActClass::MemberRemove,
    }
}

/// The digest of one member change: the vault, the actor, the verb, the
/// member and the roles it moves from and to. Another target or role is
/// another effect, so another ask.
fn member_effect_digest(
    vault_id: u64,
    actor: EntityId,
    verb: &str,
    member: EntityId,
    from: Option<Role>,
    to: Option<Role>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in membership effect v1");
    hasher.update(&vault_id.to_be_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(verb.as_bytes());
    hasher.update(&[0]);
    hasher.update(member.as_bytes());
    for role in [from, to] {
        hasher.update(role.map_or("", Role::as_str).as_bytes());
        hasher.update(&[0]);
    }
    *hasher.finalize().as_bytes()
}
