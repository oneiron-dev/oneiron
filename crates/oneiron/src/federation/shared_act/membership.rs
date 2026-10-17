//! Membership effects: the Owner handover the two Owner acts apply, and the
//! ordinary member changes an Admin's named power makes at once. Each rewrites
//! or deletes FEDERATION_GRANT records in the caller's writer and, given the
//! host's slip issuer, revokes the capability slips of whoever lost a role.
//! Removal is access revocation, never a group rekey. A new member joins only
//! by accepting an invitation (`invitation`).
mod invitation;

pub use invitation::{SHARED_INVITATION_TTL_SECS, SharedInvitation, SharedInvitationState};

use super::{
    Effect, RemoveOwnerPlan, SharedActExecutionReceipt, SharedActKind, SharedVaultChange, decode,
    invalid, live_owners, non_root,
};
use crate::authority::{CapabilitySlip, HostSlipIssuer, OwnerHandover, OwnerHandoverCause};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::record_scope::ScopedRecord;
use crate::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, OrgAdminPower, Scope,
    ScopeAxis, SharedVaultWrite, decode_federation_grant_body, encode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

/// Higher ranks hold more; a change to a lower rank revokes held slips.
const fn rank(role: Role) -> u8 {
    match role {
        Role::Owner => 4,
        Role::Admin => 3,
        Role::Member => 2,
        Role::Viewer | Role::Auditor => 1,
        Role::Delegate | Role::Guest => 0,
    }
}

impl Vault {
    /// Every live grant record over `vault_id`, delegates included.
    pub(super) fn vault_grants_in_txn(
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
    /// `member`'s one membership role in the vault, delegate grants aside.
    fn member_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        member: EntityId,
    ) -> Result<Option<Role>> {
        let mut roles = self
            .vault_grants_in_txn(txn, vault_id)?
            .into_iter()
            .filter(|(_, grant)| grant.member_ref == member && grant.role != Role::Delegate)
            .map(|(_, grant)| grant.role);
        let role = roles.next();
        if roles.any(|other| Some(other) != role) {
            return Err(invalid());
        }
        Ok(role)
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
        let mut ids: Vec<EntityId> = self
            .vault_grants_in_txn(txn, vault_id)?
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
                data: data.clone(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            })
            .collect();
        self.apply_grant_ops(txn, ops)?;
        Ok(ids)
    }
    /// Delete the grants that conferred `member`'s standing: its own grants
    /// when `leaves`, and the delegate grants it minted either way.
    fn drop_member_grants_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        member: EntityId,
        leaves: bool,
    ) -> Result<Vec<EntityId>> {
        let ids: Vec<EntityId> = self
            .vault_grants_in_txn(txn, vault_id)?
            .into_iter()
            .filter(|(_, grant)| {
                (leaves && grant.member_ref == member) || grant.delegated_by == Some(member)
            })
            .map(|(id, _)| id)
            .collect();
        self.apply_grant_ops(
            txn,
            ids.iter().map(|id| BatchOp::Delete { id: *id }).collect(),
        )?;
        Ok(ids)
    }
    /// Move `member` from `from` to `to` (`None` leaves the vault), dropping
    /// the delegates it can no longer parent and, with `slips`, its slips.
    #[allow(clippy::too_many_arguments)]
    fn move_member_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        member: EntityId,
        from: Role,
        to: Option<Role>,
        slips: Option<&HostSlipIssuer>,
        now: u64,
    ) -> Result<(Vec<EntityId>, Vec<[u8; 32]>)> {
        let mut grants = Vec::new();
        if let Some(role) = to {
            grants.extend(self.set_member_role_in_txn(txn, vault_id, member, role, now)?);
        }
        if to.is_none_or(|role| !role.is_admin()) {
            grants.extend(self.drop_member_grants_in_txn(txn, vault_id, member, to.is_none())?);
        }
        let revoked = match slips {
            Some(issuer) if to.is_none_or(|role| rank(role) < rank(from)) => {
                self.revoke_held_capability_slips_in_txn(txn, issuer, &member.to_hex(), None)?
            }
            _ => Vec::new(),
        };
        Ok((grants, revoked))
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
        now: u64,
    ) -> Result<(Vec<EntityId>, Vec<[u8; 32]>)> {
        self.check_handover_in_txn(txn, owners.clone(), loser, keeps, gainer)?;
        let mut grants = Vec::new();
        if let Some(gainer) = gainer {
            grants.extend(self.set_member_role_in_txn(txn, vault_id, gainer, Role::Owner, now)?);
        }
        let (moved, revoked) =
            self.move_member_in_txn(txn, vault_id, loser, Role::Owner, keeps, slips, now)?;
        grants.extend(moved);
        Ok((grants, revoked))
    }

    /// For an unexecuted export-first `remove_owner` act, the export of what
    /// its target could read: every axis their Owner grant reads, at the
    /// export verb. Taken before the act's writer opens, as the export door
    /// reads its own snapshot.
    pub(super) fn removal_export(
        &self,
        act_id: &str,
    ) -> Result<Option<(EntityId, Vec<ScopedRecord>)>> {
        let (target, mut reads) = {
            let txn = self.store.env.read_txn()?;
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
        let owners = live_owners(&self.live_act_holders(&txn, vault_id, now)?, None);
        let effect = apply(&mut txn, actor_id, now)?;
        let id = self.store.clock.entity_id()?.to_hex();
        let receipt = self.record_shared_change_in_txn(
            &mut txn, id, vault_id, None, actor_id, owners, effect, None, None, now,
        )?;
        txn.commit()?;
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
        let (effect, _) =
            self.issue_invitation_in_txn(txn, vault_id, creator, member, role, true, None, now)?;
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
            None,
            now,
        )
    }

    /// Invite `member`, a live person with no membership here, at a non-root
    /// role, or the creation preset's default member role when `None`. No
    /// grant is written until they accept ([`Vault::accept_shared_invitation`]);
    /// the receipt's `MemberInvited` names the invitation.
    pub fn add_shared_member(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Option<Role>,
    ) -> Result<SharedActExecutionReceipt> {
        self.invite_shared_member(admin, vault_id, member, role, None)
            .map(|(receipt, _)| receipt)
    }

    /// [`Vault::add_shared_member`], and with `credential` (the host's slip
    /// issuer and the public key `member` generated on their own device) the
    /// invitee's own slip for this invitation (FIX 1925), minted in the same
    /// writer: it reaches only the invitation's list, accept and decline, and
    /// stands while the invitation is pending.
    pub fn invite_shared_member(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        role: Option<Role>,
        credential: Option<(&HostSlipIssuer, [u8; 32])>,
    ) -> Result<(SharedActExecutionReceipt, Option<CapabilitySlip>)> {
        let mut slip = None;
        let receipt = self.change_shared_membership(
            admin,
            vault_id,
            Some(OrgAdminPower::AddMember),
            |txn, inviter, now| {
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
                let (effect, minted) = self.issue_invitation_in_txn(
                    txn, vault_id, inviter, member, role, false, credential, now,
                )?;
                slip = minted;
                Ok(effect)
            },
        )?;
        Ok((receipt, slip))
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
        self.change_shared_membership(
            admin,
            vault_id,
            Some(OrgAdminPower::AssignRole),
            |txn, _, now| {
                non_root(Some(role))?;
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner || from == role {
                    return Err(invalid());
                }
                let (grants, revoked_slips) =
                    self.move_member_in_txn(txn, vault_id, member, from, Some(role), slips, now)?;
                Ok(Effect {
                    change: SharedVaultChange::MemberRoleChanged {
                        member: member.to_hex(),
                        from,
                        to: role,
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from([member]),
                })
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
        self.change_shared_membership(
            admin,
            vault_id,
            Some(OrgAdminPower::RemoveMember),
            |txn, _, now| {
                let from = self
                    .member_role_in_txn(txn, vault_id, member)?
                    .ok_or_else(invalid)?;
                if from == Role::Owner {
                    return Err(invalid());
                }
                let (grants, revoked_slips) =
                    self.move_member_in_txn(txn, vault_id, member, from, None, slips, now)?;
                Ok(Effect {
                    change: SharedVaultChange::MemberRemoved {
                        member: member.to_hex(),
                    },
                    grants,
                    revoked_slips,
                    notify: BTreeSet::from([member]),
                })
            },
        )
    }
    /// Proof-of-control recovery (ARCH-0043): a shared vault with no live
    /// Owner left takes `claimant` as its Owner. The host judges, outside the
    /// engine, the claimant's proof that they control the organization owning
    /// the vault, and signs the handover with `issuer`. The engine checks
    /// what it holds: no live Owner remains, `from` still holds the Owner
    /// role here, and `claimant` is a live person. `from` leaves with its
    /// slips revoked, the claimant takes the Owner role, and the host's
    /// `OwnerHandover` (cause `proof_of_control`) lands in the authority log
    /// in the same writer as the receipt and its notices.
    pub fn recover_shared_owner(
        &self,
        issuer: &HostSlipIssuer,
        vault_id: u64,
        from: EntityId,
        claimant: EntityId,
    ) -> Result<SharedActExecutionReceipt> {
        self.recover_shared_owner_with_proof(issuer, vault_id, from, claimant, None)
    }
    /// [`Vault::recover_shared_owner`], keeping with the signed handover the
    /// BLAKE3 of the proof of organization control the host judged (`proof`,
    /// never the proof itself), so the authority log records what the
    /// recovery rested on.
    pub fn recover_shared_owner_with_proof(
        &self,
        issuer: &HostSlipIssuer,
        vault_id: u64,
        from: EntityId,
        claimant: EntityId,
        proof: Option<[u8; 32]>,
    ) -> Result<SharedActExecutionReceipt> {
        let mut txn = self.store.env.write_txn()?;
        super::check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let owners = live_owners(&self.live_act_holders(&txn, vault_id, now)?, None);
        if !owners.is_empty()
            || claimant == from
            || !crate::consent::person_is_live_in_txn(self, &txn, &claimant)?
            || self.member_role_in_txn(&txn, vault_id, from)? != Some(Role::Owner)
        {
            return Err(invalid());
        }
        let mut grants =
            self.set_member_role_in_txn(&mut txn, vault_id, claimant, Role::Owner, now)?;
        let (moved, revoked_slips) = self.move_member_in_txn(
            &mut txn,
            vault_id,
            from,
            Role::Owner,
            None,
            Some(issuer),
            now,
        )?;
        grants.extend(moved);
        let id = self.store.clock.entity_id()?.to_hex();
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
                receipt: id.clone(),
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
                notify: BTreeSet::from([from]),
            },
            None,
            Some(authority_entry),
            now,
        )?;
        txn.commit()?;
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
        self.change_shared_membership(member, vault_id, None, |txn, actor, now| {
            let from = self
                .member_role_in_txn(txn, vault_id, actor)?
                .ok_or_else(invalid)?;
            if from == Role::Owner {
                return Err(invalid());
            }
            let (grants, revoked_slips) =
                self.move_member_in_txn(txn, vault_id, actor, from, None, slips, now)?;
            Ok(Effect {
                change: SharedVaultChange::MemberLeft {
                    member: actor.to_hex(),
                },
                grants,
                revoked_slips,
                notify: BTreeSet::new(),
            })
        })
    }
}
