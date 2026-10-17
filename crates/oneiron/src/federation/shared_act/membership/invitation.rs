//! Invitee acceptance (CROSS-ARCH-0024: "Only an accepted, vault-specific
//! invitation" grants membership). An Admin's `add_member` power issues an
//! invitation for one live person at one non-root role in this shared vault;
//! the grant is written only when that person accepts it with their own
//! person-tier proof, before it expires and while its issuer still holds the
//! power. A declined, withdrawn or expired invitation grants nothing, and an
//! accepted one is spent. Given the public key the invitee generated on their
//! own device, the invitation's writer also mints their own human slip for
//! it (FIX 1925, `authority::invitee_slip`): good only at this invitation's
//! list, accept and decline doors, and only while it is pending.
use super::super::{
    Effect, SharedActExecutionReceipt, SharedVaultChange, check_vault, decode, encode, invalid,
    key, non_root,
};
use crate::authority::{CapabilitySlip, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::{FederationGrantRole as Role, OrgAdminPower, SharedVaultWrite};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

const INVITATION_PREFIX: &[u8] = b"shared-vault:invitation:v1:";
/// How long an invitation stays open on the store clock.
pub const SHARED_INVITATION_TTL_SECS: u64 = 14 * 24 * 60 * 60;

/// Where an invitation stands. Only `Pending` before `expires_at` admits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedInvitationState {
    Pending,
    Accepted {
        at: u64,
    },
    Declined {
        at: u64,
    },
    /// An `add_member` holder (`by`) took it back.
    Withdrawn {
        by: String,
        at: u64,
    },
}

/// One invitation of one person into this shared vault at one role.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitation {
    pub id: String,
    pub vault_id: u64,
    /// The PERSON whose `add_member` power issued it, hex.
    pub inviter: String,
    /// The PERSON it admits, hex.
    pub invitee: String,
    pub role: Role,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: SharedInvitationState,
    /// Minted by `initialize_shared_vault` for a founding member, in the
    /// creation writer: only such an invitation may name the Owner role.
    pub founding: bool,
}

/// Key: hex32 (invitee) ":" hex32 (invitation id), so a person reads their
/// own invitations by prefix.
fn invitation_key(invitee: &EntityId, id: &str) -> Vec<u8> {
    key(INVITATION_PREFIX, &format!("{}:{id}", invitee.to_hex()))
}

impl Vault {
    fn invitation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        invitee: EntityId,
        id: &str,
    ) -> Result<SharedInvitation> {
        let id = EntityId::from_hex(id)?.to_hex();
        let raw = self
            .store
            .vault_meta
            .get(txn, &invitation_key(&invitee, &id))?
            .ok_or_else(invalid)?;
        decode(&raw)
    }
    fn put_invitation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        invitation: &SharedInvitation,
    ) -> Result<()> {
        let invitee = EntityId::from_hex(&invitation.invitee)?;
        self.store.vault_meta.put(
            txn,
            &invitation_key(&invitee, &invitation.id),
            &encode(invitation)?,
        )?;
        Ok(())
    }
    fn invitations_of_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        invitee: EntityId,
        vault_id: u64,
    ) -> Result<Vec<SharedInvitation>> {
        let prefix = key(INVITATION_PREFIX, &format!("{}:", invitee.to_hex()));
        let mut invitations = Vec::new();
        for row in self.store.vault_meta.prefix_iter(txn, &prefix)? {
            let (_, raw) = row?;
            let invitation: SharedInvitation = decode(&raw)?;
            if invitation.vault_id == vault_id {
                invitations.push(invitation);
            }
        }
        Ok(invitations)
    }

    /// Whether `invitee`'s invitation `id` is pending and unexpired at `now`:
    /// an invitation-bound slip (FIX 1925) stands only while it is.
    pub(crate) fn shared_invitation_pending_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        invitee: EntityId,
        id: &str,
        now: u64,
    ) -> bool {
        self.invitation_in_txn(txn, invitee, id)
            .is_ok_and(|open| open.state == SharedInvitationState::Pending && now < open.expires_at)
    }

    /// The `add_member` effect: one pending invitation of `member` at `role`,
    /// refused while another of theirs to this vault is still open. `founding`
    /// marks the creation writer's own invitations. With `credential`, the
    /// host's issuer and the public key `member` generated on their own
    /// device, it also answers their own slip for this invitation, which ends
    /// when the invitation does.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_invitation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        inviter: EntityId,
        member: EntityId,
        role: Role,
        founding: bool,
        credential: Option<(&HostSlipIssuer, [u8; 32])>,
        now: u64,
    ) -> Result<(Effect, Option<CapabilitySlip>)> {
        if self
            .invitations_of_in_txn(txn, member, vault_id)?
            .iter()
            .any(|open| open.state == SharedInvitationState::Pending && now < open.expires_at)
        {
            return Err(invalid());
        }
        let invitation = SharedInvitation {
            id: self.store.clock.entity_id()?.to_hex(),
            vault_id,
            inviter: inviter.to_hex(),
            invitee: member.to_hex(),
            role,
            issued_at: now,
            expires_at: now
                .checked_add(SHARED_INVITATION_TTL_SECS)
                .ok_or_else(invalid)?,
            state: SharedInvitationState::Pending,
            founding,
        };
        self.put_invitation_in_txn(txn, &invitation)?;
        let slip = credential
            .map(|(issuer, holder_key)| {
                self.mint_invitee_slip_in_txn(
                    txn,
                    issuer,
                    member,
                    &invitation.id,
                    holder_key,
                    invitation.expires_at,
                )
            })
            .transpose()?;
        let effect = Effect {
            change: SharedVaultChange::MemberInvited {
                invitation: invitation.id,
                member: invitation.invitee,
                role,
                expires_at: invitation.expires_at,
            },
            grants: Vec::new(),
            revoked_slips: Vec::new(),
            notify: BTreeSet::from([member]),
        };
        Ok((effect, slip))
    }

    /// The invitee accepts `invitation_id` with their own person-tier proof:
    /// while it is pending and unexpired, they hold no membership here, and
    /// its issuer still holds the `add_member` power, the grant at its role
    /// is written, the invitation is spent, and the receipt goes to the
    /// Owners, the invitee and the issuer.
    pub fn accept_shared_invitation(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        self.change_shared_membership(invitee, vault_id, None, |txn, actor, now| {
            let mut invitation = self.invitation_in_txn(txn, actor, invitation_id)?;
            let inviter = EntityId::from_hex(&invitation.inviter)?;
            if invitation.vault_id != vault_id
                || invitation.state != SharedInvitationState::Pending
                || now >= invitation.expires_at
                || self.member_role_in_txn(txn, vault_id, actor)?.is_some()
            {
                return Err(invalid());
            }
            // Only a founding invitation may admit an Owner (OF-150's
            // co-owned vault); until it is accepted the creator is the only
            // one. Any other invitation admits no root role.
            if !(invitation.founding && invitation.role == Role::Owner) {
                non_root(Some(invitation.role))?;
            }
            self.authorize_shared_vault_write_in_txn(
                txn,
                vault_id,
                &WriteActor::new(inviter, EdgeActorClass::Human),
                &SharedVaultWrite::Admin(OrgAdminPower::AddMember),
            )?;
            let grants = self.set_member_role_in_txn(txn, vault_id, actor, invitation.role, now)?;
            invitation.state = SharedInvitationState::Accepted { at: now };
            self.put_invitation_in_txn(txn, &invitation)?;
            Ok(Effect {
                change: SharedVaultChange::InvitationAccepted {
                    invitation: invitation.id,
                    member: invitation.invitee,
                    role: invitation.role,
                },
                grants,
                revoked_slips: Vec::new(),
                notify: BTreeSet::from([inviter]),
            })
        })
    }

    /// The invitee declines a pending invitation; nothing is granted.
    pub fn decline_shared_invitation(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        self.change_shared_membership(invitee, vault_id, None, |txn, actor, now| {
            let mut invitation = self.invitation_in_txn(txn, actor, invitation_id)?;
            if invitation.vault_id != vault_id || invitation.state != SharedInvitationState::Pending
            {
                return Err(invalid());
            }
            let inviter = EntityId::from_hex(&invitation.inviter)?;
            invitation.state = SharedInvitationState::Declined { at: now };
            self.put_invitation_in_txn(txn, &invitation)?;
            Ok(Effect {
                change: SharedVaultChange::InvitationDeclined {
                    invitation: invitation.id,
                    member: invitation.invitee,
                },
                grants: Vec::new(),
                revoked_slips: Vec::new(),
                notify: BTreeSet::from([inviter]),
            })
        })
    }

    /// A live `add_member` holder takes back `invitee`'s pending invitation.
    pub fn withdraw_shared_invitation(
        &self,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        invitee: EntityId,
        invitation_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        self.change_shared_membership(
            admin,
            vault_id,
            Some(OrgAdminPower::AddMember),
            |txn, actor, now| {
                let mut invitation = self.invitation_in_txn(txn, invitee, invitation_id)?;
                if invitation.vault_id != vault_id
                    || invitation.state != SharedInvitationState::Pending
                {
                    return Err(invalid());
                }
                invitation.state = SharedInvitationState::Withdrawn {
                    by: actor.to_hex(),
                    at: now,
                };
                self.put_invitation_in_txn(txn, &invitation)?;
                Ok(Effect {
                    change: SharedVaultChange::InvitationWithdrawn {
                        invitation: invitation.id,
                        member: invitation.invitee,
                    },
                    grants: Vec::new(),
                    revoked_slips: Vec::new(),
                    notify: BTreeSet::from([invitee]),
                })
            },
        )
    }

    /// The reader's own pending, unexpired invitations to `vault_id`.
    pub fn shared_invitations(
        &self,
        reader: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<Vec<SharedInvitation>> {
        let txn = self.store.env.read_txn()?;
        // Person tier: a person reads only their own prefix.
        let reader = reader.revalidate_person_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = self.store.clock.now_recorded_at();
        Ok(self
            .invitations_of_in_txn(&txn, reader, vault_id)?
            .into_iter()
            .filter(|open| open.state == SharedInvitationState::Pending && now < open.expires_at)
            .collect())
    }
}
