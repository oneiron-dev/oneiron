//! Invitee acceptance (CROSS-ARCH-0024: "Only an accepted, vault-specific
//! invitation" grants membership). An Admin's `add_member` power issues an
//! invitation for one live person at one non-root role in this shared vault;
//! the grant is written only when that person accepts it with their own
//! person-tier proof, before it expires and while its issuer still holds the
//! power. A declined, withdrawn or expired invitation grants nothing, and an
//! accepted one is spent. The `add_member` power names no key (FIX 8745):
//! the invitee binds their invitation to the key of an independent live human
//! slip of their own, or redeems an owner's invitation pairing code with a
//! key of their own, and gets their own human slip for it (FIX 1925,
//! `authority::invitee_slip`): good only at this invitation's list, accept
//! and decline doors, only while it is pending and only while that key is
//! the one it records.
use super::super::{
    Effect, SharedActExecutionReceipt, SharedVaultChange, check_vault, decode, encode, invalid,
    key, non_root,
};
use crate::authority::{CapabilitySlip, HostSlipIssuer, PairingLink, PendingInvitationLink};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::{FederationGrantRole as Role, OrgAdminPower, SharedVaultWrite};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

const INVITATION_PREFIX: &[u8] = b"shared-vault:invitation:v1:";
/// `side_table::SHARED_VAULT_INVITATION_KEY`: the key an invitation's slips bind.
const INVITATION_KEY_PREFIX: &[u8] = b"shared-vault:invitation-key:v1:";
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
    #[serde(with = "crate::federation::vault_id_decimal")]
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

/// The key an invitation's own slips bind (FIX 8745), as its invitee bound
/// it, and what bound it. Binding again replaces it, which ends every slip
/// minted to the earlier key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvitationKeyBinding {
    /// The invitee's public key.
    pub(crate) holder_key: [u8; 32],
    /// The invitee's own independent credential that proved the key (its
    /// slip id), which must stay live for the invitation's slips to stand;
    /// `None` when the invitee redeemed an owner's invitation pairing code
    /// with it, a code spent as it bound.
    pub(crate) source_slip: Option<[u8; 32]>,
}

impl InvitationKeyBinding {
    /// The row: the key's 32 bytes, then the source slip id's when there is one.
    fn encode(&self) -> Vec<u8> {
        let mut row = self.holder_key.to_vec();
        if let Some(source) = self.source_slip {
            row.extend_from_slice(&source);
        }
        row
    }
    fn decode(row: &[u8]) -> Result<Self> {
        let bytes = |part: &[u8]| <[u8; 32]>::try_from(part).map_err(|_| invalid());
        match row.len() {
            32 => Ok(Self {
                holder_key: bytes(row)?,
                source_slip: None,
            }),
            64 => Ok(Self {
                holder_key: bytes(&row[..32])?,
                source_slip: Some(bytes(&row[32..])?),
            }),
            _ => Err(invalid()),
        }
    }
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
    fn invitation_key_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        invitee: EntityId,
        id: &str,
    ) -> Result<Option<InvitationKeyBinding>> {
        let id = EntityId::from_hex(id)?.to_hex();
        self.store
            .vault_meta
            .get(
                txn,
                &key(INVITATION_KEY_PREFIX, &format!("{}:{id}", invitee.to_hex())),
            )?
            .map(|row| InvitationKeyBinding::decode(&row))
            .transpose()
    }
    /// Records `binding` as the key `invitation`'s slips bind, replacing any
    /// earlier one.
    pub(crate) fn put_invitation_key_binding_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        invitation: &SharedInvitation,
        binding: &InvitationKeyBinding,
    ) -> Result<()> {
        let id = EntityId::from_hex(&invitation.id)?.to_hex();
        let invitee = EntityId::from_hex(&invitation.invitee)?;
        self.store.vault_meta.put(
            txn,
            &key(INVITATION_KEY_PREFIX, &format!("{}:{id}", invitee.to_hex())),
            &binding.encode(),
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

    /// Every pending invitation into `vault_id` unexpired at `now`, whoever
    /// it admits (FIX 2573): the vault's own read of who is invited, beside
    /// each person's read of their own.
    pub(crate) fn pending_shared_invitations_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        now: u64,
    ) -> Result<Vec<SharedInvitation>> {
        let mut pending = Vec::new();
        for row in self
            .store
            .vault_meta
            .prefix_iter(txn, &key(INVITATION_PREFIX, ""))?
        {
            let (_, raw) = row?;
            let invitation: SharedInvitation = decode(&raw)?;
            if invitation.vault_id == vault_id
                && invitation.state == SharedInvitationState::Pending
                && now < invitation.expires_at
            {
                pending.push(invitation);
            }
        }
        Ok(pending)
    }

    /// Whether a slip of `invitee`'s invitation `id` bound to `holder_key`
    /// stands at `now`: the invitation is pending and unexpired (FIX 1925),
    /// `holder_key` is the key it records, and the independent credential
    /// that bound it, if one did, is live (FIX 8745). A slip minted to a key
    /// no binding records, or since replaced, does not.
    pub(crate) fn invitation_slip_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        invitee: EntityId,
        id: &str,
        holder_key: &[u8; 32],
        now: u64,
    ) -> bool {
        let pending = self.invitation_in_txn(txn, invitee, id).is_ok_and(|open| {
            open.state == SharedInvitationState::Pending && now < open.expires_at
        });
        pending
            && self
                .invitation_key_binding_in_txn(txn, invitee, id)
                .is_ok_and(|binding| {
                    binding.is_some_and(|binding| {
                        binding.holder_key == *holder_key
                            && binding.source_slip.is_none_or(|source| {
                                self.capability_slip_id_is_live_in_txn(txn, &source)
                                    .unwrap_or(false)
                            })
                    })
                })
    }

    /// `invitee`'s invitation `id`, open for a slip at `now`: into
    /// `vault_id`, pending and unexpired.
    pub(crate) fn pending_invitation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        invitee: EntityId,
        id: &str,
        now: u64,
    ) -> Result<SharedInvitation> {
        let invitation = self.invitation_in_txn(txn, invitee, id)?;
        if invitation.vault_id != vault_id
            || invitation.state != SharedInvitationState::Pending
            || now >= invitation.expires_at
        {
            return Err(invalid());
        }
        Ok(invitation)
    }

    /// The `add_member` effect: one pending invitation of `member` at `role`,
    /// refused while another of theirs to this vault is still open. `founding`
    /// marks the creation writer's own invitations. It names no key: the
    /// invitee binds one ([`Vault::mint_invitation_slip`]).
    pub(super) fn issue_invitation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        vault_id: u64,
        inviter: EntityId,
        member: EntityId,
        role: Role,
        founding: bool,
        now: u64,
    ) -> Result<Effect> {
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
        Ok(Effect {
            change: SharedVaultChange::MemberInvited {
                invitation: invitation.id,
                member: invitation.invitee,
                role,
                expires_at: invitation.expires_at,
            },
            grants: Vec::new(),
            revoked_slips: Vec::new(),
            notify: BTreeSet::from([member]),
        })
    }

    /// The invitee binds their pending invitation to a key of their own and
    /// gets its slip (FIX 1925, FIX 8745): `invitee`'s request came on their
    /// own independent live human slip, presented whole, whose key the
    /// invitation records and the slip, minted under the host's `issuer`,
    /// binds. It ends when the invitation does, when that credential does
    /// (it is minted to end no later), or when the invitee binds another key. No one names this key for them: an `add_member` holder
    /// only creates or withdraws the invitation. An invitee with no such
    /// credential redeems an owner's invitation pairing code instead.
    pub fn mint_invitation_slip(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
        issuer: &HostSlipIssuer,
    ) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        let own = invitee.independent_credential_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let invitation =
            self.pending_invitation_in_txn(&txn, vault_id, own.person, invitation_id, now)?;
        self.put_invitation_key_binding_in_txn(
            &mut txn,
            &invitation,
            &InvitationKeyBinding {
                holder_key: own.holder_key,
                source_slip: Some(own.slip_id),
            },
        )?;
        let slip = self.mint_invitee_slip_in_txn(
            &mut txn,
            issuer,
            own.person,
            &invitation.id,
            own.holder_key,
            invitation.expires_at.min(own.expires_at),
        )?;
        txn.commit()?;
        Ok(slip)
    }

    /// An owner's invitation pairing code (FIX 8745), for an invitee with no
    /// independent credential of their own, a founding Owner included: the
    /// owner's act mints a one-hour single-use code for `invitee`'s pending
    /// invitation `invitation_id` and returns it to `owner`, who passes it on
    /// by any channel, as an invite link; the engine chooses none. The
    /// invitee redeems it at the pairing door with a key of their own, which
    /// binds the invitation to that key and mints its slip
    /// (`Vault::redeem_invitation_link_in_txn`). The code reaches nothing
    /// else, and an `add_member` holder who is not an owner mints none.
    pub fn issue_invitation_pairing_link(
        &self,
        owner: &AuthenticatedOwner,
        vault_id: u64,
        invitee: EntityId,
        invitation_id: &str,
        issuer: &HostSlipIssuer,
    ) -> Result<PairingLink> {
        let mut txn = self.store.env.write_txn()?;
        let owner = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        check_vault(self, &txn, vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let invitation =
            self.pending_invitation_in_txn(&txn, vault_id, invitee, invitation_id, now)?;
        let link = self.issue_invitation_pairing_link_in_txn(
            &mut txn,
            issuer,
            owner,
            PendingInvitationLink {
                vault_id,
                invitee,
                invitation: invitation.id,
            },
            invitation.expires_at,
        )?;
        txn.commit()?;
        Ok(link)
    }

    /// The invitation side of redeeming an invitation pairing code, in the
    /// redemption's writer (FIX 8745): while `link`'s invitation is still
    /// pending, `holder_key`, the key the redeemer proved, becomes the key it
    /// records, replacing any earlier one, and the invitee's slip for it is
    /// minted to that key.
    pub(crate) fn redeem_invitation_link_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        link: &PendingInvitationLink,
        holder_key: [u8; 32],
    ) -> Result<CapabilitySlip> {
        check_vault(self, txn, link.vault_id)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let invitation = self.pending_invitation_in_txn(
            txn,
            link.vault_id,
            link.invitee,
            &link.invitation,
            now,
        )?;
        self.put_invitation_key_binding_in_txn(
            txn,
            &invitation,
            &InvitationKeyBinding {
                holder_key,
                source_slip: None,
            },
        )?;
        self.mint_invitee_slip_in_txn(
            txn,
            issuer,
            link.invitee,
            &invitation.id,
            holder_key,
            invitation.expires_at,
        )
    }

    /// The invitee accepts `invitation_id` with their own person-tier proof:
    /// while it is pending and unexpired, they hold no membership here, and
    /// its issuer still holds the `add_member` power, the grant at its role
    /// is written, the invitation is spent, and the receipt goes to the
    /// Owners, the invitee and the issuer. A request slip the proof carries
    /// must be the invitation's own, on its bound key, or the invitee's own
    /// independent credential (FIX 8745).
    pub fn accept_shared_invitation(
        &self,
        invitee: &AuthenticatedOwner,
        vault_id: u64,
        invitation_id: &str,
    ) -> Result<SharedActExecutionReceipt> {
        invitee.require_invitation_acceptor(invitation_id)?;
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
