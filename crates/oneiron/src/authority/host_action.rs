//! Who a host credential acts as inside its vault (FIX 2222, owner ruling
//! "A + support", 2026-10-18).
//!
//! On a self-hosted vault, root and the explicit local dev mode act as the
//! vault's owner: the embedded owner Human the root bound under its own key
//! at install (`host_actor.rs`), reading with that owner's read key. Anywhere
//! else, a hosted operator's root or a relay's, a host credential acts as
//! nobody: every owner act gets [`Error::HostActionRequiresSupportGrant`],
//! and the customer's support grant is the path. The operator keeps its own
//! admin commands, which take no owner.
//!
//! Nothing here creates, binds or heals an owner, and nothing scans for a
//! Human: a root that binds no live owner under its own key acts for no one
//! until an owner binding is made on purpose.
use super::*;
use crate::Vault;
use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError};
use crate::write_envelope::WriteActor;

/// The holder every host root names (`ensure_host_root_slip`).
const HOST_HOLDER: &str = "host";

/// The owner a host credential acts as, resolved in one snapshot.
///
/// Opaque: only [`Vault::host_action_authority`] and
/// [`Vault::dev_action_authority`] build one, so no caller names its actor,
/// class or grade. Its read key and every owner proof built from it prove
/// again, each in its own snapshot, that the action still holds.
#[derive(Debug, Clone)]
pub struct HostActionAuthority {
    actor: EntityId,
    class: EdgeActorClass,
    read_key: ScopedReadActorKey,
    guard: HostActionGuard,
}

impl HostActionAuthority {
    fn new(owner: EntityId, root: Option<&VerifiedSlip>) -> Self {
        let guard = HostActionGuard {
            root: root.cloned(),
            owner,
        };
        let floor = ScopedReadActorKey::vault_owner(owner);
        let floor = match root {
            Some(root) => floor.while_live(root),
            None => floor,
        };
        Self {
            actor: owner,
            class: EdgeActorClass::Human,
            read_key: floor.guarded_by_host_action(guard.clone()),
            guard,
        }
    }

    /// The person this action acts as: the vault's embedded owner, human.
    #[must_use]
    pub fn actor(&self) -> WriteActor {
        WriteActor::new(self.actor, self.class)
    }

    /// The owner's floor key, held to this action: every read proves again
    /// in its own snapshot that the vault is self-hosted, that the root is
    /// still live and still binds this owner (or, for the dev mode, that the
    /// owner-verb rule still passes), and that the owner is a live PERSON.
    /// The door sets where its caller sits (`ScopedReadActorKey::at`).
    #[must_use]
    pub fn read_key(&self) -> ScopedReadActorKey {
        self.read_key.clone()
    }

    /// What every read and owner proof built from this action rechecks.
    pub(crate) fn guard(&self) -> &HostActionGuard {
        &self.guard
    }
}

/// What a host action proves again on every read (`ScopedRead`'s liveness
/// checks) and every owner act (`AuthenticatedOwner`'s revalidation). A key
/// or a proof that outlives a revoked root, a withdrawn binding or a deleted
/// owner reads and acts as no one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostActionGuard {
    /// The host root acted under; `None` is the explicit local dev mode.
    root: Option<VerifiedSlip>,
    owner: EntityId,
}

impl HostActionGuard {
    /// Whether this action still holds in `txn`. Off a self-hosted vault it
    /// is the typed refusal; a lapse is the owner refusal
    /// ([`host_action_refused`] tells both from a failure to judge).
    pub(crate) fn holds_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        vault.host_action_still_holds_in_txn(txn, self.root.as_ref(), self.owner)
    }

    /// The host root this action acts under, by slip id; `None` for the
    /// dev mode. An offer refuses an answer from the lineage that opened it
    /// or a fork of it (FIX 5064).
    pub(crate) fn root_slip_id(&self) -> Option<[u8; 32]> {
        self.root.as_ref().map(|root| root.claims().slip_id)
    }

    /// The owner this action acts as, for the actor-key fingerprint.
    pub(crate) fn owner(&self) -> EntityId {
        self.owner
    }

    /// The durable identity of this action on `vault`, for a record that
    /// outlives the request (FIX 7231): the posture it was proven under,
    /// the owner, and the install's host root by its mint. Read it only
    /// from a guard its caller just proved again in the writing snapshot.
    pub(crate) fn durable_identity(&self, vault: &Vault) -> HostActionIdentity {
        HostActionIdentity {
            posture: vault.privacy_posture(),
            owner: self.owner,
            root: self.root.as_ref().map(|root| {
                let claims = root.claims();
                HostRootIdentity {
                    slip_id: claims.slip_id,
                    vault_id: claims.vault_id,
                    binding_key: claims.binding_key,
                }
            }),
        }
    }
}

/// A host action as a durable record keeps it (FIX 7231): what a stored
/// approval proves again at every recheck in place of the
/// [`HostActionGuard`], whose presented root cannot be stored. It carries no
/// credential bytes and no signature, and it rebuilds no proof: it names
/// the posture, the owner, and the install's host root by its mint, and
/// [`Self::holds_in`] asks the same rule a guard asks of that mint as the
/// log holds it now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HostActionIdentity {
    /// The posture the action was proven under.
    posture: crate::HostingPrivacyPosture,
    owner: EntityId,
    /// The host root acted under; `None` is the explicit local dev mode.
    root: Option<HostRootIdentity>,
}

/// One install's host root, by the mint the log committed: its slip, the
/// vault it roots and the install's issuer key it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HostRootIdentity {
    slip_id: [u8; 32],
    vault_id: [u8; 32],
    binding_key: [u8; 32],
}

impl HostActionIdentity {
    /// Whether this action still holds in `txn`: the same posture, the same
    /// install's root still live and still binding this owner (or, for the
    /// dev mode, the owner-verb rule still passing), and the owner a live
    /// PERSON. Off the recorded or a self-hosted posture it is the typed
    /// refusal; a lapse is the owner refusal ([`host_action_refused`] tells
    /// both from a failure to judge).
    pub(crate) fn holds_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        if vault.privacy_posture() != self.posture {
            return Err(Error::HostActionRequiresSupportGrant);
        }
        vault.host_action_acts_as_in_txn(
            txn,
            self.root.as_ref().map(HostRoot::Recorded),
            self.owner,
        )
    }
}

/// The host root one host action names: presented with the request, or
/// recorded by a durable identity.
#[derive(Clone, Copy)]
enum HostRoot<'a> {
    Presented(&'a VerifiedSlip),
    Recorded(&'a HostRootIdentity),
}

/// Whether `error` is a host action's refusal, the typed one or the owner
/// refusal, rather than a failure to judge it.
pub(crate) fn host_action_refused(error: &Error) -> bool {
    matches!(
        error,
        Error::HostActionRequiresSupportGrant | Error::Claim(ClaimError::ScopedReadOwnerNotLive(_))
    )
}

impl Vault {
    /// The owner `root` acts as on this vault, judged in one snapshot (FIX
    /// 2222): on a self-hosted vault, a live, full, unattenuated host root
    /// acts as the embedded owner it bound under its own key at install,
    /// while that binding is active and the owner a live PERSON.
    ///
    /// # Errors
    ///
    /// [`Error::HostActionRequiresSupportGrant`] on a vault that is not
    /// self-hosted (a hosted operator's root, a relay); the owner-binding
    /// refusal when `root` is not this vault's live, full root, or binds no
    /// live owner under its key.
    pub fn host_action_authority(&self, root: &VerifiedSlip) -> Result<HostActionAuthority> {
        let txn = self.store.env.read_txn()?;
        self.host_action_authority_in_txn(&txn, root)
    }

    /// [`Self::host_action_authority`], judged in the caller's snapshot.
    pub(crate) fn host_action_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: &VerifiedSlip,
    ) -> Result<HostActionAuthority> {
        let owner = self.host_action_owner_in_txn(txn, Some(root))?;
        Ok(HostActionAuthority::new(owner, Some(root)))
    }

    /// The owner the explicit local dev mode acts as (FIX 2222): on a
    /// self-hosted vault, the live embedded owner under the owner-verb rule.
    /// Unrooted, the live embedded owner alone passes; rooted, it must also
    /// hold its active owner binding. Only a host's exact no-secret dev
    /// hatch calls this.
    ///
    /// # Errors
    ///
    /// [`Error::HostActionRequiresSupportGrant`] on a vault that is not
    /// self-hosted; the owner-binding refusal when the owner does not pass.
    #[doc(hidden)]
    pub fn dev_action_authority(&self) -> Result<HostActionAuthority> {
        let txn = self.store.env.read_txn()?;
        self.dev_action_authority_in_txn(&txn)
    }

    /// [`Self::dev_action_authority`], judged in the caller's snapshot.
    pub(crate) fn dev_action_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<HostActionAuthority> {
        let owner = self.host_action_owner_in_txn(txn, None)?;
        Ok(HostActionAuthority::new(owner, None))
    }

    /// The check a guarded read key and a host-action owner proof run again
    /// in their own snapshot: `root` (the dev mode for `None`) still acts as
    /// `owner`.
    pub(crate) fn host_action_still_holds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: Option<&VerifiedSlip>,
        owner: EntityId,
    ) -> Result<()> {
        self.host_action_acts_as_in_txn(txn, root.map(HostRoot::Presented), owner)
    }

    /// The one recheck a guard and a durable identity share: `root` (the
    /// dev mode for `None`) still acts as `owner`.
    fn host_action_acts_as_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: Option<HostRoot<'_>>,
        owner: EntityId,
    ) -> Result<()> {
        if self.host_action_owner_by_in_txn(txn, root)? != owner {
            return Err(owner_refusal(MemoryError::new(
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                "the owner this host action was resolved for is no longer the one it acts as",
                &["Resolve the host action again."],
            )));
        }
        Ok(())
    }

    /// The one rule for who a host credential acts as, in `txn`: the
    /// embedded owner, on a self-hosted vault alone, under the owner-verb
    /// rule, bound under `root`'s own key when a root is presented, and a
    /// live PERSON.
    pub(crate) fn host_action_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: Option<&VerifiedSlip>,
    ) -> Result<EntityId> {
        self.host_action_owner_by_in_txn(txn, root.map(HostRoot::Presented))
    }

    /// [`Self::host_action_owner_in_txn`] for a root presented now or
    /// recorded by a durable identity.
    fn host_action_owner_by_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: Option<HostRoot<'_>>,
    ) -> Result<EntityId> {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Err(Error::HostActionRequiresSupportGrant);
        }
        let owner = crate::vault::embedded_owner_actor_id()?;
        // The owner-verb rule first: a fold that cannot be judged suspends a
        // host action as it suspends every owner verb.
        crate::memory::verify_owner_actor_binding_in_txn(self, txn, owner)
            .map_err(owner_refusal)?;
        if let Some(root) = root {
            self.root_binds_owner_in_txn(txn, root, owner)?;
        }
        if !crate::consent::person_is_live_in_txn(self, txn, &owner)? {
            return Err(owner_refusal(MemoryError::new(
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                format!("the vault's owner {} is not a live person", owner.to_hex()),
                &[
                    "A deleted owner is not brought back; no host acts as the owner until an owner binding is made again.",
                ],
            )));
        }
        Ok(owner)
    }

    /// `root` is this vault's live, full, unattenuated host root, as the log
    /// minted it, and binds `owner` as `human` under the key that signed
    /// that mint: the owner it bound at install, never any Human bound
    /// anywhere else. A recorded root is judged by its mint alone: still
    /// live, full grade, of the same vault and the same install's key.
    fn root_binds_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: HostRoot<'_>,
        owner: EntityId,
    ) -> Result<()> {
        let slip_id = match root {
            HostRoot::Presented(root) => {
                let claims = root.claims();
                if claims.holder_ref != HOST_HOLDER
                    || claims.parent_id.is_some()
                    || !root.is_full_vault_owner_grade()
                    || !self.capability_slip_is_live_in_txn(txn, root)?
                {
                    return Err(owner_refusal(not_a_root()));
                }
                claims.slip_id
            }
            HostRoot::Recorded(root) => {
                if !self.capability_slip_id_is_live_in_txn(txn, &root.slip_id)? {
                    return Err(owner_refusal(not_a_root()));
                }
                root.slip_id
            }
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(mint) = fold.slips.mints.get(&slip_id) else {
            return Err(owner_refusal(not_a_root()));
        };
        let minted = &mint.action.claims;
        if minted.holder_ref != HOST_HOLDER
            || minted.parent_id.is_some()
            || !roster_has_live_owner(&fold.roster, &mint.signer)
        {
            return Err(owner_refusal(not_a_root()));
        }
        if let HostRoot::Recorded(root) = root
            && (!minted.is_full_vault_owner_grade()
                || minted.vault_id != root.vault_id
                || fold.vault_id != Some(root.vault_id)
                || minted.binding_key != root.binding_key)
        {
            return Err(owner_refusal(not_a_root()));
        }
        let bound = fold
            .actor_bindings
            .get(&mint.signer)
            .is_some_and(|binding| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_ref == owner
                    && binding.actor_class == ACTOR_CLASS_HUMAN
            });
        if !bound {
            return Err(owner_refusal(MemoryError::new(
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                "this host root binds no active owner under its own key",
                &[
                    "A self-hosted root binds the vault's owner when it roots the vault; a root that does not acts for no one.",
                    "Bind the owner under this root's key from an owner device; nothing binds it at request time.",
                ],
            )));
        }
        Ok(())
    }
}

/// A host action's refusal on a self-hosted vault: the owner-binding
/// refusal the owner verbs give, carried as the engine error a read lane
/// and the memory surface already unwrap back to it.
fn owner_refusal(refusal: MemoryError) -> Error {
    Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal)))
}

fn not_a_root() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the host credential is not this vault's live, full root",
        &[
            "Present the host's own unattenuated root credential; a narrowed or child slip of it acts as no owner.",
        ],
    )
}
