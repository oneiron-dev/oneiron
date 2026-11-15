//! A self-host root move to a new host secret, in-chain (OF-455).
//!
//! The current root signs one ReRoot for the new secret's key, so the vault
//! keeps its genesis and its id. A ReRoot retires every key on the roster, so
//! the same transaction carries what the vault needs to keep working under the
//! new root: its host root slip, the engine writers that were live, the
//! physical machines' standing, and the MACHINE claim histories that were
//! readable. Every slip the old root minted
//! stops verifying (OF-455: "existing slips on the old host fail verification
//! against the new root"); the holders get new ones from the new root.
//!
//! When the root's seed is lost and its escrow gives none back, the same move
//! is signed by the recovery kit's authority key the owner enrolled before the
//! loss ([`Vault::recover_host_root_to_new_seed`]; L1-07, OF-570): one move
//! body for both signers.
use super::slip_vault::require_host;
use super::*;
use crate::claim::HandoffKind;
use crate::claim::history_projection::{
    PIN_PREFIX, trusted_machine_handoff, verified_handoff_chain,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::recovery_kit::RestoredKitSecret;
use crate::world_keys::RecoveryAuthoritySigner;
use crate::{EntityId, Vault};
use rand_core::{OsRng, RngCore};

/// What a host re-root changed, for the owner's report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostReRoot {
    pub vault_id: AuthorityVaultId,
    /// Engine writers enrolled again under keys the new secret derives.
    pub writers_enrolled: usize,
    /// Live physical machines whose standing the new root signed again.
    pub machines_carried: usize,
    /// MACHINE claim histories the new root carried.
    pub histories_carried: usize,
    /// Pinned histories that were not readable before the move and stay so.
    pub histories_left: usize,
    /// Live slips a key the move retired minted (the old root, or any owner
    /// key), other than the host's own root slip. None of them verifies now.
    pub retired_slips: Vec<RetiredSlip>,
}

/// A credential the re-root retired: its holder needs a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetiredSlip {
    pub slip_id: [u8; 32],
    pub holder_ref: String,
    pub actor_class: Option<String>,
}

/// Typed reason: the restored kit's authority key is not a live owner key of
/// this vault, so it signs no root move. Nothing moved.
const RECOVERY_KIT_NOT_ENROLLED: &str = "this kit's authority key is not a live owner key of \
     this vault; a kit recovers the root only after `recovery-kit enroll-authority`, and a \
     root move retires the key it enrolled";

/// What proves the right to move a host root.
enum RootMoveProof<'a> {
    /// The live root, this install's loaded issuer (OF-455).
    Root(&'a HostSlipIssuer),
    /// A recovery kit restored here, whose authority key the owner enrolled
    /// before the loss (L1-07; OF-570).
    Kit(RestoredKitSecret),
}

/// The key that signs a host root move, judged against the fold before it.
enum RootMoveSigner<'a> {
    Root(&'a HostSlipIssuer),
    Kit(RecoveryAuthoritySigner),
}

impl<'a> RootMoveProof<'a> {
    /// The signer this proof stands for, when it is a live owner key of the
    /// vault's one settled root in `before`; the kit's key is derived for
    /// `vault_id`, the fold's own.
    fn signer(
        self,
        before: &AuthorityFold,
        vault_id: &AuthorityVaultId,
    ) -> Result<RootMoveSigner<'a>> {
        match self {
            Self::Root(current) => {
                require_host(before, current)?;
                Ok(RootMoveSigner::Root(current))
            }
            Self::Kit(secret) => {
                let kit = RecoveryAuthoritySigner::from_restored_kit(secret, vault_id)?;
                // `vault_id` is the fold's own, so its root is not conflicted.
                if !roster_has_live_owner(&before.roster, &kit.authority_key()) {
                    return Err(authority_refused(RECOVERY_KIT_NOT_ENROLLED));
                }
                Ok(RootMoveSigner::Kit(kit))
            }
        }
    }
}

impl RootMoveSigner<'_> {
    fn key(&self) -> AuthorityKey {
        match self {
            Self::Root(current) => current.public_key(),
            Self::Kit(kit) => kit.authority_key(),
        }
    }

    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Root(current) => Ok(current.sign_slip(transcript)),
            Self::Kit(kit) => kit.sign_authority_transcript(transcript),
        }
    }
}

impl Vault {
    /// Moves the host root from `current` to `next` in one transaction, on a
    /// vault no server holds. `current` must be the live root and `next` a
    /// key the vault has never seen. Engine writers whose binding an owner
    /// revoked, and histories that were quarantined, are left as they were.
    /// Once the move commits, `next`'s seed is escrowed in the vault's key
    /// custody (FIX-LIST 10770), best effort: a fault there is warned, and
    /// the move stands. Then the stale-stamp sweep runs, as after every
    /// authority commit (H213): a severed pact's worlds carry their stamp
    /// when this returns. A sweep fault is warned and the move stands: the
    /// sweep stays owed, and the next commit by any writer retries it. An
    /// error here always means nothing moved, which
    /// [`Self::re_root_host_to_new_seed`] relies on to put the old seed back.
    pub fn re_root_host(
        &self,
        current: &HostSlipIssuer,
        next: &HostSlipIssuer,
    ) -> Result<HostReRoot> {
        self.move_host_root(RootMoveProof::Root(current), next)
    }

    /// Moves the host root to `next` as [`Self::re_root_host`] does, signed
    /// by the restored recovery kit's authority key instead of the lost root
    /// (L1-07; OF-570; identity.md "Recovery reboot"): the genesis and the
    /// vault id stay, and the same rows are carried. The kit's key must be a
    /// live owner key of the vault's settled root, enrolled before the loss
    /// (`recovery-kit enroll-authority`); otherwise this refuses, by a typed
    /// reason that names that command, before anything is written.
    /// The new root holds only the roles the kit's key may hand on
    /// (`ROLE_OWNER`). Self-host only: relay keeps no host recovery path, and
    /// managed recovery rides account auth (identity.md
    /// `#cloud-agent-recovery`). The move retires the kit's key with every
    /// other key (L1-07-KIT-AFTER-MOVE = B). An error always means nothing
    /// moved, which [`Self::recover_host_root_to_new_seed`] relies on. Crate
    /// private: that wrapper is the one way in, so its refusal while this
    /// install holds the live root always runs first.
    pub(crate) fn recover_host_root_from_kit(
        &self,
        secret: RestoredKitSecret,
        next: &HostSlipIssuer,
    ) -> Result<HostReRoot> {
        if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
            return Err(invalid_authority());
        }
        self.move_host_root(RootMoveProof::Kit(secret), next)
    }

    /// The one body of a host root move: `proof`'s signer, a live owner key,
    /// signs one ReRoot to `next`, and the same transaction carries the host
    /// root slip, the live engine writers, the machines' standing and the
    /// readable MACHINE histories.
    fn move_host_root(
        &self,
        proof: RootMoveProof<'_>,
        next: &HostSlipIssuer,
    ) -> Result<HostReRoot> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(invalid_authority());
        }
        // Writer rows are created in their own transactions, before this one.
        let engine_writers = self.engine_machine_actors()?;
        let watch = crate::federation::StaleSweepWatch::begin(self);
        let mut txn = self.store.env.write_txn()?;
        let before = self.authority_fold_readonly_in_txn(&txn)?;
        let vault_id = before.vault_id.ok_or_else(invalid_authority)?;
        let signer = proof.signer(&before, &vault_id)?;
        if before.roster.contains_key(&next.public_key()) {
            return Err(invalid_authority());
        }
        let signer_key = signer.key();
        let signer_roles = before
            .roster
            .get(&signer_key)
            .map_or(0, |device| device.roles);
        let writers: Vec<EntityId> = engine_writers
            .into_iter()
            .filter(|machine| {
                before.actor_bindings.iter().any(|(key, binding)| {
                    binding.actor_ref == *machine
                        && binding.actor_class == "system"
                        && binding.status == ActorBindingStatus::Active
                        && before.roster.get(key).is_some_and(|device| !device.revoked)
                })
            })
            .collect();
        let mut carried = Vec::new();
        let mut histories_left = 0;
        for target in pinned_machine_history_targets(&self.store, &txn)? {
            if self.machine_target_admitted_in_txn(&txn, &before, target)? {
                carried.push(target);
            } else {
                histories_left += 1;
            }
        }
        let now = self.instant_in_txn(&txn)?;
        // The ReRoot revokes every roster key (op_apply), so every live slip
        // a live roster key minted stops verifying, the old root's and any
        // owner key's alike.
        let retired_slips = before
            .slips
            .mints
            .iter()
            .filter(|(id, mint)| {
                before
                    .roster
                    .get(&mint.signer)
                    .is_some_and(|device| !device.revoked)
                    && mint.action.claims.holder_ref != "host"
                    && before.slip_is_live_at(id, now)
            })
            .map(|(id, mint)| RetiredSlip {
                slip_id: *id,
                holder_ref: mint.action.claims.holder_ref.clone(),
                actor_class: mint.action.claims.actor_class.clone(),
            })
            .collect();

        let sign = |transcript: &[u8]| signer.sign(transcript);
        let joiner = match &signer {
            RootMoveSigner::Root(current) => FrontierSigner::Host(current),
            RootMoveSigner::Kit(_) => FrontierSigner::Callback(&signer_key, &sign),
        };
        let (_, re_rooted) = self.re_root_authority_in_txn(
            &mut txn,
            next.root_device_under(self.privacy_posture(), signer_roles),
            (&signer_key, Some(joiner)),
            &sign,
        )?;
        // The new root's first entry: its sequence is what enrollment extends.
        self.ensure_host_root_slip_in_txn(&mut txn, next)?;
        for machine in &writers {
            self.enroll_engine_machine_in_txn(&mut txn, next, &vault_id, *machine)?;
        }
        let machines_carried = self.carry_machine_standing_in_txn(&mut txn, &before, next)?;
        for target in &carried {
            let mut challenge = [0; 32];
            OsRng.fill_bytes(&mut challenge);
            self.carry_machine_history_in_txn(
                &mut txn,
                *target,
                next,
                challenge,
                HandoffKind::ReRootCarry,
            )?;
        }
        txn.commit()?;
        // The move and its joins reach loaded windows once it lands (FIX
        // 11993).
        self.note_committed_authority_rows(re_rooted);
        self.escrow_host_slip_issuer_logged(next);
        // The move stands whatever the sweep answers: a failed sweep stays
        // owed (L7-31).
        if let Err(error) = watch.finish() {
            tracing::warn!(
                kind = ?error.kind(),
                "the stale-stamp sweep after a host root move failed; \
                 the move stands, and the next commit sweeps again"
            );
        }
        Ok(HostReRoot {
            vault_id,
            writers_enrolled: writers.len(),
            machines_carried,
            histories_carried: carried.len(),
            histories_left,
            retired_slips,
        })
    }

    /// Whether this vault shows the fragile-genesis flag now
    /// ([`GENESIS_FRAGILE_FLAG`]; identity.md "Genesis window"): the owner
    /// dismissed saving the genesis recovery secret and no second device
    /// enrolled, or a root move retired every key, a recovery kit's among
    /// them, and no owner key has been enrolled since, so the vault holds no
    /// recovery method (L1-07-KIT-AFTER-MOVE = B). A flag the host shows,
    /// never a refusal.
    ///
    /// # Errors
    ///
    /// Storage and fold faults.
    pub fn genesis_fragile_now(&self) -> Result<bool> {
        let moved = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            if fold.genesis_fragile {
                return Ok(true);
            }
            !fold.retired_keys.is_empty()
        };
        Ok(moved && !self.enrolled_owner_keys()?.iter().any(|key| key.live))
    }

    /// Whether the claim a pinned history projects is readable now.
    fn machine_target_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        target: EntityId,
    ) -> Result<bool> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &target)?
        else {
            return Ok(false);
        };
        if crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Ok(false);
        }
        let Ok(body) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        else {
            return Ok(false);
        };
        super::claim_write::claim_causal_admitted(&self.store, txn, fold, &target, &body)
    }
}

/// Whether a MACHINE birth whose signing key a ReRoot retired still reads:
/// the key stayed bound to `actor` as a writer and was never revoked as an
/// actor, and a live root carried the birth's history at the very ReRoot
/// that made it root. A writer's actor revoke stays terminal across a move,
/// and so does a history the move left: only the move signs a `ReRootCarry`,
/// into the chain of the one birth it carried, so neither a later lifecycle
/// write nor a later birth at the same id stands in for one. The carry
/// travels with the chain, so a replica that adopts the history reads it too.
pub(super) fn origin_carried_past_re_root(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    key: &AuthorityKey,
    actor: EntityId,
) -> bool {
    fold.actor_bindings
        .get(key)
        .is_some_and(|binding| binding.actor_ref == actor && binding.actor_class == "system")
        && fold.roster.get(key).is_some_and(|device| {
            device.revoked
                && device.tier == AuthorityTier::Software
                && device.roles & ROLE_AGENT != 0
        })
        && !fold.revoked_actor_keys.contains(key)
        && carried_by_live_root(store, txn, fold, target).unwrap_or(false)
}

fn carried_by_live_root(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<bool> {
    let tip = trusted_machine_handoff(store, txn, target)?;
    if tip.births.len() != 1 {
        return Ok(false);
    }
    // Every packet in the chain names the tip's one birth.
    for packet in verified_handoff_chain(store, txn, &tip, fold)? {
        if packet.kind == HandoffKind::ReRootCarry
            && packet.previous_handoff_hash.is_some()
            && fold.valid_entries.contains(&packet.authority_head)
            && fold
                .roster
                .get(&packet.signer)
                .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
            && head_re_roots_to(store, txn, &packet.authority_head, &packet.signer)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the logged entry `head` is the ReRoot that made `key` the root.
/// On a vault that adopted a checkpoint image, a covered ReRoot it does not
/// store is read from the body the image carries, and judged the same way
/// (OF-469, slice E).
fn head_re_roots_to(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    head: &AuthorityEntryHash,
    key: &AuthorityKey,
) -> Result<bool> {
    let id = authority_log_entity_id_from_hash(head)?;
    let entry = match crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? {
        Some(raw) => {
            let body = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("authority head header"))?;
            decode_authority_log_entry_body(body)?
        }
        None => match super::adopted_evidence::CarriedRows::default().get(store, txn, head)? {
            Some(entry) => entry,
            None => return Ok(false),
        },
    };
    Ok(authority_entry_hash(&entry)? == *head
        && matches!(&entry.op, AuthorityOp::ReRoot { new_device } if new_device.key == *key))
}

/// [`Vault::re_root_authority`] signed by the live host root `current`, to
/// `next`'s key: the raw move alone, with none of [`Vault::re_root_host`]'s
/// carried rows. For the integration tests' door (L7-31).
#[cfg(oneiron_test_support)]
pub(crate) fn re_root_authority_as_host_for_test(
    vault: &Vault,
    current: &HostSlipIssuer,
    next: &HostSlipIssuer,
) -> Result<AuthorityLogEntry> {
    vault.re_root_authority(
        next.root_device(vault.privacy_posture()),
        current.public_key(),
        |transcript| Ok(current.sign_slip(transcript)),
    )
}

/// Every target with a trusted history pin, readable or not.
fn pinned_machine_history_targets(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, PIN_PREFIX)? {
        let (key, _) = row?;
        let bytes: [u8; 16] = key[PIN_PREFIX.len()..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("machine history pin"))?;
        targets.push(EntityId::from_bytes(bytes)?);
    }
    Ok(targets)
}
