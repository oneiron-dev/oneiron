//! Core half of `store::key_custody::head::scope`: its store-layer items live in `oneiron_store::key_custody::head::scope` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::head::scope::*;

use super::super::identity::{CustodyId, CustodyKind, CustodySubject};
use super::pad_scope::{PadRecipients, WORLD_PAD_COMPARTMENTS, WorldPadScope, world_of};
use crate::entity_id::EntityId;
use crate::error::Result;
use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Who a head's compartment keys are wrapped to. Domain policy picks them:
/// the stored root's public facts and the held data key, never a seed.
pub(crate) struct CustodyRecipients {
    /// The owner's recovery root, by id and hybrid public key: every
    /// compartment but a world's. `None` while no root is pinned; the kit
    /// is never enrolled by a publication.
    pub(crate) root: Option<([u8; 32], HybridPublicKey)>,
    /// The vault data key's [`super::CUSTODY_HEAD_WRAP_CONTEXT`] subkey: the
    /// control compartment and host-readable ones.
    pub(crate) data_key: Option<Zeroizing<[u8; 32]>>,
    /// The worlds (16-byte ids) whose pads the head leaves out: their
    /// settings keep their pads off where the head goes (KS-5 pad head
    /// eligibility). They stay in this machine's custody.
    pub(crate) pad_worlds_kept_local: BTreeSet<[u8; 16]>,
    /// The credentials (16-byte custody record ids) whose value and carrier
    /// keys may ride the head (KS-6): portable ones the owner may recover
    /// with his kit. Every other credential's stay in this machine's
    /// custody, as do all of them while no root is pinned.
    pub(crate) credentials_eligible: BTreeSet<[u8; 16]>,
    /// Each world's admitted machines and roots, which alone its pad
    /// compartment is wrapped to once world compartments are on (FIX 6706):
    /// never the data key, the generic root or every linked machine. A world
    /// not named keeps its pads in this machine's custody.
    pub(crate) pad_worlds: BTreeMap<EntityId, PadRecipients>,
}

impl CustodyRecipients {
    /// Whether the head leaves the live entry `id` out: a world pad of a
    /// world [`Self::pad_worlds_kept_local`] names, or (world compartments
    /// on) of a world no admitted machine or root receives; or a
    /// credential's value key unless a root is pinned and the credential is
    /// one [`Self::credentials_eligible`] names (KS-6). A carrier key is
    /// always left out (FIX 7402): it opens a retained carrier only where it
    /// is released live, so no head, which retains, carries it or a
    /// permanent key's wrap of it. So is a connector call's resume (FIX
    /// 9157).
    pub(crate) fn keeps_local(&self, id: &CustodyId) -> bool {
        if matches!(
            id.kind(),
            CustodyKind::CustodyTransition | CustodyKind::CustodyRequestInput
        ) {
            return true;
        }
        if crate::store::credential_kind(id.kind()) {
            return self.root.is_none()
                || !id
                    .subject()
                    .item()
                    .get(..16)
                    .and_then(|credential| <[u8; 16]>::try_from(credential).ok())
                    .is_some_and(|credential| self.credentials_eligible.contains(&credential));
        }
        id.kind() == CustodyKind::WorldPad
            && (id
                .subject()
                .item()
                .get(..16)
                .and_then(|world| <[u8; 16]>::try_from(world).ok())
                .is_some_and(|world| self.pad_worlds_kept_local.contains(&world))
                || (WORLD_PAD_COMPARTMENTS && !self.admits_world_of(id)))
    }

    /// Whether the head leaves the retirement fact of `id` out: a
    /// credential's kept off this member (KS-6), or (world compartments on)
    /// a pad's whose item names no world, which has no compartment to ride
    /// in. A connector call's resume fact (FIX 9157) is always left out.
    /// Every other world pad's fact rides ([`Self::fact_scope`]).
    pub(crate) fn keeps_fact_local(&self, id: &CustodyId) -> bool {
        if crate::store::credential_kind(id.kind()) {
            return self.keeps_local(id);
        }
        WORLD_PAD_COMPARTMENTS
            && id.kind() == CustodyKind::WorldPad
            && world_of(id.subject().item()).is_err()
    }

    /// The compartment the retirement fact of `id` rides: its subject's
    /// scope, but (world compartments on, FIX 9178) a pad's of a world no
    /// admitted machine or root receives, an erased world's among them,
    /// rides the host-readable compartment. A fact names an id and holds no
    /// pad or key, and every restore still sees the erase, as it did before
    /// world compartments: the pad stays erased, never missing.
    ///
    /// # Errors
    ///
    /// As [`CompartmentScope::of`].
    pub(crate) fn fact_scope(&self, id: &CustodyId) -> Result<CompartmentScope> {
        Ok(match CompartmentScope::of(id.subject())? {
            CompartmentScope::WorldPad(_) if !self.admits_world_of(id) => {
                CompartmentScope::HostReadable
            }
            scope => scope,
        })
    }

    /// Whether the world of the pad `id` has an admitted machine or root.
    fn admits_world_of(&self, id: &CustodyId) -> bool {
        world_of(id.subject().item()).is_ok_and(|world| {
            self.pad_worlds
                .get(&world)
                .is_some_and(|admitted| !admitted.is_empty())
        })
    }
}
