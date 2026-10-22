//! Who reads each compartment of a custody head, who its keys are wrapped
//! to, and what a restore opens it with.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::identity::{CustodyId, CustodyKind, CustodySubject};
use super::pad_scope::{PadRecipients, WORLD_PAD_COMPARTMENTS, WorldPadScope, world_of};

/// Who may read one kind's entries, which fixes the recipients of the
/// compartment they are sealed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompartmentScope {
    /// Kinds the host engine reads in its own process (claim keys, the
    /// training link key): their compartment opens with the vault data key
    /// as well, so a restore that unlocked a backup opens it without the kit.
    HostReadable,
    /// Kinds only the owner's own machines may read (a later client's):
    /// wrapped to the recovery root alone, never to the host-readable data
    /// key.
    OwnerOnly,
    /// One world's pads, live and retired, with world compartments on
    /// ([`WORLD_PAD_COMPARTMENTS`], FIX 6706): wrapped to the world's
    /// admitted machines and roots alone, never to the data key or the
    /// generic root wrap.
    WorldPad(WorldPadScope),
}

impl CompartmentScope {
    /// The scope `subject`'s entries go in; a later kind names its own.
    ///
    /// # Errors
    ///
    /// A world pad whose item names no world, with world compartments on.
    pub(crate) fn of(subject: &CustodySubject) -> Result<Self> {
        Ok(match subject.kind() {
            CustodyKind::WorldPad if WORLD_PAD_COMPARTMENTS => {
                Self::WorldPad(WorldPadScope::of(subject)?)
            }
            // A body instance's key is one the host engine reads in its own
            // process, as a claim key is (KS-2A); so are the known-value
            // index's master and its history entries (KS-3), which no kit
            // need open.
            //
            // A world pad too were world compartments off (KS-5, CALLS
            // WORLD_PAD_HEAD_SCOPE); they are on (FIX 9178), so a pad's
            // scope is its world's.
            CustodyKind::ClaimDecision
            | CustodyKind::BodyInstance
            | CustodyKind::KnownValueIndex
            | CustodyKind::KnownValueEntry
            | CustodyKind::WorldPad
            | CustodyKind::CheckpointPayload
            | CustodyKind::TrainingLink => Self::HostReadable,
            // An inference snapshot's key is one the host engine opens in
            // its own process to import the snapshot into its worker, as a
            // body instance's is, and no owner kit is present at that point.
            CustodyKind::InferenceSnapshot => Self::HostReadable,
            // A credential's value and its carriers' keys (KS-6, CALLS
            // `KS-6 entry eligibility`): only the owner's kit opens them; a
            // head carries one only where [`CustodyRecipients::keeps_local`]
            // lets it. A connector call's resume (FIX 9157) is owner-only
            // the same way, and no head carries one.
            CustodyKind::CredentialValue
            | CustodyKind::CustodyTransition
            | CustodyKind::CustodyRequestInput
            | CustodyKind::ConnectorResume => Self::OwnerOnly,
        })
    }

    pub(super) fn code(self) -> u8 {
        match self {
            Self::HostReadable => 1,
            Self::OwnerOnly => 2,
            Self::WorldPad(_) => 3,
        }
    }

    /// The world a world pad scope names.
    pub(super) fn world(self) -> Option<EntityId> {
        match self {
            Self::WorldPad(scope) => Some(scope.world()),
            Self::HostReadable | Self::OwnerOnly => None,
        }
    }

    /// The scope a compartment's wire `code` and `world` name.
    pub(super) fn from_wire(code: u8, world: Option<[u8; 16]>) -> Option<Self> {
        match (code, world) {
            (1, None) => Some(Self::HostReadable),
            (2, None) => Some(Self::OwnerOnly),
            (3, Some(world)) => EntityId::from_bytes(world)
                .ok()
                .map(|world| Self::WorldPad(WorldPadScope::new(world))),
            _ => None,
        }
    }
}

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
    /// credential's value or carrier key unless a root is pinned and the
    /// credential is one [`Self::credentials_eligible`] names (KS-6). A
    /// connector call's resume (FIX 9157) is always left out.
    pub(crate) fn keeps_local(&self, id: &CustodyId) -> bool {
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

/// What a restore opens a head with. The kit's root opens every
/// compartment but a world's it is not admitted to; the data key, unlocked
/// from a backup, opens the control compartment and host-readable ones; a
/// machine's secret opens only the world compartments it is admitted to,
/// never the control compartment.
pub(crate) struct CustodyOpener<'a> {
    pub(crate) root: Option<&'a HybridSecretKey>,
    pub(crate) data_key: Option<Zeroizing<[u8; 32]>>,
    pub(crate) machine: Option<(EntityId, &'a HybridSecretKey)>,
}
