//! Who reads each compartment of a custody head, who its keys are wrapped
//! to, and what a restore opens it with.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use zeroize::Zeroizing;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::head::pad_scope::PadRecipients;
use crate::key_custody::head::pad_scope::WORLD_PAD_COMPARTMENTS;
use crate::key_custody::head::pad_scope::WorldPadScope;
use crate::key_custody::head::pad_scope::world_of;
use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;

/// The compartment a host issuer seed's escrow rides (FIX-LIST 10770; CALLS
/// "L02 FIX 10770 issuer-seed custody scope (D1)"): host-readable, so a
/// managed host that unlocked a backup with the data key takes the seed back
/// without the owner's kit (Engine 10-27). `OwnerOnly` wraps it to the
/// recovery root alone; that flip also needs
/// [`CustodyRecipients::keeps_local`] to leave the seed out while no root is
/// pinned, as it does a credential's keys.
const HOST_ISSUER_SEED_CUSTODY_SCOPE: CompartmentScope = CompartmentScope::HostReadable;

/// Who may read one kind's entries, which fixes the recipients of the
/// compartment they are sealed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompartmentScope {
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
    pub fn of(subject: &CustodySubject) -> Result<Self> {
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
            | CustodyKind::TrainingLink
            // An erasable key (FIX 8875) is one the host engine reads, as a
            // claim key is (HostReadable, Engine 10-23).
            | CustodyKind::ErasableKey => Self::HostReadable,
            CustodyKind::HostIssuerSeed => HOST_ISSUER_SEED_CUSTODY_SCOPE,
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

    pub fn code(self) -> u8 {
        match self {
            Self::HostReadable => 1,
            Self::OwnerOnly => 2,
            Self::WorldPad(_) => 3,
        }
    }

    /// The world a world pad scope names.
    pub fn world(self) -> Option<EntityId> {
        match self {
            Self::WorldPad(scope) => Some(scope.world()),
            Self::HostReadable | Self::OwnerOnly => None,
        }
    }

    /// The scope a compartment's wire `code` and `world` name.
    pub fn from_wire(code: u8, world: Option<[u8; 16]>) -> Option<Self> {
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

/// What a restore opens a head with. The kit's root opens every
/// compartment but a world's it is not admitted to; the data key, unlocked
/// from a backup, opens the control compartment and host-readable ones; a
/// machine's secret opens only the world compartments it is admitted to,
/// never the control compartment.
pub struct CustodyOpener<'a> {
    pub root: Option<&'a HybridSecretKey>,
    pub data_key: Option<Zeroizing<[u8; 32]>>,
    pub machine: Option<(EntityId, &'a HybridSecretKey)>,
}
