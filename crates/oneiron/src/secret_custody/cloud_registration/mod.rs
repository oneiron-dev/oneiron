//! The engine's own custody for its cloud registration (G7, FIX 5347; L04
//! FIX 9056): the token set the native registration client holds, and the
//! value-free binding that maps it to the local owner who linked it.
//!
//! Each link is one ordinary custody record, a slot: device-bound and this
//! device only, used at T0 alone, its value the client's opaque token set,
//! sealed under its own generation's custody key (KS-6). Its name sits in
//! the engine's reserved namespace (`oneiron.cloud-registration/<id>`), so
//! the slot stays known as one after a logout or a replacement: no owner
//! door registers or rotates a name there, an export never carries its
//! value, a copy beside its source never holds a usable key of it, and the
//! known-value index never keys it. A refresh rotates the slot in place, so
//! every token generation is one credential id, and an erase of that id
//! retires every generation's key (KS-6 part 2).
//!
//! The binding is one `CLOUD_REGISTRATION` row per slot: the owner who
//! linked it, the pinned issuer and audience, the verified cloud subject,
//! its phase and the slot generation it is fenced at. A row outlives its
//! slot's use: a replaced or logged-out slot keeps its row, so the owner's
//! erase still reaches it, and an erased slot keeps it, `Erasing`, until
//! every key of it is retired. Nothing here makes a network call.
//!
//! Lifecycle (L04 08:3x): an erase of the owner, or of the registration,
//! crypto-shreds every slot and generation it reached; a delete keeps them;
//! a logout stops the binding and empties the slot's value at rest, which
//! is not an erase.

mod lifecycle;
mod store;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};

use super::types::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};

pub(crate) use self::lifecycle::{
    cloud_registration_erased_with, erase_cloud_registration_actor_in_txn,
};

/// Every slot's name starts with this: the engine's reserved namespace.
const SLOT_PREFIX: &str = "oneiron.cloud-registration/";

/// The binding row of each slot, by the slot's record id.
const ROWS: SideTable<EntityId, Row, Named> = SideTable::new(&side_table::CLOUD_REGISTRATION);

/// Whether `name` is a cloud registration slot's: the engine's own, under
/// its reserved namespace.
pub(crate) fn is_cloud_registration_slot(name: &str) -> bool {
    name.starts_with(SLOT_PREFIX)
}

/// The custody name of slot `slot`.
fn slot_name(slot: &EntityId) -> String {
    format!("{SLOT_PREFIX}{}", slot.to_hex())
}

/// What the client sends a slot's token to, each its own T0 binding, so a
/// door receipt names the use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloudRegistrationTokenUse {
    /// The refresh token to the pinned issuer's token endpoint.
    Refresh,
    /// The access token to the pinned audience, the registration status.
    Access,
    /// A token to the pinned issuer's revocation endpoint.
    Revoke,
}

impl CloudRegistrationTokenUse {
    const ALL: [Self; 3] = [Self::Refresh, Self::Access, Self::Revoke];

    /// The effector of this use's binding.
    #[must_use]
    pub const fn effector(self) -> &'static str {
        match self {
            Self::Refresh => "oneiron.cloud-registration.refresh",
            Self::Access => "oneiron.cloud-registration.access",
            Self::Revoke => "oneiron.cloud-registration.revoke",
        }
    }
}

/// A slot's bindings: one per use, each at T0 with the read grant.
fn slot_bindings() -> Vec<SecretBinding> {
    CloudRegistrationTokenUse::ALL
        .iter()
        .map(|token_use| SecretBinding {
            effector: token_use.effector().to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: vec![SECRET_SCOPE_READ.to_owned()],
        })
        .collect()
}

/// Where one slot's binding stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRegistrationPhase {
    /// Linked and usable.
    Linked,
    /// A refresh is reserved: its token may be spent. Never sent again.
    InFlight,
    /// The family is lost or uncertain: the owner logs in again.
    NeedsLogin,
    /// The owner logged out: the binding is stopped, the slot kept for the
    /// owner's erase.
    LoggedOut,
    /// A later login replaced it: kept for the owner's erase.
    Replaced,
    /// The owner's erase took it: its record, name and value are gone, and
    /// the row stays until every key of it is retired, so a later erase
    /// still reports it.
    Erasing,
}

impl CloudRegistrationPhase {
    /// Whether this is the owner's current link for its issuer.
    #[must_use]
    pub const fn current(self) -> bool {
        matches!(self, Self::Linked | Self::InFlight | Self::NeedsLogin)
    }
}

/// One slot's stored binding: value-free.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Row {
    /// The local owner whose explicit login linked it.
    owner: EntityId,
    issuer: String,
    audience: String,
    /// The verified cloud subject, `cp-owner:<account>:<revision>`.
    subject: String,
    phase: CloudRegistrationPhase,
    /// The slot generation the binding is fenced at.
    generation: u32,
    linked_at: u64,
    changed_at: u64,
}

/// What a login links: the pinned issuer and audience, and the subject the
/// verified access token names.
#[derive(Clone, Copy, Debug)]
pub struct CloudRegistrationLink<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub subject: &'a str,
}

/// One slot's binding, as the owner reads it: no token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudRegistrationBinding {
    /// The slot's custody record id.
    pub slot: EntityId,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub phase: CloudRegistrationPhase,
    pub generation: u32,
    pub linked_at: u64,
    pub changed_at: u64,
}

impl CloudRegistrationBinding {
    fn of(slot: EntityId, row: &Row) -> Self {
        Self {
            slot,
            issuer: row.issuer.clone(),
            audience: row.audience.clone(),
            subject: row.subject.clone(),
            phase: row.phase,
            generation: row.generation,
            linked_at: row.linked_at,
            changed_at: row.changed_at,
        }
    }

    /// The fence a later act on this binding names.
    #[must_use]
    pub const fn fence(&self) -> CloudRegistrationFence {
        CloudRegistrationFence {
            slot: self.slot,
            generation: self.generation,
        }
    }
}

/// The slot and generation an act expects: one that moved since refuses
/// nothing and changes nothing (`None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloudRegistrationFence {
    pub slot: EntityId,
    pub generation: u32,
}

/// What a login's link did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudRegistrationLinked {
    /// The new slot is linked; the owner's earlier current link for the
    /// issuer, if any, is replaced and kept for the owner's erase.
    Linked {
        binding: CloudRegistrationBinding,
        replaced: Option<CloudRegistrationBinding>,
    },
    /// The owner's current link names another cloud subject, and the login
    /// did not ask to replace it: nothing was stored (CALLS
    /// G7_LINK_REPLACEMENT).
    ReplaceRequired { current: CloudRegistrationBinding },
}

/// What an owner's erase of the registration took: every slot, those an
/// earlier erase left pending with it, and whether every key of each is
/// already retired everywhere it must be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudRegistrationErased {
    pub slots: Vec<EntityId>,
    /// `false` is pending, never failed: the finisher retries.
    pub complete: bool,
}
