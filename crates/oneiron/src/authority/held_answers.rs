//! The owner's list of held machine answers, his confirm and his dismissal
//! (row CARRIER-OWNER-PROOF; ruling CARRIER-GRANDFATHER = C: one prompt
//! lists every machine whose answer is held, with a confirm for all of them
//! and a decline for each).
//!
//! A carried answer that needed an owner key's proof and carried none is
//! held: stored, standing for nothing, asking the owner. The list is that
//! ask. A confirm is the owner's own answer, carried again by an install
//! that holds his key, so it is proven and stands; it writes no new kind of
//! entry. A dismissal writes nothing to the log: it is a local mark on this
//! install, the answer stays held, and his other devices still ask.

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

use super::*;

/// One held machine answer as the owner's surface lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedHeldAnswer {
    /// The held answer's log entry: what a confirm or a dismissal names.
    pub entry: AuthorityEntryHash,
    /// The answer as it was carried: the machine, and the role, class and
    /// keys it asks for.
    pub answer: MachineRevision,
    /// The role the machine stands in now; `None` when no revision names it.
    pub standing: Option<MachineRole>,
    /// The role the answer's carrier stands in; `None` when no revision
    /// names the carrier.
    pub carrier_role: Option<MachineRole>,
    /// Whether this install trusts the carrier as the owner's machine.
    pub carrier_is_mine: bool,
    /// Whether the owner dismissed this ask on this install.
    pub dismissed: bool,
}

/// The owner's acts that wait for his proof, as this install lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAnswerListing {
    /// Each held machine answer that still asks, by machine, then by entry.
    pub answers: Vec<ListedHeldAnswer>,
    /// Each owner choice that waits for his proof and still asks, by entry
    /// ([`AuthorityFold::waiting_owner_choices`]). He confirms one by making
    /// the choice again on an owner device.
    pub waiting_choices: Vec<AuthorityEntryHash>,
    /// Whether this install holds an owner key, so a confirm here is proven.
    pub can_confirm: bool,
}

/// What the owner's confirm did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedHeldAnswers {
    /// The machines a confirmed answer removed. Their mesh pairing and
    /// grants are the caller's to revoke, as after a removal through
    /// [`Vault::set_machine_role`].
    pub removed: Vec<EntityId>,
    /// The list after the confirm.
    pub listing: HeldAnswerListing,
}

impl Vault {
    /// The owner's acts that wait for his proof on this vault.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the vault's live owner; the
    /// door is not built yet.
    pub fn held_machine_answers(&self, owner: &AuthenticatedOwner) -> Result<HeldAnswerListing> {
        owner.revalidate(self)?;
        Err(invalid_authority())
    }

    /// The owner confirms the held answers `entries` name, from `surface`.
    ///
    /// # Errors
    /// As [`Vault::held_machine_answers`].
    pub fn confirm_held_machine_answers(
        &self,
        owner: &AuthenticatedOwner,
        _surface: ActSurface,
        _entries: &[AuthorityEntryHash],
    ) -> Result<ConfirmedHeldAnswers> {
        owner.revalidate(self)?;
        Err(invalid_authority())
    }

    /// The owner dismisses the ask of the held answers `entries` name, on
    /// this install only.
    ///
    /// # Errors
    /// As [`Vault::held_machine_answers`].
    pub fn dismiss_held_machine_answers(
        &self,
        owner: &AuthenticatedOwner,
        _entries: &[AuthorityEntryHash],
    ) -> Result<HeldAnswerListing> {
        owner.revalidate(self)?;
        Err(invalid_authority())
    }
}
