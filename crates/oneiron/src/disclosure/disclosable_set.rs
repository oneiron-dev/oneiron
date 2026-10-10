//! The ILDF2 room rule (ONE-1592, ratified 2026-09-23):
//! `disclosable_set = public ∪ (∩ clearances of all non-owner present)`.
//! A clearance is the contact's Scope, so ∩ is the meet of Scopes.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
use crate::interlocutor::InterlocutorSet;

/// What one audience may be shown. The clearance half is a Scope; the
/// public half is a property of the record (P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosableSet(Scope);

impl DisclosableSet {
    /// An unknown party's set: the empty clearance, so public-only.
    #[must_use]
    pub fn unknown_reader() -> Self {
        Self(Scope::default())
    }

    /// The met clearance of every non-owner present.
    #[must_use]
    pub fn clearance(&self) -> &Scope {
        &self.0
    }

    /// P7: a record is disclosed iff it is positively public, or its Scope
    /// sits at or under the met clearance. Relevance never bypasses this,
    /// and a missing sensitivity stamp is never public.
    #[must_use]
    pub fn admits(&self, record: &Scope) -> bool {
        record.sensitivity == SensitivityCeiling::AtMost(Sensitivity::Public)
            || self.0.admits("read", record, &Scope::top())
    }
}

/// The one resolver of the room rule. The owner's presence contributes no
/// clearance term; with no non-owner present the fold is the top of the
/// Scope lattice (P1), never bottom. An unknown party, a missing or revoked
/// clearance, or a row that does not decode contributes bottom, so that
/// party narrows the room to public-only. Only storage I/O errors surface.
pub fn disclosable_set(vault: &Vault, roster: &InterlocutorSet) -> Result<DisclosableSet> {
    let mut met = Scope::top();
    for party in roster.non_owner() {
        let clearance = match party.contact_ref() {
            Some(hex) => match vault.counterparty_disclosure_scope(&EntityId::from_hex(hex)?) {
                Ok(Some(clearance)) => clearance.effective_scope(),
                Ok(None) => Scope::default(),
                Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => Scope::default(),
                Err(error) => return Err(error),
            },
            None => Scope::default(),
        };
        met = met.meet(&clearance);
    }
    Ok(DisclosableSet(met))
}
