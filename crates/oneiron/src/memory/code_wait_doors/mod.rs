//! Typed code consent wait doors (DOOR-079): `vault.code.waits.resolve`
//! answers one exact sealed code consent wait as its owner or eligible holder,
//! and `vault.code.waits.receipt` reads that wait with its answer,
//! settlement and replay-consumption receipts. Each one projects the
//! engine's own operation unchanged: the answer is
//! `Vault::settle_code_consent_wait_as` and the read is
//! `Vault::code_consent_wait_as`. No raw reply, delivery, consumption, grant
//! or listing of waits is reachable here.
//!
//! A person's live proof (`Memory::code_wait_person`) authenticates this
//! handle's own human actor before any id resolves. The engine then requires
//! current Owner authority or the wait's settlement policy and action power.
//! An answer is also a person's word: a surface bound to generated code's
//! origin never answers in that person's name, whoever's credential it runs
//! under.

mod operations;
mod rebind;
mod types;

pub use types::*;

use std::collections::BTreeSet;

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;

impl Memory<'_> {
    /// Authentication behind both DOOR-079 doors. The engine's wait-specific
    /// policy and power checks decide authority; this proof must be live on
    /// this vault and name this handle's own human actor. No request field
    /// names an actor, and an agent never borrows the proof.
    fn code_wait_person(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate_person(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "code consent waits are answered and read as the authenticated person",
                &["Present this person's own verified credential."],
            ));
        }
        Ok(actor)
    }

    /// Lists the records a wait's view derives from (its ask and the person's
    /// word), each once, and reads each through this credential. `false`
    /// when one that exists reads as no row: the view is then withheld whole.
    fn code_wait_rows_read(&self, rows: impl IntoIterator<Item = EntityId>) -> MemoryResult<bool> {
        for row in rows.into_iter().collect::<BTreeSet<_>>() {
            if self.vault.get_entity_type(&row)?.is_none() {
                continue;
            }
            self.produced_from([row]);
            if self.get_entity_tolerant(&row.to_hex())?.value.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
