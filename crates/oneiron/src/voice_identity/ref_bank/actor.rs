//! Who acts on a voice through the bank's typed doors (FIX 4393). A real
//! person acts on their own voice on their own person proof, revalidated as
//! a live person in the acting transaction, owner of the vault or not: the
//! same consent the owner gives, applied to that subject. A designed
//! (synthetic) voice belongs to the entity that created it, the owner by
//! default: its creator acts on it on its own credential-bound read key and
//! the actor binding every write checks, with no person proof, since no real
//! person is its subject. A creator without a person's proof never acts on a
//! real person's voice, and nobody acts on another's.
use super::{VoiceRefSubjectKind, invalid, read_identity, render_history::read_render_consent};
use crate::EntityId;
use crate::error::{Error, Result};

pub(super) use crate::memory::voice_actor::VoiceParty;
pub use crate::memory::voice_actor::{VoiceBankActor, VoiceCreator};

/// The refusal of an act on a voice that is another's.
pub(super) fn others_voice() -> Error {
    invalid(
        "the voice is another's: only its subject, or a designed voice's creator, banks, \
         consents to or provisions it",
    )
}

pub(super) trait VoicePartyBankExt {
    fn bind_in(
        self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        voice_id: &str,
    ) -> Result<Option<(EntityId, VoiceRefSubjectKind)>>;
}

impl VoicePartyBankExt for VoiceParty {
    /// Refuses unless this party is `voice_id`'s subject or creator as the
    /// bank holds it, and may act on its kind. The voice's subject and kind
    /// as the bank holds them: its identity's, or before its first pack its
    /// render decision's; None when the bank holds nothing of the voice.
    fn bind_in(
        self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        voice_id: &str,
    ) -> Result<Option<(EntityId, VoiceRefSubjectKind)>> {
        let held = match read_identity(store, txn, voice_id)? {
            Some(identity) => Some((identity.owner, identity.subject_kind)),
            None => read_render_consent(store, txn, voice_id)?
                .map(|consent| (consent.decision.subject, consent.decision.subject_kind)),
        };
        if let Some((subject, kind)) = held {
            if subject != self.entity {
                return Err(others_voice());
            }
            self.admits(kind)?;
        }
        Ok(held)
    }
}
