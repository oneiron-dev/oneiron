//! The stamp tokens a NOTE document names, recorded as it is written (FIX
//! 11965): each new commit's stamp and each live authorship entry's token,
//! under the NOTE, so an actor erase's hold check finds a held NOTE's tokens
//! without a history walk (`provenance::actor_stamp`).

use loro::{LoroDoc, LoroValue, ValueOrContainer, VersionVector};

use super::{NoteActor, NoteAuthorship};
use crate::{EntityId, Result, Vault};

/// Records the stamp tokens `doc` names under `note`, in the writer's
/// transaction: those of its changes past `since` (every change it retains
/// when `since` is `None`), and those of its live authorship entries. The
/// sequence rows of a record with no document birth share this storage, so
/// an entity document's stamp counts too.
///
/// # Errors
///
/// Storage errors.
pub(super) fn record_token_uses_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    doc: &LoroDoc,
    since: Option<&VersionVector>,
) -> Result<()> {
    let mut tokens = crate::provenance::tokens_named_since(doc, since, |message| {
        stamp_token(message).or_else(|| crate::entity_doc::engine_stamp_token(message))
    });
    tokens.extend(authorship_tokens(doc, note));
    crate::provenance::record_actor_stamp_uses_in_txn(&vault.store, txn, &note, tokens)
}

/// The token a NOTE engine stamp names (FIX 10930): a write's
/// `oneiron.note/v1 actor=<token>` or a program edit's
/// `note:v1:<action>:actor=<token>`. None for a stamp that names no one, or
/// any other message.
fn stamp_token(message: &str) -> Option<EntityId> {
    let named = match message.strip_prefix("oneiron.note/v1 actor=") {
        Some(named) => named,
        None => message.strip_prefix("note:v1:")?.split_once(":actor=")?.1,
    };
    EntityId::from_hex(named).ok()
}

/// The tokens `doc`'s live authorship entries name (FIX 11964): every entry
/// but the birth's own, which names the NOTE core's author. An entry that
/// does not read names none.
fn authorship_tokens(doc: &LoroDoc, note: EntityId) -> Vec<EntityId> {
    let mut tokens = Vec::new();
    for value in doc.get_map("authorship").values() {
        let ValueOrContainer::Value(LoroValue::String(value)) = value else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<NoteAuthorship>(&value) else {
            continue;
        };
        if record.operation != note
            && let NoteActor::Actor(token) = record.actor
        {
            tokens.push(token);
        }
    }
    tokens
}
