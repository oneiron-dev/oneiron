//! An imported conversation's recorded speakers, conversation-scoped (FIX 11353).
//!
//! Import records speakers as side strings (a TURN's `speaker`, a MESSAGE's
//! provenance `import.role`/`import.said_by`), never as member `EntityId`s, and
//! lands no membership rows. A never-joined imported conversation therefore has
//! empty people, and `source_people_in` needs its recorded speakers to decide
//! whether it is the owner's side alone. This helper reads only this
//! conversation's body, its own `ChildOf` TURNs and their own `PartOf`
//! MESSAGEs; it never consults the import ledger (vault-wide, copy-shared
//! native ids) and never classes a member.
//!
//! Premise: the import door is the owner's own-history door
//! (`AuthenticatedOwner`, ARCH-0027), so an import's no-`said_by` user side is
//! the owner. Any present user-side `said_by` (`delegating_agent`, `unknown`,
//! or any future value) is other people. Read-only.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::decode_turn_body;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What an imported conversation's recorded speakers say about who else it
/// holds (FIX 11353).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportedConversationSpeakers {
    /// The conversation carries no `import_source`: not an import, not this
    /// helper's case.
    NotImported,
    /// Imported, and every speaker is owner-side: user turns whose MESSAGEs
    /// all lack `said_by`, plus assistant turns. Premise: the import door is
    /// the owner's own-history door (`AuthenticatedOwner`, ARCH-0027), so an
    /// import's no-`said_by` user side is the owner.
    OwnerSide,
    /// Imported but holds other people: any user-side `said_by`, any
    /// non-imported or unexpected-speaker TURN, or any unreadable row (fail
    /// closed).
    Others,
}

/// Classifies `conversation` by its recorded import speakers, in the caller's
/// snapshot.
///
/// Premise: the import door is the owner's own-history door
/// (`AuthenticatedOwner`, ARCH-0027), so an import's no-`said_by` user side is
/// the owner. A TURN outside `{user, assistant}`, a non-imported TURN, any
/// present user-side `said_by`, and any missing or undecodable row are
/// `Others`; only a fully owner-side import is `OwnerSide`.
///
/// # Errors
///
/// Storage or I/O errors reading rows or edges. Every decode or missing-row
/// surprise is `Others`, never an error.
pub(crate) fn imported_speakers_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    conversation: EntityId,
) -> Result<ImportedConversationSpeakers> {
    let Some(body) = body_in(vault, rtxn, &conversation)? else {
        return Ok(ImportedConversationSpeakers::Others);
    };
    let facts = decode_turn_body(&body);
    if !facts.imported {
        return Ok(ImportedConversationSpeakers::NotImported);
    }
    if facts.import_source.is_none() {
        return Ok(ImportedConversationSpeakers::Others);
    }
    for (_, turn) in vault.childof_turns_in(rtxn, &conversation)? {
        let Some(body) = body_in(vault, rtxn, &turn)? else {
            return Ok(ImportedConversationSpeakers::Others);
        };
        let facts = decode_turn_body(&body);
        if !facts.imported {
            return Ok(ImportedConversationSpeakers::Others);
        }
        match facts.speaker.as_deref() {
            Some("user" | "assistant") => {}
            _ => return Ok(ImportedConversationSpeakers::Others),
        }
        if facts.speaker.as_deref() != Some("user") {
            continue;
        }
        for message in vault.turn_message_ids_in(rtxn, &turn)? {
            let Some(body) = body_in(vault, rtxn, &message)? else {
                return Ok(ImportedConversationSpeakers::Others);
            };
            if message_has_said_by(&body) {
                return Ok(ImportedConversationSpeakers::Others);
            }
        }
    }
    Ok(ImportedConversationSpeakers::OwnerSide)
}

/// A row's body bytes, or `None` when the row is missing or its header does
/// not parse. Storage errors propagate.
fn body_in(vault: &Vault, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<u8>>> {
    let Some(raw) = vault.get_raw_in(rtxn, id)? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw).is_none() {
        return Ok(None);
    }
    Ok(raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .map(|body| body.to_vec()))
}

/// Whether a MESSAGE body carries a user-side `said_by` (any present value).
/// An undecodable body fails closed (`true`); a readable body without the key
/// is `false`. The walk is the `message_import_source` shape
/// (`metadata` -> `import` -> `said_by`).
fn message_has_said_by(body: &[u8]) -> bool {
    let Ok(message) = rmpv::decode::read_value(&mut &body[..]) else {
        return true;
    };
    let field = |value: &rmpv::Value, name: &str| match value {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value),
        _ => None,
    };
    let Some(metadata) = field(&message, "metadata") else {
        return false;
    };
    let Some(import) = field(metadata, "import") else {
        return false;
    };
    let rmpv::Value::Map(entries) = import else {
        return false;
    };
    entries
        .iter()
        .any(|(key, _)| key.as_str() == Some("said_by"))
}
