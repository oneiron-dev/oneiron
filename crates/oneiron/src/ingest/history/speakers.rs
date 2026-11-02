//! An imported conversation's recorded speakers, conversation-scoped (FIX 11353).
//!
//! Import records speakers as side strings (a TURN's `speaker`, a MESSAGE's
//! provenance `import.role`/`import.said_by`), never as member `EntityId`s, and
//! lands no membership rows. A never-joined imported conversation therefore has
//! empty people, and `source_people_in` needs its recorded speakers to decide
//! whether it is the owner's side alone. This helper reads only this
//! conversation's body, its own `ChildOf` TURNs and its live `BelongsTo`
//! MESSAGEs; it never consults the import ledger (vault-wide, copy-shared
//! native ids) and never classes a member.
//!
//! Deleted turns do not hide a recorded speaker: the room's live MESSAGEs
//! `BelongsTo` the room decide `said_by`, whatever TURN they sit under.
//! Deleted message shells are skipped (a shell holds no words). Read cost: 1
//! (conversation) + T (turn bodies) + M (live message bodies).
//!
//! Premise: the import door is the owner's own-history door
//! (`AuthenticatedOwner`, ARCH-0027), so an import's no-`said_by` user side is
//! the owner. Any present user-side `said_by` (`delegating_agent`, `unknown`,
//! or any future value) is other people. Read-only.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::decode_turn_body;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// What an imported conversation's recorded speakers say about who else it
/// holds (FIX 11353).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportedConversationSpeakers {
    /// The conversation carries no `import_source`: not an import, not this
    /// helper's case.
    NotImported,
    /// Imported, and every speaker is owner-side: live TURNs in
    /// `{user, assistant}` with the room's live MESSAGEs all lacking `said_by`.
    /// Premise: the import door is the owner's own-history door
    /// (`AuthenticatedOwner`, ARCH-0027), so an import's no-`said_by` user side
    /// is the owner.
    OwnerSide,
    /// Imported but holds other people: any live `said_by`, any live
    /// non-imported or unexpected-speaker TURN, or any undecodable live body
    /// (fail closed).
    Others,
}

/// Classifies `conversation` by its recorded import speakers, in the caller's
/// snapshot.
///
/// Premise: the import door is the owner's own-history door
/// (`AuthenticatedOwner`, ARCH-0027), so an import's no-`said_by` user side is
/// the owner. A live TURN outside `{user, assistant}`, a live non-imported
/// TURN, and any present `said_by` on a live MESSAGE `BelongsTo` the room are
/// `Others`; deleted turns do not hide a recorded speaker, and deleted message
/// shells are skipped (no words). An undecodable live body fails closed; only
/// a fully owner-side import is `OwnerSide`.
///
/// # Errors
///
/// Storage or I/O errors reading rows or edges. Every undecodable live body
/// is `Others`, never an error.
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
    // All ChildOf TURN targets, live or not (childof_turns_in is live-only):
    // a shelled or absent turn gives no verdict itself; its live MESSAGEs
    // still decide said_by below.
    for edge in vault.store.port_edges(
        rtxn,
        &conversation,
        EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let turn = edge?.target;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&vault.store, rtxn, &turn)?
        else {
            continue;
        };
        let facts = decode_turn_body(&body);
        if !facts.imported {
            return Ok(ImportedConversationSpeakers::Others);
        }
        match facts.speaker.as_deref() {
            Some("user" | "assistant") => {}
            _ => return Ok(ImportedConversationSpeakers::Others),
        }
    }
    // One scan of the room's live MESSAGEs: deleted turns do not hide a
    // recorded speaker, and deleted shells hold no words.
    for edge in vault.store.port_edges(
        rtxn,
        &conversation,
        EdgeDirection::In,
        Some(EdgeKind::BelongsTo),
        None,
    )? {
        let message = edge?.target;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } = live_entity_row_in_txn(&vault.store, rtxn, &message)?
        else {
            continue;
        };
        if message_has_said_by(&body) {
            return Ok(ImportedConversationSpeakers::Others);
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

/// The value a msgpack map stores under `name`.
fn field<'a>(value: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    match value {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value),
        _ => None,
    }
}
