//! A resident's craft on the surfaces it speaks on besides its pumped runs
//! (OF-490): a workflow leaf and a wave plan (`step`), a Retry or Continue
//! (`turn_actions`) and a chat answer (`api::ai::chat`). Each call is shown
//! every note its resident keeps, in the craft reader's order, as one
//! system message after its instructions, before anything it reads.
//!
//! A call on a queue attempt loads each note on that attempt, so its
//! manifest names what it was shown. A call with no attempt to stamp reads
//! one snapshot and keeps the exact pack beside the reply. The message
//! names each note's claim and revision beside its text, so a captured
//! request that is sent again shows, and stamps, exactly what it showed.
//! A craft that does not read leaves the call as it always ran.

use oneiron::actor_claims::{craft_message_entries, craft_message_text, resident_craft_pack};
use oneiron::attempt_queue::{AttemptId, ManifestEntry};
use oneiron::{ContentPart, EntityId, LlmMessage, LlmMessageRole, LlmRequest, Vault};

/// What a call with no attempt to stamp is shown: its craft message, and
/// the pack it shows, in its order, stamped at the read's time.
pub(crate) struct SnapshotCraft {
    pub(crate) message: LlmMessage,
    pub(crate) entries: Vec<ManifestEntry>,
}

/// The craft message a call on the queue attempt `attempt` sends as
/// `resident`, read at `at`: each note loaded on the attempt through the
/// resident's pack door. `None` without craft, or when it does not read.
pub(crate) fn queue_craft(
    vault: &Vault,
    attempt: AttemptId,
    resident: &EntityId,
    at: u64,
) -> Option<LlmMessage> {
    match vault.load_resident_craft(attempt, resident, at) {
        Ok(notes) => craft_message_text(&notes).map(system),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), agent = %resident.to_hex(), "a resident's craft did not read; its call goes on without it");
            None
        }
    }
}

/// `resident`'s craft for a call with no attempt to stamp, read on one
/// snapshot at `at`. `None` without craft, or when it does not read.
pub(crate) fn snapshot_craft(vault: &Vault, resident: &EntityId, at: u64) -> Option<SnapshotCraft> {
    let notes = match resident_craft_pack(vault, resident, at) {
        Ok(notes) => notes,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), agent = %resident.to_hex(), "a resident's craft did not read; its answer goes on without it");
            return None;
        }
    };
    let text = craft_message_text(&notes)?;
    Some(SnapshotCraft {
        message: system(text),
        entries: notes.iter().map(|note| note.entry(at)).collect(),
    })
}

/// The craft a captured `request` showed: the rows its craft message
/// names, in its order, stamped at `at`. Empty for one that shows none.
pub(crate) fn captured_craft(request: &LlmRequest, at: u64) -> Vec<ManifestEntry> {
    request
        .messages
        .iter()
        .filter(|message| message.role == LlmMessageRole::System)
        .find_map(|message| craft_message_entries(&message_text(message), at))
        .unwrap_or_default()
}

/// Puts `craft` after `messages`' leading system messages, its
/// instructions, before anything the call reads.
pub(crate) fn join_craft(messages: &mut Vec<LlmMessage>, craft: LlmMessage) {
    let at = messages
        .iter()
        .take_while(|message| message.role == LlmMessageRole::System)
        .count();
    messages.insert(at, craft);
}

fn system(text: String) -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text { text }],
    }
}

fn message_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}
