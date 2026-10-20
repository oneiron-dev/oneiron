//! OPEN FULL HISTORY, the Owner's alone (owner ruling 2026-10-20, FIX 6383):
//! the explicit act that opens a private thread's every turn to the Owner,
//! who is in its audience already, walked in from now on or added. Admins
//! never get it, and no other path serves a joiner the turns before their
//! add, but the Owner's add with full history from outside the thread
//! ([`super::audience_doors`]), which counts as this act.
//!
//! The act is one audience edit TURN of the thread
//! ([`super::audience_events`]): its root, the Owner as both person and
//! editor, and its op. That edit is the act's durable log line; its fold
//! keeps the Owner reading every turn until a remove. The thread's members
//! are told it happened ([`super::audience_notices`]).

use super::audience_doors::{EditedThread, put_audience_event_in, receipt_in};
use super::audience_events::{AudienceEvent, AudienceOp, AudiencePerson};
use super::audience_notices::{ThreadNotice, tell_thread_members};
use super::*;
use crate::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use crate::workspace_roster::RosterActor;

/// `vault.rooms.thread_audience.open_full_history`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceOpenFullHistoryRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

impl Memory<'_> {
    /// Opens a private thread's full history to the vault's Owner, who is in
    /// its audience now (FIX 6383): one audience edit TURN of the thread,
    /// after which the Owner reads its every turn, those before their own
    /// add too, until a remove. Its members are told. Only the Owner, a live
    /// owner acting as a person, may call it; an Admin may not.
    pub fn rooms_thread_audience_open_full_history(
        &self,
        input: &ThreadAudienceOpenFullHistoryRequest,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        let root = EntityId::from_hex(&input.thread_ref)?;
        let actor = self.actor();
        let (receipt, event) = self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            let EditedThread {
                binding, folded, ..
            } = self.edited_thread_in(txn, root)?;
            if self.actor_class() != EdgeActorClass::Human
                || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?
            {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "opening a private thread's full history is the vault Owner's alone",
                    &["Ask the vault's Owner to open it, or the thread's members to share it."],
                ));
            }
            if !folded.current().contains(&actor) {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the Owner opens a private thread's full history from inside it: walk in first",
                    &["Add yourself to the thread with vault.rooms.thread_audience.add, then open its history."],
                ));
            }
            let event = put_audience_event_in(
                vault,
                txn,
                &binding,
                &AudienceEvent {
                    root,
                    person: AudiencePerson::Live(actor),
                    by: RosterActor::Actor(actor),
                    op: AudienceOp::OpenFullHistory,
                    history: None,
                },
            )?;
            Ok((receipt_in(vault, txn, &binding, event, Some(actor)), event))
        })?;
        tracing::info!(
            thread = %root.to_hex(),
            owner = %actor.to_hex(),
            event = %event.to_hex(),
            "the Owner opened a private thread's full history"
        );
        tell_thread_members(
            self.vault(),
            root,
            actor,
            ThreadNotice::OpenFullHistory { event },
        );
        Ok(receipt)
    }
}
