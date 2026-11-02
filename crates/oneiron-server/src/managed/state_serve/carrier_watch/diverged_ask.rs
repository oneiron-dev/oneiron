//! The owner's ask for each copy the outbox carrier keeps unagreed
//! (FIX 11074): one inbox Ask per live owner, "remove or keep", raised at
//! the look that first finds the copy waiting for his answer and cleared at
//! the look that finds it answered or gone. The answer is taken at
//! [`DIVERGED_ANSWER_ROUTE`] and carried by the companion; nothing here
//! removes a copy.

use std::collections::HashMap;

use oneiron::EntityId;
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};

use super::super::ManagedState;
use super::super::admission::WriteKind;
use crate::managed::vm_outbox::{
    DIVERGED_ANSWER_ROUTE, VmOutboxMemberStatus, companion_member_statuses,
};

/// The asks the watch raised, by copy.
#[derive(Default)]
pub(super) struct DivergedAsks {
    /// Each waiting copy's ask rows, by its key ([`copy_key`]).
    raised: HashMap<String, Vec<EntityId>>,
    /// Whether the asks a start found open for copies that no longer wait
    /// were cleared.
    settled_at_start: bool,
}

/// A diverged copy's key, as its ask names it: `<kind>:<member>:<digest>`.
fn copy_key(kind: VmOutboxKind, member: &str, held: &str) -> String {
    format!("{kind}:{member}:{held}")
}

impl DivergedAsks {
    /// Reads the companion's member statuses and raises one ask per diverged
    /// copy that waits for the owner's answer, and clears the asks of copies
    /// that no longer wait. It writes under a background admission, so a
    /// vault frozen for reap raises and clears nothing until it thaws; a
    /// companion that does not answer leaves every ask as it stands, and a
    /// write that does not go through is tried again at the next look.
    pub(super) fn look(mut self, state: &ManagedState, vault: &oneiron::Vault) -> Self {
        let Some(statuses) = companion_member_statuses() else {
            return self;
        };
        let waiting: Vec<(String, String)> = statuses
            .iter()
            .filter_map(|status| match status {
                VmOutboxMemberStatus::DivergedUnagreed {
                    kind,
                    member,
                    held_by,
                    held,
                    retired,
                    answer: None,
                    ..
                } => Some((
                    copy_key(*kind, member, held),
                    ask_detail(*kind, member, *held_by, held, retired.as_deref()),
                )),
                _ => None,
            })
            .collect();
        let Some(admitted) = state.admit_background(WriteKind::BackgroundOther) else {
            return self;
        };
        if !self.settled_at_start {
            let keys: Vec<String> = waiting.iter().map(|(key, _)| key.clone()).collect();
            match vault.clear_settled_outbox_diverged_asks(&keys) {
                Ok(_) => self.settled_at_start = true,
                Err(error) => said_unwritten("cleared", &error),
            }
        }
        let answered: Vec<String> = self
            .raised
            .keys()
            .filter(|key| !waiting.iter().any(|(waits, _)| waits == *key))
            .cloned()
            .collect();
        for key in answered {
            if let Some(rows) = self.raised.remove(&key)
                && let Err(error) = vault.clear_outbox_diverged_ask(&rows)
            {
                said_unwritten("cleared", &error);
                self.raised.insert(key, rows);
            }
        }
        for (key, detail) in waiting {
            if self.raised.contains_key(&key) {
                continue;
            }
            match vault.raise_outbox_diverged_ask(&key, &detail, DIVERGED_ANSWER_ROUTE) {
                Ok(rows) => {
                    tracing::info!(
                        reason = "vm_outbox_diverged_asked",
                        copy = %key,
                        "the owner is asked to remove or keep an outbox copy the carrier never \
                         agreed on"
                    );
                    self.raised.insert(key, rows);
                }
                Err(error) => said_unwritten("raised", &error),
            }
        }
        drop(admitted);
        self
    }
}

/// What the ask says of one diverged copy, in plain words.
fn ask_detail(
    kind: VmOutboxKind,
    member: &str,
    held_by: VmOutboxSide,
    held: &str,
    retired: Option<&str>,
) -> String {
    let end = match held_by {
        VmOutboxSide::Guest => "the vault VM",
        VmOutboxSide::Host => "its host",
    };
    let retired = retired.map_or_else(
        || "its agreed version".to_owned(),
        |retired| format!("its agreed version {retired}"),
    );
    format!(
        "The {kind} outbox member {member} was retired ({retired}), but {end} keeps a copy the \
         carrier never agreed on ({held}). Nothing removes it without your answer: remove it, or \
         keep it under its own name, out of the way of the member's next version."
    )
}

fn said_unwritten(what: &str, error: &oneiron::Error) {
    tracing::warn!(
        reason = "vm_outbox_diverged_ask_unwritten",
        %error,
        "a diverged outbox copy's owner ask was not {what}; the next look tries again"
    );
}
