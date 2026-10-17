//! The newcomer barrier on a live reply (OF-365 P5, FIX 1389). A call bound
//! to a container, or a chat reply written into one, listens for committed
//! TASKs from before its output goes out. When one is an attendee's first
//! entry into that container, or when wakes were lost, the reply stops what
//! it was assembling for the audience before the entry; the container's
//! output mark already refuses it. Its next turn is assembled afresh for
//! the new audience; nothing resumes on its own.

use oneiron::voice_cascade::{AudienceRefresh, Brain, CascadeControl, TtsSeamClient};
use oneiron::{EntityId, Vault};
use tokio::sync::broadcast::{self, error::RecvError};

use super::media_bridge::MediaBridge;
use super::{HostError, VoiceHost, VoiceOutputs, speech};

/// Committed TASK ids, while a reply listens for entries.
pub(crate) type EntryWakes = Option<broadcast::Receiver<EntityId>>;

/// The next committed TASK; forever once nothing listens.
pub(crate) async fn next_entry_wake(wakes: &mut EntryWakes) -> Result<EntityId, RecvError> {
    match wakes {
        Some(wakes) => wakes.recv().await,
        None => std::future::pending().await,
    }
}

/// What one wake says about a container.
pub(crate) enum EntryWake {
    /// No attendee entered it.
    Quiet,
    /// An attendee entered it under this entry fact.
    Entered(EntityId),
    /// The TASK could not be read, wakes were lost, or the channel closed:
    /// one may have, so the reply stops as for an entry.
    Unknown,
}

/// What `woke` says about `container`. A closed channel also ends the
/// listening, and the output mark guards what is left.
pub(crate) fn entry_wake(
    vault: &Vault,
    container: EntityId,
    woke: Result<EntityId, RecvError>,
    wakes: &mut EntryWakes,
) -> EntryWake {
    match woke {
        Ok(task) => match vault.container_attendee_entry_by_ref(task) {
            Ok(Some(entry)) if entry.container == container => EntryWake::Entered(entry.entry_ref),
            Ok(_) => EntryWake::Quiet,
            Err(error) => {
                tracing::warn!(%error, "a committed TASK was not read; stopping as for an entry");
                EntryWake::Unknown
            }
        },
        Err(RecvError::Lagged(lost)) => {
            tracing::debug!(lost, "entry wakes were lost; stopping as for an entry");
            EntryWake::Unknown
        }
        Err(RecvError::Closed) => {
            *wakes = None;
            EntryWake::Unknown
        }
    }
}

impl VoiceHost {
    /// Subscribes to committed TASKs before the call's first read, when its
    /// session is bound to a container.
    pub(super) fn entry_wakes(&self) -> EntryWakes {
        self.container
            .as_ref()
            .map(|(vault, _)| vault.subscribe_task_updates())
    }

    /// One wake. An attendee's entry into the bound container stops the
    /// generation assembled before it and moves the session's audience. An
    /// entry the session recorded and read itself, at a final or a roster
    /// refresh, was in that audience already; any other TASK changes
    /// nothing.
    pub(super) fn entry_woke<B: Brain, T: TtsSeamClient, C: CascadeControl>(
        &self,
        woke: Result<EntityId, RecvError>,
        wakes: &mut EntryWakes,
        bridge: Option<&mut MediaBridge>,
        outputs: &mut VoiceOutputs<B, T, C>,
    ) {
        let Some((vault, container)) = &self.container else {
            return;
        };
        match entry_wake(vault, *container, woke, wakes) {
            EntryWake::Quiet => return,
            EntryWake::Entered(entry_ref) if self.audience_names_entry(entry_ref) => return,
            EntryWake::Entered(_) | EntryWake::Unknown => {}
        }
        let refresh = match self.entry_barrier() {
            Ok(refresh) => refresh,
            Err(error) => {
                tracing::warn!(%error, "voice: the newcomer barrier was refused");
                return;
            }
        };
        let Some(stop) = refresh.stop else {
            return;
        };
        match bridge {
            Some(bridge) => speech::stopped(&stop, bridge, outputs),
            None => {
                let errors =
                    stop.dispatch(&mut outputs.brain, &mut outputs.tts, &mut outputs.control);
                if !errors.is_empty() {
                    tracing::warn!(
                        count = errors.len(),
                        "voice: a newcomer stop arm was not delivered"
                    );
                }
            }
        }
    }

    fn entry_barrier(&self) -> Result<AudienceRefresh, HostError> {
        Ok(self.lock()?.core.entry_barrier()?)
    }

    /// A poisoned session names nothing, so its wake stops as for an entry.
    fn audience_names_entry(&self, entry_ref: EntityId) -> bool {
        self.lock()
            .is_ok_and(|state| state.core.audience_names_entry(entry_ref))
    }
}
