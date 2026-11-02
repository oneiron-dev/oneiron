//! The stretch instance a session-bound run's late type feedback lands on
//! (FIX 10389, CALLS "session feedback lives on the session route only"):
//! the instance the run was bound to, held weakly, bound again for one brief
//! write when a check lands after its step. It holds no view, read lease,
//! body or row of the room, so a close never waits on it; once that
//! instance closes it binds nothing, and a name taken again names another
//! instance, which it never reaches.

use std::sync::Arc;

use super::super::registry::{live_session_entry, session_entry_state};
use super::OffRecordSession;
use crate::Vault;
use crate::code_run::SessionInstanceBind;

impl OffRecordSession<'_> {
    /// This instance as a run bound to it acts in it, bound again for each
    /// late call on `vault`: the call runs on a fresh handle for the same
    /// participant while the instance is the one `vault` registers under its
    /// name, and is neither closing nor closed. Otherwise the call does not
    /// run.
    pub(crate) fn instance_bind(&self) -> SessionInstanceBind {
        let session_ref = self.session_ref.clone();
        let instance = Arc::downgrade(&self.entry);
        let participant = self.participant;
        Box::new(
            move |vault: &Vault, call: &mut dyn FnMut(OffRecordSession<'_>)| {
                let Some(entry) = instance.upgrade() else {
                    return;
                };
                let registered = live_session_entry(&vault.store, &session_ref)
                    .is_ok_and(|held| Arc::ptr_eq(&held, &entry));
                let live = registered
                    && session_entry_state(&entry).is_ok_and(|state| {
                        !state.gone && !state.overlay_closed && !state.record.closing
                    });
                if !live {
                    return;
                }
                call(OffRecordSession {
                    vault,
                    session_ref: session_ref.clone(),
                    entry,
                    participant,
                });
            },
        )
    }
}
