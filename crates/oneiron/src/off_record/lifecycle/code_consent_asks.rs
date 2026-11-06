//! A sealed held call's caller binding, kept in its session's RAM until
//! its typed code consent ask opens (FIX 4520).
//!
//! A NoRecord caller's held call keeps its arguments sealed and keeps no
//! caller context on disk. When the first typed ask of its code consent
//! wait does not open, the binding captured from the caller's own surface
//! stays here, in that exact session instance, under the wait. It is never
//! serialized, never rebuilt from a session name, and it goes with the
//! session. It is correlation, not authority: each retry checks the caller
//! and the session again.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::SessionWitnessBinding;

use super::registry::OffRecordSessionRegistry;
use super::session::OffRecordSession;

/// One kept ask: its wait, its held call and the caller's binding.
#[derive(Clone)]
pub(crate) struct RetainedCodeConsentAsk {
    pub(crate) wait_id: EntityId,
    pub(crate) call_ref: EntityId,
    pub(crate) binding: Arc<SessionWitnessBinding>,
}

/// One session instance's kept asks, by wait. RAM only.
#[derive(Default)]
pub(super) struct CodeConsentAskBindings {
    asks: Mutex<BTreeMap<EntityId, RetainedCodeConsentAsk>>,
}

impl CodeConsentAskBindings {
    fn locked(&self) -> Result<MutexGuard<'_, BTreeMap<EntityId, RetainedCodeConsentAsk>>> {
        self.asks
            .lock()
            .map_err(|_| Error::InvariantViolation("session code consent asks mutex poisoned"))
    }

    /// Drops every kept ask, a poisoned keep's too, so a close never stops
    /// here. Close calls it once `closing` is published.
    pub(super) fn clear(&self) {
        self.asks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl OffRecordSession<'_> {
    /// Keeps `binding` in this exact instance for wait `wait_id` of the held
    /// call `call_ref`, whose first typed ask did not open (FIX 4520).
    pub(crate) fn retain_code_consent_ask(
        &self,
        wait_id: EntityId,
        call_ref: EntityId,
        binding: Arc<SessionWitnessBinding>,
    ) -> Result<()> {
        let kept = &self.entry.code_consent_asks;
        kept.locked()?.insert(
            wait_id,
            RetainedCodeConsentAsk {
                wait_id,
                call_ref,
                binding,
            },
        );
        // Close publishes `closing` before it clears the keep, so an ask
        // kept after that clear sees it here and goes.
        if !self.is_open_for_witness() {
            kept.locked()?.remove(&wait_id);
        }
        Ok(())
    }
}

impl OffRecordSessionRegistry {
    /// Every ask each live session keeps (FIX 4520), read from the
    /// published snapshot. RAM only.
    pub(crate) fn retained_code_consent_asks(&self) -> Result<Vec<RetainedCodeConsentAsk>> {
        let mut retained = Vec::new();
        self.each_code_consent_asks(|kept| {
            retained.extend(kept.locked()?.values().cloned());
            Ok(())
        })?;
        Ok(retained)
    }

    /// Drops the kept ask of wait `wait_id` from the live session that
    /// keeps it (FIX 4520). A wait names one held call, so at most one
    /// session keeps it.
    pub(crate) fn release_code_consent_ask(&self, wait_id: EntityId) -> Result<()> {
        self.each_code_consent_asks(|kept| {
            kept.locked()?.remove(&wait_id);
            Ok(())
        })
    }
}
