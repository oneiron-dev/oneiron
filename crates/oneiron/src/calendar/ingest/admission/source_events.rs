//! A pack calendar source's EVENTs (FIX 12559; MAIL-SHARE = A). A system
//! named `mail_pack:<source>` lands EVENTs of its own: one per source and
//! UID, its id derived from both, so two people's copies of one meeting
//! never share a row and a person's copy never attaches to another's. The
//! birth commit stamps each with the source's audience and binds it there
//! ([`crate::mail_pack::calendar_source_landing_in`], called from
//! [`PollAdmission::mint_event_with_id`]), so its details read only to the
//! calendar's owner, or the vault when the owner shares it. Everything
//! after the identity (passport, properties, drift, cancellation) is the
//! ordinary admission's.

use super::*;
use crate::calendar::passport::classify_event_passport;
use crate::entity_id::derived_domains::MAIL_CALENDAR_EVENT;

/// The pack calendar source a system names: its id and audience policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::calendar) struct PackCalendarSource {
    pub(in crate::calendar) source: EntityId,
    pub(in crate::calendar) audience: EntityId,
}

/// The pack calendar source `system` names, if it names one.
///
/// # Errors
///
/// A system with the pack's prefix that names no calendar source: it never
/// lands unbound.
pub(in crate::calendar) fn pack_source(
    vault: &Vault,
    system: &str,
) -> Result<Option<PackCalendarSource>, CalendarError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    Ok(
        crate::mail_pack::calendar_source_of_system_in(vault, &txn, system)?
            .map(|(source, audience)| PackCalendarSource { source, audience }),
    )
}

/// A pack calendar source's EVENT id for `uid`.
pub(in crate::calendar) fn source_event_id(
    source: EntityId,
    uid: &str,
) -> Result<EntityId, CalendarError> {
    Ok(EntityId::derive(
        MAIL_CALENDAR_EVENT,
        &[source.as_bytes(), uid.as_bytes()],
    )?)
}

impl PollAdmission<'_> {
    /// [`Self::apply_event`] for a pack calendar source: the source-local
    /// EVENT, classified by its own passport, minted at its derived id when
    /// absent.
    pub(super) fn apply_source_event(
        &mut self,
        event: &ParsedVEvent,
        source: PackCalendarSource,
    ) -> Result<(), CalendarError> {
        let master = source_event_id(source.source, &event.uid)?;
        if let Some(original) = event.properties.recurrence_id_utc {
            if !self.source_event_stands(master, source)? {
                return Err(ingest("recurrence exception has no master in its source"));
            }
            return self.apply_exception_on(event, original, master);
        }
        let decision = if self.source_event_stands(master, source)? {
            classify_event_passport(
                self.vault,
                master,
                self.system,
                &event.uid,
                event.sequence,
                event.content_hash,
            )?
        } else {
            PassportDecision::CreateEvent
        };
        match decision {
            PassportDecision::CreateEvent => {
                let event_ref = self.mint_event_with_id(event, master)?;
                self.admit_properties(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::AttachToExisting { event_ref } => {
                self.admit_properties(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::SkipUnchanged { .. } | PassportDecision::MarkSourceAbsent { .. } => {}
            PassportDecision::UpdateExisting { event_ref } => {
                self.rewrite_event(event_ref, event)?;
                self.admit_properties(event_ref, event)?;
                let next = self.passport_value(event_ref, event, CalendarPassportPresence::Live)?;
                let body = screen_body(event);
                self.admit_superseding_passport(event_ref, &next, &body)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
        }
        Ok(())
    }

    /// Whether the source's EVENT `id` stands, bound to the source's
    /// audience. A row of another kind at that id, or an EVENT bound to
    /// another audience, is refused.
    fn source_event_stands(
        &self,
        id: EntityId,
        source: PackCalendarSource,
    ) -> Result<bool, CalendarError> {
        match self.vault.get_entity_type(&id)? {
            None => return Ok(false),
            Some(ENTITY_TYPE_EVENT) => {}
            Some(_) => {
                return Err(ingest(
                    "calendar source identity collides with another kind",
                ));
            }
        }
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        if crate::source_audience::binding_in(self.vault, &txn, &id)? != Some(source.audience) {
            return Err(ingest("calendar source EVENT is not bound to its source"));
        }
        Ok(true)
    }
}
