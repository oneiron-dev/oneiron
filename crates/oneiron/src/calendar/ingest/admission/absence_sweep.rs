//! Which live passports a pull's absence sweep reads as its own source's,
//! and which of them the pull leaves out. The claim door can store a
//! passport's system name or UID as a custody handle, so each is read as
//! custody reads it where it is pinned, as the keyed lookup reads them
//! (CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP).

use std::collections::BTreeSet;

use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarPassportValue;
use crate::calendar::passport::{CalendarSystems, passport_uid_among};
use crate::code_run::CompareKnown;
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// One sweep's source: its system, the vault's calendar systems, the UIDs a
/// sync delta names (every UID of the system when `None`), and the
/// `(UID, instance)` pairs the pull carries.
pub(super) struct SweepSource<'s> {
    pub(super) vault: &'s Vault,
    pub(super) system: &'s str,
    pub(super) systems: CalendarSystems,
    pub(super) only_uids: Option<&'s BTreeSet<&'s str>>,
    pub(super) present: BTreeSet<(&'s str, Option<u64>)>,
}

impl SweepSource<'_> {
    /// Whether the pull leaves out `value`, a live passport of `event_ref`
    /// (`instance` its exception start, `None` for no exception); `None`
    /// when the passport is not this sweep's: another system's, or of a UID
    /// the delta does not name. The stored system name is the source's as
    /// [`CalendarSystems::carries`] reads it, and the stored UID is one the
    /// pull names as [`passport_uid_among`] reads it on `event_ref`.
    ///
    /// # Errors
    ///
    /// Store failures, the custody read's, and an exception claim that does
    /// not decode.
    pub(super) fn omission(
        &self,
        event_ref: &EntityId,
        instance: Option<u64>,
        value: &CalendarPassportValue,
        known: &CompareKnown<'_>,
    ) -> Result<Option<bool>, CalendarError> {
        if !self.systems.carries(&value.system, self.system, known)? {
            return Ok(None);
        }
        if let Some(only) = self.only_uids
            && !only.contains(value.uid.as_str())
        {
            let named: Vec<&str> = only.iter().copied().collect();
            if !passport_uid_among(self.vault, event_ref, &value.uid, &named, known)? {
                return Ok(None);
            }
        }
        if self.present.contains(&(value.uid.as_str(), instance)) {
            return Ok(Some(false));
        }
        let carried: Vec<&str> = self
            .present
            .iter()
            .filter(|(_, at)| *at == instance)
            .map(|(uid, _)| *uid)
            .collect();
        Ok(Some(!passport_uid_among(
            self.vault, event_ref, &value.uid, &carried, known,
        )?))
    }
}
