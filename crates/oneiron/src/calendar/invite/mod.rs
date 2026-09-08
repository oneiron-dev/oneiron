//! Outbound iMIP invite adapter (CAL-04, ONE-1786).
//!
//! One calendar-specific adapter over the already-shipped OF-327 outbound
//! spine. Nothing here mints a second dispatcher, ledger, gate, transport,
//! grant system, connector queue, entity type, edge kind, or claim predicate:
//! the verb `calendar.invite` is registered in the ordinary capability
//! manifest, the payload is frozen by the ordinary dispatch pipeline, the
//! durability and governance rails are the ordinary ones.
//!
//! What this module owns is exactly the calendar half:
//!
//! * **The frozen five-field payload.** [`CalendarInvitePayload`] is C7's exact
//!   contract — `{method, uid, sequence, ics_blob_ref, recipient}`, in that
//!   order, uppercase iMIP method, closed to unknown keys. The frozen body
//!   carries the blob *reference*; raw `.ics` bytes never enter it.
//! * **The UID/SEQUENCE law.** A UID is minted once, at the first confirm, and
//!   reused forever; every update and cancel bumps `SEQUENCE` on the SAME UID.
//!   The state lives in the CAL-00 `calendar.passport` claim
//!   ([`CalendarPassportValue`]) with direction `outbound` — no local passport
//!   type, no new predicate. A connector retry replays the frozen payload and
//!   never re-enters [`admit_calendar_invite`], so it can neither mint a UID
//!   nor bump a sequence.
//! * **Hygiene from vault evidence only.** [`CalendarInviteHygieneContext`] has
//!   no public constructor and no public field: it is hydrated at the
//!   chokepoint from live vault state. A caller cannot hand the engine a
//!   consent boolean, because there is no API that accepts one.
//!
//! ## The order is fixed
//!
//! [`admit_calendar_invite`] runs exact decode → emit/state validation →
//! vault-only hygiene hydration → hygiene evaluation, and hands back a
//! [`CalendarInviteAdmission`] whose `CalendarInviteAdmission::commit_in_txn`
//! joins the caller's existing durable transaction. That is what makes "no
//! bumped sequence survives without its frozen intent" true by construction:
//! the passport head and the attempt/TASK land in one write transaction or
//! neither does.

mod admission;
mod hygiene;
mod mime;
mod payload;

#[cfg(test)]
mod tests;

pub use self::admission::{
    CALENDAR_INVITE_PASSPORT_SYSTEM, CalendarInviteAdmission, CalendarInviteStateChange,
    admit_calendar_invite,
};
pub use self::hygiene::{CalendarInviteConsentBasis, CalendarInviteHygieneContext};
pub use self::mime::{
    CalendarInviteMimePart, build_calendar_invite_mime_part, read_calendar_invite_ics,
};
pub use self::payload::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_MEDIA_TYPE, CALENDAR_INVITE_PART_FILENAME,
    CALENDAR_INVITE_TOOL_DESCRIPTOR, CALENDAR_INVITE_VERB, CalendarInviteMethod,
    CalendarInvitePayload, decode_frozen_calendar_invite,
};

use super::CalendarError;
#[cfg(test)]
use super::claims::{CalendarPassportDirection, PREDICATE_CALENDAR_ATTENDEE};
use super::{claims, ics, passport};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::channel_identity::{ChannelIdentityState, SelfHeldShape};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::temporal::TimeRange;

#[cfg(test)]
use self::hygiene::{primary_calendar_domain, sending_identity};

/// Standalone-transaction form of [`CalendarInviteAdmission::commit_in_txn`],
/// for unit tests that exercise the passport law without standing up the whole
/// schedule chokepoint. Production always composes into the caller's txn — that
/// composition is the atomicity guarantee — so this is deliberately test-only.
#[cfg(test)]
fn commit_admission(
    vault: &Vault,
    admission: &CalendarInviteAdmission,
    now: u64,
) -> Result<(), CalendarError> {
    let mut wtxn = vault.store.env.write_txn().map_err(crate::Error::from)?;
    admission.commit_in_txn(vault, &mut wtxn, now)?;
    wtxn.commit().map_err(crate::Error::from)?;
    Ok(())
}
