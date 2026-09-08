//! ICS feed poll runner and imported-claim admission (CAL-02, ONE-1784).
//!
//! The v1 read path for secret-URL calendar feeds. The data flow is fixed by
//! the ratified blueprint:
//!
//! 1. An owner-configured SECRET custody `secret_ref` names the encrypted
//!    secret ICS URL. Poll payloads carry the `secret_ref`, NEVER the URL.
//! 2. [`enqueue_ics_feed_poll`] places one deduped `calendar.ics.poll`
//!    attempt on the existing attempt queue — no new recurrence primitive.
//! 3. The fetcher resolves the custody record and touches the URL only at
//!    the HTTP egress door ([`CustodyDoorIcsFeedFetcher`]); a 304 is a true
//!    no-op plus re-enqueue; a complete 200 archives the raw body, parses,
//!    hashes, and only then diffs.
//! 4. UID resolution runs through [`super::passport`]'s UID-first index
//!    before anything is minted; fuzzy matching is not part of the adapter.
//! 5. The per-`(system × UID)` diff: create/attach, skip, update, or mark
//!    one source's passport absent. EVENT cancellation derives through
//!    `calendar.status` only when every live inbound passport reports
//!    absence — never on a parse/fetch failure.
//! 6. Every semantic claim candidate is `ClaimSource::Imported` and crosses
//!    the Gate through `admit_imported_evidence_claim*`; immediately before
//!    each admission the candidate passes through CAL-09's
//!    [`super::safeguard::screen_then_claim`] hook, and admission runs from
//!    the typed `CalendarAdmissionRequest` — no zero-argument claim closure,
//!    no direct `put_claim`. Superseding admissions (passport updates,
//!    source absence) cross the same hook: [`super::passport`] owns only the
//!    scoped claim replacement, never an admission of its own.
//! 7. Success and 304 both re-enqueue with bounded cadence jitter. A
//!    provider-side secret-URL reset pauses loudly: paused state on the
//!    attempt row and the feed cursor, one inbox exception, no retry storm,
//!    no event cancellation.
//!
//! ## Declared deviations from the blueprint
//!
//! * SECRET-02's `inject_secret_at_door` / `materialize_secret_lease` are not
//!   merged at this branch base, so [`CustodyDoorIcsFeedFetcher`] implements
//!   the door inline: it resolves via `Vault::resolve_secret_ref` and reads
//!   the value through the crate-private `get_secret_value_in_txn` door
//!   (binding-enforced), consuming it inside the transport call so the URL
//!   never escapes the fetch. The internals swap to the formal SECRET-02 API
//!   with no signature change when it lands.
//! * No HTTP client stack exists at HEAD and Cargo manifests are non-claims
//!   for this lane, so the egress itself is a host-injected
//!   [`IcsHttpTransport`]; the reqwest reservation lands with its owner.

mod admission;
mod fetch;
mod poll;

// Moved bodies still spell `super::ics`, `super::passport`, and
// `super::safeguard` (their `super` used to be `calendar`); these aliases keep
// those paths byte-identical now that `super` is `ingest`.
pub(crate) use super::{ics, passport, safeguard};

pub(crate) use self::admission::admit_calendar_import_claim;
pub use self::admission::ics_import_actor_id;
pub use self::fetch::{
    CustodyDoorIcsFeedFetcher, IcsFeedFetcher, IcsFeedSource, IcsFetchResponse, IcsHttpResponse,
    IcsHttpTransport,
};
pub use self::poll::{
    ICS_POLL_ATTEMPT_KIND, IcsFeedCursorSnapshot, IcsFeedPauseException, IcsFeedPollConfig,
    IcsFeedPollPayload, IcsPollRunState, enqueue_ics_feed_poll, ics_feed_cursor_snapshot,
    ics_feed_pause_exceptions, ics_feed_poll_dedupe_key, run_ics_feed_poll,
    run_ics_feed_poll_with_screener,
};

use sha2::{Digest, Sha256};

use super::CalendarError;
use crate::entity_id::EntityId;

pub(crate) fn derive_entity_id(domain: &[u8], key: &[u8]) -> crate::Result<EntityId> {
    let digest = Sha256::digest([domain, key].concat());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
}

pub(crate) fn credential(context: &'static str, err: &crate::Error) -> CalendarError {
    CalendarError::IcsCredential {
        reason: format!("{context}: {err}"),
    }
}

pub(crate) fn ingest(reason: &'static str) -> CalendarError {
    CalendarError::IcsIngest {
        reason: reason.to_owned(),
    }
}
