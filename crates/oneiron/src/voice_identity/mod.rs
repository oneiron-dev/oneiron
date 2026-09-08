//! VOX-02 voice identity substrate: consent log, enrollment, local matching.
//!
//! One embedding space at a time, consent-gated enrollment, deterministic
//! enrolled-principal matching, residual-only stranger clustering, and
//! non-biometric invite/elimination naming. Every biometric row is a private
//! home-node `vault_meta` sidecar (the `session_lifecycle` / `disclosure`
//! enforcement-record pattern): no entity type byte is allocated, so a
//! centroid can never reach retrieval, context assembly, or sync. Withdrawal
//! is therefore a plain atomic deletion of those private rows.
//!
//! Split of authority:
//!
//! * **Consent is the capability door.** Enrollment reads a stored
//!   [`VoiceConsentEventV1`] that is `Granted`, covers the requested purpose,
//!   and precedes the request. A later withdrawal for the same purpose
//!   permanently closes that door; a granted record alone is not enough.
//! * **Matching is local and total.** Segment vectors are compared only with
//!   active centroids in the SAME embedding space. A cross-space comparison is
//!   an error, never a low score, so a model/revision/preprocessing change
//!   forces re-enrollment instead of silently reusing an old centroid.
//! * **Naming never lowers the bar.** Invite elimination runs after residual
//!   clustering, only on an unambiguous one-to-one remainder, and changes the
//!   display/reference evidence — never a biometric score.
//!
//! The resolved roster is vector-free by construction and is the only thing
//! the ILD-3 interlocutor seam consumes. `owner_print_matched` stays display
//! corroboration: an authenticated session remains the sole path to an
//! `Owner`-class interlocutor entry.

mod codec_core;
mod codec_records;
mod math_keys;
mod storage_admission;
mod types;
mod vault;

pub use self::types::{
    VOICE_MATCH_THRESHOLD_DEFAULT, VOICE_MATCH_THRESHOLD_MAX, VOICE_MATCH_THRESHOLD_MIN,
    VoiceAttributionEvidence, VoiceConsentBasis, VoiceConsentEventV1, VoiceConsentState,
    VoiceEmbeddingFamily, VoiceEmbeddingSpaceV1, VoiceEnrollmentOrigin, VoiceEnrollmentRequest,
    VoiceEnrollmentSampleV1, VoiceMatchPolicy, VoiceMatchRequest, VoicePrintCalibration,
    VoicePrintPurpose, VoicePrintRecordV1, VoiceResolvedSegment, VoiceSegmentEmbeddingInput,
    VoiceSessionRosterV1, VoiceWithdrawalReceipt, VoiceWithdrawalRequest,
};

#[cfg(test)]
pub(crate) use self::vault::{put_raw_voice_roster_for_test, put_voice_roster_for_test};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{codec_core::*, codec_records::*, math_keys::*, storage_admission::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_RELATIONSHIP;
#[cfg(test)]
use rmpv::Value;
