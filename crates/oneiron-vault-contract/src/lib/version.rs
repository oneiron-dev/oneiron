//! Wire version constants, SLIM gating and the revisions of the additive
//! extensions a v3 vault reports on `Ping`.

use serde::{Deserialize, Deserializer};

/// First contract version carrying the SLIM rung. The v1 -> v2 bump is
/// additive-only: every v1 request and response keeps byte-identical semantics
/// except `Ping.contract_version`, which now reports 2 as the negotiation signal;
/// v1 peers are never sent a v2-only request.
pub const SLIM_CONTRACT_VERSION: u32 = 2;

/// The wire version this crate speaks. v3 adds the typed ctl refusal
/// ([`CtlResponse::Refused`](crate::CtlResponse::Refused)): a vault frozen for
/// reap answers a write it refuses with the bound it names, where v2 answered
/// `Ok { ok: false }`. v3 also carries the vault's live training setting
/// ([`ManagedTrainingSetting`](crate::ManagedTrainingSetting)) on every ledger
/// report, required on `LedgerUpdate` and `PrepareReap` alike, and how the
/// vault came up ([`ManagedReadiness`](crate::ManagedReadiness)) on every
/// `Ping`. v3 also carries the training purge ctl request
/// ([`CtlRequest::TrainingPurge`](crate::CtlRequest::TrainingPurge)), the
/// owner-signing recovery ctl request
/// ([`CtlRequest::RecoverOwnerSigning`](crate::CtlRequest::RecoverOwnerSigning))
/// and the legal holds ctl request
/// ([`CtlRequest::LegalHolds`](crate::CtlRequest::LegalHolds)), each with a
/// build floor: a supervisor sends one only to vaults built at or after it,
/// and a v3 vault built before it answers it as an unknown request. The
/// managed backup facts on `Ping`
/// ([`ManagedBackupFacts`](crate::ManagedBackupFacts)) carry a build floor
/// too: a v3 vault built before it sends none, which a supervisor reads as
/// unknown. So do the revisions of the shared owner-path rule
/// (`settings_paths_revision`, FIX 5187) and of the artifact origin's public
/// slug binding (`artifact_public_slug_revision`, FIX 5389) on `Ping`; the
/// latter's `--artifact-public-slug` flag is passed only to an installed
/// engine at or after its floor, since a `Ping` comes after the flags are
/// parsed. The supervisor SLIM recovery surface (FIX 5186) carries a build
/// floor too: the `slim_status` and `unslim` ctl requests and the optional
/// `wait_id` on `Shed`, proven by `slim_recovery_revision` on `Ping`
/// ([`SLIM_RECOVERY_REVISION`](crate::slim_control::SLIM_RECOVERY_REVISION)).
/// A v3 vault built before it answers either request as unknown and ignores
/// a `wait_id`, shedding unguarded, so a supervisor relies on that guard only
/// after the vault's `Ping` reports the revision. The cold managed restore
/// start mode ([`restore`](crate::restore): `--restore`, its two pipes, the
/// commit marker and the `restore_status` ctl request) carries a build
/// floor too, at the engine revision it merged in: a supervisor starts a
/// restore only on an installed engine at or after it, since an older one
/// refuses the flag before it touches anything. Supervisor and vault move
/// to v3 together; no v2 reader is kept.
pub const CONTRACT_VERSION: u32 = 3;

/// True when a peer advertising `version` accepts the SLIM ctl surface.
/// Supervisors ping first and send `Shed` only when this holds. With a v1 peer,
/// they skip the shed rung and retain the existing reap protocol. It proves
/// nothing of the recovery surface (`slim_status`, `unslim`, `Shed.wait_id`):
/// only `Ping`'s `slim_recovery_revision` does.
#[must_use]
pub const fn supports_slim(version: u32) -> bool {
    version >= SLIM_CONTRACT_VERSION
}

/// One extension's revision on `Ping` as a supervisor reads it: a value that
/// is not a whole number a u32 holds reads as `None`, unknown, and never
/// fails the `Ping` it rides.
pub(super) fn observed_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .and_then(|revision| u32::try_from(revision).ok()))
}
