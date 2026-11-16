//! Purposes of the native check record (`oneiron::check_record`; ARCH-0068
//! `#rc5-check-reuse`, FIX [L4-30-CHECK-REUSE-RECORD]).
//!
//! A check record keeps, for each input part the engine captured before the command
//! ran, its fingerprint, and compares them when the check finishes. Environment values
//! are never stored: the record keeps their names and the fingerprint of the whole map.
//! A passed check on a pinned tree is filed under a reuse key made from those
//! fingerprints. Each fingerprint has one part: the value's canonical bytes.

purposes! {
    /// A recorded check's command (`CheckInputVersions.command_digest`). Part: the
    /// argument list.
    COMMAND = "oneiron.check_record.command.v1";

    /// A recorded check's toolchain (`CheckInputVersions.toolchain_digest`). Part: the
    /// toolchain map, name to version.
    TOOLCHAIN = "oneiron.check_record.toolchain.v1";

    /// A recorded check's environment (`CheckInputVersions.environment_digest`). Part:
    /// the environment map, name to value.
    ENVIRONMENT = "oneiron.check_record.environment.v1";

    /// A reusable check's reuse key (`check_record::reuse::reuse_key`), the key of its
    /// inputs index row. Part: the repo, the ref, the pinned tree and the command,
    /// toolchain and environment fingerprints, as one record.
    REUSE_KEY = "oneiron.check_record.reuse_key.v1";
}

legacy_purposes! {}
