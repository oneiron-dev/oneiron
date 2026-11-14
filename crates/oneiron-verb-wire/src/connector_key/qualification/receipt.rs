//! Moved from `crates/oneiron/src/connector_key/qualification/receipt.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub const CONNECTOR_QUALIFICATION_SUITE: &str = "oneiron.connector.qualification.v1";

/// A built-in connector pack's suite: the engine's own hash-verified adapter
/// rides its Verified setup connection instead of a probe suite. Only an
/// embedded built-in source may carry it.
pub const SETUP_CHECK_QUALIFICATION_SUITE: &str = "oneiron.connector.setup_check.v1";

/// A built-in connector pack's isolated probe (FIX 710): the host runs each
/// declared connection's own read-only identity call through the channel's
/// client, on fresh transports, with no send and no vault write. Only an
/// embedded built-in source may carry it.
pub const BUILTIN_PROBE_QUALIFICATION_SUITE: &str = "oneiron.connector.builtin_probe.v1";

/// The OpenAI proxy's own connector (ARCH-0028): the engine is the
/// connector, so no probe suite runs. Its admission is the owner's stamp on
/// the proxy's fixed slate. Only the proxy connector's key may carry it.
pub const PROXY_ADMISSION_QUALIFICATION_SUITE: &str = "oneiron.connector.proxy_admission.v1";

/// The owner's attestation in place of the probe suite (CONNECTOR-QUALIFY =
/// A, owner ruling 2026-10-30 05:52 JST): a connector the suite cannot grade
/// activates on his authenticated act. The probes stay the default; any
/// catalog connector's key may carry it.
pub const OWNER_ATTESTED_QUALIFICATION_SUITE: &str = "oneiron.connector.owner_attested.v1";
