//! Moved from `crates/oneiron/src/linkedin_connector/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_linkedin_policy::LINKEDIN_CHANNEL;
pub use oneiron_linkedin_policy::LINKEDIN_CONNECT_REQUEST_VERB;
pub use oneiron_linkedin_policy::LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS;
pub use oneiron_linkedin_policy::LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS;
pub use oneiron_linkedin_policy::LINKEDIN_DEFAULT_DAILY_DM_CAP;
pub use oneiron_linkedin_policy::LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP;
pub use oneiron_linkedin_policy::LINKEDIN_SEND_DM_VERB;
pub use oneiron_linkedin_policy::LinkedInAccountRiskLimits;
pub use oneiron_linkedin_policy::LinkedInEscalationConfig;
pub use oneiron_linkedin_policy::LinkedInKillSwitchState;
pub use oneiron_linkedin_policy::LinkedInLoginHandoff;
pub use oneiron_linkedin_policy::LinkedInManagedTransport;
pub use oneiron_linkedin_policy::LinkedInMcpServerHarness;
pub use oneiron_linkedin_policy::LinkedInNetworkRoute;
pub use oneiron_linkedin_policy::LinkedInPasswordCustody;
pub use oneiron_linkedin_policy::LinkedInSandboxHostConfig;
pub use oneiron_linkedin_policy::LinkedInSandboxRuntime;
pub use oneiron_linkedin_policy::LinkedInSeatDispatchState;
pub use oneiron_linkedin_policy::LinkedInSeatPolicyAction;
pub use oneiron_linkedin_policy::LinkedInSeatPolicyDecision;
pub use oneiron_linkedin_policy::LinkedInSeatSandboxPolicy;
pub use oneiron_linkedin_policy::LinkedInSelectorDriver;

/// Default initial lookback for timestamped LinkedIn messages.
pub const DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

pub const MAX_LINKEDIN_ADDRESS_BYTES: usize = 512;

pub const MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS: u64 = 366 * 24 * 60 * 60;
pub mod inbox_sync;
