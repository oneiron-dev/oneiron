//! Consolidated integration-test binary: five former standalone
//! `tests/*.rs` Cargo targets compiled and linked once.

mod agent_credentials;
mod booking_agent_api;
mod campaign_surface_oracle;
mod core_discover;
mod first_owner_bootstrap;
mod history_import;
mod mcp_booking;
mod mcp_oracle;
mod owner_backup;
mod remote_pairing;
// SIGTERM through `libc::kill` is Unix-only.
#[cfg(unix)]
mod reopen_after_restart;
mod ws_sync;
