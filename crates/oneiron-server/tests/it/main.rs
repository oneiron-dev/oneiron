//! Consolidated integration-test binary: five former standalone
//! `tests/*.rs` Cargo targets compiled and linked once.

mod ai_serve;
mod booking_agent_api;
mod campaign_surface_oracle;
mod core_discover;
#[path = "../support/fake_llm.rs"]
mod fake_llm;
mod first_owner_bootstrap;
mod mcp_booking;
mod mcp_oracle;
mod owner_backup;
mod remote_pairing;
// SIGTERM through `libc::kill` is Unix-only.
#[cfg(unix)]
mod reopen_after_restart;
mod skills_pack;
mod ws_sync;
