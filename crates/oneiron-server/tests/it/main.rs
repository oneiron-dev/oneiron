//! Consolidated integration-test binary: five former standalone
//! `tests/*.rs` Cargo targets compiled and linked once.

mod agent_credentials;
mod ai_serve;
mod booking_agent_api;
mod campaign_surface_oracle;
mod core_discover;
#[path = "../support/fake_llm.rs"]
mod fake_llm;
mod first_owner_bootstrap;
mod history_import;
// The secret file's owner-only mode and SIGTERM are Unix-only.
#[cfg(unix)]
mod host_re_root;
mod mcp_oracle;
// The credential file's owner-only mode and SIGTERM are Unix-only.
#[cfg(unix)]
mod mcp_stdio_agent;
mod notes_import;
mod owner_backup;
mod remote_pairing;
// SIGTERM through `libc::kill` is Unix-only.
#[cfg(unix)]
mod reopen_after_restart;
mod ws_sync;
