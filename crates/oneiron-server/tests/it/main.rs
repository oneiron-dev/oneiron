//! Consolidated integration-test binary: five former standalone
//! `tests/*.rs` Cargo targets compiled and linked once.

mod agent_credentials;
mod ai_serve;
mod api_cli;
mod booking_agent_api;
// The broker runs as a second user through a user namespace: Linux only.
#[cfg(target_os = "linux")]
mod broker_paid_leg;
mod campaign_surface_oracle;
mod code_mode_compaction;
mod core_discover;
#[path = "../support/fake_llm.rs"]
mod fake_llm;
mod first_owner_bootstrap;
mod history_import;
// The secret file's owner-only mode and SIGTERM are Unix-only.
#[cfg(unix)]
mod host_re_root;
mod import_claims;
// The wake ledger talks to Hypnos over a Unix socket.
#[cfg(unix)]
mod managed_ledger_wire;
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
// Restarts the shipped server through `reopen_after_restart`'s helpers.
#[cfg(unix)]
mod slip_clock;
mod ws_sync;
