//! Who actually receives a repo read's bytes, as its host proved it (FIX
//! 7608 slice 2b-ii-A, ASK 1 addition).
//!
//! A Memory handle the host bound to an MCP tool call or a run reads repo
//! bytes masked (FIX 8961). When the host also proves who the receiving
//! agent is (its registered actor, never the credential's owner standing in
//! for one), it binds that agent here, and a per-file read that says why
//! may then ask the owner for the file's real bytes through the shipped
//! file reveal. The binding admits nothing: the engine still revalidates
//! the agent, its scope and the live grant at every read, and an unknown
//! recipient reads masked.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B binds a proven recipient at the MCP and run hosts"
)]

use oneiron_contracts::entity_id::EntityId;

