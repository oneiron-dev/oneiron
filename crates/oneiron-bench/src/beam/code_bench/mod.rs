//! CODE-BENCH (ARCH-0042 #code-bench, owner intent 2026-10-21, cut by 90%):
//! a small dogfood check of Oneiron CODE that works for us, not a published
//! benchmark. Three checks over three merged PRs of our own repo: memory on
//! and off, grep against symbol and graph reads, and three writers through
//! Oneiron's fork, proposal and merge path against plain Git worktrees.
//!
//! The harness never runs an agent, so building it spends no prompt.
//! `code-bench-pack` materializes each ready cell (its world, prompt, tools
//! and MCP servers) for a driver; a missing piece marks the arm not ready,
//! and nothing is faked. The task's own tests stay sealed from the writer.
//!
//! `code-bench` grades what the writers left: the PR's sealed tests, diff
//! size, and from each transcript the turns, tokens, files opened, time and
//! any call outside the arm's profile. A failed run is kept and counted.
//!
//! `oneiron-bench beam code-bench-pack <plan.json>`;
//! `oneiron-bench beam code-bench <attempts.json>`.

mod grade;
mod manifest;
mod pack;
mod profile;
mod transcript;

pub(super) use self::{grade::grade, pack::write_pack};
