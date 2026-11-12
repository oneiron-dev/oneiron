//! `oneiron-testkit`: what every door test and the E2E seeding script stand
//! on (Fable's verdict 2026-11-09, sections 3 and 4; owner ruling TEST-SUITE
//! = A, 9 Nov 22:52).
//!
//! | Need | Module |
//! |---|---|
//! | One vault per test, seeded once | [`fixture`]: [`FixtureVault`], [`TestVault`] |
//! | Time that moves only when the test moves it | [`clock`]: [`FakeClock`] |
//! | A model that answers from a script | [`provider`]: [`ScriptedProvider`] (HTTP), [`ScriptedBackend`] (in process) |
//! | Embeddings with no model | [`embedder`]: [`HashingEmbedder`] |
//! | A server on a free port | [`server`]: [`ServerProcess`] |
//! | Crashes, lost leases, failing providers | [`fault`] |
//! | A public verb, by name, in process | [`door`] |
//! | Receipts read through the public door | [`receipt`] |
//! | No sleeps, wall clock, network or real model | [`lint`] |
//! | The PR, nightly and quarantine tiers | [`quarantine`] |
//! | Tests waiting on a product door, nightly only | [`pending_door`] |
//! | Private words that must not reach a reader outside their audience | [`canary`]: [`CanaryVault`] |
//! | One Dreamer wake pass in process, its model scripted | [`dreamer`]: [`DreamerPass`] |
//!
//! The rules a door test keeps (Fable, section 4):
//! 1. The test's name is the promise, in one sentence a user or agent would say.
//! 2. It enters through a door: a public verb, an HTTP route, the CLI or an E2E
//!    flow. Never an engine function. With no door, file the door; do not
//!    write the test.
//! 3. It asserts only on what leaves the door: the response, the receipt,
//!    state read back through another door, the authority log.
//! 4. One scenario per test; many assertions are fine.
//! 5. It runs red on main and green on the PR head, and the PR shows both.
//! 6. An area that promises anything under failure gets one failure test.
//! 7. It uses this kit: a fixture vault, the fake clock, the scripted provider,
//!    the hashing embedder, a free port. No sleeps, no network, no real model.
//! 8. A door test runs under two seconds, an E2E case under 30.
//! 9. A test is not edited to pass unless its promise changed, and the PR says so.
//! 10. Deleting a test that restates the code is a good PR.
//!
//! Everything here reaches the engine through public API and public verbs.
//! This crate adds no door into the engine and is a dev-dependency only.

pub mod canary;
pub mod clock;
pub mod door;
pub mod dreamer;
pub mod embedder;
pub mod fault;
pub mod fixture;
pub mod lint;
pub mod pending_door;
pub mod provider;
pub mod quarantine;
pub mod receipt;
#[cfg(unix)]
pub mod server;

pub use canary::{CanaryActor, CanaryVault};
pub use clock::{FAKE_EPOCH, FakeClock};
pub use dreamer::{DreamerPass, DreamerPassReport};
pub use embedder::HashingEmbedder;
pub use fixture::{FixtureCache, FixtureError, FixtureVault, TestVault};
pub use provider::{PromptDigest, Reply, ScriptedBackend, ScriptedProvider, Step};
#[cfg(unix)]
pub use server::{ServerProcess, ServerSpec};
