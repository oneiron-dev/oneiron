//! Engine-owned typed git subprocess boundary (ONE-1903, RC6/ARCH-0068).
//!
//! Every engine-initiated git call is a GitWire-class effect. The module holds
//! four load-bearing invariants:
//!
//! 1. **Identity is the object store.** A [`GitWireRepo`] is only obtainable by
//!    proving, through git, that a `RepoRef`, a working root, and a pinned
//!    commit all name one verified canonical git common directory. Durable rows
//!    are keyed by that store, never by a rendered path.
//! 2. **Stored claims are current claims.** A durable record replays only while
//!    the ref postcondition it recorded still holds, so an `A -> B -> A` ref
//!    cycle can never be answered from the first receipt.
//! 3. **One transactional publication path.** Every ref move — direct, staged,
//!    or recovered — is published by a single `update-ref --stdin` transaction
//!    whose durable intent was written first, so a crash is always recoverable
//!    and a partial multi-ref result is never certified.
//! 4. **The boundary is closed.** `spawn_git` is the crate's only production
//!    git process constructor: a pinned executable, a cleared environment, a
//!    fixed config policy that disables every repository-configured program,
//!    bounded runtime and output, and redacted failures.
//!
//! Absence is always read from a positive signal (`for-each-ref` output,
//! `cat-file --batch-check` `missing`, `rev-list --missing=print`), never from
//! an exit code, so an expected absence can never be confused with a fatal git
//! failure.

mod argv;
mod bridge;
mod checkout;
mod config;
mod env;
mod failure;
mod ids;
mod objects;
mod operation;
mod plan;
mod process;
mod record;
mod repo;
mod wire_publish;
mod wire_reads;
mod wire_stage;
mod wire_store;
mod wire_worktree;

#[cfg(test)]
mod tests;

pub use self::config::{
    GIT_WIRE_CHECKOUT_ROOT_NAME, GIT_WIRE_CONFIG_POLICY, GIT_WIRE_DOMAIN, GIT_WIRE_FIXED_ENV,
    GIT_WIRE_INHERITED_ENV_KEYS, GIT_WIRE_KEEP_REF_PREFIX, GIT_WIRE_RECORD_KEY_PREFIX,
    GIT_WIRE_REPO_LOCK_FILE_NAME, GIT_WIRE_SCHEMA_VERSION,
};
pub use self::env::GitWireProcessEnv;
pub use self::failure::{GitWireFailure, GitWireFailureClass, GitWireResult};
pub use self::ids::{GitOid, GitRefExpectation, GitRefName, GitRefPublication, ObservedGitRef};
pub use self::objects::{GitCommitHeader, GitCommitRequest, GitTreeEntry};
pub use self::operation::{GitWireEffectClass, GitWireOperation};
pub use self::plan::{GitWireObjectWrite, GitWirePlan, GitWirePlannedOid};
pub use self::record::{
    GitWireCommitOutcome, GitWirePrepared, GitWireReceipt, GitWireRecordState, GitWireRejection,
};
pub use self::repo::{GitWireRepo, GitWireRepoIdentity};
pub use self::wire_reads::GitWire;

pub(crate) use self::bridge::{redact_bridged_failure, run_bridged_git_argv};
use self::process::GitWireProcessOutput;
pub(crate) use self::repo::lock_repository;
// The guard type itself is only named outside this module by the
// `repo_mutation` queue tests; production callers hold it through
// `lock_repository`'s return type.
#[cfg(test)]
pub(crate) use self::repo::GitWireRepoGuard;

// The flat git_wire.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every git_wire-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{
    argv::*, bridge::*, failure::*, operation::*, process::*, record::*, wire_reads::*,
    wire_stage::*, wire_worktree::*,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutRepoOps, PushedHeadReceipt, TeardownReceiptMatch,
};
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use std::ffi::OsString;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use std::time::Duration;
