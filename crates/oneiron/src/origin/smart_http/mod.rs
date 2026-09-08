//! Git smart-HTTP serving over the vault (ARCH-0068 Phase A, ONE-1908).
//!
//! One subprocess model and one only: `git http-backend`. There is no gitoxide
//! serving engine here and no per-request upload-pack/receive-pack split — the
//! CGI backend is the whole wire, and every invocation is built from a frozen
//! argv and a closed environment.
//!
//! # The serve invariants this module carries
//!
//! - **Frozen argv / scoped env (RC6).** [`ServeCommand`] is built once and
//!   never mutated. Its argv always carries `-c core.hooksPath=<door-owned
//!   dir>` ahead of the verb, so no repository-supplied hook can ever run:
//!   `core.hooksPath` is a git *config key*, not an environment variable, and
//!   `git -c` reaches every git child a git child spawns.
//! - **Closed environment.** The child is spawned after `env_clear`, with
//!   exactly [`SERVE_BASE_ENV_KEYS`] plus the typed CGI request keys in
//!   [`SERVE_REQUEST_ENV_KEYS`]. Nothing is inherited from the ambient
//!   environment except `PATH`, and `GIT_HTTP_EXPORT_ALL=1` is the export pin.
//! - **Quarantine.** The vetted `pre-receive` hook decides while the received
//!   objects still sit under `GIT_QUARANTINE_PATH`, so a rejected push leaves
//!   refs unmoved and the objects unreachable — rejected before objects become
//!   durable. The hook enumerates every added or modified blob from the RAW
//!   diff and hands the door those blobs WHOLE, length-framed: no text patch is
//!   parsed, so binary bytes cannot slip past a patch grammar, and an
//!   extraction the origin cannot read whole is a refusal rather than an empty
//!   scan.
//! - **No substituted bytes.** Replacement-object lookup is OFF on every git the
//!   serve path runs: `GIT_NO_REPLACE_OBJECTS` is part of the closed baseline
//!   (an environment variable reaches every git a git spawns) and the vetted
//!   hook additionally passes `--no-replace-objects` to each of its own git
//!   children. A push that proposes a `refs/replace/*` name is refused in the
//!   door window on top of that, so no replacement can be planted through this
//!   wire at all. Without both, a planted `refs/replace/<oid>` would make the
//!   door's scan read benign substitute bytes while the original object is what
//!   the push makes durable.
//! - **Only journalable refs move.** The door window refuses a push whose
//!   proposed names the landing could not journal — names outside the GitWire
//!   ref grammar, a name proposed twice, or a batch larger than the GitWire
//!   publication bound — WHILE the objects are still quarantined. The landing's
//!   own parse is the last line of defence, not the first: discovering an
//!   unpublishable name after `git receive-pack` has moved refs would leave a
//!   mutated repository with no receipt.
//! - **Single writer (RA2).** A receive-pack holds the repository coordinator —
//!   the same advisory lock in the git common directory that
//!   [`crate::Vault::apply_repo_mutation`] and every GitWire ref effect take —
//!   across its WHOLE mutation window: it is acquired before the backend is
//!   spawned and released after the landing is journaled, so the ref mutation,
//!   the quarantine migration and the journaled advance cannot interleave with
//!   a queued repo mutation. The advance is journaled through GitWire's
//!   transactional publication. Repo refs and objects ride the git wire;
//!   nothing here writes the sync plane.
//! - **Receipts and replay.** Every landing produces a [`GitWireReceipt`](crate::git_wire::GitWireReceipt). The
//!   durable record is keyed by the exact publication, so a replayed outcome is
//!   answered from the record instead of re-running git, and no second record
//!   is written.
//!
//! # What this module deliberately does not do
//!
//! It mints no origin credential (Edge #2). The single thing it asks the
//! secret stack is the catastrophe dial's verdict on the `door:receive-pack`
//! effector, because a dial that cannot shut the push door shuts nothing that
//! matters — it READS that dial and mints nothing from it. It buffers no
//! request or response body, adds no size cap and no rate cap, and expands no
//! gix feature. `git_wire.rs` and `credential_door.rs` are consumed read-only;
//! this module owns neither.

mod advertise;
mod cgi_finish;
mod door;
mod door_window;
mod evidence;
mod hooks;
mod intent;
mod landing;
mod landing_lfs;
mod paths;
mod serve;
mod serve_cmd;

// The flat module reached its sibling as `super::publication`; the children
// keep that path through this seam.
use super::publication;

pub use self::door::{DoorAdmissionStamp, DoorSeam};
pub use self::door_window::{DoorWindowReport, DoorWindowVerdict};
pub use self::evidence::{ObservedRef, PackStats, ReceivePackOutcome, RefUpdate};
pub(super) use self::evidence::{RECEIVE_PACK_ADMISSION_PREDICATE, RECEIVE_PACK_OUTCOME_PREDICATE};
pub use self::hooks::DoorHooksDir;
pub use self::intent::{ReceivePackRefResult, ReceivePackRefStatus};
pub use self::landing::{ReceivePackAttribution, ReceivePackLanding, refs_already_applied};
pub use self::paths::{
    DOOR_PRE_RECEIVE_HOOK_NAME, DOOR_WINDOW_TIMEOUT, ORIGIN_DOOR_ROOT_NAME, ORIGIN_MAX_REF_UPDATES,
    ORIGIN_MAX_REPO_NAME_BYTES, ORIGIN_REFUSED_REF_PREFIX, ORIGIN_REPO_DIR_SUFFIX,
    ORIGIN_SERVING_ROOT_NAME, SERVE_BASE_ENV_KEYS, SERVE_REQUEST_ENV_KEYS, origin_repo_dir,
    origin_serving_root, validate_repo_name,
};
pub use self::serve::{ServeReport, ServeSink, serve, serve_with_provenance};
pub use self::serve_cmd::{ServeChild, ServeCommand, ServeRequest};

#[cfg(test)]
mod advertise_tests;
#[cfg(test)]
mod door_serve_tests;
#[cfg(test)]
mod intent_recovery_tests;
#[cfg(test)]
mod landing_tests;
#[cfg(test)]
mod tests;

// The flat smart_http.rs module used to provide these names to the sibling
// test modules through `use super::*`: its own private crate/std import
// header, and every module-internal item the tests name bare. After the
// directory split the seam re-imports both so the test files resolve exactly
// as they did before.
#[cfg(test)]
use self::{
    advertise::*, cgi_finish::*, door::*, door_window::*, evidence::*, hooks::*, paths::*, serve::*,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimLifecycleStatus, encode_claim_body};
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::credential_door::{CredentialDoorService, DoorCredential, DoorScanVerdict, PushedBlob};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWire};
#[cfg(test)]
use crate::origin::lfs::{LfsOid, LfsPushedPointer, lfs_repo_id};
#[cfg(test)]
use crate::origin::publication::{OriginPublicationRequest, OriginPublicationStatus};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::time::{Duration, Instant};
