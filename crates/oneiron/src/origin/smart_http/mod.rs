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
//!   diff, plus every other blob the new tips reach that no existing ref
//!   already reaches, and hands the door those blobs WHOLE, length-framed: no
//!   text patch is parsed, so binary bytes cannot slip past a patch grammar, a
//!   blob an intermediate commit adds and a later one removes is still
//!   scanned, and an extraction the origin cannot read whole is a refusal
//!   rather than an empty scan.
//! - **No substituted bytes.** Replacement-object lookup is OFF on every git the
//!   serve path runs: `GIT_NO_REPLACE_OBJECTS` is part of the closed baseline
//!   (an environment variable reaches every git a git spawns) and the vetted
//!   hook additionally passes `--no-replace-objects` to each of its own git
//!   children. A push that proposes a `refs/replace/*` name is refused in the
//!   door window on top of that, so no replacement can be planted through this
//!   wire at all. Without both, a planted `refs/replace/<oid>` would make the
//!   door's scan read benign substitute bytes while the original object is what
//!   the push makes durable.
//! - **No signed push.** `git receive-pack` writes a push certificate into the
//!   object store as a blob before any hook runs, where no door window reads
//!   it. The advertisement never offers `push-cert`, whatever the repository's
//!   config says, and a request whose command section carries one is refused
//!   before the backend reads a byte. That section, up to its first flush, is
//!   the one part of a request body read ahead. It grows with the refs a push
//!   names, so it is held whatever its size: in memory up to
//!   `ORIGIN_COMMAND_SECTION_MEMORY_BYTES`, then in an unnamed file in the
//!   door root ([`HeldBytes`]), above the disk floor its host keeps
//!   ([`ExchangeBounds::spill_floor`]). A body the backend would inflate
//!   (gzip, as JGit sends one) is inflated here instead, once, so the section
//!   read is the one receive-pack reads; the backend gets it plain.
//! - **Only journalable refs move.** The door window refuses a push whose
//!   proposed names the landing could not journal — names outside the GitWire
//!   ref grammar or a name proposed twice — WHILE the objects are still
//!   quarantined. A push may name any number of refs. The landing's
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
//! request or response body, caps no body, no rate and no push (its door holds
//! one blob at a time under a per-blob memory floor, and its hook keeps a disk
//! floor while it frames them), and expands no gix feature; an exchange that
//! moves no byte for its idle limit is ended, never one that is merely slow. `git_wire.rs` and
//! `credential_door.rs` are consumed read-only; this module owns neither.

mod advertise;
mod bounds;
mod cgi_finish;
mod door;
mod door_window;
mod evidence;
mod exchange_idle;
mod held;
mod hooks;
mod intent;
mod intent_erase;
mod landing;
mod landing_lfs;
mod maintain;
mod owner_pins;
mod paths;
mod push_admission;
mod projected_serve;
mod push_paths;
pub(crate) mod push_projection;
mod read_projection;
mod recipient_serve;
mod retained_reasons;
pub(in crate::origin) mod secret_marks;
mod serve;
mod serve_cmd;

pub use self::bounds::{ExchangeBounds, ScanBounds};
pub use self::door::{DoorAdmissionStamp, DoorSeam};
pub use self::door_window::{DoorWindowReport, DoorWindowVerdict};
pub use self::evidence::{ObservedRef, PackStats, ReceivePackOutcome, RefUpdate};
pub(super) use self::evidence::{RECEIVE_PACK_ADMISSION_PREDICATE, RECEIVE_PACK_OUTCOME_PREDICATE};
// An actor's erase reaches the receive-pack rows (FIX 3877).
pub(crate) use self::evidence::erase_receive_pack_evidence_actor_in_txn;
pub use self::held::{AtDiskFloor, HeldBytes, SpillFloor};
pub use self::hooks::DoorHooksDir;
pub use self::intent::{ReceivePackRefResult, ReceivePackRefStatus};
pub(crate) use self::intent_erase::erase_receive_pack_intent_actor_in_txn;
pub use self::landing::{
    ReceivePackAttribution, ReceivePackCertificate, ReceivePackLanding, refs_already_applied,
};
pub use self::maintain::{
    SERVED_REPOSITORY_GC_TIMEOUT, ServedRepositoryMaintenance, maintain_served_repositories,
};
pub use self::paths::{
    DOOR_PRE_RECEIVE_HOOK_NAME, DOOR_WINDOW_TIMEOUT, ORIGIN_DOOR_ROOT_NAME,
    ORIGIN_MAX_REPO_NAME_BYTES, ORIGIN_REF_UPDATE_BATCH, ORIGIN_REFUSED_REF_PREFIX,
    ORIGIN_REPO_DIR_SUFFIX, ORIGIN_SERVING_ROOT_NAME, SERVE_BASE_ENV_KEYS, SERVE_IDLE_TIMEOUT,
    SERVE_REQUEST_ENV_KEYS, origin_door_root, origin_repo_dir, origin_serving_root,
    validate_repo_name,
};
pub use self::push_admission::{admit_receive_pack, serve_bounded_as};
pub use self::recipient_serve::{RepoGitReadContext, serve_bounded_for_recipient};
pub(crate) use self::recipient_serve::store_holds_readable_marks_in_txn;
pub use self::secret_marks::ReceiveSecretMarks;
pub use self::serve::{
    ServeReport, ServeSink, push_queue_key, serve, serve_bounded, serve_bounded_with_authority,
    serve_with_authority, serve_with_provenance,
};
pub use self::serve_cmd::{ServeChild, ServeCommand, ServeRequest};

#[cfg(test)]
mod advertise_tests;
#[cfg(test)]
mod checkout_tests;
#[cfg(test)]
mod door_serve_tests;
#[cfg(test)]
mod epoch_tests;
#[cfg(test)]
mod exchange_tests;
#[cfg(test)]
mod history_scan_tests;
#[cfg(test)]
mod intent_recovery_tests;
#[cfg(test)]
mod landing_tests;
#[cfg(test)]
mod maintain_tests;
#[cfg(test)]
mod push_cert_tests;
#[cfg(test)]
mod recreate_tests;
#[cfg(test)]
mod scan_cap_tests;
#[cfg(test)]
mod tests;

// The flat smart_http.rs module used to provide these names to the sibling
// test modules through `use super::*`: its own private crate/std import
// header, and every module-internal item the tests name bare. After the
// directory split the seam re-imports both so the test files resolve exactly
// as they did before.
#[cfg(test)]
use self::{advertise::*, cgi_finish::*, door::*, door_window::*, evidence::*, paths::*, serve::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimLifecycleStatus, encode_claim_body};
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::credential_door::{CredentialDoorService, DoorCredential};
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
