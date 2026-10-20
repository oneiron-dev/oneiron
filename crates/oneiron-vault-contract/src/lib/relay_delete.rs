//! The relay locker delete the engine executes (FIX 6826, Engine 10-21).
//!
//! A hosted relay room keeps a vault's backup ciphertext in its locker. A
//! delete there never unlinks in the relay: the relay asks the vault's
//! running engine, through its supervisor's broker, to delete the object
//! itself (`relay_delete_execute`, [`RelayDeleteRequest`]). The engine checks
//! that the object still holds the ciphertext the delete names, then claims,
//! unlinks and syncs it inside its backup-hold writer exclusion, so a legal
//! hold placed meanwhile commits before the hold read or after the sync. It
//! answers [`RelayDeleteState`]: `deleted`, `absent`, `held`, `unknown` with a
//! closed reason, or `storage_io` with a closed stage and kind. Only
//! `deleted` and `absent` settle a delete; every other answer leaves it
//! deferred, its intent kept.
//!
//! The supervisor alone names the room's locker objects directory to the
//! engine (`relay_locker_bind`, [`RelayLockerBindRequest`]), which opens it
//! itself: no relay request carries a path or a descriptor. A relay follows
//! the engine's recheck counter (`relay_delete_rechecks`,
//! [`RelayDeleteRechecksRequest`]), a long poll answered when the counter
//! moves or the wait ends, and asks again after a hold release, a hold
//! maintenance pass or a bind.
//!
//! An engine with this surface reports [`RELAY_DELETE_REVISION`] and its boot
//! instance on `Ping` (`relay_delete_revision`, `engine_instance`). The three
//! requests ride v3 with a build floor at the engine revision they merged
//! in: an engine before it answers each as an unknown request, which
//! deletes, binds and proves nothing.

use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize};

/// The revision of this surface, which an engine built with it reports on
/// `Ping` (`relay_delete_revision`).
pub const RELAY_DELETE_REVISION: u32 = 1;

/// How long a delete has to be admitted, in milliseconds, from the moment a
/// valid `relay_delete_execute` reaches the engine's dispatch: its queue, its
/// hash and its wait for the writer all count. Admission is the engine's own
/// step into the destructive section, inside the writer. Past the deadline a
/// delete not yet admitted answers `unknown` (`admission_timeout`) and never
/// runs; one admitted finishes its unlink and sync however long they take.
pub const RELAY_DELETE_ADMISSION_MS: u64 = 2000;

/// `relay_delete_execute`: delete one locker object of one vault. Its fields
/// ride flat beside `op`, and every answer repeats them as they were sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeleteRequest {
    /// The vault's registry id: a canonical lowercase hyphenated UUID.
    pub vault: String,
    /// The engine's vault id, 64 lowercase hex: the relay room's.
    pub engine_vault_id: String,
    /// The engine boot the delete is for, as its `Ping` reported it.
    pub engine_instance: String,
    /// 16 random bytes as 32 lowercase hex, naming this one request.
    pub request_id: String,
    /// The locker object: 64 lowercase hex, or `manifest`.
    pub object: String,
    /// The BLAKE3 digest of the ciphertext the delete names, 64 lowercase
    /// hex.
    pub ciphertext_blake3: String,
}

impl RelayDeleteRequest {
    /// Reject-not-truncate: every field's shape. The engine runs it after
    /// parsing; a request that fails is answered `Ok { ok: false }`, which
    /// deletes nothing.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_identity(&self.vault, &self.engine_vault_id)?;
        anyhow::ensure!(
            is_hex(&self.engine_instance, 32),
            "relay delete engine_instance must be 32 lowercase hex"
        );
        anyhow::ensure!(
            is_hex(&self.request_id, 32),
            "relay delete request_id must be 32 lowercase hex"
        );
        anyhow::ensure!(
            valid_locker_object(&self.object),
            "relay delete object must be 64 lowercase hex or manifest"
        );
        anyhow::ensure!(
            is_hex(&self.ciphertext_blake3, 64),
            "relay delete ciphertext_blake3 must be 64 lowercase hex"
        );
        Ok(())
    }
}

/// What became of one `relay_delete_execute`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RelayDeleteState {
    /// No hold stood, the object held the named ciphertext, and it is
    /// unlinked and its directory synced, inside the engine's writer.
    Deleted,
    /// The object was not there, and its directory is synced, inside the
    /// engine's writer: nothing is left to delete.
    Absent,
    /// A standing legal hold keeps the vault's backups: the object stays
    /// until the hold lifts.
    Held,
    /// Nothing is known to be deleted: the delete stays deferred.
    Unknown { reason: RelayDeleteUnknown },
    /// A filesystem step failed and nothing is claimed deleted. It names no
    /// path and no error's text.
    StorageIo {
        stage: RelayDeleteStage,
        kind: RelayDeleteIoKind,
    },
}

impl RelayDeleteState {
    /// Whether the delete settled: the object is gone, its directory
    /// synced. Every other answer keeps the delete's intent.
    #[must_use]
    pub const fn settled(self) -> bool {
        matches!(self, Self::Deleted | Self::Absent)
    }
}

/// Why a relay delete, or a recheck, is not known to have done anything.
/// None of them means "no hold".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDeleteUnknown {
    /// The supervisor has bound no locker directory the engine could open.
    NotBound,
    /// The registry id or the engine vault id is not this vault's.
    VaultMismatch,
    /// The request names another engine boot.
    InstanceMismatch,
    /// The delete was not admitted within [`RELAY_DELETE_ADMISSION_MS`].
    AdmissionTimeout,
    /// The engine's delete worker or its recheck counter failed.
    GuardUnavailable,
    /// The vault's holds did not read.
    Unresolved,
    /// The object holds other bytes than the delete names, or another file
    /// took its name meanwhile.
    TargetChanged,
    /// The object is a link or not a plain file.
    InvalidTarget,
    /// The vault is not running and ready: cold, draining, frozen for reap,
    /// stopping or unproven.
    NotReady,
    /// The engine is older than this surface.
    Unsupported,
    /// The request or its answer was lost on the way.
    TransportUnavailable,
    /// The answer did not read as one for the request sent.
    AnswerUnrecognized,
}

impl RelayDeleteUnknown {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotBound => "not_bound",
            Self::VaultMismatch => "vault_mismatch",
            Self::InstanceMismatch => "instance_mismatch",
            Self::AdmissionTimeout => "admission_timeout",
            Self::GuardUnavailable => "guard_unavailable",
            Self::Unresolved => "unresolved",
            Self::TargetChanged => "target_changed",
            Self::InvalidTarget => "invalid_target",
            Self::NotReady => "not_ready",
            Self::Unsupported => "unsupported",
            Self::TransportUnavailable => "transport_unavailable",
            Self::AnswerUnrecognized => "answer_unrecognized",
        }
    }
}

/// The filesystem step a `storage_io` answer failed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDeleteStage {
    /// Opening or reading the object to hash it.
    Hash,
    /// Reading the object's file identity.
    Stat,
    /// Claiming, unlinking or putting back the object.
    Unlink,
    /// Syncing the objects directory.
    Sync,
}

impl RelayDeleteStage {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Stat => "stat",
            Self::Unlink => "unlink",
            Self::Sync => "sync",
        }
    }
}

/// The kind of a `storage_io` failure, coarse on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDeleteIoKind {
    /// The engine may not read or change it.
    PermissionDenied,
    /// A part of the path was missing. Never an `absent` answer.
    NotFound,
    /// Any other failure.
    Other,
}

impl RelayDeleteIoKind {
    /// The coarse kind of an I/O error's `kind`.
    #[must_use]
    pub fn of(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::NotFound => Self::NotFound,
            _ => Self::Other,
        }
    }

    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Other => "other",
        }
    }
}

/// The answer to `relay_delete_execute`: the request's six fields as sent,
/// and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeleteExecuteWire {
    #[serde(flatten)]
    pub request: RelayDeleteRequest,
    #[serde(flatten)]
    pub state: RelayDeleteState,
}

/// `relay_delete_rechecks`: a long poll on the engine's relay delete recheck
/// counter, which moves after each committed hold release, each hold
/// maintenance pass and each locker bind. Flat beside `op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeleteRechecksRequest {
    /// The vault's registry id: a canonical lowercase hyphenated UUID.
    pub vault: String,
    /// The engine's vault id, 64 lowercase hex.
    pub engine_vault_id: String,
    /// The engine boot `after` was read on, or `null` for a first snapshot
    /// of whichever boot answers, at once. Required, though it may be null.
    #[serde(deserialize_with = "Option::deserialize")]
    pub engine_instance: Option<String>,
    /// The counter last seen on that boot. Counters of two boots never
    /// compare.
    pub after: u64,
    /// How long to wait, in milliseconds, for the counter to move past
    /// `after`; bounded only by its width.
    pub wait_ms: u32,
}

impl RelayDeleteRechecksRequest {
    /// Reject-not-truncate: every field's shape.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_identity(&self.vault, &self.engine_vault_id)?;
        anyhow::ensure!(
            self.engine_instance
                .as_deref()
                .is_none_or(|instance| is_hex(instance, 32)),
            "relay delete rechecks engine_instance must be null or 32 lowercase hex"
        );
        Ok(())
    }
}

/// The answer to `relay_delete_rechecks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RelayDeleteRechecksWire {
    /// The engine boot `engine_instance` answers with its counter;
    /// `changed` says whether it is past the request's `after`. A wait that
    /// ended with the counter unmoved is `changed: false`, never a release.
    Bound {
        vault: String,
        engine_vault_id: String,
        engine_instance: String,
        counter: u64,
        changed: bool,
    },
    /// No counter is known: a relay keeps every delete deferred until one is.
    Unknown {
        vault: String,
        engine_vault_id: String,
        reason: RelayDeleteUnknown,
    },
}

impl RelayDeleteRechecksWire {
    /// The shape of every field after parsing.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Bound {
                vault,
                engine_vault_id,
                engine_instance,
                ..
            } => {
                validate_identity(vault, engine_vault_id)?;
                anyhow::ensure!(
                    is_hex(engine_instance, 32),
                    "relay delete rechecks engine_instance must be 32 lowercase hex"
                );
            }
            Self::Unknown {
                vault,
                engine_vault_id,
                ..
            } => validate_identity(vault, engine_vault_id)?,
        }
        Ok(())
    }

    /// The registry id and engine vault id it answers for.
    #[must_use]
    pub fn identity(&self) -> (&str, &str) {
        match self {
            Self::Bound {
                vault,
                engine_vault_id,
                ..
            }
            | Self::Unknown {
                vault,
                engine_vault_id,
                ..
            } => (vault, engine_vault_id),
        }
    }
}

/// `relay_locker_bind`: the supervisor names the absolute objects directory
/// of this vault's relay locker room, which the engine opens itself, never
/// through a link. A rebind replaces the binding. Flat beside `op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLockerBindRequest {
    /// The vault's registry id: a canonical lowercase hyphenated UUID.
    pub vault: String,
    /// The engine's vault id, 64 lowercase hex.
    pub engine_vault_id: String,
    /// The room's objects directory: absolute, with no `.` or `..` part.
    pub objects_dir: String,
}

impl RelayLockerBindRequest {
    /// Reject-not-truncate: every field's shape.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_identity(&self.vault, &self.engine_vault_id)?;
        anyhow::ensure!(
            valid_objects_dir(&self.objects_dir),
            "relay locker objects_dir must be an absolute path with no `.` or `..` part"
        );
        Ok(())
    }
}

/// The answer to `relay_locker_bind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RelayLockerBindWire {
    /// The engine boot `engine_instance` holds the directory open: its
    /// deletes run there from now on.
    Bound {
        vault: String,
        engine_vault_id: String,
        engine_instance: String,
    },
    /// Not bound. After `open_failed` the engine holds no directory, and
    /// every delete answers `unknown` (`not_bound`) until a bind succeeds.
    Refused {
        vault: String,
        engine_vault_id: String,
        reason: RelayLockerRefusal,
    },
}

impl RelayLockerBindWire {
    /// The shape of every field after parsing.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Bound {
                vault,
                engine_vault_id,
                engine_instance,
            } => {
                validate_identity(vault, engine_vault_id)?;
                anyhow::ensure!(
                    is_hex(engine_instance, 32),
                    "relay locker bind engine_instance must be 32 lowercase hex"
                );
            }
            Self::Refused {
                vault,
                engine_vault_id,
                ..
            } => validate_identity(vault, engine_vault_id)?,
        }
        Ok(())
    }
}

/// Why the engine did not bind a relay locker directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLockerRefusal {
    /// The registry id or the engine vault id is not this vault's.
    VaultMismatch,
    /// The directory did not open as a directory, or opened through a link.
    OpenFailed,
    /// The vault is frozen for reap or stopping.
    NotReady,
}

impl RelayLockerRefusal {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultMismatch => "vault_mismatch",
            Self::OpenFailed => "open_failed",
            Self::NotReady => "not_ready",
        }
    }
}

/// A strict read of the answer line to the `relay_delete_execute` request
/// `request`: its one wrapper and nothing beside it, a payload that
/// validates, and all six fields as sent.
///
/// # Errors
///
/// Any other line, which settles nothing.
pub fn decode_execute_answer(
    line: &str,
    request: &RelayDeleteRequest,
) -> anyhow::Result<RelayDeleteState> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Line {
        relay_delete_execute: RelayDeleteExecuteWire,
    }
    let Line {
        relay_delete_execute: wire,
    } = serde_json::from_str(line)?;
    wire.request.validate()?;
    anyhow::ensure!(
        wire.request == *request,
        "the relay delete answer repeats another request"
    );
    Ok(wire.state)
}

/// A strict read of the answer line to the `relay_delete_rechecks` request
/// `request`: its one wrapper, a payload that validates, the request's vault
/// ids, and, for a request that names a boot, a counter of that boot alone.
///
/// # Errors
///
/// Any other line, which proves no counter.
pub fn decode_rechecks_answer(
    line: &str,
    request: &RelayDeleteRechecksRequest,
) -> anyhow::Result<RelayDeleteRechecksWire> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Line {
        relay_delete_rechecks: RelayDeleteRechecksWire,
    }
    let Line {
        relay_delete_rechecks: wire,
    } = serde_json::from_str(line)?;
    wire.validate()?;
    anyhow::ensure!(
        wire.identity() == (request.vault.as_str(), request.engine_vault_id.as_str()),
        "the relay delete rechecks answer names another vault"
    );
    if let (
        Some(pinned),
        RelayDeleteRechecksWire::Bound {
            engine_instance, ..
        },
    ) = (&request.engine_instance, &wire)
    {
        anyhow::ensure!(
            pinned == engine_instance,
            "the relay delete rechecks answer names another engine boot"
        );
    }
    Ok(wire)
}

/// A strict read of the answer line to the `relay_locker_bind` request
/// `request`: its one wrapper, a payload that validates, and the request's
/// vault ids.
///
/// # Errors
///
/// Any other line, which binds nothing that may be relied on.
pub fn decode_bind_answer(
    line: &str,
    request: &RelayLockerBindRequest,
) -> anyhow::Result<RelayLockerBindWire> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Line {
        relay_locker_bind: RelayLockerBindWire,
    }
    let Line {
        relay_locker_bind: wire,
    } = serde_json::from_str(line)?;
    wire.validate()?;
    let (RelayLockerBindWire::Bound {
        vault,
        engine_vault_id,
        ..
    }
    | RelayLockerBindWire::Refused {
        vault,
        engine_vault_id,
        ..
    }) = &wire;
    anyhow::ensure!(
        *vault == request.vault && *engine_vault_id == request.engine_vault_id,
        "the relay locker bind answer names another vault"
    );
    Ok(wire)
}

/// Whether `value` is a registry id: a canonical lowercase hyphenated UUID.
#[must_use]
pub fn valid_registry_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => is_lower_hex(byte),
        })
}

/// Whether `value` names a locker object: 64 lowercase hex, or `manifest`.
#[must_use]
pub fn valid_locker_object(value: &str) -> bool {
    value == "manifest" || is_hex(value, 64)
}

/// `Ping`'s `engine_instance` as a supervisor reads it: anything but 32
/// lowercase hex reads as `None`, unknown, and never fails the `Ping` it
/// rides.
pub(super) fn observed_instance<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .filter(|instance| is_hex(instance, 32))
        .map(str::to_owned))
}

/// The two vault ids every request and answer carries.
fn validate_identity(vault: &str, engine_vault_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        valid_registry_uuid(vault),
        "relay delete vault must be a canonical lowercase UUID"
    );
    anyhow::ensure!(
        is_hex(engine_vault_id, 64),
        "relay delete engine_vault_id must be 64 lowercase hex"
    );
    Ok(())
}

/// Whether `value` is an absolute path with no `.` or `..` part.
fn valid_objects_dir(value: &str) -> bool {
    let path = Path::new(value);
    !value.contains('\0')
        && value.starts_with('/')
        && path.components().count() > 1
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && !value.split('/').any(|part| part == "." || part == "..")
}

/// Whether `value` is `len` lowercase hex digits.
fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(is_lower_hex)
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}
