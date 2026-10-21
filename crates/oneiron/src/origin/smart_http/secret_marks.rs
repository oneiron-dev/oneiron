//! The marks a push's admitted scan hits carry from the door window to the
//! push's intent (FIX 7608, owner ruling SECRETS-IN-REPOS = A).
//!
//! The door thread holds each blob's original bytes once, as it reads the
//! hook's streams. While it does, each hit the one disposition admits is
//! planned there (`batch::secret_scan::plan_retained_repo_blob`) and goes,
//! with where the door saw the blob, into a request-local spool as one
//! framed record: its place, its length and its BLAKE3, then its bytes. The
//! spool is a [`HeldBytes`], in memory up to the command section's bound and
//! past it in the unnamed file in the door root that keeps its host's disk
//! floor, so one blob and one plan are held at a time, never a push of
//! them. The verdict carries [`ReceiveSecretMarks`], an opaque handle; the
//! intent's writer drains the spool inside its own transaction
//! (`origin::secret_marks`) before the hook hears its answer, and the spool
//! is gone however that ends. A push the disposition refuses makes no spool
//! and reads no custody.
//!
//! Where a blob was seen is never more than the door knows. A tip record
//! names the move it was diffed for, so its marks name every proposed ref
//! making that move, and its path when the raw diff printed the path as it
//! is. A history record names no ref and no exact path: the quarantine saw
//! it.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

use rmpv::Value;
use zeroize::Zeroizing;

use super::held::{HeldBytes, SpillFloor};
use super::paths::{ORIGIN_COMMAND_SECTION_MEMORY_BYTES, origin_door_root};
use crate::Vault;
use crate::batch::secret_scan::{RetainedRepoBlobPlan, plan_retained_repo_blob};
use crate::credential_door::{PushedBlob, ReceiveBlobKind, ReceiveScanHit};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::secret_custody::KnownSource;

/// A record's frame: its place, its payload's length, its payload's BLAKE3.
const FRAME_HEADER_BYTES: usize = 8 + 8 + 32;

/// Where the door saw one blob it marks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiveSeen {
    /// A tip record, framed after the move it was diffed for: every proposed
    /// ref making that move reaches the blob.
    RefMove { old: Option<GitOid>, new: GitOid },
    /// A history record, or a tip record before any move: the push's
    /// quarantine held the blob, with no proved ref.
    Quarantine,
}

/// One marked blob as the door saw it. It holds no byte of the blob.
pub(crate) struct ReceiveSecretObservation {
    pub(crate) seen: ReceiveSeen,
    /// The exact path, when the door knows it.
    pub(crate) path: Option<String>,
    pub(crate) blob_oid: GitOid,
    pub(crate) content_kind: ReceiveBlobKind,
}

/// The marks one admitted push carries from its door window to its intent.
///
/// Opaque: the operation it belongs to and how many records it spooled,
/// and the spool itself, which only the intent's writer drains. It has no
/// accessor for any byte and no wire form; its `Debug`, its clones and its
/// equality read the value-free identity only.
#[derive(Clone)]
pub struct ReceiveSecretMarks {
    operation_id: EntityId,
    records: u64,
    spool: Arc<Mutex<Option<HeldMarks>>>,
}

impl std::fmt::Debug for ReceiveSecretMarks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSecretMarks")
            .field("operation_id", &self.operation_id)
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ReceiveSecretMarks {
    fn eq(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id && self.records == other.records
    }
}

impl Eq for ReceiveSecretMarks {}

impl ReceiveSecretMarks {
    /// The admitted operation these marks belong to.
    pub(crate) fn operation_id(&self) -> EntityId {
        self.operation_id
    }

    /// Hands each spooled mark to `each`, in the order the door saw them,
    /// and drops the spool: it is taken whatever `each` answers, so a second
    /// drain finds none.
    ///
    /// # Errors
    /// A spool already drained, a record whose frame, length or BLAKE3 does
    /// not hold, a read the spool's file refused, or `each`'s own error.
    pub(crate) fn drain(
        &self,
        each: &mut dyn FnMut(ReceiveSecretObservation, RetainedRepoBlobPlan) -> Result<()>,
    ) -> Result<()> {
        let taken = self
            .spool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let mut marks = taken.ok_or(Error::InvariantViolation(
            "a push's receive marks were already recorded",
        ))?;
        let HeldMarks {
            held,
            records,
            reasons,
        } = &mut marks;
        let mut reader = held.reader()?;
        for index in 0..*records {
            let (observation, plan) = read_record(&mut *reader, index, reasons.as_slice())?;
            each(observation, plan)?;
        }
        let mut rest = [0_u8; 1];
        if reader.read(&mut rest)? != 0 {
            return Err(unspooled());
        }
        Ok(())
    }
}

/// One push's spooled records, and each reason code a record names, once,
/// by its place here: a set the engine's own codes bound, never the push.
struct HeldMarks {
    held: HeldBytes,
    records: u64,
    reasons: Vec<&'static str>,
}

impl HeldMarks {
    /// Spools one record: `observation`, then `plan`, in one framed payload
    /// built in a wiping buffer.
    fn write(
        &mut self,
        observation: &ReceiveSecretObservation,
        plan: &RetainedRepoBlobPlan,
    ) -> Result<()> {
        let mut payload = Zeroizing::new(Vec::new());
        rmpv::encode::write_value(&mut *payload, &observation_value(observation))
            .map_err(|_| Error::InvariantViolation("a receive mark record did not encode"))?;
        let reasons = &mut self.reasons;
        plan.encode_into(&mut payload, &mut |reason| intern(reasons, reason))?;
        let len = u64::try_from(payload.len())
            .map_err(|_| Error::ArithmeticOverflow("receive mark record length"))?;
        self.held.write_all(&self.records.to_be_bytes())?;
        self.held.write_all(&len.to_be_bytes())?;
        self.held.write_all(blake3::hash(&payload).as_bytes())?;
        self.held.write_all(&payload)?;
        self.records += 1;
        Ok(())
    }
}

/// What a door window gathers toward one push's marks. It holds nothing,
/// and reads no custody, until the disposition admits a hit.
pub(super) struct ReceiveSecretMarksBuilder<'a> {
    vault: &'a Vault,
    operation_id: Option<EntityId>,
    floor: Option<&'a Arc<dyn SpillFloor>>,
    pending: Option<MarkSpool>,
}

/// A push's spool as the door window writes it, and the known-value source
/// its plans read through.
struct MarkSpool {
    marks: HeldMarks,
    known: Option<KnownSource>,
}

impl<'a> ReceiveSecretMarksBuilder<'a> {
    /// A builder for the admitted operation `operation_id`, spilling past
    /// memory under `floor`, the host's disk floor.
    pub(super) fn new(
        vault: &'a Vault,
        operation_id: Option<EntityId>,
        floor: Option<&'a Arc<dyn SpillFloor>>,
    ) -> Self {
        Self {
            vault,
            operation_id,
            floor,
            pending: None,
        }
    }

    /// Plans each of `hits` on `blob`, seen at `seen`, and spools each plan
    /// with where the door saw it. The first call opens the spool.
    ///
    /// # Errors
    /// No admitted operation, a plan that could not be made, or a spool
    /// write the disk refused: the door then refuses the push.
    pub(super) fn observe(
        &mut self,
        blob: &PushedBlob,
        hits: &[ReceiveScanHit],
        seen: ReceiveSeen,
    ) -> Result<()> {
        let operation_id = self.operation_id.ok_or(Error::InvariantViolation(
            "a marked push has no admitted operation",
        ))?;
        if self.pending.is_none() {
            self.pending = Some(self.open_spool()?);
        }
        let Some(spool) = self.pending.as_mut() else {
            return Err(Error::InvariantViolation(
                "a push's receive mark spool did not open",
            ));
        };
        let blob_oid = GitOid::parse_hex(blob.oid.to_ascii_lowercase())?;
        let path = match seen {
            ReceiveSeen::RefMove { .. } => exact_tip_path(&blob.path),
            ReceiveSeen::Quarantine => None,
        };
        for hit in hits {
            let plan = match &spool.known {
                Some(source) => source.pass(|known| {
                    plan_retained_repo_blob(&blob.content, known, hit.reason, operation_id)
                })??,
                None => plan_retained_repo_blob(&blob.content, None, hit.reason, operation_id)?,
            };
            let observation = ReceiveSecretObservation {
                seen: seen.clone(),
                path: path.clone(),
                blob_oid: blob_oid.clone(),
                content_kind: hit.content_kind,
            };
            spool.marks.write(&observation, &plan)?;
        }
        Ok(())
    }

    fn open_spool(&self) -> Result<MarkSpool> {
        let held = HeldBytes::new(
            ORIGIN_COMMAND_SECTION_MEMORY_BYTES,
            origin_door_root(self.vault).ok(),
        )
        .with_floor(self.floor.cloned());
        Ok(MarkSpool {
            marks: HeldMarks {
                held,
                records: 0,
                reasons: Vec::new(),
            },
            known: self.vault.known_source()?,
        })
    }

    /// The push's marks, or `None` when no hit was admitted.
    ///
    /// # Errors
    /// The spool's last bytes could not be written.
    pub(super) fn finish(self) -> Result<Option<ReceiveSecretMarks>> {
        let (Some(spool), Some(operation_id)) = (self.pending, self.operation_id) else {
            return Ok(None);
        };
        let MarkSpool {
            mut marks,
            known: _,
        } = spool;
        marks.held.flush()?;
        Ok(Some(ReceiveSecretMarks {
            operation_id,
            records: marks.records,
            spool: Arc::new(Mutex::new(Some(marks))),
        }))
    }
}

/// A tip record's path label, when it is exactly the path: the hook's raw
/// diff quotes every path it cannot print as it is (`"..."`, escaped), and
/// a quoted label is never taken for the path it stands for.
fn exact_tip_path(label: &str) -> Option<String> {
    (!label.starts_with('"')).then(|| label.to_owned())
}

/// The place `reason` takes among `reasons`, added once.
fn intern(reasons: &mut Vec<&'static str>, reason: &'static str) -> Result<u16> {
    let at = match reasons.iter().position(|held| *held == reason) {
        Some(at) => at,
        None => {
            reasons.push(reason);
            reasons.len() - 1
        }
    };
    u16::try_from(at).map_err(|_| Error::ArithmeticOverflow("receive mark reason codes"))
}

fn reason_at(reasons: &[&'static str], index: u16) -> Result<&'static str> {
    reasons
        .get(usize::from(index))
        .copied()
        .ok_or_else(unspooled)
}

fn unspooled() -> Error {
    Error::CorruptedIndex("a receive mark spool record")
}

fn observation_value(observation: &ReceiveSecretObservation) -> Value {
    let seen = match &observation.seen {
        ReceiveSeen::RefMove { old, new } => Value::Array(vec![
            old.as_ref()
                .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
            Value::from(new.as_str()),
        ]),
        ReceiveSeen::Quarantine => Value::Nil,
    };
    let kind = match observation.content_kind {
        ReceiveBlobKind::Text => "text",
        ReceiveBlobKind::Binary => "binary",
    };
    Value::Array(vec![
        seen,
        observation.path.as_deref().map_or(Value::Nil, Value::from),
        Value::from(observation.blob_oid.as_str()),
        Value::from(kind),
    ])
}

fn observation_of(value: Value) -> Result<ReceiveSecretObservation> {
    let Value::Array(fields) = value else {
        return Err(unspooled());
    };
    let [seen, path, blob_oid, kind] = <[Value; 4]>::try_from(fields).map_err(|_| unspooled())?;
    let seen = match seen {
        Value::Nil => ReceiveSeen::Quarantine,
        Value::Array(pair) => {
            let [old, new] = <[Value; 2]>::try_from(pair).map_err(|_| unspooled())?;
            let old = match old {
                Value::Nil => None,
                old => Some(oid_of(&old)?),
            };
            ReceiveSeen::RefMove {
                old,
                new: oid_of(&new)?,
            }
        }
        _ => return Err(unspooled()),
    };
    let path = match path {
        Value::Nil => None,
        path => Some(path.as_str().ok_or_else(unspooled)?.to_owned()),
    };
    let content_kind = match kind.as_str() {
        Some("text") => ReceiveBlobKind::Text,
        Some("binary") => ReceiveBlobKind::Binary,
        _ => return Err(unspooled()),
    };
    Ok(ReceiveSecretObservation {
        seen,
        path,
        blob_oid: oid_of(&blob_oid)?,
        content_kind,
    })
}

fn oid_of(value: &Value) -> Result<GitOid> {
    Ok(GitOid::parse_hex(value.as_str().ok_or_else(unspooled)?)?)
}

fn u64_of(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| unspooled())?,
    ))
}

/// Record `index` of a spool, read back and checked against its frame.
fn read_record(
    reader: &mut dyn Read,
    index: u64,
    reasons: &[&'static str],
) -> Result<(ReceiveSecretObservation, RetainedRepoBlobPlan)> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    let (frame, rest) = header.split_at(8);
    let (len, digest) = rest.split_at(8);
    if u64_of(frame)? != index {
        return Err(unspooled());
    }
    let len = usize::try_from(u64_of(len)?).map_err(|_| unspooled())?;
    let mut payload = Zeroizing::new(vec![0_u8; len]);
    reader.read_exact(&mut payload)?;
    if blake3::hash(&payload).as_bytes().as_slice() != digest {
        return Err(unspooled());
    }
    let mut cursor = std::io::Cursor::new(payload.as_slice());
    let head = rmpv::decode::read_value(&mut cursor).map_err(|_| unspooled())?;
    let at = usize::try_from(cursor.position()).map_err(|_| unspooled())?;
    let observation = observation_of(head)?;
    let plan = RetainedRepoBlobPlan::decode(payload.get(at..).ok_or_else(unspooled)?, &|reason| {
        reason_at(reasons, reason)
    })?;
    Ok((observation, plan))
}
