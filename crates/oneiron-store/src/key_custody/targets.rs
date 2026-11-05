//! The all-target acknowledgement journal (KS-4A2, FIX 5685), kept beside
//! the keyless log in `<compartment>/.journal/`, outside the vault's image:
//! no restore of an image rolls it back.
//!
//! - `targets`: the required set, `{version, revision, members, history}`.
//!   A member is added before its first exposure and the revision rises;
//!   none is ever dropped by a pass, a config change or an outage (no
//!   silent removal). Only the owner's drain takes one out, after its
//!   deletion ack, at a new revision with a history row (`drain`, FIX 5843);
//!   `drains/f.<target hex>` fences a member while its drain is begun.
//! - `acks/a.<target hex>`: the newest accepted ack per member;
//!   `acks/p.<target hex>`: why it is pending, sanitized, with its time;
//!   `acks/l.<target hex>`: its publish lock (FIX 6394).
//! - `obligations/r.<tag>.<item>.<through>.<cause>`: one per retirement
//!   handed off by the finisher, naming its Retire frame's position;
//!   `obligations/r.rcpt.<fingerprint>`: one per released escrow recipient
//!   a cold managed restore retired (`recipients`);
//!   `obligations/t.<epoch>`: the retirements a disaster recovery's landing
//!   carries; `obligations/reconciled`: how far the log was walked for a
//!   Retire frame without one. A completed one moves to `obligations/done/`.
//! - `completed`: the completion watermark, a log position that only rises.
//!   Every obligation at or before it is complete: each member acked a head
//!   at or past it, and the anchor stands at or past it.
//!
//! The obligations and the watermark carry completion, not the LMDB intent:
//! the intent clears at the handoff, once its Retire frame and obligation
//! are durable (Engine 10-20). A fork starts an empty journal, so it never
//! inherits its source's obligations; a landing carries the admitted ones
//! as one takeover obligation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::files::open_dir;
use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::files::write_once;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::identity::decode_native_path;
use crate::key_custody::identity::encode_native_path;
use crate::key_custody::identity::hex_decode;
use crate::key_custody::log::CustodyEpoch;
use crate::key_custody::log::CustodyPosition;
use crate::key_custody::log::frame_hash;
use crate::key_custody::platform;
use crate::key_custody::protocol::ACK_VERSION;
use crate::key_custody::protocol::AckOperation;
use crate::key_custody::protocol::EvidenceKind;
use crate::key_custody::protocol::PendingCode;
use crate::key_custody::protocol::TargetId;
use crate::key_custody::protocol::TargetKind;
use crate::key_custody::protocol::TargetPending;
use crate::key_custody::protocol::TargetScope;
use crate::key_custody::protocol::TargetSpec;
use crate::key_custody::protocol::hex;

pub mod drain;

pub const TARGETS: &str = "targets";
pub const ACKS: &str = "acks";
pub const OBLIGATIONS: &str = "obligations";
pub const DONE: &str = "done";
pub const RECONCILED: &str = "reconciled";
pub const COMPLETED: &str = "completed";
pub const LOCK: &str = "acks.lock";
pub const WIRE_VERSION: u8 = 1;

pub fn journal_corrupt() -> Error {
    Error::CorruptedIndex("key custody acknowledgement journal")
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| journal_corrupt())
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| journal_corrupt())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetWire {
    pub version: u8,
    pub revision: u64,
    pub members: Vec<MemberWire>,
    /// The owner's drains and re-enrolments (FIX 5843).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<drain::SetEvent>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberWire {
    id: String,
    kind: TargetKind,
    scope: TargetScope,
    /// The revision that added it.
    added: u64,
    /// A folder member's absolute folder, its native bytes in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
}

/// One member of the required set, as persisted.
#[derive(Clone, Debug)]
pub struct Member {
    pub spec: TargetSpec,
    pub added: u64,
}

/// The required set at one revision.
#[derive(Clone, Debug, Default)]
pub struct RequiredSet {
    pub revision: u64,
    pub members: Vec<Member>,
    pub history: Vec<drain::SetEvent>,
}

impl RequiredSet {
    pub fn member(&self, id: &TargetId) -> Option<&Member> {
        self.members.iter().find(|member| member.spec.id() == id)
    }

    /// Whether `id` is a member a publication goes to.
    pub fn holds(&self, id: &TargetId) -> bool {
        self.member(id).is_some()
    }

    pub fn wire(&self) -> SetWire {
        SetWire {
            version: WIRE_VERSION,
            revision: self.revision,
            members: self
                .members
                .iter()
                .map(|member| MemberWire {
                    id: member.spec.id().as_str().to_owned(),
                    kind: member.spec.kind(),
                    scope: member.spec.scope(),
                    added: member.added,
                    folder: member
                        .spec
                        .folder_path()
                        .and_then(|folder| std::path::absolute(folder).ok())
                        .and_then(|folder| encode_native_path(&folder))
                        .map(|bytes| hex(&bytes)),
                })
                .collect(),
            history: self.history.clone(),
        }
    }

    pub fn from_wire(wire: SetWire) -> Result<Self> {
        if wire.version != WIRE_VERSION {
            return Err(journal_corrupt());
        }
        let members = wire
            .members
            .into_iter()
            .map(|member| {
                let folder = member
                    .folder
                    .map(|folder| {
                        hex_decode(&folder)
                            .and_then(|bytes| decode_native_path(&bytes))
                            .ok_or_else(journal_corrupt)
                    })
                    .transpose()?;
                Ok(Member {
                    spec: TargetSpec::member(
                        TargetId::new(&member.id)?,
                        member.kind,
                        member.scope,
                        folder,
                    ),
                    added: member.added,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            revision: wire.revision,
            members,
            history: wire.history,
        })
    }
}

/// Why a member is pending, as the last attempt left it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingNote {
    pub at: u64,
    pub code: PendingCode,
    pub detail: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkWire {
    pub version: u8,
    pub epoch: u64,
    pub seq: u64,
    pub tip: String,
}

impl MarkWire {
    pub fn of(at: &CustodyPosition) -> Self {
        Self {
            version: WIRE_VERSION,
            epoch: at.epoch.get(),
            seq: at.seq,
            tip: hex(&at.tip),
        }
    }
}

/// One member's progress.
#[derive(Clone, Debug)]
pub struct MemberProgress {
    pub id: TargetId,
    pub kind: TargetKind,
    /// The log position its newest accepted ack names, in this epoch.
    pub acked: Option<u64>,
    pub pending: Option<PendingNote>,
}

/// Where this lineage's retirements stand.
#[derive(Clone, Debug)]
pub struct RetirementProgress {
    pub revision: u64,
    pub members: Vec<MemberProgress>,
    /// The log positions of every obligation not yet complete, ascending.
    pub outstanding: Vec<u64>,
    /// The completion watermark, in this epoch.
    pub completed: Option<u64>,
    /// Whether any retirement was ever handed off here.
    pub any: bool,
}

pub fn target_file(prefix: &str, id: &TargetId) -> String {
    format!("{prefix}.{}", hex(id.as_str().as_bytes()))
}

/// The obligation file names in `dir` (`r.` and `t.`); none when it is
/// missing.
pub fn obligation_names(dir: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut names = Vec::new();
    for entry in entries {
        if let Some(name) = entry?.file_name().to_str()
            && (name.starts_with("r.") || name.starts_with("t."))
        {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

pub fn remove_quietly(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(kind = ?err.kind(), "a custody pending note was not removed");
    }
}
