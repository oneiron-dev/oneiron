//! The all-target acknowledgement journal (KS-4A2, FIX 5685), kept beside
//! the keyless log in `<compartment>/.journal/`, outside the vault's image:
//! no restore of an image rolls it back.
//!
//! - `targets`: the required set, `{version, revision, members}`. A member
//!   is added before its first exposure and the revision rises; none is ever
//!   dropped by a pass, a config change or an outage (no silent removal).
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

use crate::error::{Error, Result};

use super::files::{open_dir, read_whole, replace_file, write_once};
use super::identity::{CustodySubject, decode_native_path, encode_native_path, hex_decode};
use super::log::{CustodyEpoch, CustodyPosition, Journal, LogEntry, frame_hash, open_frame};
use super::platform;
use super::protocol::{
    ACK_VERSION, AckOperation, AckRecord, BatchFacts, CustodyBatch, EvidenceKind, PendingCode,
    TargetId, TargetKind, TargetPending, TargetScope, TargetSpec, hex,
};
use super::retirement::{RetireCause, RetirementIntent};

const TARGETS: &str = "targets";
const ACKS: &str = "acks";
const OBLIGATIONS: &str = "obligations";
const DONE: &str = "done";
const RECONCILED: &str = "reconciled";
const COMPLETED: &str = "completed";
const LOCK: &str = "acks.lock";
const WIRE_VERSION: u8 = 1;

fn journal_corrupt() -> Error {
    Error::CorruptedIndex("key custody acknowledgement journal")
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| journal_corrupt())
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| journal_corrupt())
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetWire {
    version: u8,
    revision: u64,
    members: Vec<MemberWire>,
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
pub(crate) struct Member {
    pub(crate) spec: TargetSpec,
    pub(crate) added: u64,
}

/// The required set at one revision.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequiredSet {
    pub(crate) revision: u64,
    pub(crate) members: Vec<Member>,
}

impl RequiredSet {
    fn member(&self, id: &TargetId) -> Option<&Member> {
        self.members.iter().find(|member| member.spec.id() == id)
    }

    fn wire(&self) -> SetWire {
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
        }
    }

    fn from_wire(wire: SetWire) -> Result<Self> {
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
        })
    }
}

/// Why a member is pending, as the last attempt left it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingNote {
    pub(crate) at: u64,
    pub(crate) code: PendingCode,
    pub(crate) detail: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkWire {
    version: u8,
    epoch: u64,
    seq: u64,
    tip: String,
}

impl MarkWire {
    fn of(at: &CustodyPosition) -> Self {
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
pub(crate) struct MemberProgress {
    pub(crate) id: TargetId,
    pub(crate) kind: TargetKind,
    /// The log position its newest accepted ack names, in this epoch.
    pub(crate) acked: Option<u64>,
    pub(crate) pending: Option<PendingNote>,
}

/// Where this lineage's retirements stand.
#[derive(Clone, Debug)]
pub(crate) struct RetirementProgress {
    pub(crate) revision: u64,
    pub(crate) members: Vec<MemberProgress>,
    /// The log positions of every obligation not yet complete, ascending.
    pub(crate) outstanding: Vec<u64>,
    /// The completion watermark, in this epoch.
    pub(crate) completed: Option<u64>,
    /// Whether any retirement was ever handed off here.
    pub(crate) any: bool,
}

fn cause_code(cause: RetireCause) -> u8 {
    match cause {
        RetireCause::Retention => 0,
        RetireCause::Erase => 1,
    }
}

fn obligation_name(subject: &CustodySubject, through: u64, cause: RetireCause) -> String {
    format!(
        "r.{}.{through:016x}.{}",
        subject.dir_name(),
        cause_code(cause)
    )
}

fn target_file(prefix: &str, id: &TargetId) -> String {
    format!("{prefix}.{}", hex(id.as_str().as_bytes()))
}

impl Journal {
    pub(super) fn sub(&self, name: &str) -> Result<PathBuf> {
        open_dir(self.dir(), true, None)?;
        let dir = self.dir().join(name);
        open_dir(&dir, true, None)?;
        Ok(dir)
    }

    /// Holds the journal's lock for the life of the returned file: every
    /// read-modify-write of the set, an ack, the cursor, the watermark or a
    /// pass's recorded status.
    pub(super) fn lock(&self) -> Result<File> {
        open_dir(self.dir(), true, None)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        let lock = platform::secure(&mut options).open(self.dir().join(LOCK))?;
        platform::lock_exclusive(&lock)?;
        Ok(lock)
    }

    /// Holds `target`'s publish lock for the life of the returned file (FIX
    /// 6394): one pass at a time reads the head the target holds, checks
    /// that its batch extends it and switches its head in. One per member,
    /// apart from the journal's own lock: a slow target holds up no other.
    pub(super) fn publish_lock(&self, target: &TargetId) -> Result<File> {
        platform::lock_at(&self.sub(ACKS)?.join(target_file("l", target)))
    }

    /// The required set; empty before the first registration.
    pub(crate) fn required_set(&self) -> Result<RequiredSet> {
        match read_whole(&self.dir().join(TARGETS))? {
            Some(bytes) => RequiredSet::from_wire(decode(&bytes)?),
            None => Ok(RequiredSet::default()),
        }
    }

    /// Adds every member of `specs` the set lacks, at the next revision.
    /// Nothing is ever removed here.
    pub(crate) fn register(&self, specs: &[TargetSpec]) -> Result<RequiredSet> {
        let _lock = self.lock()?;
        let mut set = self.required_set()?;
        let missing: Vec<&TargetSpec> = specs
            .iter()
            .filter(|spec| set.member(spec.id()).is_none())
            .collect();
        if missing.is_empty() {
            return Ok(set);
        }
        let revision = set
            .revision
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("key custody target set revision"))?;
        for spec in missing {
            set.members.push(Member {
                spec: spec.clone(),
                added: revision,
            });
        }
        set.revision = revision;
        replace_file(self.dir(), TARGETS, &encode(&set.wire())?)?;
        Ok(set)
    }

    /// Accepts `ack` from a member for `batch`, once it names exactly that
    /// batch: the member, a set revision it belonged to, the position, the
    /// head object, the operation, and deletion evidence that leaves one head
    /// (none for a log-only member). Stored durably; an older one never
    /// replaces a newer.
    pub(crate) fn accept_ack(&self, batch: &CustodyBatch, ack: &AckRecord) -> Result<()> {
        self.accept_facts(&batch.facts(), ack)
    }

    /// [`Self::accept_ack`] of the batch `facts` describes: a retained one
    /// whose head is gone (FIX 5899).
    pub(super) fn accept_facts(&self, facts: &BatchFacts, ack: &AckRecord) -> Result<()> {
        let id = self.check_ack(facts, ack)?;
        let acks = self.sub(ACKS)?;
        let _lock = self.lock()?;
        let name = target_file("a", &id);
        let newer = match read_whole(&acks.join(&name))? {
            Some(bytes) => {
                let held: AckRecord = decode(&bytes)?;
                held.position.epoch < ack.position.epoch
                    || (held.position.epoch == ack.position.epoch
                        && held.position.seq <= ack.position.seq)
            }
            None => true,
        };
        if newer {
            replace_file(&acks, &name, &encode(ack)?)?;
            remove_quietly(&acks.join(target_file("p", &id)));
            // A head sealed without the data key is sealed again for this
            // member once the key is held (FIX 5791).
            let root_only = target_file("r", &id);
            if facts.data_key {
                remove_quietly(&acks.join(root_only));
            } else {
                replace_file(&acks, &root_only, &[])?;
            }
        }
        Ok(())
    }

    /// The member `ack` names, once it names exactly the batch `facts`
    /// describes; nothing is written.
    pub(super) fn check_ack(&self, facts: &BatchFacts, ack: &AckRecord) -> Result<TargetId> {
        let mismatch = || {
            Error::InvalidConfig(
                "the custody target's acknowledgement does not match its batch".into(),
            )
        };
        let id = TargetId::new(&ack.target_id)?;
        let set = self.required_set()?;
        let member = set.member(&id).ok_or_else(mismatch)?;
        let expected = facts.ack(&id, ack.evidence.clone(), &ack.attester);
        let remaining = match member.spec.scope() {
            TargetScope::HeadAndLog => 1,
            TargetScope::LogOnly => 0,
        };
        let evidence_fits = ack.evidence.remaining_heads == remaining
            && (member.spec.scope() == TargetScope::HeadAndLog)
                != (ack.evidence.kind == EvidenceKind::NoHeadInScope)
            && hex_decode(&ack.evidence.inventory_digest).is_some_and(|digest| digest.len() == 32);
        if ack.version != ACK_VERSION
            || ack.operation != AckOperation::PublishAndDeleteSuperseded
            || ack.set_revision != facts.set_revision
            || member.added > ack.set_revision
            || ack.position != expected.position
            || ack.head_object_id != expected.head_object_id
            || ack.operation_id != expected.operation_id
            || ack.attester.is_empty()
            || !evidence_fits
        {
            return Err(mismatch());
        }
        Ok(id)
    }

    /// Whether `target`'s acknowledged head is wrapped to the recovery root
    /// alone: it was sealed while the vault data key was not held.
    pub(crate) fn root_only(&self, target: &TargetId) -> bool {
        self.dir()
            .join(ACKS)
            .join(target_file("r", target))
            .exists()
    }

    /// Records why `target` is pending, replacing the last reason.
    pub(crate) fn note_pending(&self, target: &TargetId, pending: &TargetPending) -> Result<()> {
        let acks = self.sub(ACKS)?;
        let note = PendingNote {
            at: crate::unix_seconds_now(),
            code: pending.code,
            detail: pending.detail.clone(),
        };
        replace_file(&acks, &target_file("p", target), &encode(&note)?)
    }

    /// Every member's newest accepted ack.
    pub(crate) fn acks(&self) -> Result<BTreeMap<TargetId, AckRecord>> {
        let mut acks = BTreeMap::new();
        for member in self.required_set()?.members {
            let path = self
                .dir()
                .join(ACKS)
                .join(target_file("a", member.spec.id()));
            if let Some(bytes) = read_whole(&path)? {
                acks.insert(member.spec.id().clone(), decode(&bytes)?);
            }
        }
        Ok(acks)
    }

    fn pending_note(&self, id: &TargetId) -> Result<Option<PendingNote>> {
        read_whole(&self.dir().join(ACKS).join(target_file("p", id)))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    /// The log position of the obligation `intent` was handed off as, if
    /// it was: outstanding or done.
    pub(crate) fn obligation(&self, intent: &RetirementIntent) -> Result<Option<u64>> {
        self.obligation_named(&obligation_name(
            &intent.subject,
            intent.through,
            intent.cause,
        ))
    }

    /// The log position of the obligation named `name`, outstanding or
    /// done, if it was recorded.
    pub(super) fn obligation_named(&self, name: &str) -> Result<Option<u64>> {
        let dir = self.dir().join(OBLIGATIONS);
        for path in [dir.join(name), dir.join(DONE).join(name)] {
            if let Some(bytes) = read_whole(&path)? {
                return Ok(Some(decode::<MarkWire>(&bytes)?.seq));
            }
        }
        Ok(None)
    }

    /// Records `intent`'s obligation at `at`, its Retire frame's position:
    /// once, synced. A second record of the same keeps the first.
    pub(crate) fn record_obligation(
        &self,
        intent: &RetirementIntent,
        at: &CustodyPosition,
    ) -> Result<()> {
        let name = obligation_name(&intent.subject, intent.through, intent.cause);
        self.record_obligation_named(&name, at)
    }

    /// Records the obligation `name` at `at`, its frame's position: once,
    /// synced.
    pub(super) fn record_obligation_named(&self, name: &str, at: &CustodyPosition) -> Result<()> {
        let dir = self.sub(OBLIGATIONS)?;
        write_once(&dir, name, &encode(&MarkWire::of(at))?).map(drop)
    }

    /// The obligation a disaster recovery's landing carries: every
    /// retirement up to the admitted position, which the new writer's
    /// targets and anchor must reach again at its epoch.
    pub(crate) fn record_takeover(&self, at: &CustodyPosition) -> Result<()> {
        let dir = self.sub(OBLIGATIONS)?;
        write_once(
            &dir,
            &format!("t.{:016x}", at.epoch.get()),
            &encode(&MarkWire::of(at))?,
        )
        .map(drop)
    }

    /// Walks the log past the last walk for a Retire frame whose obligation
    /// an interrupted handoff never recorded, and records it: no retirement
    /// journaled here is ever missing from the completion set.
    pub(crate) fn reconcile(&self) -> Result<()> {
        let Some(control) = self.control()? else {
            return Ok(());
        };
        let position = self.position()?;
        let dir = self.dir().join(OBLIGATIONS);
        let walked = read_whole(&dir.join(RECONCILED))?
            .and_then(|bytes| bytes.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
            .max(control.base_seq());
        if walked >= position.seq {
            return Ok(());
        }
        let dir = self.sub(OBLIGATIONS)?;
        let _lock = self.lock()?;
        for seq in walked.saturating_add(1)..=position.seq {
            let Some(frame) = self.frame(seq)? else {
                continue;
            };
            let (header, entry) = open_frame(&control, &frame)?;
            // A released recipient's retirement is owed as a key's is (LC
            // FIX 5384/5385).
            let name = match entry {
                LogEntry::Retire {
                    subject,
                    through,
                    cause,
                } => obligation_name(&subject, through, cause),
                LogEntry::RetireRecipient(fact) => fact.obligation_name(),
                LogEntry::Mint(_) | LogEntry::PublicationPolicy(_) | LogEntry::BodyHistory(_) => {
                    continue;
                }
            };
            let at = CustodyPosition {
                vault: header.vault,
                namespace: header.namespace,
                epoch: header.epoch,
                seq,
                tip: frame_hash(&frame),
            };
            if !dir.join(DONE).join(&name).exists() {
                write_once(&dir, &name, &encode(&MarkWire::of(&at))?)?;
            }
        }
        replace_file(&dir, RECONCILED, &position.seq.to_be_bytes())
    }

    /// The completion watermark in `epoch`.
    fn completed(&self, epoch: CustodyEpoch) -> Result<Option<u64>> {
        Ok(read_whole(&self.dir().join(COMPLETED))?
            .map(|bytes| decode::<MarkWire>(&bytes))
            .transpose()?
            .filter(|mark| mark.epoch == epoch.get())
            .map(|mark| mark.seq))
    }

    /// Raises the completion watermark to `at` (never lowers it), then
    /// moves every obligation it completes to `done/`.
    pub(crate) fn advance_completed(&self, at: &CustodyPosition) -> Result<()> {
        let _lock = self.lock()?;
        if self.completed(at.epoch)?.is_some_and(|seq| seq >= at.seq) {
            return Ok(());
        }
        replace_file(self.dir(), COMPLETED, &encode(&MarkWire::of(at))?)?;
        let dir = self.sub(OBLIGATIONS)?;
        let done = self.sub(&format!("{OBLIGATIONS}/{DONE}"))?;
        let mut moved = false;
        for (name, mark) in self.marks(&dir, |_| true)? {
            if mark.epoch == at.epoch.get() && mark.seq <= at.seq {
                fs::rename(dir.join(&name), done.join(&name))?;
                moved = true;
            }
        }
        if moved {
            platform::sync_dir(&done)?;
            platform::sync_dir(&dir)?;
        }
        Ok(())
    }

    /// Every obligation file in `dir` whose name `wanted` takes, with its
    /// mark.
    fn marks(&self, dir: &Path, wanted: impl Fn(&str) -> bool) -> Result<Vec<(String, MarkWire)>> {
        let mut marks = Vec::new();
        for name in obligation_names(dir)? {
            if wanted(&name)
                && let Some(bytes) = read_whole(&dir.join(&name))?
            {
                marks.push((name, decode(&bytes)?));
            }
        }
        Ok(marks)
    }

    /// The handed-off retirements of `subject` this journal records, by
    /// their log positions, and whether each is complete, for an erase
    /// receipt's custody step; the takeover obligations too, which cover
    /// every subject retired before them.
    pub(crate) fn subject_obligations(
        &self,
        subject: &CustodySubject,
        retired_here: bool,
    ) -> Result<Vec<(u64, bool)>> {
        let prefix = format!("r.{}.", subject.dir_name());
        let wanted =
            |name: &str| name.starts_with(&prefix) || (retired_here && name.starts_with("t."));
        let dir = self.dir().join(OBLIGATIONS);
        let mut found = Vec::new();
        for (_, mark) in self.marks(&dir, wanted)? {
            found.push((mark.seq, false));
        }
        for (_, mark) in self.marks(&dir.join(DONE), wanted)? {
            found.push((mark.seq, true));
        }
        Ok(found)
    }

    /// Where this lineage's retirements stand at `local`, read from the
    /// journal alone.
    pub(crate) fn progress(&self, local: &CustodyPosition) -> Result<RetirementProgress> {
        self.reconcile()?;
        let set = self.required_set()?;
        let acks = self.acks()?;
        let completed = self.completed(local.epoch)?;
        let dir = self.dir().join(OBLIGATIONS);
        let mut outstanding: Vec<u64> = self
            .marks(&dir, |_| true)?
            .into_iter()
            .filter(|(_, mark)| {
                mark.epoch == local.epoch.get() && completed.is_none_or(|done| mark.seq > done)
            })
            .map(|(_, mark)| mark.seq)
            .collect();
        outstanding.sort_unstable();
        let any = !outstanding.is_empty()
            || completed.is_some()
            || !obligation_names(&dir.join(DONE))?.is_empty();
        let members = set
            .members
            .iter()
            .map(|member| {
                let id = member.spec.id().clone();
                Ok(MemberProgress {
                    acked: acked_seq(&acks, &id, local),
                    pending: self.pending_note(&id)?,
                    kind: member.spec.kind(),
                    id,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RetirementProgress {
            revision: set.revision,
            members,
            outstanding,
            completed,
            any,
        })
    }
}

/// The log position `id`'s newest accepted ack names, when it is of
/// `local`'s lineage and writer epoch.
pub(crate) fn acked_seq(
    acks: &BTreeMap<TargetId, AckRecord>,
    id: &TargetId,
    local: &CustodyPosition,
) -> Option<u64> {
    let held = acks.get(id)?.position.position()?;
    (held.same_lineage(local) && held.epoch == local.epoch).then_some(held.seq)
}

/// The obligation file names in `dir` (`r.` and `t.`); none when it is
/// missing.
fn obligation_names(dir: &Path) -> Result<Vec<String>> {
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

fn remove_quietly(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(kind = ?err.kind(), "a custody pending note was not removed");
    }
}
