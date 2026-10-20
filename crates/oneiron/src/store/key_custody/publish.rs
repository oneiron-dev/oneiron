//! Publishing one lineage's custody (KS-4, FIX 5685): its keyless log, then
//! its latest sealed head, to every member of the required target set, then
//! its anchor, then the completion watermark (KS-4A2).
//!
//! The journal is synced before anything is shipped (each frame at its
//! act). A pass registers the targets it drives (members are never dropped),
//! seals one batch at the local log position when a member is behind it,
//! and hands it to each target the pass reaches: the folders given, and every
//! folder member an earlier configuration registered, retried at its own
//! folder. A target acks (stored in the journal) or stays pending by name.
//! Only once every member acked the position does the anchor advance, by
//! compare-and-swap; the watermark then rises to the anchored position, and
//! every retirement obligation at or before it is complete. A member that
//! publishes on its own channel (the residence home, a hosted adapter) runs
//! the same batch and ack through [`Store::custody_batch_for`]. Nothing here
//! is ever waited on by a save or a backup: a step that does not go through
//! stays pending by name, and the next pass retries. Each pass records where
//! it got (`<journal>/status`, no secret in it), which the owner's status
//! read reports. A pass older than a head a newer pass already published at
//! one of its targets (two passes race; FIX 6394) stops at its targets: that
//! target answers covered, and the pass acks nothing for its older position,
//! moves no watermark, advances no anchor and records no status.

use crate::error::Result;
use crate::store::Store;

use super::anchor::{anchor_record, verified_position};
use super::files::{EntryState, LocalCustody, read_whole, replace_file};
use super::folder::FolderTarget;
use super::head::{CustodyRecipients, HeadEntry, seal_head};
use super::identity::CustodySubject;
use super::log::{CustodyPosition, Journal, POSITION_LEN};
use super::outbox::OutboxTarget;
use super::protocol::{
    AckRecord, AnchorAdvance, AnchorStore, CustodyBatch, CustodyTarget, Lineage, PendingCode,
    TargetId, TargetKind, TargetPending, TargetPublication, TargetSpec,
};
use super::targets::{RequiredSet, RetirementProgress, acked_seq};

const STATUS: &str = "status";

/// Where one lineage's publication stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationState {
    /// Nothing is in custody yet, so there is no head to publish.
    Nothing,
    /// Every member holds the head at the local log position, and it is
    /// anchored.
    Published,
    /// A member does not hold the head at the local position yet.
    TargetPending,
    /// The anchor step is not done: no anchor root is set up, it is
    /// missing, or its advance has not gone through.
    AnchorPending,
    /// The anchor names a newer writer epoch: another install took this
    /// lineage over in a disaster recovery, and this one publishes no more.
    Fenced,
}

/// One lineage's publication: its state, the positions it compared, why a
/// step is pending in words naming no secret, and whether every member's
/// head is wrapped to the vault data key as well as the recovery root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Publication {
    pub(crate) state: PublicationState,
    pub(crate) local: Option<CustodyPosition>,
    /// The least advanced member's acknowledged position, once every
    /// member has one.
    pub(crate) published: Option<CustodyPosition>,
    pub(crate) anchored: Option<CustodyPosition>,
    pub(crate) detail: Option<String>,
    /// `Some(false)` while a member holds a head sealed when the data key
    /// was not held: it is sealed again once the key is (FIX 5791).
    pub(crate) data_key_wrapped: Option<bool>,
    /// No anchor is configured: retirements complete on every required
    /// target's acknowledgement alone, with rollback not proven (CALLS
    /// CUSTODY_COMPLETION_NEEDS_ANCHOR, overruled).
    pub(crate) anchor_unset: bool,
}

impl Publication {
    fn nothing() -> Self {
        Self {
            state: PublicationState::Nothing,
            local: None,
            published: None,
            anchored: None,
            detail: None,
            data_key_wrapped: None,
            anchor_unset: false,
        }
    }
}

/// CALLS CUSTODY_COMPLETION_NEEDS_ANCHOR, OVERRULED (Engine 10-20 07:0x):
/// `false`, so a retirement is complete once every required target acked it;
/// with no anchor configured it carries the "rollback not proven" note
/// instead of owing the anchor step forever. `true` would keep it pending
/// on the anchor.
pub(crate) const CUSTODY_COMPLETION_NEEDS_ANCHOR: bool = false;

/// What the anchor step reads when no anchor root is set up (CALLS
/// CUSTODY_ANCHOR_ROOT: unset by default).
pub(crate) const ANCHOR_UNSET: &str =
    "no custody anchor is set (backup.custody_anchor_root or backup.custody_anchor_url)";

impl PublicationState {
    fn code(self) -> u8 {
        match self {
            Self::Nothing => 0,
            Self::Published => 1,
            Self::TargetPending => 2,
            Self::AnchorPending => 3,
            Self::Fenced => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Nothing,
            1 => Self::Published,
            2 => Self::TargetPending,
            3 => Self::AnchorPending,
            4 => Self::Fenced,
            _ => return None,
        })
    }
}

/// `state | wraps (0 unknown, 1 root only, 2 data key too) | anchor (0 set,
/// 1 unset) | 3 x (0 | 1 position) | detail utf-8`.
fn encode_status(publication: &Publication) -> Vec<u8> {
    let mut out = vec![
        publication.state.code(),
        match publication.data_key_wrapped {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        },
        u8::from(publication.anchor_unset),
    ];
    for position in [
        publication.local,
        publication.published,
        publication.anchored,
    ] {
        match position {
            Some(position) => {
                out.push(1);
                out.extend_from_slice(&position.to_bytes());
            }
            None => out.push(0),
        }
    }
    out.extend_from_slice(publication.detail.as_deref().unwrap_or("").as_bytes());
    out
}

fn decode_status(bytes: &[u8]) -> Option<Publication> {
    let (&state, rest) = bytes.split_first()?;
    let (&wraps, rest) = rest.split_first()?;
    let (&unset, mut rest) = rest.split_first()?;
    let mut positions = [None; 3];
    for slot in &mut positions {
        let (&present, after) = rest.split_first()?;
        rest = after;
        if present == 1 {
            *slot = Some(CustodyPosition::from_bytes(rest.get(..POSITION_LEN)?)?);
            rest = &rest[POSITION_LEN..];
        }
    }
    let detail = std::str::from_utf8(rest).ok()?;
    Some(Publication {
        state: PublicationState::from_code(state)?,
        local: positions[0],
        published: positions[1],
        anchored: positions[2],
        detail: (!detail.is_empty()).then(|| detail.to_owned()),
        data_key_wrapped: match wraps {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return None,
        },
        anchor_unset: match unset {
            0 => false,
            1 => true,
            _ => return None,
        },
    })
}

fn recorded(journal: &Journal) -> Result<Option<Publication>> {
    Ok(read_whole(&journal.dir().join(STATUS))?.and_then(|bytes| decode_status(&bytes)))
}

/// What sealing at the local position gave.
enum Sealed {
    /// Nothing is in custody yet.
    Nothing,
    /// No target the caller drives is behind this position.
    Current(CustodyPosition),
    /// A head sealed at the position.
    Batch(CustodyBatch),
    /// The head did not seal: why, naming no secret.
    Failed(CustodyPosition, String),
}

/// The least advanced member's acknowledged position, once every member
/// acknowledged one in `local`'s lineage and epoch.
fn least_acked(
    set: &RequiredSet,
    acks: &std::collections::BTreeMap<TargetId, AckRecord>,
    local: &CustodyPosition,
) -> Option<CustodyPosition> {
    let mut least: Option<CustodyPosition> = None;
    for member in &set.members {
        acked_seq(acks, member.spec.id(), local)?;
        let held = acks.get(member.spec.id())?.position.position()?;
        if least.is_none_or(|least| held.seq < least.seq) {
            least = Some(held);
        }
    }
    least
}

/// Whether nothing was ever in this custody: no frame, no entry.
fn custody_empty(store: &Store, custody: LocalCustody<'_>, journal: &Journal) -> Result<bool> {
    let _guard = store.core.key_custody.read_guard()?;
    Ok(journal.position()?.seq == 0 && custody.census()?.is_empty())
}

impl Store {
    /// Under the read guard: the local position, then, when `behind` says a
    /// target the caller drives lacks a head there, a head sealed at it:
    /// every entry a frame up to the position mints is published before its
    /// frame, and no retirement runs until the head is sealed.
    fn seal_batch(
        &self,
        custody: LocalCustody<'_>,
        journal: &Journal,
        recipients: &CustodyRecipients,
        revision: u64,
        behind: impl FnOnce(&CustodyPosition) -> bool,
    ) -> Result<Sealed> {
        let _guard = self.core.key_custody.read_guard()?;
        let position = journal.position()?;
        if position.seq == 0 && custody.census()?.is_empty() {
            return Ok(Sealed::Nothing);
        }
        if !behind(&position) {
            return Ok(Sealed::Current(position));
        }
        let control = journal.control_or_create()?;
        let mut entries = Vec::new();
        let mut retired = Vec::new();
        for (id, state) in custody.census()? {
            match state {
                EntryState::Live => entries.push(HeadEntry {
                    secret: custody.read(&id)?,
                    id,
                }),
                EntryState::Retired => retired.push(id),
                EntryState::Missing => {}
            }
        }
        let released = journal.recipient_facts()?;
        Ok(
            match seal_head(&position, &control, entries, retired, released, recipients) {
                Ok(head) => Sealed::Batch(CustodyBatch {
                    position,
                    head,
                    set_revision: revision,
                    journal: journal.dir().to_path_buf(),
                    data_key: recipients.data_key.is_some(),
                }),
                Err(error) => Sealed::Failed(position, error.to_string()),
            },
        )
    }

    /// One publication pass over this vault's custody lineage: its head to
    /// every target in `given` and every folder member registered before,
    /// then `anchor` (`None`: no anchor is set up, the step left pending by
    /// name), then the completion watermark. Each Hypnos outbox in
    /// `outboxes` (also in `given`) has its ack taken in first (FIX 5899).
    /// What happens on the way is the pass's state, recorded for the status
    /// read, never a refusal of anything; only a fault in the local custody
    /// itself is an error. A pass a newer one covered records nothing and
    /// answers the status read (FIX 6394).
    pub(crate) fn publish_custody(
        &self,
        recipients: &CustodyRecipients,
        given: &[&dyn CustodyTarget],
        outboxes: &[&OutboxTarget],
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<Publication> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Publication::nothing());
        };
        // An archived vault's custody is the one of the vault that replaced
        // it.
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(Publication::nothing());
        }
        let journal = custody.journal()?;
        let Some(mut publication) =
            self.publish_pass(custody, &journal, recipients, given, outboxes, anchor)?
        else {
            // A newer pass covered this one and records its own status.
            return self.custody_publication();
        };
        if publication.state != PublicationState::Nothing {
            publication.anchor_unset = anchor.is_none();
            replace_file(journal.dir(), STATUS, &encode_status(&publication))?;
        }
        Ok(publication)
    }

    /// The pass [`Self::publish_custody`] records; `None` when a target held
    /// a newer head of this log than the pass sealed: a newer pass covers it
    /// (FIX 6394).
    fn publish_pass(
        &self,
        custody: LocalCustody<'_>,
        journal: &Journal,
        recipients: &CustodyRecipients,
        given: &[&dyn CustodyTarget],
        outboxes: &[&OutboxTarget],
        anchor: Option<&dyn AnchorStore>,
    ) -> Result<Option<Publication>> {
        if custody_empty(self, custody, journal)? {
            return Ok(Some(Publication::nothing()));
        }
        // Every folder member an earlier pass registered is retried at its
        // own folder, whatever the configuration names now.
        let given_ids: Vec<TargetId> = given
            .iter()
            .map(|target| target.spec().id().clone())
            .collect();
        let retried: Vec<FolderTarget> = journal
            .required_set()?
            .members
            .iter()
            .filter(|member| {
                member.spec.kind() == TargetKind::Folder && !given_ids.contains(member.spec.id())
            })
            .filter_map(|member| {
                member
                    .spec
                    .folder_path()
                    .map(|folder| FolderTarget::at(folder.to_path_buf()))
            })
            .collect();
        let mut targets: Vec<&dyn CustodyTarget> = given.to_vec();
        targets.extend(retried.iter().map(|target| target as &dyn CustodyTarget));
        let specs: Vec<TargetSpec> = targets.iter().map(|target| target.spec()).collect();
        let set = journal.register(&specs)?;
        journal.reconcile()?;
        for outbox in outboxes {
            outbox.take_in(journal);
        }
        let acks = journal.acks()?;
        let previous = recorded(journal)?;
        let wrapped_before = previous
            .as_ref()
            .and_then(|previous| previous.data_key_wrapped);
        // A member holding a head sealed while the data key was not held
        // gets one wrapped to it as well, once it is (FIX 5791).
        let reseal = |id: &TargetId| recipients.data_key.is_some() && journal.root_only(id);
        let due = |id: &TargetId, position: &CustodyPosition| {
            acked_seq(&acks, id, position) != Some(position.seq) || reseal(id)
        };
        let sealed = self.seal_batch(custody, journal, recipients, set.revision, |position| {
            specs.iter().any(|spec| due(spec.id(), position))
        })?;
        let (position, batch) = match sealed {
            Sealed::Nothing => return Ok(Some(Publication::nothing())),
            Sealed::Failed(position, detail) => {
                return Ok(Some(Publication {
                    state: PublicationState::TargetPending,
                    local: Some(position),
                    published: least_acked(&set, &acks, &position),
                    anchored: previous.and_then(|previous| previous.anchored),
                    detail: Some(detail),
                    data_key_wrapped: wrapped_before,
                    anchor_unset: anchor.is_none(),
                }));
            }
            Sealed::Current(position) => (position, None),
            Sealed::Batch(batch) => (batch.position(), Some(batch)),
        };
        let lineage = Lineage::of(&position);
        let control = journal.control_or_create()?;
        let pending = |state, published, anchored, detail: String, wrapped| Publication {
            state,
            local: Some(position),
            published,
            anchored,
            detail: Some(detail),
            data_key_wrapped: wrapped,
            anchor_unset: anchor.is_none(),
        };
        // The anchor is read before any target is written: a newer writer
        // epoch fenced this one, and its head would only overwrite the new
        // writer's.
        let current = match anchor.map(|anchor| anchor.read(lineage.vault, lineage.namespace)) {
            None => None,
            Some(Ok(current)) => current,
            Some(Err(error)) => {
                return Ok(Some(pending(
                    PublicationState::AnchorPending,
                    least_acked(&set, &acks, &position),
                    None,
                    error.to_string(),
                    wrapped_before,
                )));
            }
        };
        let anchored = current
            .as_deref()
            .map(|record| verified_position(record, &control.anchor_key()))
            .transpose()?;
        if anchored.is_some_and(|anchored| anchored.epoch > position.epoch) {
            return Ok(Some(pending(
                PublicationState::Fenced,
                least_acked(&set, &acks, &position),
                anchored,
                "another install took this vault's custody over in a disaster recovery".into(),
                wrapped_before,
            )));
        }
        // A target holding a newer head of this log than the batch: a newer
        // pass published it there, and that pass acks it (FIX 6394).
        let mut covered = false;
        if let Some(batch) = &batch {
            for target in &targets {
                let spec = target.spec();
                if !due(spec.id(), &position) {
                    continue;
                }
                let outcome =
                    match target.publish(batch) {
                        Ok(TargetPublication::Acked(ack)) => journal
                            .accept_ack(batch, &ack)
                            .map_err(|error| TargetPending {
                                code: PendingCode::Failed,
                                detail: error.to_string(),
                            }),
                        Ok(TargetPublication::Covered) => {
                            covered = true;
                            Ok(())
                        }
                        Ok(TargetPublication::Pending(pending)) => Err(pending),
                        Err(error) => Err(TargetPending {
                            code: PendingCode::Failed,
                            detail: error.to_string(),
                        }),
                    };
                if let Err(pending) = outcome {
                    journal.note_pending(spec.id(), &pending)?;
                }
            }
        }
        drop(batch);
        // This pass is older than a head already published: it reports no
        // ack of its position as current, moves no watermark and advances
        // no anchor. The newer pass does all three.
        if covered {
            return Ok(None);
        }
        let set = journal.required_set()?;
        let acks = journal.acks()?;
        let published = least_acked(&set, &acks, &position);
        let wrapped = published.is_some().then(|| {
            !set.members
                .iter()
                .any(|member| journal.root_only(member.spec.id()))
        });
        let complete = |at: Option<CustodyPosition>| -> Result<()> {
            if let Some(at) = at
                && at.same_lineage(&position)
                && at.epoch == position.epoch
                && published.is_some_and(|published| published.seq >= at.seq)
            {
                journal.advance_completed(&at)?;
            }
            Ok(())
        };
        let behind: Vec<&str> = set
            .members
            .iter()
            .map(|member| member.spec.id())
            .filter(|id| acked_seq(&acks, id, &position) != Some(position.seq))
            .map(TargetId::as_str)
            .collect();
        // With no anchor configured, completion is every required target's
        // acknowledgement (CUSTODY_COMPLETION_NEEDS_ANCHOR, overruled).
        let unanchored = anchor.is_none() && !CUSTODY_COMPLETION_NEEDS_ANCHOR;
        if !behind.is_empty() {
            complete(if unanchored { published } else { anchored })?;
            return Ok(Some(pending(
                PublicationState::TargetPending,
                published,
                anchored,
                format!(
                    "custody target(s) {} hold no acknowledged head at log position {}; the next \
                     pass retries",
                    behind.join(", "),
                    position.seq
                ),
                wrapped,
            )));
        }
        let Some(anchor) = anchor else {
            if unanchored {
                complete(Some(position))?;
            }
            return Ok(Some(pending(
                PublicationState::AnchorPending,
                published,
                None,
                ANCHOR_UNSET.into(),
                wrapped,
            )));
        };
        let done = |anchored| Publication {
            state: PublicationState::Published,
            local: Some(position),
            published: Some(position),
            anchored: Some(anchored),
            detail: None,
            data_key_wrapped: wrapped,
            anchor_unset: false,
        };
        if anchored == Some(position) {
            complete(Some(position))?;
            return Ok(Some(done(position)));
        }
        let expected = current
            .as_deref()
            .map(|record| *blake3::hash(record).as_bytes());
        let advanced = anchor.advance(expected, &anchor_record(&position, &control));
        if let Ok(AnchorAdvance::Advanced) = advanced {
            complete(Some(position))?;
            return Ok(Some(done(position)));
        }
        complete(anchored)?;
        Ok(Some(pending(
            PublicationState::AnchorPending,
            published,
            anchored,
            match advanced {
                Err(error) => error.to_string(),
                Ok(_) => "the custody anchor moved during this pass; the next pass retries".into(),
            },
            wrapped,
        )))
    }

    /// Where this vault's custody publication stands, read without
    /// publishing: the last pass's record, behind the local log when a
    /// change since waits for the next pass.
    pub(crate) fn custody_publication(&self) -> Result<Publication> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Publication::nothing());
        };
        let journal = custody.journal()?;
        let local = journal.position()?;
        let pending = |recorded: Option<Publication>, detail: &str| Publication {
            state: PublicationState::TargetPending,
            local: Some(local),
            published: recorded.as_ref().and_then(|recorded| recorded.published),
            anchored: recorded.as_ref().and_then(|recorded| recorded.anchored),
            detail: Some(detail.to_owned()),
            anchor_unset: recorded
                .as_ref()
                .is_some_and(|recorded| recorded.anchor_unset),
            data_key_wrapped: recorded.and_then(|recorded| recorded.data_key_wrapped),
        };
        Ok(match recorded(&journal)? {
            None if local.seq == 0 && custody.census()?.is_empty() => Publication::nothing(),
            None => pending(None, "no publication pass has run yet"),
            Some(recorded)
                if recorded.local != Some(local) && recorded.state != PublicationState::Fenced =>
            {
                pending(
                    Some(recorded),
                    "a custody change waits for the next publication pass",
                )
            }
            Some(recorded) => recorded,
        })
    }

    /// Where this vault's retirements stand against every required target
    /// and the anchor, from the journal; `None` before any was handed off.
    pub(crate) fn custody_retirement(&self) -> Result<Option<RetirementProgress>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        let journal = custody.journal()?;
        let progress = journal.progress(&journal.position()?)?;
        Ok(progress.any.then_some(progress))
    }

    /// For a member that publishes on its own channel (the residence home,
    /// a hosted adapter): registers `spec` before its first exposure and,
    /// when it is behind the local position or holds a head without the
    /// data-key wrap the key now allows, seals a batch for it. `None` when
    /// it is current or nothing is in custody.
    pub(crate) fn custody_batch_for(
        &self,
        spec: &TargetSpec,
        recipients: &CustodyRecipients,
    ) -> Result<Option<CustodyBatch>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(None);
        }
        let journal = custody.journal()?;
        if custody_empty(self, custody, &journal)? {
            return Ok(None);
        }
        let set = journal.register(std::slice::from_ref(spec))?;
        journal.reconcile()?;
        let acks = journal.acks()?;
        let reseal = recipients.data_key.is_some() && journal.root_only(spec.id());
        let sealed = self.seal_batch(custody, &journal, recipients, set.revision, |position| {
            reseal || acked_seq(&acks, spec.id(), position) != Some(position.seq)
        })?;
        match sealed {
            Sealed::Batch(batch) => Ok(Some(batch)),
            Sealed::Failed(_, detail) => {
                journal.note_pending(
                    spec.id(),
                    &TargetPending {
                        code: PendingCode::Failed,
                        detail,
                    },
                )?;
                Ok(None)
            }
            Sealed::Nothing | Sealed::Current(_) => Ok(None),
        }
    }

    /// Accepts a member's ack of `batch` into the journal, once it names
    /// exactly that batch.
    pub(crate) fn accept_custody_ack(&self, batch: &CustodyBatch, ack: &AckRecord) -> Result<()> {
        let custody =
            self.core
                .key_custody
                .local()
                .ok_or(crate::error::Error::InvariantViolation(
                    "custody batch without custody",
                ))?;
        custody.journal()?.accept_ack(batch, ack)
    }

    /// The registered members of the required set of kind `kind`; `None`
    /// while nothing is in custody here, or the vault is archived.
    pub(crate) fn custody_members(&self, kind: TargetKind) -> Result<Option<Vec<TargetSpec>>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(None);
        }
        let journal = custody.journal()?;
        if custody_empty(self, custody, &journal)? {
            return Ok(None);
        }
        let members = journal.required_set()?.members.into_iter();
        Ok(Some(
            members
                .map(|member| member.spec)
                .filter(|spec| spec.kind() == kind)
                .collect(),
        ))
    }

    /// The custody subject of `item` of `kind` in this vault's binding;
    /// `None` while nothing was ever in custody here.
    pub(crate) fn custody_subject(
        &self,
        kind: super::identity::CustodyKind,
        item: &[u8],
    ) -> Result<Option<CustodySubject>> {
        self.core
            .key_custody
            .local()
            .map(|custody| custody.binding().subject(kind, item))
            .transpose()
    }

    /// The handed-off retirements of `subject` in this custody's journal, by
    /// log position, and whether each is complete; a disaster recovery's
    /// takeover obligation too, once the subject had a generation retired.
    pub(crate) fn custody_obligations_of(
        &self,
        subject: &CustodySubject,
    ) -> Result<Vec<(u64, bool)>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        let retired_here = custody.first_unretired(subject)? > 0;
        custody
            .journal()?
            .subject_obligations(subject, retired_here)
    }

    /// Records why `target` is still pending.
    pub(crate) fn note_custody_pending(
        &self,
        target: &TargetId,
        pending: &TargetPending,
    ) -> Result<()> {
        match self.core.key_custody.local() {
            Some(custody) => custody.journal()?.note_pending(target, pending),
            None => Ok(()),
        }
    }
}
