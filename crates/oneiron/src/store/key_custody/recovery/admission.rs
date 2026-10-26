//! Admitting a lineage's custody for a restore (KS-4, FIX 5685): its head
//! opened, checked against the anchor when one is configured, reconciled
//! through the keyless log, and required to cover what the image needs.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason as R, because};

use super::super::anchor::verified_position;
use super::super::body_history::HistoryRows;
use super::super::erase_evidence::{FenceFact, fold_fact};
use super::super::head::{CustodyOpener, OpenedHead, open_head};
use super::super::identity::{CustodyId, CustodySecret, CustodySubject};
use super::super::log::{Control, CustodyPosition, FrameHeader, LogEntry, frame_hash, open_frame};
use super::super::protocol::{AnchorStore, CustodySource, Lineage};
use super::super::recipients::RecipientRetirement;
use super::{
    CUSTODY_ANCHOR_UNSET_RESTORE, CustodyRequirement, ROLLBACK_NOT_PROVEN, refused, unopened,
};

/// A lineage's custody as admitted for a restore.
pub(crate) struct AdmittedCustody {
    /// The position admitted: the anchor's, or the head's where it is newer
    /// or no anchor is configured, at the newer of their writer epochs.
    pub(super) position: CustodyPosition,
    pub(super) control: Zeroizing<[u8; 32]>,
    pub(super) live: BTreeMap<CustodyId, CustodySecret>,
    pub(super) retired: BTreeSet<CustodyId>,
    /// Subjects whose generations through this one the log after the head
    /// retired.
    pub(super) retired_through: BTreeMap<CustodySubject, u64>,
    /// The anchor record admission read; `None` with no anchor configured.
    pub(super) anchor: Option<Vec<u8>>,
    /// The head's own position, before its anchor reconciled it.
    pub(super) head: CustodyPosition,
    /// The released escrow recipients the lineage retired, by fingerprint:
    /// the head's, and the log's after it (LC FIX 5384/5385).
    pub(super) recipients: BTreeMap<[u8; 32], RecipientRetirement>,
    /// The lineage's body history: the head's, and the log's after it.
    pub(super) history: HistoryRows,
    /// Each erased credential's fact (FIX 10584 item 3): the head's, and
    /// the log's after it.
    pub(super) evidence: BTreeMap<EntityId, FenceFact>,
}

impl AdmittedCustody {
    /// What the restore says about this admission: rollback is not proven
    /// when no anchor was configured.
    pub(crate) fn note(&self) -> Option<&'static str> {
        self.anchor.is_none().then_some(ROLLBACK_NOT_PROVEN)
    }

    pub(super) fn retires(&self, id: &CustodyId) -> bool {
        self.retired.contains(id)
            || self
                .retired_through
                .get(id.subject())
                .is_some_and(|through| id.generation() <= *through)
    }
}

/// The frames of `source` after `from` through `to`, each checked to
/// extend the one before it, from `from`'s tip to `to`'s.
fn chain(
    source: &dyn CustodySource,
    lineage: Lineage,
    from: &CustodyPosition,
    to: &CustodyPosition,
) -> std::result::Result<Vec<Vec<u8>>, Rejected> {
    let mut tip = from.tip;
    let mut frames = Vec::new();
    for seq in from.seq.saturating_add(1)..=to.seq {
        let frame = source.frame(lineage, seq)?.ok_or_else(|| {
            Rejected::new(
                R::CustodyLogIncomplete,
                refused("the custody log beside the backup is missing a frame".into()),
            )
        })?;
        let (header, _): (FrameHeader, _) =
            FrameHeader::parse(&frame).map_err(because(R::CodecInvalid))?;
        if header.seq != seq
            || header.prev != tip
            || header.epoch > to.epoch
            || header.vault != lineage.vault
            || header.namespace != lineage.namespace
        {
            return Err(diverged());
        }
        tip = frame_hash(&frame);
        frames.push(frame);
    }
    if tip != to.tip {
        return Err(diverged());
    }
    Ok(frames)
}

fn diverged() -> Rejected {
    Rejected::new(
        R::CustodyDiverged,
        refused("the custody log beside the backup does not chain".into()),
    )
}

/// A frame of the lineage opened under its control secret: one that does
/// not parse is a codec failure, one that does not open is another
/// lineage's.
fn open_lineage_frame(control: &Control, frame: &[u8]) -> std::result::Result<LogEntry, Rejected> {
    open_frame(control, frame)
        .map(|(_, entry)| entry)
        .map_err(|error| match error {
            Error::CorruptedIndex(_) => Rejected::new(R::CodecInvalid, error),
            error => Rejected::new(R::CustodyDiverged, error),
        })
}

/// Admits the custody `required` names from `source`, opened with
/// `opener`, against `anchor` when one is configured. Refuses a missing
/// head; with an anchor, a missing or stale anchor record; and a bad seal,
/// lineage, chain or coverage. Each refusal names its reason beside the
/// error it always returned.
pub(crate) fn admit_recovery(
    required: &CustodyRequirement,
    source: &dyn CustodySource,
    opener: &CustodyOpener<'_>,
    anchor: Option<&dyn AnchorStore>,
) -> std::result::Result<AdmittedCustody, Rejected> {
    let wanted = required
        .position()
        .map_err(because(R::CustodyRequirementInvalid))?;
    let lineage = Lineage::of(&wanted);
    let record = match anchor {
        Some(anchor) => Some(
            anchor
                .read(lineage.vault, lineage.namespace)
                .map_err(because(R::AnchorUnavailable))?
                .ok_or_else(|| {
                    Rejected::new(
                        R::AnchorMissing,
                        refused(
                            "the custody anchor holds no record of this vault's custody".into(),
                        ),
                    )
                })?,
        ),
        None if CUSTODY_ANCHOR_UNSET_RESTORE => None,
        None => {
            return Err(Rejected::new(
                R::AnchorMissing,
                refused(ROLLBACK_NOT_PROVEN.into()),
            ));
        }
    };
    let head = source.head(lineage)?.ok_or_else(|| {
        Rejected::new(
            R::CustodyHeadInvalid,
            refused("no custody head of this vault is beside the backup".into()),
        )
    })?;
    let opened: OpenedHead = open_head(&head, opener).map_err(because(R::CustodyHeadInvalid))?;
    drop(head);
    if !opened.position.same_lineage(&wanted) {
        return Err(Rejected::new(
            R::CustodyLineageMismatch,
            refused("the custody head beside the backup is another vault's".into()),
        ));
    }
    let control = Control::for_secret(opened.control);
    // Ids the log after the head mints: their keys are in no head admitted.
    let mut minted_after = BTreeSet::new();
    let mut admitted = AdmittedCustody {
        position: opened.position,
        control: Zeroizing::new(*control.secret()),
        live: opened.live,
        retired: opened.retired,
        retired_through: BTreeMap::new(),
        anchor: None,
        head: opened.position,
        recipients: opened
            .recipients
            .into_iter()
            .map(|fact| (fact.fingerprint, fact))
            .collect(),
        history: opened.history,
        evidence: opened.evidence,
    };
    if let Some(record) = record {
        let anchored =
            verified_position(&record, &control.anchor_key()).map_err(because(R::AnchorInvalid))?;
        let head = admitted.position;
        if !anchored.same_lineage(&head) {
            return Err(Rejected::new(
                R::CustodyLineageMismatch,
                refused("the custody anchor record is another vault's".into()),
            ));
        }
        let epoch = head.epoch.max(anchored.epoch);
        if anchored.seq == head.seq && anchored.tip == head.tip && head.epoch <= anchored.epoch {
            admitted.position = anchored;
        } else if head.seq > anchored.seq && head.epoch >= anchored.epoch {
            chain(source, lineage, &anchored, &head)?;
        } else if head.seq < anchored.seq {
            // The head is older than its anchor: the retirements after it
            // still apply, and a key minted after it is not in it.
            for frame in chain(source, lineage, &head, &anchored)? {
                match open_lineage_frame(&control, &frame)? {
                    LogEntry::Retire {
                        subject, through, ..
                    } => {
                        admitted.live.retain(|id, _| {
                            !(id.subject() == &subject && id.generation() <= through)
                        });
                        let slot = admitted.retired_through.entry(subject).or_insert(through);
                        *slot = (*slot).max(through);
                    }
                    LogEntry::Mint(id) => {
                        minted_after.insert(id);
                    }
                    LogEntry::RetireRecipient(fact) => {
                        admitted.recipients.insert(fact.fingerprint, fact);
                    }
                    LogEntry::BodyHistory(rows) => admitted.history.extend(rows),
                    LogEntry::EraseEvidence(fact) => fold_fact(&mut admitted.evidence, fact),
                    LogEntry::PublicationPolicy(_) => {}
                }
            }
            admitted.position = anchored;
        } else {
            return Err(Rejected::new(
                R::CustodyDiverged,
                refused("the custody head and its anchor have diverged".into()),
            ));
        }
        admitted.position.epoch = epoch;
        admitted.anchor = Some(record);
    }
    // The image's position is the admitted one, or its ancestor.
    let current = admitted.position;
    if wanted.seq > current.seq || wanted.epoch > current.epoch {
        return Err(Rejected::new(
            R::CustodyHeadTooOld,
            refused(
                "the custody head is older than the backup: it cannot hold every key the backup \
                 needs"
                    .into(),
            ),
        ));
    }
    if wanted.seq == current.seq {
        if wanted.tip != current.tip {
            return Err(Rejected::new(
                R::CustodyDiverged,
                refused("the custody head and the backup have diverged".into()),
            ));
        }
    } else {
        chain(source, lineage, &wanted, &current)?;
    }
    let missing: Vec<CustodyId> = required
        .ids()
        .map_err(because(R::CustodyRequirementInvalid))?
        .into_iter()
        .filter(|id| !admitted.live.contains_key(id) && !admitted.retires(id))
        .collect();
    if !missing.is_empty() {
        let count = missing.len();
        let (reason, message) = if missing.iter().any(|id| minted_after.contains(id)) {
            (
                R::CustodyHeadTooOld,
                format!(
                    "{count} key(s) the backup needs were minted after the newest custody head \
                     beside it"
                ),
            )
        } else if !unopened::may_hold_required(&opened.unopened) {
            (
                R::CustodyKeyMissing,
                format!("the custody head does not hold {count} key(s) the backup needs"),
            )
        } else {
            (
                R::CustodyOwnerKeyRequired,
                unopened::owner_key_required(count, &opened.unopened),
            )
        };
        return Err(Rejected::new(reason, refused(message)));
    }
    Ok(admitted)
}
