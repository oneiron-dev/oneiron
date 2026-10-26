//! The status names of a vault's custody (KS-4A1/KS-4A2, FIX 5685), on the
//! owner's status read (`doctor`, `GET /v1/owner/status`), `oneiron backup`
//! and an erase receipt's sweep read.
//!
//! Publication: `custody_none`, `custody_published`, `custody_target_pending`,
//! `custody_anchor_pending`, `custody_fenced`. Retirement, from the journal's
//! obligations and completion watermark (never the LMDB intent, which clears
//! at the handoff): `custody_retirement_pending`, then every outstanding
//! `custody_target_pending(<target id>)`, then `custody_anchor_pending`, then
//! `custody_retirement_complete`. An unset anchor stays pending; a fenced
//! writer is never complete; a hosted member stays pending until its adapter
//! acks. An erasable key another machine holds a copy of reads
//! `custody_remote_retirement_pending(<holder machine>)` until that holder's
//! retirement of it is verified (FIX 8875): pending, never `not required`.

use serde::Serialize;

use crate::store::custody_protocol::{
    CustodyBatch, CustodySource, CustodyTarget, Lineage, PendingCode, TargetPending,
    TargetPublication, TargetSpec,
};
use crate::store::{
    CUSTODY_COMPLETION_NEEDS_ANCHOR, MemberProgress, Publication, PublicationState,
    ROLLBACK_NOT_PROVEN, RetirementProgress,
};

/// The owner's status read's names for where a vault's custody publication
/// stands.
pub const CUSTODY_NONE: &str = "custody_none";
pub const CUSTODY_PUBLISHED: &str = "custody_published";
pub const CUSTODY_TARGET_PENDING: &str = "custody_target_pending";
pub const CUSTODY_ANCHOR_PENDING: &str = "custody_anchor_pending";
pub const CUSTODY_FENCED: &str = "custody_fenced";
/// A retirement is not complete everywhere yet.
pub const CUSTODY_RETIREMENT_PENDING: &str = "custody_retirement_pending";
/// Every handed-off retirement is acknowledged by every required target and
/// anchored.
pub const CUSTODY_RETIREMENT_COMPLETE: &str = "custody_retirement_complete";
/// A retired erasable key's copy another machine holds is not verified
/// retired yet (FIX 8875); its step names the holder machine.
pub const CUSTODY_REMOTE_RETIREMENT_PENDING: &str = "custody_remote_retirement_pending";

/// Where one vault's custody publication stands: the status read's state
/// name, the positions it compared (writer epoch, log sequence numbers;
/// public structure, never a key), why a step is pending, and where its
/// retirements stand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyStatus {
    /// One of [`CUSTODY_NONE`], [`CUSTODY_PUBLISHED`],
    /// [`CUSTODY_TARGET_PENDING`] (a required target lacks the head at the
    /// local position), [`CUSTODY_ANCHOR_PENDING`] (the anchor is not set
    /// up, missing, or behind) or [`CUSTODY_FENCED`] (another install took
    /// the custody over in a disaster recovery).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchored_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `false` while a target holds a head sealed when the vault data key
    /// was not held (the recovery root's wrap only): the next pass with the
    /// key held seals it again (FIX 5791).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_key_wrapped: Option<bool>,
    /// Where this vault's key retirements stand; absent before any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retirement: Option<CustodyRetirement>,
}

/// Where a vault's key retirements stand against every required target and
/// the anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyRetirement {
    /// [`CUSTODY_RETIREMENT_PENDING`] or [`CUSTODY_RETIREMENT_COMPLETE`].
    pub state: &'static str,
    /// Each step still owed, in order.
    pub pending: Vec<CustodyPendingStep>,
    /// The same steps as the CLI prints them:
    /// `custody_target_pending(<target id>)`.
    pub names: Vec<String>,
    /// Handed-off retirements not complete yet.
    pub outstanding: u64,
    /// The completion watermark: every retirement at or before this log
    /// position is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_seq: Option<u64>,
    /// The required target set's revision.
    pub set_revision: u64,
    /// Every member of the required set.
    pub targets: Vec<CustodyTargetState>,
    /// "rollback not proven: no custody anchor configured" while no anchor
    /// is configured: a retirement completes on every required target's
    /// acknowledgement alone (CALLS CUSTODY_COMPLETION_NEEDS_ANCHOR,
    /// overruled Engine 10-20).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// One step a retirement still owes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyPendingStep {
    /// [`CUSTODY_RETIREMENT_PENDING`] (an intent not handed off yet),
    /// [`CUSTODY_TARGET_PENDING`], [`CUSTODY_ANCHOR_PENDING`] or
    /// [`CUSTODY_REMOTE_RETIREMENT_PENDING`] (its `target_id` the holder
    /// machine).
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// The target's last sanitized reason: `offline`, `locked`, `denied`,
    /// `no_adapter`, `moved` or `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl CustodyPendingStep {
    /// `state`, or `state(<target id>)` for a target's step.
    pub fn name(&self) -> String {
        match &self.target_id {
            Some(target) => format!("{}({target})", self.state),
            None => self.state.to_owned(),
        }
    }
}

/// One required target's acknowledgement state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodyTargetState {
    pub target_id: String,
    /// `folder`, `residence`, or a hosted kind.
    pub kind: &'static str,
    /// The log position its newest accepted acknowledgement names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_seq: Option<u64>,
    /// Why its last attempt did not ack, and when (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CustodyStatus {
    pub(super) fn of(publication: Publication, retirement: Option<CustodyRetirement>) -> Self {
        Self {
            state: match publication.state {
                PublicationState::Nothing => CUSTODY_NONE,
                PublicationState::Published => CUSTODY_PUBLISHED,
                PublicationState::TargetPending => CUSTODY_TARGET_PENDING,
                PublicationState::AnchorPending => CUSTODY_ANCHOR_PENDING,
                PublicationState::Fenced => CUSTODY_FENCED,
            },
            writer_epoch: publication.local.map(|local| local.epoch.get()),
            log_seq: publication.local.map(|local| local.seq),
            published_seq: publication.published.map(|published| published.seq),
            anchored_seq: publication.anchored.map(|anchored| anchored.seq),
            detail: publication.detail,
            data_key_wrapped: publication.data_key_wrapped,
            retirement,
        }
    }
}

fn target_step(member: &MemberProgress) -> CustodyPendingStep {
    CustodyPendingStep {
        state: CUSTODY_TARGET_PENDING,
        target_id: Some(member.id.as_str().to_owned()),
        reason: member.pending.as_ref().map(|note| note.code.name()),
    }
}

/// The step a retired erasable key's copy on `holder` (its machine's hex)
/// owes until that holder's retirement is verified (FIX 8875).
pub(super) fn remote_step(holder: String) -> CustodyPendingStep {
    CustodyPendingStep {
        state: CUSTODY_REMOTE_RETIREMENT_PENDING,
        target_id: Some(holder),
        reason: None,
    }
}

fn anchor_step() -> CustodyPendingStep {
    CustodyPendingStep {
        state: CUSTODY_ANCHOR_PENDING,
        target_id: None,
        reason: None,
    }
}

/// The steps still owed for retirements whose newest outstanding log
/// position is `newest`: every member whose ack is behind it, then the
/// anchor when it is behind it or fenced. With no anchor configured the
/// anchor is owed nothing: every member's ack completes a retirement, with
/// rollback not proven. With every member there but the watermark not
/// raised yet, the anchor step stands: the next pass records the
/// completion.
pub(super) fn owed(
    progress: &RetirementProgress,
    publication: &Publication,
    newest: u64,
) -> Vec<CustodyPendingStep> {
    let mut steps: Vec<CustodyPendingStep> = progress
        .members
        .iter()
        .filter(|member| member.acked.is_none_or(|acked| acked < newest))
        .map(target_step)
        .collect();
    let anchored = publication
        .anchored
        .zip(publication.local)
        .filter(|(anchored, local)| anchored.epoch == local.epoch)
        .map(|(anchored, _)| anchored.seq);
    let unanchored = publication.anchor_unset && !CUSTODY_COMPLETION_NEEDS_ANCHOR;
    if publication.state == PublicationState::Fenced
        || (!unanchored && anchored.is_none_or(|anchored| anchored < newest))
        || steps.is_empty()
    {
        steps.push(anchor_step());
    }
    steps
}

/// What a retirement read says about rollback: not proven while no anchor
/// is configured.
pub(super) fn rollback_note(publication: &Publication) -> Option<&'static str> {
    publication.anchor_unset.then_some(ROLLBACK_NOT_PROVEN)
}

/// The retirement status from the journal's `progress`, the count of
/// intents not handed off yet and the holders whose copy of a retired
/// erasable key is not verified retired (FIX 8875); `None` before any
/// retirement.
pub(super) fn retirement(
    progress: Option<RetirementProgress>,
    standing: usize,
    remote: Vec<String>,
    publication: &Publication,
) -> Option<CustodyRetirement> {
    if standing == 0 && progress.is_none() && remote.is_empty() {
        return None;
    }
    let mut pending = Vec::new();
    if standing > 0 {
        pending.push(CustodyPendingStep {
            state: CUSTODY_RETIREMENT_PENDING,
            target_id: None,
            reason: None,
        });
    }
    pending.extend(remote.into_iter().map(remote_step));
    let (outstanding, completed_seq, set_revision, targets) = match &progress {
        Some(progress) => {
            if let Some(&newest) = progress.outstanding.last() {
                pending.extend(owed(progress, publication, newest));
            }
            (
                u64::try_from(progress.outstanding.len()).unwrap_or(u64::MAX),
                progress.completed,
                progress.revision,
                progress
                    .members
                    .iter()
                    .map(|member| CustodyTargetState {
                        target_id: member.id.as_str().to_owned(),
                        kind: member.kind.name(),
                        acked_seq: member.acked,
                        pending: member.pending.as_ref().map(|note| note.code.name()),
                        pending_since: member.pending.as_ref().map(|note| note.at),
                        detail: member.pending.as_ref().map(|note| note.detail.clone()),
                    })
                    .collect(),
            )
        }
        None => (0, None, 0, Vec::new()),
    };
    Some(CustodyRetirement {
        state: if pending.is_empty() {
            CUSTODY_RETIREMENT_COMPLETE
        } else {
            CUSTODY_RETIREMENT_PENDING
        },
        names: pending.iter().map(CustodyPendingStep::name).collect(),
        pending,
        outstanding,
        completed_seq,
        set_revision,
        targets,
        note: rollback_note(publication),
    })
}

/// A member a host declared that this build has no adapter for (a hosted
/// holder until KS-C4): registered, and pending as `no_adapter` on every
/// pass, never acknowledged.
pub struct DeclaredTarget(TargetSpec);

impl DeclaredTarget {
    pub fn new(spec: TargetSpec) -> Self {
        Self(spec)
    }
}

impl CustodySource for DeclaredTarget {
    fn head(&self, _: Lineage) -> crate::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn frame(&self, _: Lineage, _: u64) -> crate::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

impl CustodyTarget for DeclaredTarget {
    fn spec(&self) -> TargetSpec {
        self.0.clone()
    }

    fn publish(&self, _: &CustodyBatch) -> crate::Result<TargetPublication> {
        Ok(TargetPublication::Pending(TargetPending {
            code: PendingCode::NoAdapter,
            detail: format!(
                "no {} adapter in this build: its custody stays pending until KS-C4",
                self.0.kind().name()
            ),
        }))
    }
}
