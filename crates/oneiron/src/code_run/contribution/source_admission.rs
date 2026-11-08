//! A contribution check reads its captured source only under each reader's
//! own admission (FIX 20607, L07-B's answer of 2026-11-06 23:27).
//!
//! The host declares who reads the pair's processed source, and why, before
//! any of it is read ([`ContributionSourceReadRequest`]): the held-out judge
//! under its own principal, the audit's judge, or the owner the pair's
//! question asks. The request is a fact. No actor or Grant id in it admits a
//! read.
//!
//! The Coach processes the pair: it prepares, generates and runs each fork.
//! Each captured step it reads is admitted first by the Coach's own live
//! Grant, by the code fix's evaluator under its own rule
//! ([`admitting_grant_in`]). One agent Grant that an owner gave the Coach
//! must confer read now and keep its pact standing. It must admit the record
//! position of every row the step's request was read from, and the Coach's
//! scoped read must read each row. For an engine step it must also admit
//! every Scope the step was served (FIX 7027). Unknown rows or Scopes admit
//! no one. That one Grant is read again before each later read of the step
//! ([`ContributionSourceAdmission`]).
//!
//! The consumer reads under its own admission as well. It is asked before
//! each body the scorer gets, before each send to the scorer's model, and
//! before the owner is shown the pair. The held-out judge's principal, and
//! the owner the pair asks, must each read every row of each step under that
//! reader's own authority ([`question_lane`]). The audit's judge is asked and
//! paid for by the Coach, so it reads under the Coach's admission. A pair
//! whose reader is not admitted now stops as `Unfinished`. That is never
//! lasting: a Grant given later runs the pair.
//!
//! A kept owner pair keeps the Coach's admission to every step as proof
//! data ([`PairSourceIdentity`]). The writer that records the owner's word
//! rebuilds it and asks the owner's own admission again before it reads
//! each held answer. A lapse keeps the owner's word for the Coach's next
//! pass, which asks again.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::replay_capsule::{CapsuleHost, StepReplayCapsule};
use super::super::shadow_runner::{ShadowSourceAdmission, ShadowSourceWitness, ShadowStepIdentity};
use super::super::storage::{fork_response, step_replay_capsules_in_txn};
use super::{
    ContributionForkReceipt, ContributionReplayUnavailable as Unavailable, Outcome, Prepared,
    Runner,
};
use crate::claim::ScopedReadActorKey;
use crate::dreamer_runner::maintenance::code_fix::{CaptureRefs, admitting_grant_in};
use crate::learning::Anchor;
use crate::llm::decision::questions::question_lane;
use crate::{EntityId, Error, LlmResponse, Result, Vault};

/// Who reads a contribution pair's processed source (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionSourceConsumer {
    /// The held-out judge's question, asked under `principal`, the judge's
    /// own principal.
    HeldOutJudge { principal: EntityId },
    /// The completed audit's frozen judge. The Coach asks it and pays.
    Audit,
    /// The vault owner the pair's question asks.
    OwnerReview,
}

/// Why the consumer reads the pair's processed source (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionSourcePurpose {
    /// A model scores each fork against the pair's frozen rubric.
    ForkScoring,
    /// The owner reads both blinded answers and judges them.
    OwnerVerdict,
}

/// What a host declares before a pair reads any of its source (FIX 20607):
/// the consumer and the purpose. These are facts. They admit no read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributionSourceReadRequest {
    pub consumer: ContributionSourceConsumer,
    pub purpose: ContributionSourcePurpose,
}

impl ContributionSourceReadRequest {
    /// Whether `anchor`'s pair reads under this request: an owner verdict's
    /// for owner review, an audit's for the audit's judge, and any other's
    /// for the held-out judge, each for its own purpose.
    pub(super) const fn fits(&self, anchor: &Anchor) -> bool {
        use ContributionSourceConsumer as Consumer;
        use ContributionSourcePurpose as Purpose;
        match anchor {
            Anchor::OwnerVerdict => matches!(
                (self.consumer, self.purpose),
                (Consumer::OwnerReview, Purpose::OwnerVerdict)
            ),
            Anchor::Audit { .. } => matches!(
                (self.consumer, self.purpose),
                (Consumer::Audit, Purpose::ForkScoring)
            ),
            _ => matches!(
                (self.consumer, self.purpose),
                (Consumer::HeldOutJudge { .. }, Purpose::ForkScoring)
            ),
        }
    }
}

/// Who a read of a pair's source is for (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairReader {
    /// The Coach, while it prepares, generates and runs the pair's forks.
    Coach,
    /// The pair's consumer. `owner` is the owner an owner review asks.
    Consumer { owner: Option<EntityId> },
}

/// The pair's two readers (FIX 20607): the Coach, which the engine resolves,
/// and the consumer the host declared.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ContributionSourceReader {
    coach: EntityId,
    request: ContributionSourceReadRequest,
}

impl ContributionSourceReader {
    /// The Coach of `vault`, and `request`'s consumer. Resolved outside any
    /// read: resolving the Coach may seed it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn new(vault: &Vault, request: ContributionSourceReadRequest) -> Result<Self> {
        Ok(Self {
            coach: vault.coach_authority()?.entity_ref(),
            request,
        })
    }

    /// The Coach whose own Grant admits each step.
    pub(crate) const fn coach(&self) -> EntityId {
        self.coach
    }

    /// The Coach's admission to `capsule`'s step, in a snapshot of its own;
    /// `None` while no Grant admits it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn admit(
        &self,
        vault: &Vault,
        capsule: &StepReplayCapsule,
    ) -> Result<Option<Arc<ContributionSourceAdmission>>> {
        let txn = vault.store.env.read_txn()?;
        ContributionSourceAdmission::take_in(vault, &txn, self.coach, capsule)
    }
}

/// The Coach's admission to one captured step's source (FIX 20607): the
/// Grant that alone admits it, where the step was found, and whether the
/// step's served Scopes bind it too (an engine step's do, FIX 7027). A
/// workflow step's fork sends its kept request alone, as a code fix's
/// replay of a kept request does, so its rows' positions decide. A kept
/// owner pair keeps it as proof data. It admits nothing until it is asked
/// again ([`PairSourceIdentity`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContributionSourceAdmission {
    coach: EntityId,
    grant: EntityId,
    step: ShadowStepIdentity,
    request_hash: [u8; 32],
    refs: CaptureRefs,
    step_bound: bool,
}

impl ContributionSourceAdmission {
    /// `coach`'s admission to `capsule`'s step, read in `txn`: the first
    /// Grant in id order that admits the step's capture alone. `None` while
    /// no Grant admits it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn take_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        coach: EntityId,
        capsule: &StepReplayCapsule,
    ) -> Result<Option<Arc<Self>>> {
        let refs = CaptureRefs::of_step(capsule);
        let step_bound = capsule.host == CapsuleHost::EngineStep;
        let bound = step_bound.then_some(capsule);
        let Ok(grant) = admitting_grant_in(vault, txn, coach, &refs, None, bound)? else {
            return Ok(None);
        };
        Ok(Some(Arc::new(Self {
            coach,
            grant,
            step: ShadowStepIdentity::of(capsule),
            request_hash: capsule.request_hash,
            refs,
            step_bound,
        })))
    }

    /// Whether its Grant still admits the step's capture alone, read in
    /// `txn`: the step is still kept as it was found, from the same rows,
    /// and that Grant still admits them, as it did when it was taken.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn admits_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let found = step_replay_capsules_in_txn(vault, txn, self.step.attempt)?
            .into_iter()
            .find(|capsule| {
                ShadowStepIdentity::of(capsule) == self.step
                    && capsule.request_hash == self.request_hash
            });
        let Some(capsule) = found else {
            return Ok(false);
        };
        if CaptureRefs::of_step(&capsule) != self.refs {
            return Ok(false);
        }
        let bound = self.step_bound.then_some(&capsule);
        let only = Some(self.grant);
        Ok(admitting_grant_in(vault, txn, self.coach, &self.refs, only, bound)?.is_ok())
    }

    /// Whether `reader` reads every row the step's request was read from,
    /// in `txn`, under its own authority: as a question's own reader reads
    /// (FIX 7461), its own Grants and its live owner standing included.
    /// Unknown rows are read by no one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn read_by_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>, reader: EntityId) -> Result<bool> {
        let Some(rows) = self.refs.rows() else {
            return Ok(false);
        };
        let key = ScopedReadActorKey::new(reader.to_hex())
            .ok_or(Error::InvariantViolation(
                "canonical contribution source reader",
            ))?
            .exempt_while_owner(reader);
        let lane = question_lane(vault, key);
        let policy = lane.live_policy_manifest_in(txn)?;
        for row in rows {
            if !lane.is_entity_readable_with_policy_in(txn, &policy, row)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The witness of `admission` (FIX 20607): the Coach's admission to its
    /// step, held by the host's program run and asked before each raw read
    /// of the step and each release of an arm's body.
    pub(crate) fn witness(admission: &Arc<Self>) -> ShadowSourceWitness {
        let held: Arc<Self> = Arc::clone(admission);
        ShadowSourceWitness::new(admission.step, held)
    }
}

impl ShadowSourceAdmission for ContributionSourceAdmission {
    fn admits_now(&self, vault: &Vault) -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        self.admits_in(vault, &txn)
    }
}

/// Every captured step a pair's forks are made from, each under the
/// Coach's own admission, and the pair's two readers (FIX 20607). A
/// knowledge pair's is its regenerated step. A callable's or a delivery's
/// pair adds its caller's step, whose branches made the forks' requests.
pub(crate) struct PairSourceAdmission {
    reader: ContributionSourceReader,
    steps: Vec<Arc<ContributionSourceAdmission>>,
}

impl PairSourceAdmission {
    /// The pair's admission to `steps`, read for `reader`'s readers.
    pub(crate) fn new(
        reader: ContributionSourceReader,
        steps: Vec<Arc<ContributionSourceAdmission>>,
    ) -> Self {
        Self { reader, steps }
    }

    /// Whether `reader` may read the pair's source now, in `txn`: the Coach
    /// is still admitted to every step, and a consumer reads every step
    /// under its own admission too. An owner review with no owner is read
    /// by no one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn admits_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        reader: PairReader,
    ) -> Result<bool> {
        use ContributionSourceConsumer as Consumer;
        for step in &self.steps {
            if !step.admits_in(vault, txn)? {
                return Ok(false);
            }
        }
        let principal = match (reader, self.reader.request.consumer) {
            (PairReader::Coach, _) | (PairReader::Consumer { .. }, Consumer::Audit) => {
                return Ok(true);
            }
            (PairReader::Consumer { .. }, Consumer::HeldOutJudge { principal }) => principal,
            (PairReader::Consumer { owner: Some(owner) }, Consumer::OwnerReview) => owner,
            (PairReader::Consumer { owner: None }, Consumer::OwnerReview) => return Ok(false),
        };
        for step in &self.steps {
            if !step.read_by_in(vault, txn, principal)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// [`Self::admits_in`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn admits_now(&self, vault: &Vault, reader: PairReader) -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        self.admits_in(vault, &txn, reader)
    }

    /// What a kept owner pair keeps of it (FIX 20607): the Coach's admission
    /// to every step, the caller's step of a callable's or a delivery's pair
    /// included. No reader and no admission result is kept.
    pub(crate) fn identity(&self) -> PairSourceIdentity {
        PairSourceIdentity {
            steps: self.steps.iter().map(Arc::as_ref).cloned().collect(),
        }
    }
}

/// The source of a kept owner pair (FIX 20607): the Coach's admission to
/// every step its forks were made from, as proof data only. Each keeps the
/// Coach, the exact Grant, the step, its request hash, the rows it was read
/// from and whether its served Scopes bind it. It admits no read until it
/// is asked again in the reading writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PairSourceIdentity {
    steps: Vec<ContributionSourceAdmission>,
}

impl PairSourceIdentity {
    /// Whether `owner` reads the pair's source now, in `txn` (FIX 20607).
    /// The kept admissions are rebuilt and asked as before the owner was
    /// shown the pair: each step's own Grant is read again, never another,
    /// and `owner` reads every row under its own question lane. A pair
    /// with no kept step is read by no one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn owner_reads_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
    ) -> Result<bool> {
        let Some(first) = self.steps.first() else {
            return Ok(false);
        };
        let reader = ContributionSourceReader {
            coach: first.coach,
            request: ContributionSourceReadRequest {
                consumer: ContributionSourceConsumer::OwnerReview,
                purpose: ContributionSourcePurpose::OwnerVerdict,
            },
        };
        let steps = self.steps.iter().cloned().map(Arc::new).collect();
        let source = PairSourceAdmission::new(reader, steps);
        source.admits_in(vault, txn, PairReader::Consumer { owner: Some(owner) })
    }
}

impl Runner<'_> {
    /// Why a read of the pair's source for `reader` came back empty (FIX
    /// 20607): `Unfinished` while `reader` is not admitted now, which is
    /// never lasting, else `unread`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn unread(
        &self,
        prepared: &Prepared,
        reader: PairReader,
        unread: Unavailable,
    ) -> Result<Unavailable> {
        Ok(if prepared.source.admits_now(self.vault, reader)? {
            unread
        } else {
            Unavailable::Unfinished
        })
    }

    /// `fork`'s kept answer as `reader` reads it now (FIX 20607): read while
    /// `reader` is admitted in the read's own snapshot. An answer that does
    /// not read is `Unfinished` while `reader` is not admitted, else
    /// `Erased` or `Unreadable`, as before.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn read_response(
        &self,
        prepared: &Prepared,
        fork: &ContributionForkReceipt,
        reader: PairReader,
    ) -> Outcome<LlmResponse> {
        let source = &prepared.source;
        let admits = |txn: &heed::RoTxn<'_>| source.admits_in(self.vault, txn, reader);
        if let Some(response) = fork_response(self.vault, prepared.capsule.run, fork, &admits)? {
            return Ok(Ok(response));
        }
        let unread = if fork.response_erased {
            Unavailable::Erased
        } else {
            Unavailable::Unreadable
        };
        Ok(Err(self.unread(prepared, reader, unread)?))
    }
}
