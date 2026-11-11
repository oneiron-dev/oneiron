//! Door for `tests/check_in_pending_handle.rs`, `tests/check_in_rung_waits.rs`
//! and `tests/check_in_ladder.rs` (ROLES-CHECKIN P2.2, pieces 2b, 2d and 2c):
//! the pending check-in's doors, each in one write transaction at the vault's
//! store clock, read once. In the plain doors the chain is the test's: each
//! rung's holders as the test names them, each of them free to answer. The
//! `_verified` doors run the ladder from verified records (2c), with the
//! test's agent verdicts.

use std::collections::BTreeMap;

use crate::check_in::{
    AgentHolderVerdict, CheckInTransition, HolderAnswer, HolderKind, NoAgentVerdict,
    OpenPendingCheckIn, PendingCheckIn, Rung, RungHolder, RungMembers, RungResolver, VerifiedChain,
    advance_pending_check_in_in_txn, answer_pending_check_in_in_txn,
    extend_pending_check_in_in_txn, open_pending_check_in_in_txn, record_objection_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// A chain the test names: each rung's members. A rung it does not name is
/// missing, with the link "not in the test chain".
#[derive(Clone, Debug, Default)]
pub struct FixedChain {
    rungs: BTreeMap<Rung, RungMembers>,
    verdicts: FixedVerdicts,
}

impl FixedChain {
    /// This chain, with `rung`'s members.
    #[must_use]
    pub fn with(mut self, rung: Rung, members: RungMembers) -> Self {
        self.rungs.insert(rung, members);
        self
    }

    /// The test chain whose agent `agent` gives `answer` when the ask enters
    /// its rung.
    #[must_use]
    pub fn with_verdict(mut self, agent: EntityId, answer: HolderAnswer) -> Self {
        self.verdicts = self.verdicts.with(agent, answer);
        self
    }
}

/// Agent holders' verdicts as the test names them; an agent it does not
/// name passes the ask up.
#[derive(Clone, Debug, Default)]
pub struct FixedVerdicts {
    answers: BTreeMap<EntityId, HolderAnswer>,
}

impl FixedVerdicts {
    #[must_use]
    pub fn with(mut self, agent: EntityId, answer: HolderAnswer) -> Self {
        self.answers.insert(agent, answer);
        self
    }
}

impl AgentHolderVerdict for FixedVerdicts {
    fn verdict(&self, _pending: &PendingCheckIn, agent: EntityId) -> Option<HolderAnswer> {
        self.answers.get(&agent).copied()
    }
}

impl RungResolver for FixedChain {
    fn members(
        &self,
        _vault: &Vault,
        _txn: &heed::RoTxn<'_>,
        _pending: &PendingCheckIn,
        rung: Rung,
    ) -> Result<RungMembers> {
        Ok(self
            .rungs
            .get(&rung)
            .cloned()
            .unwrap_or_else(|| RungMembers::Missing("not in the test chain".to_owned())))
    }

    /// Every holder the test names may answer.
    fn may_answer(
        &self,
        _vault: &Vault,
        _txn: &heed::RoTxn<'_>,
        _pending: &PendingCheckIn,
        _holder: &RungHolder,
        _now: u64,
    ) -> Result<bool> {
        Ok(true)
    }

    fn agent_verdict(&self, pending: &PendingCheckIn, holder: &RungHolder) -> Option<HolderAnswer> {
        (holder.kind == HolderKind::Agent)
            .then(|| self.verdicts.verdict(pending, holder.principal))
            .flatten()
    }
}

/// Opens a pending check-in for `request` on `chain`.
///
/// # Errors
///
/// As `open_pending_check_in_in_txn`.
pub fn open(
    vault: &Vault,
    request: OpenPendingCheckIn,
    chain: &FixedChain,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        open_pending_check_in_in_txn(vault, txn, request, chain, now)
    })
}

/// Makes the one transition due now for `id` on `chain`.
///
/// # Errors
///
/// As `advance_pending_check_in_in_txn`.
pub fn advance(
    vault: &Vault,
    id: &EntityId,
    chain: &FixedChain,
) -> Result<Option<CheckInTransition>> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        advance_pending_check_in_in_txn(vault, txn, id, chain, now)
    })
}

/// `person`'s answer to `id` over `effect_digest`.
///
/// # Errors
///
/// As `answer_pending_check_in_in_txn`.
pub fn answer(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    effect_digest: &[u8; 32],
    answer: HolderAnswer,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        answer_pending_check_in_in_txn(
            vault,
            txn,
            person,
            id,
            effect_digest,
            answer,
            &FixedChain::default(),
            now,
        )
    })
}

/// `person`'s "give me until `until`" on `id`'s current rung.
///
/// # Errors
///
/// As `extend_pending_check_in_in_txn`.
pub fn extend(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    until: u64,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        extend_pending_check_in_in_txn(vault, txn, person, id, until, &FixedChain::default(), now)
    })
}

/// An objection by `by` to `id`'s delay window, as canon's PR 4 producer
/// would admit it.
///
/// # Errors
///
/// As `record_objection_in_txn`.
pub fn object(vault: &Vault, id: &EntityId, by: EntityId) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        record_objection_in_txn(&vault.store, txn, id, by, now)
    })
}

/// [`open`] on the ladder from verified records (2c), with the test's agent
/// verdicts.
pub fn open_verified(
    vault: &Vault,
    request: OpenPendingCheckIn,
    verdicts: &FixedVerdicts,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        open_pending_check_in_in_txn(vault, txn, request, &VerifiedChain::new(verdicts), now)
    })
}

/// [`advance`] on the ladder from verified records, with the test's agent
/// verdicts.
pub fn advance_verified(
    vault: &Vault,
    id: &EntityId,
    verdicts: &FixedVerdicts,
) -> Result<Option<CheckInTransition>> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        advance_pending_check_in_in_txn(vault, txn, id, &VerifiedChain::new(verdicts), now)
    })
}

/// [`answer`], re-checking the person's live grant and own check-in on the
/// ladder from verified records.
pub fn answer_verified(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    effect_digest: &[u8; 32],
    answer: HolderAnswer,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        answer_pending_check_in_in_txn(
            vault,
            txn,
            person,
            id,
            effect_digest,
            answer,
            &VerifiedChain::new(&NoAgentVerdict),
            now,
        )
    })
}

/// [`extend`], re-checking the person on the ladder from verified records.
pub fn extend_verified(
    vault: &Vault,
    person: &AuthenticatedOwner,
    id: &EntityId,
    until: u64,
) -> Result<PendingCheckIn> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        extend_pending_check_in_in_txn(
            vault,
            txn,
            person,
            id,
            until,
            &VerifiedChain::new(&NoAgentVerdict),
            now,
        )
    })
}
