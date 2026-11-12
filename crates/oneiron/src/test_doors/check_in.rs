//! Door for `tests/check_in_pending_handle.rs`, `tests/check_in_rung_waits.rs`
//! and `tests/check_in_ladder.rs` (ROLES-CHECKIN P2.2, pieces 2b, 2d and 2c):
//! the pending check-in's doors, each in one write transaction at the vault's
//! store clock, read once. In the plain doors the chain is the test's: each
//! rung's holders as the test names them, each of them free to answer. The
//! `_verified` doors run the ladder from verified records (2c), with the
//! test's agent verdicts. Beside them: the check-in tables' actor scrubs, as
//! an erase runs them, the rows the off-device screen reads a receipt by, and
//! a member grant narrowed to some worlds in place.

use std::collections::BTreeMap;

use crate::batch::BatchOp;
use crate::check_in::{
    AgentHolderVerdict, CheckInTransition, HolderAnswer, HolderKind, NoAgentVerdict,
    OpenPendingCheckIn, PendingCheckIn, Rung, RungHolder, RungMembers, RungResolver, VerifiedChain,
    advance_pending_check_in_in_txn, answer_pending_check_in_in_txn,
    extend_pending_check_in_in_txn, open_pending_check_in_in_txn, record_objection_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::{
    ScopeAxis, ScopeId, decode_federation_grant_body, encode_federation_grant_body,
};
use crate::receipt::ReceiptRecord;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, TimeRange, Vault};

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

/// The check-in tables with an actor scrub.
const CHECK_IN_TABLES: [&str; 2] = ["CHECK_IN_PENDING", "CHECK_IN_RECEIPT"];

/// The part of `actor`'s erase that runs over the check-in tables: the actor
/// scrub each of [`CHECK_IN_TABLES`] registers, in one write transaction, as
/// an erase and a restore's rerun run it. Returns how many ran.
///
/// # Errors
///
/// Storage errors.
pub fn erase_actor(vault: &Vault, actor: &EntityId) -> Result<usize> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut ran = 0;
    for (decl, scrub) in crate::side_table::actor_scrubs() {
        if CHECK_IN_TABLES.contains(&decl.name) {
            scrub(vault, &mut wtxn, actor)?;
            ran += 1;
        }
    }
    wtxn.commit()?;
    Ok(ran)
}

/// The rows a caller off this device has `receipt` screened on (FIX 1119):
/// `None` when they cannot be known.
///
/// # Errors
///
/// Storage errors.
pub fn screened_rows(vault: &Vault, receipt: &ReceiptRecord) -> Result<Option<Vec<EntityId>>> {
    crate::receipt::referenced_rows(vault, receipt)
}

/// Narrows the live FederationGrant `grant` to `worlds` in place, as a
/// writer that rewrites a member's grant does: its other bounds stay.
///
/// # Errors
///
/// No live grant under `grant`; storage errors.
pub fn narrow_grant_worlds(vault: &Vault, grant: EntityId, worlds: &[EntityId]) -> Result<()> {
    vault.with_write_txn(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &grant)?
        else {
            return Err(Error::EntityNotFound);
        };
        let mut row = decode_federation_grant_body(&body)?;
        row.authority_scope.worlds = worlds
            .iter()
            .copied()
            .map(ScopeId)
            .collect::<ScopeAxis<_>>();
        let put = BatchOp::Put {
            id: grant,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: None,
            data: encode_federation_grant_body(&row)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![put],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}
