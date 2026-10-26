//! The Coach's admission to a failure's captured source (FIX 6357, 7031,
//! 7548, 8704). Where the capture sits is read first, its bytes only once
//! the Coach is admitted to it: one live agent Grant whose member is the
//! Coach, that an owner of this vault delegated and that confers read now,
//! lists every world the failing run touched and, alone, admits the record
//! position of every row the capture was taken from (the failing attempt's
//! recorded input set with its TASK row, and a blocked report's own row), as
//! the scoped read's own explicit-Scope gate judges a position; and the
//! Coach's own scoped read reads each of those rows. The first such Grant in
//! id order whose pact membership, on a shared vault, still stands is the
//! one the replay reads under, and that Grant alone is read again before
//! each read of the capture, each send of it and the write that keeps what
//! it came to. No two Grants' axes are met, nothing is inferred from an
//! arm's lease, and no other copy stands in for a capture none admits: an
//! engine pair of it is kept not run, and an instruction's replay rebuilds
//! the call from the failure's own text, as when no copy was kept. A capture
//! whose rows are unknown has no position to prove, and is not replayed.

use super::publisher::{EngineAdmission, EngineCandidateRun, EngineNotRun, EnginePairState};
use super::{CodeFixSettled, SealedRun};
use crate::claim::ScopedReadActorKey;
use crate::code_run::shadow_runner::ShadowSourceAdmission;
use crate::failure_signals::{
    CodeFixSource, CodeFixVerdict, CodeFixWithheld, ReplayFidelity, code_fix_subject_in,
};
use crate::federation::ScopeId;
use crate::ports::EntityStoreRead;
use crate::{EntityId, Error, Result, Vault};

/// Where a failure's captured source sits, read before any of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureRefs {
    /// Every world the failing run touched.
    worlds: Vec<EntityId>,
    /// Every row the capture was taken from; `None`, unknown.
    rows: Option<Vec<EntityId>>,
}

impl CaptureRefs {
    /// The capture of `source`'s failing run, which touched `worlds` and
    /// whose texts were read from `source_rows`, with a blocked report's own
    /// row, which keeps the request it names. Unknown rows stay unknown.
    pub(crate) fn new(
        source: &CodeFixSource,
        worlds: Vec<EntityId>,
        source_rows: Option<&[EntityId]>,
    ) -> Self {
        let rows = source_rows.map(|rows| {
            let mut rows = rows.to_vec();
            if let CodeFixSource::Blocked { receipt, .. } = source {
                rows.push(*receipt);
            }
            rows.sort_unstable();
            rows.dedup();
            rows
        });
        Self { worlds, rows }
    }
}

/// Where `source`'s capture sits, read in `txn`; `None` once its failure no
/// longer stands, or its worlds cannot be proved.
fn capture_refs_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &CodeFixSource,
) -> Result<Option<CaptureRefs>> {
    let Some(subject) = code_fix_subject_in(vault, txn, source)? else {
        return Ok(None);
    };
    let Ok((failure, worlds)) = subject.failure.read() else {
        return Ok(None);
    };
    Ok(Some(CaptureRefs::new(
        source,
        worlds,
        failure.source_rows.as_deref(),
    )))
}

/// The Coach's admission to one failure's captured source (FIX 8704): the
/// Grant that alone admits it, taken where the snapshot found the capture,
/// and read again before each read, send and keep of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoachReplayAdmission {
    coach: EntityId,
    grant: EntityId,
    source: CodeFixSource,
    refs: CaptureRefs,
}

impl CoachReplayAdmission {
    /// The Coach `coach`'s admission to `source`'s capture at `refs`, read
    /// in a snapshot of its own; or why there is none.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn take(
        vault: &Vault,
        coach: EntityId,
        source: &CodeFixSource,
        refs: CaptureRefs,
    ) -> Result<std::result::Result<Self, EngineAdmission>> {
        let txn = vault.store.env.read_txn()?;
        Ok(
            admitting_grant_in(vault, &txn, coach, &refs, None)?.map(|grant| Self {
                coach,
                grant,
                source: source.clone(),
                refs,
            }),
        )
    }

    /// The Grant the replay reads under.
    pub(crate) const fn grant(&self) -> EntityId {
        self.grant
    }

    /// Whether that Grant still admits the capture, alone, in a snapshot of
    /// its own, the capture still where it was found. A lapsed pact keeps
    /// its own reason (FIX 7548); any other lapse is `Lapsed`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn still_admits(
        &self,
        vault: &Vault,
    ) -> Result<std::result::Result<(), EngineAdmission>> {
        let txn = vault.store.env.read_txn()?;
        if capture_refs_in(vault, &txn, &self.source)?.as_ref() != Some(&self.refs) {
            return Ok(Err(EngineAdmission::Lapsed));
        }
        Ok(
            match admitting_grant_in(vault, &txn, self.coach, &self.refs, Some(self.grant))? {
                Ok(_) => Ok(()),
                Err(EngineAdmission::PactStandingLapsed) => {
                    Err(EngineAdmission::PactStandingLapsed)
                }
                Err(_) => Err(EngineAdmission::Lapsed),
            },
        )
    }
}

impl ShadowSourceAdmission for CoachReplayAdmission {
    fn admits_now(&self, vault: &Vault) -> Result<bool> {
        Ok(self.still_admits(vault)?.is_ok())
    }
}

/// The first Grant in id order, or `only` alone when it names one, that
/// admits the capture at `refs` for `coach` in `txn`; or why none does. The
/// Coach's scoped read must read every row of the capture, and one Grant
/// must hold every world of the run and every row's record position.
fn admitting_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    coach: EntityId,
    refs: &CaptureRefs,
    only: Option<EntityId>,
) -> Result<std::result::Result<EntityId, EngineAdmission>> {
    let Some(rows) = refs.rows.as_deref() else {
        return Ok(Err(EngineAdmission::ScopeUnproved));
    };
    let mut raws = Vec::with_capacity(rows.len());
    for id in rows {
        // A row that is gone has no position left to prove.
        let Some(raw) = vault.store.port_entity_raw_wiped(txn, id)? else {
            return Ok(Err(EngineAdmission::ScopeUnproved));
        };
        raws.push((*id, raw));
    }
    let key = ScopedReadActorKey::with_actor_class(coach.to_hex(), "system")
        .ok_or_else(|| Error::InvalidConfig("invalid Coach read key".into()))?
        .require_relationship_grants(Some(coach));
    let lane = vault.scoped_read(key);
    let policy = lane.live_policy_manifest_in(txn)?;
    for (id, _) in &raws {
        if !lane.is_entity_readable_with_policy_in(txn, &policy, id)? {
            return Ok(Err(EngineAdmission::NoGrant));
        }
    }
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut lapsed = false;
    'grants: for standing in vault.agent_grants_in_txn(txn)? {
        let grant = &standing.grant;
        if only.is_some_and(|only| only != standing.id)
            || grant.member_ref != coach
            || !owners.contains(&standing.delegated_by)
            || !grant.confers_at(now)
            || !refs
                .worlds
                .iter()
                .all(|world| grant.authority_scope.worlds.contains(&ScopeId(*world)))
        {
            continue;
        }
        for (id, raw) in &raws {
            if !lane.grant_admits_position_in(txn, id, raw, &grant.authority_scope)? {
                continue 'grants;
            }
        }
        if standing.pact_standing_lapsed_in_txn(vault, txn) {
            lapsed = true;
            continue;
        }
        return Ok(Ok(standing.id));
    }
    Ok(Err(if lapsed {
        EngineAdmission::PactStandingLapsed
    } else {
        EngineAdmission::NoGrant
    }))
}

/// Whether the Coach's Grant now admits a pair of `settled`, the failure
/// `source`'s runs, that was kept not run for want of one (FIX 7031): the
/// same admission as the pair's own, read in `txn` only when such a pair is
/// there; `false` otherwise.
pub(super) fn read_granted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    settled: &CodeFixSettled,
    source: &CodeFixSource,
    coach: EntityId,
) -> Result<bool> {
    let waits = settled.candidates.iter().any(|run| {
        run.engine
            .as_ref()
            .is_some_and(EngineCandidateRun::waits_on_grant)
    });
    if !waits {
        return Ok(false);
    }
    let Some(refs) = capture_refs_in(vault, txn, source)? else {
        return Ok(false);
    };
    Ok(admitting_grant_in(vault, txn, coach, &refs, None)?.is_ok())
}

/// `run`, the failure `source`'s, as the write `txn` that keeps it may keep
/// it (FIX 8704): a judged engine pair, or an instruction's replay of the
/// kept request, while the Grant it read under still admits the capture
/// alone (FIX 9448). Otherwise its verdict is dropped unsent, and a pair is
/// kept not run: its Grant lapsed. Any other run is kept as it is.
///
/// # Errors
///
/// Storage errors.
pub(super) fn settle_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &CodeFixSource,
    coach: EntityId,
    (mut run, sealed): SealedRun,
) -> Result<SealedRun> {
    let (only, instruction) = match &run.engine {
        Some(engine) if matches!(engine.state, EnginePairState::Judged) => (engine.grant, false),
        None if matches!(
            run.replay,
            Some(ReplayFidelity::Exact | ReplayFidelity::ExactMasked)
        ) =>
        {
            (run.grant, true)
        }
        _ => return Ok((run, sealed)),
    };
    let admits = match capture_refs_in(vault, txn, source)? {
        // An instruction's replay that names no Grant read under none this
        // recheck can hold it to.
        Some(_) if instruction && only.is_none() => Err(EngineAdmission::Lapsed),
        Some(refs) => admitting_grant_in(vault, txn, coach, &refs, only)?,
        None => Err(EngineAdmission::Lapsed),
    };
    let reason = match admits {
        Ok(_) => return Ok((run, sealed)),
        Err(EngineAdmission::PactStandingLapsed) => EngineAdmission::PactStandingLapsed,
        Err(_) => EngineAdmission::Lapsed,
    };
    run.outcome = None;
    run.replay = None;
    run.grant = None;
    run.export = CodeFixVerdict::Withheld {
        reason: CodeFixWithheld::ReplayUnavailable,
    };
    if let Some(engine) = &mut run.engine {
        engine.state = EnginePairState::NotRun {
            reason: EngineNotRun::Admission(reason),
        };
    }
    Ok((run, None))
}
