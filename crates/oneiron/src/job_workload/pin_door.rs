//! The pin door, `vault.jobs.workloads.pin` (pass 33, section 6 row 2; pass
//! 34, `34-compute-general/DESIGN.md` section 6.5): one check-in for each new
//! pin.
//!
//! 1. Power: the owner, or an agent whose own live Grant names the verb and
//!    covers where the pin sits: its project, placed by the project's world.
//!    That Grant is the one the ask names and the row is pinned under.
//! 2. Mode: `jobs.workloads.check_in_mode` at the agent and the vault, the
//!    stricter winning, passed as the explicit mode, so the role table never
//!    decides a pin. The owner's own pin goes on his own proof.
//! 3. Rung 0, in `auto` and `full-access`: a live `compute.pin` grant of the
//!    agent's Grant that covers the pin. In `manual` no standing row is
//!    passed, so every pin waits.
//! 4. Rung 1, in `auto` for a pin no grant covers: the screen
//!    ([`WorkloadScreen`]), run before the writer, after the secret scan
//!    reads the pin. For a pin with no network it decides; a network pin
//!    always asks, and the screen's verdict rides on its record as the
//!    recommendation. With no model on the host the deterministic fallback
//!    decides; a model that fails or abstains is unsure, so the pin asks.
//! 5. A wait opens the keyed pending check-in and answers `CHECK_IN_PENDING`
//!    naming it; the same call naming `check_in_ref` once it is approved
//!    spends it and lets the pin go, and its record keeps the screen the
//!    pin was asked with. The owner may instead approve the exact digest
//!    (`vault.jobs.workloads.approve`).
//!
//! The host reads the act from the pin (DEC-0006 invariant 6): a pin with no
//! network, in a fenced scope, writing only its `out/` directory, is
//! `ReversibleWork`; a pin with the host's network is `OutboundSend`
//! (EM-23-EGRESS-ACT-CLASS = A).
use crate::check_in::{
    ActClass, CheckInScope, DoorRungs, PinCheckIn, PinCheckInAsk, UnsureTest,
    workload_pin_check_in_in_txn, workload_pin_grant_in_txn, workload_pin_scope_in_txn,
};
use crate::memory::Memory;
use crate::setting::SettingSource;
use crate::{EdgeActorClass, EntityId, Vault};

use super::compute_bound::pin_candidate;
use super::doors::{WorkloadError, WorkloadVerb, agent_reads};
use super::pin_shape::check_pin_shape;
use super::record::{
    JOB_WORKLOADS, JobWorkload, PinCheckInOutcome, PinGoBasis, WorkloadCheckIn, digest_key,
};
use super::screen::{PinScreen, PinSignals, WorkloadScreen, pin_signals_in_txn};
use super::setting_keys::{PinCheckInMode, approval_window_ms_in_txn, check_in_mode_in_txn};
use super::wire::{WorkloadChange, WorkloadPinRequest, WorkloadView};
use super::{NetworkMode, WorkloadPin};

/// The act the host reads from `pin`, and why.
fn pin_act(pin: &WorkloadPin) -> (ActClass, Vec<String>) {
    match pin.network {
        NetworkMode::Host => (
            ActClass::OutboundSend,
            vec!["network host: the run reaches the network, irreversible in effect".to_owned()],
        ),
        NetworkMode::None => (
            ActClass::ReversibleWork,
            vec![
                "network none".to_owned(),
                "a fenced scope".to_owned(),
                "writes only its out/ directory".to_owned(),
            ],
        ),
    }
}

/// Rung 1 as the pin door passes it: the screen's answer for a pin with no
/// network; never sure for a network pin, whose screen only recommends, nor
/// for a pin no screen answered.
struct PinUnsureTest<'a> {
    act: ActClass,
    screen: Option<&'a PinScreen>,
}

impl UnsureTest for PinUnsureTest<'_> {
    fn is_sure(&self) -> crate::Result<bool> {
        Ok(self.act == ActClass::ReversibleWork && self.screen.is_some_and(|screen| screen.sure))
    }
}

/// Who pins, as the pin door's read resolved it.
#[derive(Clone, Copy)]
enum Pinner {
    Owner(EntityId),
    Agent { actor: EntityId, grant: EntityId },
}

/// What the agent's ladder reads before the writer: its mode and where it
/// came from, the covering grant, and the screen when one ran.
struct AgentRead {
    mode: PinCheckInMode,
    mode_source: SettingSource,
    covering_grant: Option<String>,
    screen: Option<PinScreen>,
}

/// One pin call's inputs, as the door parsed them.
struct PinCall<'a> {
    request: &'a WorkloadPinRequest,
    digest: &'a str,
    key: [u8; 32],
    project: Option<EntityId>,
    check_in_ref: Option<EntityId>,
    now_ms: u64,
}

/// What the writer did.
enum Pinned {
    Done(WorkloadChange),
    Waits(EntityId),
}

impl Memory<'_> {
    /// `vault.jobs.workloads.pin`: this handle's caller pins the exact
    /// workload `request.pin`, and the pin checks in (DESIGN 6.5). A pin is
    /// written once: pinning the same workload again answers the row that
    /// stands, unless it waits, when the call judges it again, and spends
    /// `request.check_in_ref` when it names the pin's approved ask. `screen`
    /// is the host's decision ladder; it runs before the writer, only for an
    /// agent's pin in `auto` that no `compute.pin` grant covers.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::BadPin`] for a pin of the wrong shape;
    /// [`WorkloadError::BadId`] for a project or check-in that is not an id;
    /// [`WorkloadError::PinConflict`] for a digest pinned with other content
    /// or for another project; the secret scan's refusal for a new pin that
    /// holds a secret; [`WorkloadError::PinnedElsewhere`] for an agent's pin
    /// of a workload that stands under a Grant it may not read it through;
    /// [`WorkloadError::Caller`] for a caller the door does not admit, and
    /// for a `check_in_ref` that is not this pin's approved ask or names a
    /// pin that goes at once; [`crate::Error::CheckInPending`] naming the
    /// pending check-in the pin waits on.
    pub fn pin_job_workload(
        &self,
        request: &WorkloadPinRequest,
        screen: &dyn WorkloadScreen,
        now_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        check_pin_shape(&request.pin).map_err(|why| WorkloadError::BadPin { why })?;
        let digest = request.pin.digest()?;
        let key = digest_key(&digest).ok_or(crate::Error::InvariantViolation(
            "a workload digest is 64 lower hex",
        ))?;
        let project = optional_id("project", request.project.as_deref())?;
        let check_in_ref = optional_id("check_in_ref", request.check_in_ref.as_deref())?;
        let vault = self.vault();
        let agent_read = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let (pinner, _) = self.pinner_in_txn(&txn, &key, project)?;
            match judge_repeat(vault, &txn, &key, request, project, pinner, now_ms)? {
                Repeat::Answer(change) => return Ok(change),
                Repeat::Judge { project } => match pinner {
                    Pinner::Owner(_) => None,
                    Pinner::Agent { actor, grant } => {
                        let (read, signals) = read_agent_ladder(
                            vault,
                            &txn,
                            actor,
                            grant,
                            project,
                            &request.pin,
                            check_in_ref.is_none(),
                        )?;
                        // The screen sends the pin's facts to a model: the
                        // secret scan reads the pin first.
                        if signals.is_some() {
                            scan_pin_in_txn(vault, &txn, &request.pin)?;
                        }
                        Some((read, signals))
                    }
                },
            }
        };
        // The model runs here, before the writer: no transaction spans it.
        let agent_read = match agent_read {
            Some((mut read, Some(signals))) => {
                read.screen = Some(PinScreen::of(screen.screen(&signals), &signals));
                Some(read)
            }
            Some((read, None)) => Some(read),
            None => None,
        };
        let call = PinCall {
            request,
            digest: &digest,
            key,
            project,
            check_in_ref,
            now_ms,
        };
        let pinned = vault.try_with_write_txn_grouped(|txn| -> Result<Pinned, WorkloadError> {
            self.pin_in_txn(txn, &call, agent_read)
        })?;
        match pinned {
            Pinned::Done(change) => Ok(change),
            Pinned::Waits(check_in) => Err(crate::Error::CheckInPending(check_in.to_hex()).into()),
        }
    }

    /// The caller in `txn`, and where its pin under `key` for `project` sits
    /// (the stored row's project once one stands): the vault owner, or an
    /// agent under the live Grant that names the pin verb and covers that
    /// place, the Grant its ask names.
    fn pinner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &[u8; 32],
        project: Option<EntityId>,
    ) -> Result<(Pinner, CheckInScope), WorkloadError> {
        let vault = self.vault();
        let (actor, class) = (self.actor(), self.actor_class());
        crate::memory::verify_actor_binding_in_txn(vault, txn, actor, class)
            .map_err(WorkloadError::Caller)?;
        let project = match JOB_WORKLOADS.get(&vault.store, txn, key)? {
            Some(row) => row.project,
            None => project,
        };
        let scope = workload_pin_scope_in_txn(vault, txn, project)?;
        if class == EdgeActorClass::Human
            && crate::memory::actor_is_vault_owner_in_txn(vault, txn, actor, class)
                .map_err(WorkloadError::Caller)?
        {
            return Ok((Pinner::Owner(actor), scope));
        }
        // The standing refusals first (binding, credential, lapsed pact),
        // then the Grant whose bounds cover the pin's place.
        self.workload_agent()
            .grant_in_txn(vault, txn, WorkloadVerb::Pin)
            .map_err(WorkloadError::Caller)?;
        let grant = workload_pin_grant_in_txn(self, txn, WorkloadVerb::Pin.name(), &scope)
            .map_err(WorkloadError::Caller)?;
        Ok((Pinner::Agent { actor, grant }, scope))
    }

    /// The writer: judges the caller again, composes the ladder live, and
    /// writes the pin with its check-in, or opens its pending check-in.
    fn pin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        call: &PinCall<'_>,
        agent_read: Option<AgentRead>,
    ) -> Result<Pinned, WorkloadError> {
        let vault = self.vault();
        let (pinner, scope) = self.pinner_in_txn(txn, &call.key, call.project)?;
        let project = match judge_repeat(
            vault,
            txn,
            &call.key,
            call.request,
            call.project,
            pinner,
            call.now_ms,
        )? {
            Repeat::Answer(change) => return Ok(Pinned::Done(change)),
            Repeat::Judge { project } => project,
        };
        let (act, act_reasons) = pin_act(&call.request.pin);
        let ladder = live_ladder_in_txn(vault, txn, pinner, project, call, agent_read)?;
        let unsure = PinUnsureTest {
            act,
            screen: ladder.as_ref().and_then(|read| read.screen.as_ref()),
        };
        let standing_row = ladder.as_ref().and_then(|read| match read.mode {
            PinCheckInMode::Manual => None,
            PinCheckInMode::Auto | PinCheckInMode::FullAccess => read.covering_grant.as_deref(),
        });
        let ask = PinCheckInAsk {
            verb: WorkloadVerb::Pin.name(),
            act,
            scope,
            grant: match pinner {
                Pinner::Agent { grant, .. } => Some(grant),
                Pinner::Owner(_) => None,
            },
            rungs: DoorRungs {
                explicit_mode: ladder.as_ref().map(|read| read.mode.check_in_mode()),
                standing_row,
                unsure: &unsure,
            },
            effect_digest: call.key,
            check_in_ref: call.check_in_ref.as_ref(),
        };
        let judged =
            workload_pin_check_in_in_txn(self, txn, &ask).map_err(WorkloadError::Caller)?;
        let until_ms = call
            .now_ms
            .saturating_add(approval_window_ms_in_txn(vault, txn)?);
        let (outcome, waits) = outcome_of(judged, until_ms);
        let record = WorkloadCheckIn {
            act: act.as_str().to_owned(),
            act_reasons,
            mode: ladder.as_ref().map(|read| read.mode),
            mode_source: ladder.as_ref().map(|read| read.mode_source.clone()),
            covering_grant: standing_row.map(str::to_owned),
            outcome,
            screen: ladder.and_then(|read| read.screen),
            at_ms: call.now_ms,
        };
        let row = pinned_row_in_txn(vault, txn, call, pinner, project, record)?;
        JOB_WORKLOADS.put(&vault.store, txn, &call.key, &row)?;
        Ok(match waits {
            Some(check_in) => Pinned::Waits(check_in),
            None => Pinned::Done(WorkloadChange {
                changed: true,
                workload: WorkloadView::of(&row, call.now_ms),
            }),
        })
    }
}

/// A repeat of a pin, judged before the ladder.
enum Repeat {
    /// The row stands as it is: the answer.
    Answer(WorkloadChange),
    /// A new pin, or one whose check-in waits: judge it, for `project`.
    Judge { project: Option<EntityId> },
}

/// What a pin of `request` under `key` by `pinner` meets in `txn`: a new
/// pin, a pin that waits (judged again), or a row that stands.
fn judge_repeat(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    request: &WorkloadPinRequest,
    project: Option<EntityId>,
    pinner: Pinner,
    now_ms: u64,
) -> Result<Repeat, WorkloadError> {
    let Some(row) = JOB_WORKLOADS.get(&vault.store, txn, key)? else {
        return Ok(Repeat::Judge { project });
    };
    if row.pin != request.pin || (project.is_some() && project != row.project) {
        return Err(WorkloadError::PinConflict);
    }
    if let Pinner::Agent { grant, .. } = pinner
        && !agent_reads(&row, grant, now_ms)
    {
        return Err(WorkloadError::PinnedElsewhere);
    }
    let waits = matches!(
        row.check_in.as_ref().map(|check_in| &check_in.outcome),
        Some(PinCheckInOutcome::Waits { .. })
    );
    let judged_again = waits
        && row.approval.is_none()
        && row.revoked.is_none()
        && matches!(pinner, Pinner::Agent { grant, .. } if row.pinned_under == Some(grant));
    if judged_again {
        return Ok(Repeat::Judge {
            project: row.project,
        });
    }
    if request.check_in_ref.is_some() {
        return Err(WorkloadError::Caller(
            crate::check_in::named_check_in_at_once().into(),
        ));
    }
    Ok(Repeat::Answer(WorkloadChange {
        changed: false,
        workload: WorkloadView::of(&row, now_ms),
    }))
}

/// The agent's ladder as the writer reads it again, live: the mode and the
/// covering grant decide, not the read before the model. The screen kept is
/// the one that ran before the writer, where the screen is still wanted
/// (`auto`, no covering grant). A call that names its check-in keeps the
/// screen its pin was asked with, so the answered record carries the
/// recommendation the person saw. A pin no screen answered asks: a screen
/// that did not run never clears it. `None` for the owner's own pin.
fn live_ladder_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pinner: Pinner,
    project: Option<EntityId>,
    call: &PinCall<'_>,
    agent_read: Option<AgentRead>,
) -> Result<Option<AgentRead>, WorkloadError> {
    let Pinner::Agent { actor, grant } = pinner else {
        return Ok(None);
    };
    let (live, _) = read_agent_ladder(vault, txn, actor, grant, project, &call.request.pin, false)?;
    let screen = if call.check_in_ref.is_some() {
        JOB_WORKLOADS
            .get(&vault.store, txn, &call.key)?
            .and_then(|row| row.check_in)
            .and_then(|record| record.screen)
    } else if live.mode == PinCheckInMode::Auto && live.covering_grant.is_none() {
        agent_read.and_then(|read| read.screen)
    } else {
        None
    };
    Ok(Some(AgentRead { screen, ..live }))
}

/// The record's outcome of `judged`, and the pending check-in the pin waits
/// on, if it waits.
fn outcome_of(judged: PinCheckIn, until_ms: u64) -> (PinCheckInOutcome, Option<EntityId>) {
    match judged {
        PinCheckIn::Went { basis, .. } => (
            PinCheckInOutcome::Went {
                basis,
                check_in: None,
                until_ms,
            },
            None,
        ),
        PinCheckIn::Answered { check_in, .. } => (
            PinCheckInOutcome::Went {
                basis: PinGoBasis::Answered,
                check_in: Some(check_in.to_hex()),
                until_ms,
            },
            None,
        ),
        PinCheckIn::Waits { check_in, reason } => (
            PinCheckInOutcome::Waits {
                check_in: check_in.to_hex(),
                reason: reason.as_str().to_owned(),
            },
            Some(check_in),
        ),
    }
}

/// The row the writer puts: the pin that waited, with its new check-in, or
/// a new pin, which the secret scan reads first.
fn pinned_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    call: &PinCall<'_>,
    pinner: Pinner,
    project: Option<EntityId>,
    record: WorkloadCheckIn,
) -> Result<JobWorkload, WorkloadError> {
    if let Some(mut row) = JOB_WORKLOADS.get(&vault.store, txn, &call.key)? {
        row.check_in = Some(record);
        return Ok(row);
    }
    scan_pin_in_txn(vault, txn, &call.request.pin)?;
    let (pinned_by, pinned_under) = match pinner {
        Pinner::Owner(owner) => (owner, None),
        Pinner::Agent { actor, grant } => (actor, Some(grant)),
    };
    Ok(JobWorkload {
        digest: call.digest.to_owned(),
        pin: call.request.pin.clone(),
        pinned_by: Some(pinned_by),
        pinned_under,
        pinned_at_ms: call.now_ms,
        approval: None,
        revoked: None,
        project,
        check_in: Some(record),
    })
}

/// The agent's ladder as `txn` holds it: the mode in force for `actor`, and
/// the live `compute.pin` grant of `grant` that covers `pin` for `project`.
/// With `screen_wanted`, also the screen's signals when the screen runs: in
/// `auto`, with no covering grant.
fn read_agent_ladder(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    grant: EntityId,
    project: Option<EntityId>,
    pin: &WorkloadPin,
    screen_wanted: bool,
) -> Result<(AgentRead, Option<PinSignals>), WorkloadError> {
    let (mode, mode_source) = check_in_mode_in_txn(vault, txn, actor)?;
    let candidate = pin_candidate(grant, project, pin, None)?;
    let covering_grant = vault.covering_compute_grant_in_txn(txn, &candidate)?;
    let signals = if screen_wanted && mode == PinCheckInMode::Auto && covering_grant.is_none() {
        Some(pin_signals_in_txn(vault, txn, grant, pin)?)
    } else {
        None
    };
    Ok((
        AgentRead {
            mode,
            mode_source,
            covering_grant,
            screen: None,
        },
        signals,
    ))
}

/// The secret scan of `pin`, under the owner's switch. The pin is hashed into
/// its own key and compared on a repeat, so no custody handle can stand in
/// for a secret in it: the batch door's scan refuses one before the screen
/// sends the pin's facts to a model, and again before a new row is written.
fn scan_pin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &WorkloadPin,
) -> Result<(), WorkloadError> {
    let pin_bytes = crate::llm::canonical_json_bytes(pin)
        .map_err(|_| crate::Error::InvariantViolation("workload pin encode"))?;
    crate::batch::secret_scan::scan_content_in_txn(&vault.store, txn, &pin_bytes)?;
    Ok(())
}

/// The id `hex` names, if any, or a bad request naming `field`.
fn optional_id(field: &'static str, hex: Option<&str>) -> Result<Option<EntityId>, WorkloadError> {
    hex.map(|hex| EntityId::from_hex(hex).map_err(|_| WorkloadError::BadId { field }))
        .transpose()
}
