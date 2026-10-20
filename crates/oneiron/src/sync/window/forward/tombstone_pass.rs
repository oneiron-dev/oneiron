//! Tombstone pass of forward rematerialization: reason-aware replay of window tombstones.

use super::super::loro_support::{map_for_each_tombstone_value, map_get_bytes};
use super::super::quarantine::{self, QuarantineContainer};
use super::{RematCtx, RematLedger};

use crate::Vault;
use crate::deletion::{ReplayedTombstoneOutcome, decode_tombstone_value};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::ingest::{TombstoneStep, classify_tombstone, classify_tombstone_in_txn};
use crate::sync::types::{
    TombstoneResidence, retained_world_shell_belongs_to_window, tombstone_residence_in,
};

/// Tombstones replayed under one parent transaction, whose hard ids share one
/// decision-ledger scan (SCAN C049). A batching size, not a cap: every
/// tombstone of the window still replays, one chunk after another.
const FORWARD_TOMBSTONE_CHUNK: usize = 128;

/// Outcome of the tombstone pass. The error is DEFERRED past the marker
/// bookkeeping txn (Trap 2): the caller runs that txn first and only then
/// returns `deferred_error`.
pub(super) struct TombstonePassOutcome {
    pub(super) purge_failures: Vec<EntityId>,
    /// Each failed replay's tombstone value, for the fence its delete earns
    /// if the protection gates admit it.
    pub(super) unapplied: Vec<(EntityId, Vec<u8>)>,
    pub(super) cleared: Vec<EntityId>,
    pub(super) receiver_scrub_candidates: Vec<EntityId>,
    pub(super) deferred_error: Option<Error>,
}

/// Run the tombstone pass: replay each tombstone through the shared
/// primitive and collect the marker bookkeeping inputs. Returns the outcome
/// struct instead of falling through — never `?` at the call site.
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> TombstonePassOutcome {
    // Tombstones — reason-aware replay (ONE-1133 / ARCH-0038): the VALUE
    // decides the effect, routed through the shared primitive, never a
    // bare purge. Known-soft `user_delete` keeps the 25 B shell (SoftErase
    // + D16 refresh); every other shape hard-purges and — when local state
    // was erased — writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep
    // row. The tombstone-aware iterator visits EVERY value: a non-Binary
    // tombstone replays as the empty slice, which decodes HARD — a
    // malformed remote tombstone must never be skipped (it would leave the
    // entity pass's re-materialized body live forever = durable
    // resurrection). The primitive is idempotent (no receipt when nothing
    // local remains), so this every-boot pass cannot multiply receipts.
    //
    // Retry state is ENTITY-scoped (ONE-1124): `rm:w:{window}:{entity_hex}`
    // is written for the specific entity whose replay failed, and cleared
    // ONLY when that entity's own replay succeeds — an unrelated
    // tombstone's success must never discharge another entity's retry.
    // (`marked` is the up-front snapshot loaded before the entity pass.)
    //
    // SCAN C049: the tombstones replay FORWARD_TOMBSTONE_CHUNK at a time
    // under one parent transaction, each in a child of its own, so a chunk's
    // unknown hard ids share one decision-ledger scan. Nothing of a chunk is
    // recorded before its parent commits; a chunk whose parent fails replays
    // one by one, each in its own transaction.
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    map_for_each_tombstone_value(ctx.tombstones.map(), |key, value| {
        entries.push((key.to_owned(), value.to_vec()));
    });
    let mut pass = Pass {
        ctx,
        ledger,
        outcome: TombstonePassOutcome {
            purge_failures: Vec::new(),
            unapplied: Vec::new(),
            cleared: Vec::new(),
            receiver_scrub_candidates: Vec::new(),
            deferred_error: None,
        },
    };
    for chunk in entries.chunks(FORWARD_TOMBSTONE_CHUNK) {
        if pass.outcome.deferred_error.is_some() {
            break;
        }
        if let Err(error) = pass.replay_chunk(chunk) {
            tracing::warn!(
                window = %ctx.window_key,
                tombstones = chunk.len(),
                kind = ?error.kind(),
                "forward remat: tombstone chunk transaction failed; replaying its tombstones one by one"
            );
            for (key, value) in chunk {
                if pass.outcome.deferred_error.is_some() {
                    break;
                }
                pass.replay_one(key, value);
            }
        }
    }
    pass.outcome
}

/// The pass's running state: the window, its ledger and what the pass has
/// recorded so far.
struct Pass<'a> {
    ctx: &'a RematCtx<'a>,
    ledger: &'a mut RematLedger,
    outcome: TombstonePassOutcome,
}

/// Where one tombstone goes before replay.
enum Gate {
    /// Refused into `x:`. `id` is `None` when the key names no entity.
    Refuse {
        id: Option<EntityId>,
        err: Error,
    },
    /// The entity pass admitted a delete-protected row at this id, and its
    /// ingest step already refused every tombstone naming it into `x:`.
    Protected(EntityId),
    /// A world tombstone whose residence is unknown here: not replayed.
    Unproven,
    Replay {
        id: EntityId,
        hard: bool,
    },
}

/// One tombstone of a chunk, held until the chunk's parent commits.
enum Staged<'e> {
    /// Quarantined in the parent, or already refused by the entity pass.
    Terminal(Option<EntityId>),
    /// A replay its own child applied, or rolled back with this error.
    Replayed {
        key: &'e str,
        value: &'e [u8],
        id: EntityId,
        hard: bool,
        replayed: Result<ReplayedTombstoneOutcome>,
    },
}

impl Pass<'_> {
    /// Replays one chunk under ONE parent transaction, the raw topology of
    /// the one-by-one replay. Each tombstone applies in a child of its own,
    /// so a failure rolls back only that item, and the chunk's hard ids share
    /// one decision-ledger scan while the parent is held. Once the parent
    /// commits, each replay gets the cleanup and bookkeeping the one-by-one
    /// path gives it, in order. An `Err` means nothing of the chunk
    /// committed and nothing was recorded: the caller replays it one by one.
    fn replay_chunk(&mut self, chunk: &[(String, Vec<u8>)]) -> Result<()> {
        let vault = self.ctx.vault;
        let hard_ids = chunk.iter().filter_map(|(key, value)| {
            EntityId::from_hex(key)
                .ok()
                .filter(|_| decode_tombstone_value(value).is_hard())
        });
        // An apply that erases signs a receipt in the txn: load the device
        // key first, as the one-by-one replay does.
        let _ = vault.prepare_install_signing();
        let mut staged = Vec::new();
        let mut stopped = None;
        let committed = vault.store.env.write_txn().and_then(|mut parent| {
            let probes = vault.batch_tombstone_scope_probes_in_txn(&parent, hard_ids)?;
            for (key, value) in chunk {
                if let Err(error) = self.stage(&mut parent, key, value, &mut staged) {
                    stopped = Some(error);
                    break;
                }
            }
            drop(probes);
            parent.commit()?;
            Ok(())
        });
        // A refusal a hold made is logged once the chunk's writer ended,
        // committed or dropped.
        vault.store.flush_legal_hold_refusals_settled();
        committed?;
        for step in staged {
            match step {
                Staged::Terminal(id) => self.ledger.terminal_quarantines.extend(id),
                Staged::Replayed {
                    key,
                    value,
                    id,
                    hard,
                    replayed,
                } => {
                    let replayed =
                        replayed.and_then(|outcome| collect_after_replay(vault).map(|()| outcome));
                    self.settle(key, value, id, hard, replayed);
                }
            }
        }
        if let Some(error) = stopped {
            self.defer(error);
        }
        Ok(())
    }

    /// Applies one tombstone of a chunk in `parent`, each write in a child of
    /// its own, and stages what the pass records once `parent` commits. An
    /// `Err` (a quarantine write or a residence read failed) stops the chunk
    /// there, as it stops the pass.
    fn stage<'e>(
        &self,
        parent: &mut heed::RwTxn<'_>,
        key: &'e str,
        value: &'e [u8],
        staged: &mut Vec<Staged<'e>>,
    ) -> Result<()> {
        let vault = self.ctx.vault;
        let (id, hard) = match self.gate(Some(&**parent), key, value)? {
            Gate::Unproven => return Ok(()),
            Gate::Protected(id) => {
                staged.push(Staged::Terminal(Some(id)));
                return Ok(());
            }
            Gate::Refuse { id, err } => {
                self.quarantine_in(parent, key, value, &err)?;
                staged.push(Staged::Terminal(id));
                return Ok(());
            }
            Gate::Replay { id, hard } => (id, hard),
        };
        let replayed = savepoint(vault, parent, |child| {
            quarantine::apply_replayed_tombstone_for_sync_in_txn(vault, child, &id, value)
                .map(|(outcome, _changed)| outcome)
        });
        match replayed {
            Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                self.quarantine_in(parent, key, value, &err)?;
                staged.push(Staged::Terminal(Some(id)));
            }
            replayed => staged.push(Staged::Replayed {
                key,
                value,
                id,
                hard,
                replayed,
            }),
        }
        Ok(())
    }

    /// Replays one tombstone in its own transactions, as the pass always
    /// has: the path a chunk takes when its parent fails.
    fn replay_one(&mut self, key: &str, value: &[u8]) {
        match self.gate(None, key, value) {
            Err(error) => self.defer(error),
            Ok(Gate::Unproven) => {}
            Ok(Gate::Protected(id)) => self.ledger.terminal_quarantines.push(id),
            Ok(Gate::Refuse { id, err }) => self.quarantine(key, value, id, &err),
            Ok(Gate::Replay { id, hard }) => {
                let replayed =
                    quarantine::apply_replayed_tombstone_for_sync(self.ctx.vault, &id, value);
                self.settle(key, value, id, hard, replayed);
            }
        }
    }

    /// Classifies one tombstone and checks its window residence: in `txn`
    /// when a chunk holds one, else in fresh reads as the one-by-one path
    /// does. An `Err` is a residence read that failed.
    fn gate(&self, txn: Option<&heed::RoTxn<'_>>, key: &str, value: &[u8]) -> Result<Gate> {
        let ctx = self.ctx;
        let step = match txn {
            Some(txn) => classify_tombstone_in_txn(ctx.vault, txn, &ctx.entities_map, key, value),
            None => classify_tombstone(ctx.vault, &ctx.entities_map, key, value),
        };
        let (id, hard) = match step {
            TombstoneStep::Refuse { id, err } => return Ok(Gate::Refuse { id, err }),
            TombstoneStep::Replay { id, hard } => (id, hard),
        };
        if self.ledger.protected_admissions.contains(&id) {
            return Ok(Gate::Protected(id));
        }
        let residence = match txn {
            Some(txn) => residence_in(ctx, txn, &id)?,
            None => residence_in(ctx, &ctx.vault.store.env.read_txn()?, &id)?,
        };
        Ok(match residence {
            TombstoneResidence::Wrong => Gate::Refuse {
                id: Some(id),
                err: Error::InvalidConfig("tombstone outside window residence".into()),
            },
            TombstoneResidence::Unknown if ctx.window_key.world().is_some() => Gate::Unproven,
            _ => Gate::Replay { id, hard },
        })
    }

    /// Writes a refused tombstone's `x:` row in a child of `parent`: a failed
    /// write leaves nothing behind, as its own transaction did.
    fn quarantine_in(
        &self,
        parent: &mut heed::RwTxn<'_>,
        key: &str,
        value: &[u8],
        err: &Error,
    ) -> Result<()> {
        let vault = self.ctx.vault;
        savepoint(vault, parent, |child| {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                child,
                self.ctx.window_key.as_str(),
                QuarantineContainer::Tombstones,
                key,
                err,
                value,
            )
        })
        .map(|_| ())
    }

    /// Quarantines a refused tombstone in its own transaction; its id is
    /// terminal once the row is written.
    fn quarantine(&mut self, key: &str, value: &[u8], id: Option<EntityId>, err: &Error) {
        match quarantine::quarantine_rejected_op(
            self.ctx.vault,
            self.ctx.window_key.as_str(),
            QuarantineContainer::Tombstones,
            key,
            err,
            value,
        ) {
            Ok(_) => self.ledger.terminal_quarantines.extend(id),
            Err(error) => self.defer(error),
        }
    }

    /// Records one replay's result as the pass always has: a success writes
    /// its world deletion address and discharges the entity's own retry
    /// marker, a typed refusal is quarantined, and any other failure is
    /// flagged for durable retry while the pass keeps going.
    fn settle(
        &mut self,
        key: &str,
        value: &[u8],
        id: EntityId,
        hard: bool,
        replayed: Result<ReplayedTombstoneOutcome>,
    ) {
        let vault = self.ctx.vault;
        let window_key = self.ctx.window_key;
        match replayed {
            Ok(outcome) => {
                if window_key.world().is_some()
                    && let Err(error) = vault.with_write_txn_grouped(|txn| {
                        vault.store.sync_state.put(
                            txn,
                            &format!("m:dw:{}", id.to_hex()),
                            window_key.as_str().as_bytes(),
                        )?;
                        Ok(())
                    })
                {
                    self.defer(error);
                    return;
                }
                if outcome.changed_local_state() {
                    self.ledger.count += 1;
                }
                if hard {
                    self.outcome.receiver_scrub_candidates.push(id);
                }
                // The goal state for THIS tombstone's reason holds (purge
                // done, already absent, or soft shell kept) — the entity's
                // own retry marker (if flagged) is discharged.
                if self.ledger.marked.contains(&id.to_hex()) {
                    self.outcome.cleared.push(id);
                }
            }
            Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                self.quarantine(key, value, Some(id), &err);
            }
            Err(err) => {
                // Replay failure — the tombstoned content may still be
                // live. Flag THIS entity for durable retry; the pass keeps
                // going so one failure cannot starve other tombstones.
                self.outcome.purge_failures.push(id);
                self.outcome.unapplied.push((id, value.to_vec()));
                tracing::error!(
                    entity = %id.to_hex(),
                    kind = ?err.kind(),
                    "forward remat: tombstone replay FAILED — hard-deleted content may still be live (GDPR SLA breach signal)"
                );
            }
        }
    }

    /// Keeps the first error that stops the pass: no later chunk runs, and
    /// the caller returns it after the marker bookkeeping.
    fn defer(&mut self, error: Error) {
        if self.outcome.deferred_error.is_some() {
            tracing::error!(
                kind = ?error.kind(),
                "forward remat: tombstone pass failed again after its deferred error"
            );
        } else {
            self.outcome.deferred_error = Some(error);
        }
    }
}

/// The window residence of `id`'s tombstone in `txn`. A retained world claim
/// shell this window binds to the tombstone counts as resident.
fn residence_in(
    ctx: &RematCtx<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<TombstoneResidence> {
    let state = tombstone_residence_in(ctx.vault, txn, id, ctx.window_key)?;
    if state == TombstoneResidence::Unknown
        && ctx.window_key.world().is_some()
        && let Some(raw) = map_get_bytes(&ctx.entities_map, &id.to_hex())
        && retained_world_shell_belongs_to_window(
            ctx.vault,
            txn,
            ctx.doc,
            &ctx.tombstones,
            id,
            &raw,
            ctx.window_key,
            false,
        )?
    {
        return Ok(TombstoneResidence::Match);
    }
    Ok(state)
}

/// Runs `apply` in a child of `parent`, committed into it only on success: a
/// failure rolls back that child's writes alone.
fn savepoint<T>(
    vault: &Vault,
    parent: &mut heed::RwTxn<'_>,
    apply: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
) -> Result<T> {
    let mut child = vault.store.env.nested_write_txn(parent)?;
    let applied = apply(&mut child)?;
    child.commit()?;
    Ok(applied)
}

/// The cleanup the one-by-one replay runs once its purge committed, with the
/// same budgets: an error here fails that replay, as it does there.
fn collect_after_replay(vault: &Vault) -> Result<()> {
    while vault.collect_lfs_garbage(32)? != 0 {}
    #[cfg(unix)]
    vault.collect_released_result_bodies(256)?;
    vault.finish_gate_decision_retirements_after_commit();
    Ok(())
}
