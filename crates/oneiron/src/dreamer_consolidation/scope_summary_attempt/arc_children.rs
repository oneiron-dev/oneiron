//! An Arc composed in parts (FIX 7509 PR3, SUMMARY-SOURCE = A): its input
//! does not fit one call on its model, so it is one durable work generation
//! whose parts each fit one ([`super::arc_chunks`]). The generation's
//! manifest and each part's membership are written before any call. After
//! each checked call the part's result refs, its cursor and what it owes
//! next are written together; a wake that stops (its deadline, its budget,
//! its pace) keeps them, and the next wake of the same try goes on at the
//! first part not done, its earlier steps replaying from their memos.
//!
//! A part's reply naming a TURN it showed and has not read whole writes
//! nothing final: the engine opens the TURN through its handle, registers
//! it once in the manifest, and the part reads it whole before it is done.
//! A part with no room for what it must read beside its lines splits in two
//! and each half reads it. Only once every part is done is the Arc
//! assembled ([`super::arc_reduce`]) and landed, its completion proven in
//! the landing writer: nothing lands in part.

use super::super::residency::spent_or_deferred;
use super::super::step_charge::StepChargeTally;
use super::super::support::invalid_consolidation;
use super::arc_chunks::{
    MemberText, context_cells, halve, member_texts, observation_parts, opened_member, plan_groups,
    ranges_cost, resume_members,
};
use super::arc_compose::{owe, owe_bare};
use super::arc_evidence::ArcView;
use super::arc_output::arc_schema;
use super::arc_reduce::{Landing, Observed, observations};
use super::arc_review::{
    CallBuilder, CallShape, Called, KIND_COMPOSE, KIND_REVIEW, call_input, frame_tokens,
    show_observation, store_exit,
};
use super::arc_turns::{Opened, open_turns};
use super::window::framed_tokens;
use super::{ScopeSummaryEvidence, ScopeSummaryExecutor};
use crate::EntityId;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::Result;
use crate::llm::DurableStepContext;
use crate::scope_summary::{
    ArcChildPlan, ArcChildRow, ArcManifest, ArcPendingCause, ArcPins, ArcWorkState, ChildMode,
    MemberKind, ScopeSummaryPlan, arc_member_kinds, check_manifest,
};
use std::collections::BTreeSet;

/// The identity an Arc composed in parts is known by: its parts' contract.
const ARC_PARTS_DOMAIN: &str = "oneiron:arc-summary-parts:v1";

/// One Arc attempt's work in one wake.
pub(super) struct ArcRun<'a> {
    pub(super) plan: &'a ScopeSummaryPlan,
    pub(super) evidence: &'a ScopeSummaryEvidence,
    pub(super) view: &'a ArcView,
    pub(super) instruction: &'a str,
    pub(super) schema: serde_json::Value,
    pub(super) work: [u8; 32],
    pub(super) manifest: ArcManifest,
    pub(super) members: Vec<MemberText>,
    /// The tokens a call holds beside its frame, and that frame.
    pub(super) room: u64,
    pub(super) frame: u64,
    pub(super) covers: BTreeSet<EntityId>,
    pub(super) charges: StepChargeTally,
    /// New model calls this wake, and the pace that checkpoints the rest.
    pub(super) calls: u32,
    pub(super) limit: u32,
    /// The parts reset this wake because a settled step of theirs did not
    /// read back (FIX 8288): a second miss parks as before.
    pub(super) reset: BTreeSet<u32>,
}

/// Where one part stands after a run.
enum ChildStep {
    Done,
    /// It split in two: the replacement parts' rows, by id.
    Split(Vec<(u32, ArcChildRow)>),
    Exit(DreamerAttemptExecution),
}

/// What opening a part's turns came to.
enum Opening {
    /// Opened; whether the manifest gained a member.
    Opened(bool),
    /// The part has no room to read them: it splits.
    Split,
    Exit(DreamerAttemptExecution),
}

impl ArcRun<'_> {
    /// Co-commits part `id`'s `row`, with the manifest when it `changed`;
    /// the exit when the write does not hold.
    fn save(
        &self,
        ctx: &WakeAttemptContext<'_>,
        id: u32,
        row: &ArcChildRow,
        changed: bool,
    ) -> Option<DreamerAttemptExecution> {
        let manifest = changed.then_some(&self.manifest);
        ctx.vault
            .save_arc_work(&self.work, manifest, &[(id, row)], None, None)
            .err()
            .map(|error| store_exit(&error, &self.charges, ctx.now_ms))
    }

    /// The member index a TURN already has: read in place of a line, or
    /// opened before.
    fn turn_member(&self, turn: EntityId) -> Option<u32> {
        let handle = turn.to_hex();
        self.manifest
            .members
            .iter()
            .position(|member| {
                matches!(&member.kind,
                    MemberKind::Fallback { turn } | MemberKind::Opened { turn } if *turn == handle)
            })
            .map(|index| index as u32)
    }

    /// Every claim member, in order.
    fn claims(&self) -> Vec<u32> {
        (0_u32..)
            .zip(&self.manifest.members)
            .filter(|(_, member)| matches!(member.kind, MemberKind::Claim { .. }))
            .map(|(index, _)| index)
            .collect()
    }

    /// Resets part `id`'s `row` once this wake (FIX 8288): its compose
    /// steps from `composed`, and with `reviewed` its reviews from there,
    /// are dropped, so the part composes again from them; every other part
    /// and every earlier step stand. `Some` exit when it was reset already,
    /// which parks Retry as an unread step did, or the write did not hold.
    fn reset_part(
        &mut self,
        ctx: &WakeAttemptContext<'_>,
        id: u32,
        row: &mut ArcChildRow,
        (composed, reviewed): (usize, Option<usize>),
    ) -> Option<DreamerAttemptExecution> {
        if !self.reset.insert(id) {
            return Some(
                self.charges
                    .park_for("an arc part's step did not read", DreamerParkCause::Retry),
            );
        }
        tracing::info!(
            part = id,
            code = "arc_part_step_unread",
            "an arc part composes again from a step that did not read"
        );
        if let Some(reviewed) = reviewed {
            row.reviewed.truncate(reviewed);
            row.parts = 0;
        }
        row.composed.truncate(composed);
        row.done = false;
        self.save(ctx, id, row, false)
    }

    /// The Arc's window, and why it is too small.
    fn too_small(&self) -> ArcPendingCause {
        ArcPendingCause::WindowTooSmall {
            window: self.manifest.pins.window,
            frame_tokens: self.frame,
        }
    }
}

impl<E> ScopeSummaryExecutor<'_, E> {
    /// The params and memo an Arc composed in parts on `window` is known by.
    fn arc_work_identity(
        &self,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        instruction: &str,
        window: u64,
    ) -> Result<([u8; 32], [u8; 32])> {
        let params = serde_json::to_vec(&(
            instruction,
            self.model.as_str(),
            &arc_schema(),
            ARC_PARTS_DOMAIN,
            window,
        ))
        .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
        let params_hash = *blake3::hash(&params).as_bytes();
        Ok((params_hash, plan.composition_memo(evidence, &params_hash)?))
    }

    /// Whether `plan`'s Arc already composes in parts on `window`, its
    /// generation not yet landed.
    pub(super) fn arc_work_open(
        &self,
        ctx: &WakeAttemptContext<'_>,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        instruction: &str,
        window: u64,
    ) -> Result<bool> {
        let (_, memo) = self.arc_work_identity(plan, evidence, instruction, window)?;
        let work = ctx.vault.arc_work_id(plan, &memo)?;
        let (manifest, _) = ctx.vault.arc_work_rows(&work)?;
        Ok(manifest.is_some_and(|manifest| manifest.state == ArcWorkState::Open))
    }

    /// Composes `plan`'s Arc in parts on `window`, `charges` carrying what
    /// the attempt already spent, and lands it once every part is done.
    pub(super) async fn compose_arc_work(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        instruction: &str,
        (window, charges): (u64, StepChargeTally),
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        let (Some(arc), Some(view), Some(scope), Some(first)) = (
            &plan.arc,
            &evidence.arc,
            &plan.scope,
            evidence.covers.first().copied(),
        ) else {
            return Err(invalid_consolidation("an arc composes from its sittings"));
        };
        let (params_hash, memo) = match self.arc_work_identity(plan, evidence, instruction, window)
        {
            Ok(identity) => identity,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        // The same composition in parts already stands: nothing is asked.
        match ctx.vault.reuse_composed_scope_summary(
            attempt_id,
            plan,
            evidence,
            &first,
            &memo,
            &params_hash,
        ) {
            Ok(true) => {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                });
            }
            Ok(false) => {}
            Err(error) => return Ok(store_exit(&error, &charges, ctx.now_ms)),
        }
        let schema = arc_schema();
        let frame = match frame_tokens(plan, instruction, &schema) {
            Ok(frame) => frame,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        let too_small = ArcPendingCause::WindowTooSmall {
            window,
            frame_tokens: frame,
        };
        let Some(room) = window.checked_sub(frame).filter(|room| *room > 0) else {
            return owe(ctx, plan, too_small, &charges);
        };
        let mut members = match member_texts(plan, view, arc_member_kinds(arc, &view.claim_ids)) {
            Ok(members) => members,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        let pins = match ArcPins::of(plan, evidence, &memo, &params_hash, window) {
            Ok(pins) => pins,
            Err(error) => return spent_or_deferred(error, ctx, &charges),
        };
        let work = match ctx.vault.arc_work_id(plan, &memo) {
            Ok(work) => work,
            Err(error) => return Ok(store_exit(&error, &charges, ctx.now_ms)),
        };
        let (stored, mut rows) = match ctx.vault.arc_work_rows(&work) {
            Ok(loaded) => loaded,
            Err(error) => return Ok(store_exit(&error, &charges, ctx.now_ms)),
        };
        let resumed = match stored {
            Some(stored) => match resume_members(&stored, &pins, &members, view) {
                Ok(resumed) => resumed.map(|opened| {
                    members.extend(opened);
                    stored
                }),
                Err(error) => return spent_or_deferred(error, ctx, &charges),
            },
            None => None,
        };
        let manifest = match resumed {
            Some(manifest) => {
                if let Err(error) = ctx.vault.record_arc_progress(&plan.input, &work, None) {
                    return Ok(store_exit(&error, &charges, ctx.now_ms));
                }
                manifest
            }
            None => {
                let groups = match plan_groups(&members, view, room) {
                    Ok(groups) => groups,
                    Err(error) => return spent_or_deferred(error, ctx, &charges),
                };
                let Some(groups) = groups else {
                    return owe(ctx, plan, too_small, &charges);
                };
                let manifest = ArcManifest {
                    pins,
                    members: members.iter().map(|member| member.member.clone()).collect(),
                    next_child: groups.len() as u32,
                    children: (0_u32..)
                        .zip(groups)
                        .map(|(id, ranges)| ArcChildPlan { id, ranges })
                        .collect(),
                    state: ArcWorkState::Open,
                };
                if let Err(error) =
                    ctx.vault
                        .record_arc_progress(&plan.input, &work, Some(&manifest))
                {
                    return Ok(store_exit(&error, &charges, ctx.now_ms));
                }
                rows.clear();
                manifest
            }
        };
        tracing::info!(
            parts = manifest.children.len(),
            members = manifest.members.len(),
            "an arc composes in parts"
        );
        let limit = match ctx.vault.dreamer_recipe_policy() {
            Ok(policy) => policy.arc_child_calls_per_wake,
            Err(error) => return Ok(charges.park_on_error(&error)),
        };
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject: scope.conversation,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let mut run = ArcRun {
            plan,
            evidence,
            view,
            instruction,
            schema,
            work,
            manifest,
            members,
            room,
            frame,
            covers: evidence.covers.iter().copied().collect(),
            charges,
            calls: 0,
            limit,
            reset: BTreeSet::new(),
        };
        let mut position = 0;
        loop {
            while let Some(child) = run.manifest.children.get(position) {
                let id = child.id;
                let mut row = rows
                    .remove(&id)
                    .unwrap_or_else(|| ArcChildRow::fresh(Vec::new()));
                match self
                    .run_child(&mut run, ctx, &step_ctx, position, &mut row)
                    .await
                {
                    Ok(ChildStep::Done) => {
                        rows.insert(id, row);
                        position += 1;
                    }
                    Ok(ChildStep::Split(parts)) => rows.extend(parts),
                    Ok(ChildStep::Exit(execution)) => return Ok(execution),
                    Err(error) => return spent_or_deferred(error, ctx, &run.charges),
                }
            }
            let landed = match self.land_arc_work(ctx, attempt_id, &run, &rows, (params_hash, memo))
            {
                Ok(landed) => landed,
                Err(error) => return spent_or_deferred(error, ctx, &run.charges),
            };
            let (part, step) = match landed {
                Landing::Exit(execution) => return Ok(execution),
                Landing::Recompose { part, step } => (part, step),
            };
            // A settled step that no longer reads back (FIX 8288): only that
            // part composes again, from that step; the rest stand.
            let (Some(at), Some(row)) = (
                run.manifest
                    .children
                    .iter()
                    .position(|child| child.id == part),
                rows.get_mut(&part),
            ) else {
                return spent_or_deferred(
                    invalid_consolidation("an arc's part has no record"),
                    ctx,
                    &run.charges,
                );
            };
            if let Some(exit) = run.reset_part(ctx, part, row, (step, None)) {
                return Ok(exit);
            }
            position = at;
        }
    }

    /// Runs the part at `position` from where its `row` stands until it is
    /// done, splits, or the attempt exits.
    async fn run_child(
        &self,
        run: &mut ArcRun<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_ctx: &DurableStepContext<'_>,
        position: usize,
        row: &mut ArcChildRow,
    ) -> Result<ChildStep> {
        let Some(child) = run.manifest.children.get(position) else {
            return Err(invalid_consolidation(
                "an arc's part is not in its manifest",
            ));
        };
        let (id, group) = (child.id, child.ranges.clone());
        let room = run
            .room
            .checked_sub(ranges_cost(&run.members, &group)?)
            .ok_or_else(|| invalid_consolidation("an arc's part outgrew its window"))?;
        loop {
            if row.done {
                return Ok(ChildStep::Done);
            }
            let children = run.manifest.children.len() as u64;
            let child = position as u64 + 1;
            let (shape, shown) = match row.mode {
                ChildMode::Single => {
                    let mut read = run.claims();
                    read.extend(row.opened.iter().copied());
                    let mut cost = 0_u64;
                    for index in &read {
                        cost = cost.saturating_add(
                            super::arc_chunks::member(&run.members, *index)?.whole_cost()?,
                        );
                    }
                    if cost > room {
                        // The part reads its claims and opened words in cells.
                        let Some(cells) = context_cells(&run.members, run.view, &read, room)?
                        else {
                            return self.split(run, ctx, position, row);
                        };
                        row.mode = ChildMode::Review;
                        row.cells = cells;
                        if let Some(exit) = run.save(ctx, id, row, false) {
                            return Ok(ChildStep::Exit(exit));
                        }
                        continue;
                    }
                    let mut call = CallBuilder::new(&run.members, run.view);
                    call.group(&group)?;
                    call.whole(&read)?;
                    let shape = CallShape {
                        kind: KIND_COMPOSE,
                        child,
                        children,
                        part: 1,
                        parts: 1,
                    };
                    (shape, call.finish()?)
                }
                ChildMode::Review if row.reviewed.len() < row.cells.len() => {
                    let cell = row.reviewed.len();
                    let mut call = CallBuilder::new(&run.members, run.view);
                    call.group(&group)?;
                    call.context(&row.cells[cell])?;
                    let shape = CallShape {
                        kind: KIND_REVIEW,
                        child,
                        children,
                        part: cell as u64 + 1,
                        parts: row.cells.len() as u64,
                    };
                    (shape, call.finish()?)
                }
                ChildMode::Review => {
                    let read = {
                        let memory = ctx
                            .vault
                            .memory(self.actor.entity_ref(), self.actor.actor_class());
                        observations(&memory, &row.reviewed)
                    };
                    let observed = match read {
                        Ok(Observed::All(observed)) => observed,
                        // A review that no longer reads back (FIX 8288) is
                        // asked again, with every compose step after it.
                        Ok(Observed::Unread(index)) => {
                            if let Some(exit) = run.reset_part(ctx, id, row, (0, Some(index))) {
                                return Ok(ChildStep::Exit(exit));
                            }
                            continue;
                        }
                        Err(error) => {
                            return Ok(ChildStep::Exit(run.charges.park_on_error(&error)));
                        }
                    };
                    let rendered = observed
                        .iter()
                        .map(|observation| show_observation(run.view, observation))
                        .collect::<Result<Vec<_>>>()?;
                    let Some(parts) = observation_parts(&rendered, room)? else {
                        return self.split(run, ctx, position, row);
                    };
                    row.parts = parts.len() as u32;
                    let part = row.composed.len();
                    let Some(indices) = parts.get(part) else {
                        row.done = true;
                        if let Some(exit) = run.save(ctx, id, row, false) {
                            return Ok(ChildStep::Exit(exit));
                        }
                        continue;
                    };
                    let chosen: Vec<_> = indices
                        .iter()
                        .filter_map(|index| observed.get(*index))
                        .collect();
                    let mut call = CallBuilder::new(&run.members, run.view);
                    call.group(&group)?;
                    call.observations(&chosen)?;
                    let shape = CallShape {
                        kind: KIND_COMPOSE,
                        child,
                        children,
                        part: part as u64 + 1,
                        parts: parts.len() as u64,
                    };
                    (shape, call.finish()?)
                }
            };
            let (fields, context, whole) = shown;
            let mut opened: BTreeSet<EntityId> = whole;
            for index in &row.opened {
                let member = super::arc_chunks::member(&run.members, *index)?;
                opened.extend(member.turns.iter().copied());
            }
            let user = call_input(run.plan, &shape, &fields)?;
            // The call's whole request is counted once against the window
            // (FIX 8286): one the summed estimate let past it splits.
            if framed_tokens(run.instruction, &user, &run.schema)? > run.manifest.pins.window {
                return self.split(run, ctx, position, row);
            }
            let (reply, step) = match self
                .child_call(run, ctx, step_ctx, user, context, opened)
                .await?
            {
                Called::Reply(reply, step) => (reply, step),
                Called::Exit(exit) => return Ok(ChildStep::Exit(exit)),
            };
            // A review step is kept at once; a compose step only when its
            // reply opened nothing.
            let compose_step = if shape.kind == KIND_REVIEW {
                row.reviewed.push(step);
                None
            } else {
                Some(step)
            };
            let mut changed = false;
            if !reply.open.is_empty() {
                match self.open_for(run, ctx, row, &reply.open, room)? {
                    Opening::Opened(grew) => changed = grew,
                    Opening::Split => return self.split(run, ctx, position, row),
                    Opening::Exit(exit) => return Ok(ChildStep::Exit(exit)),
                }
                if row.mode == ChildMode::Review {
                    // Its observations grew: every compose part is asked again.
                    row.composed.clear();
                    row.parts = 0;
                }
            } else if let Some(step) = compose_step {
                row.composed.push(step);
                if row.mode == ChildMode::Single {
                    row.parts = 1;
                    row.done = true;
                } else if row.composed.len() == row.parts as usize {
                    row.done = true;
                }
            }
            if let Some(exit) = run.save(ctx, id, row, changed) {
                return Ok(ChildStep::Exit(exit));
            }
        }
    }

    /// Opens the turns a part's reply named through their handles, each
    /// registered once in the manifest and owed whole by the part: in cells
    /// of `room` tokens when the part reviews.
    fn open_for(
        &self,
        run: &mut ArcRun<'_>,
        ctx: &WakeAttemptContext<'_>,
        row: &mut ArcChildRow,
        ask: &[EntityId],
        room: u64,
    ) -> Result<Opening> {
        let turns = match open_turns(ctx.vault, run.evidence, run.view, ask) {
            Ok(Opened::Turns(turns)) => turns,
            Ok(Opened::Unavailable(turn)) => {
                let cause = ArcPendingCause::SourceUnavailable {
                    handle: turn.to_hex(),
                };
                return Ok(Opening::Exit(owe_bare(ctx, run.plan, cause, &run.charges)?));
            }
            Err(error) => return Ok(Opening::Exit(store_exit(&error, &run.charges, ctx.now_ms))),
        };
        let mut grew = false;
        let mut fresh = Vec::new();
        for opened in &turns {
            let index = match run.turn_member(opened.turn) {
                Some(index) => index,
                None => {
                    let member = opened_member(run.view, opened.turn)?;
                    run.manifest.members.push(member.member.clone());
                    run.members.push(member);
                    grew = true;
                    (run.members.len() - 1) as u32
                }
            };
            if !row.opened.contains(&index) {
                row.opened.push(index);
                fresh.push(index);
            }
        }
        if row.mode == ChildMode::Review {
            let Some(cells) = context_cells(&run.members, run.view, &fresh, room)? else {
                return Ok(Opening::Split);
            };
            row.cells.extend(cells);
        }
        Ok(Opening::Opened(grew))
    }

    /// Replaces the part at `position` by two that own its ranges between
    /// them, in order, each owing what it owed; its words cut at a character
    /// when it owns one range. A part of one character cannot split: the
    /// window is too small for the Arc.
    fn split(
        &self,
        run: &mut ArcRun<'_>,
        ctx: &WakeAttemptContext<'_>,
        position: usize,
        row: &ArcChildRow,
    ) -> Result<ChildStep> {
        let Some(old) = run.manifest.children.get(position).map(|child| child.id) else {
            return Err(invalid_consolidation(
                "an arc's part is not in its manifest",
            ));
        };
        let halves = run
            .manifest
            .children
            .get(position)
            .and_then(|child| halve(&child.ranges, &run.members));
        let Some((first, second)) = halves else {
            let cause = run.too_small();
            return Ok(ChildStep::Exit(owe_bare(
                ctx,
                run.plan,
                cause,
                &run.charges,
            )?));
        };
        let ids = [
            run.manifest.next_child,
            run.manifest.next_child.saturating_add(1),
        ];
        run.manifest.next_child = run.manifest.next_child.saturating_add(2);
        run.manifest.children[position] = ArcChildPlan {
            id: ids[0],
            ranges: first,
        };
        run.manifest.children.insert(
            position + 1,
            ArcChildPlan {
                id: ids[1],
                ranges: second,
            },
        );
        if let Err(error) = check_manifest(&run.manifest) {
            return Ok(ChildStep::Exit(run.charges.park_on_error(&error)));
        }
        let parts = vec![
            (ids[0], ArcChildRow::fresh(row.opened.clone())),
            (ids[1], ArcChildRow::fresh(row.opened.clone())),
        ];
        let written: Vec<(u32, &ArcChildRow)> = parts.iter().map(|(id, row)| (*id, row)).collect();
        if let Err(error) =
            ctx.vault
                .save_arc_work(&run.work, Some(&run.manifest), &written, Some(old), None)
        {
            return Ok(ChildStep::Exit(store_exit(
                &error,
                &run.charges,
                ctx.now_ms,
            )));
        }
        tracing::info!(
            parts = run.manifest.children.len(),
            "an arc's part splits in two"
        );
        Ok(ChildStep::Split(parts))
    }
}
