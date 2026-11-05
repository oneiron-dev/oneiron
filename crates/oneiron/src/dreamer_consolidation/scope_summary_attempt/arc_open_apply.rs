//! Applies advisory openings only when the next original call still fits whole.

use super::arc_children::ArcRun;
use super::arc_chunks::opened_member;
use super::arc_review::{
    CallBuilder, CallFields, CallShape, KIND_COMPOSE, KIND_REVIEW, call_input,
};
use super::arc_turns::{Opened, open_turns};
use super::window::framed_tokens;
use crate::EntityId;
use crate::dreamer_wake::WakeAttemptContext;
use crate::scope_summary::{ArcChildRow, ArcRange, ChildMode, MemberKind};

pub(super) fn open_advised(
    run: &mut ArcRun<'_>,
    ctx: &WakeAttemptContext<'_>,
    row: &mut ArcChildRow,
    shape: &CallShape,
    fields: &CallFields,
    ask: &[EntityId],
) -> bool {
    if ask.is_empty() {
        return false;
    }
    let review_at = match row.mode {
        ChildMode::Single => None,
        ChildMode::Review if shape.kind == KIND_REVIEW => Some(row.reviewed.len()),
        ChildMode::Review => None,
    };
    let Ok(Opened::Turns(turns)) = open_turns(ctx.vault, run.evidence, run.view, ask) else {
        return false;
    };
    let mut added = Vec::new();
    let mut indices = Vec::new();
    for turn in turns {
        let handle = turn.turn.to_hex();
        let existing = run.manifest.members.iter().position(|member| {
            matches!(&member.kind,
                MemberKind::Fallback { turn } | MemberKind::Opened { turn } if *turn == handle)
        });
        let index = match existing {
            Some(index) => index as u32,
            None => {
                let Ok(member) = opened_member(run.view, turn.turn) else {
                    return false;
                };
                let index = (run.members.len() + added.len()) as u32;
                added.push(member);
                index
            }
        };
        if !row.opened.contains(&index) {
            indices.push(index);
        }
    }
    if indices.is_empty() {
        return false;
    }
    let before = run.members.len();
    run.members.extend(added);
    let fits = (|| -> crate::Result<bool> {
        let mut call = CallBuilder::new(&run.members, run.view);
        call.whole(&indices)?;
        let (extra, _, _) = call.finish()?;
        let user = call_input(run.plan, shape, &fields.with_opened(&extra))?;
        Ok(framed_tokens(run.instruction, &user, &run.schema)? <= run.manifest.pins.window)
    })();
    if !matches!(fits, Ok(true)) {
        run.members.truncate(before);
        return false;
    }
    run.manifest.members.extend(
        run.members[before..]
            .iter()
            .map(|member| member.member.clone()),
    );
    if let Some(at) = review_at {
        row.cells[at].extend(indices.iter().map(|index| ArcRange {
            member: *index,
            start: 0,
            end: run.members[*index as usize].member.len,
        }));
    }
    if row.mode == ChildMode::Review && shape.kind == KIND_COMPOSE {
        row.compose_opened
            .entry(row.composed.len() as u32)
            .or_default()
            .extend(indices);
    } else {
        row.opened.extend(indices);
    }
    true
}
