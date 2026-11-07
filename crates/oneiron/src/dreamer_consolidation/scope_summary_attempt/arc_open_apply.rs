//! Applies advisory openings only when the next original call still fits whole.

use super::arc_children::ArcRun;
use super::arc_chunks::opened_member;
use super::arc_review::{CallBuilder, CallShape, call_input};
use super::arc_turns::{Opened, open_turns};
use super::window::framed_tokens;
use crate::EntityId;
use crate::dreamer_wake::WakeAttemptContext;
use crate::scope_summary::{ArcChildRow, ArcRange, ChildMode, MemberKind};

pub(super) fn open_advised(
    run: &mut ArcRun<'_>,
    ctx: &WakeAttemptContext<'_>,
    row: &mut ArcChildRow,
    group: &[ArcRange],
    shape: &CallShape,
    ask: &[EntityId],
) -> bool {
    if ask.is_empty() || row.mode != ChildMode::Single {
        return false;
    }
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
        let mut read: Vec<u32> = (0_u32..)
            .zip(&run.manifest.members)
            .filter(|(_, member)| matches!(member.kind, MemberKind::Claim { .. }))
            .map(|(index, _)| index)
            .collect();
        read.extend(row.opened.iter().copied());
        read.extend(indices.iter().copied());
        let mut call = CallBuilder::new(&run.members, run.view);
        call.group(group)?;
        call.whole(&read)?;
        let (fields, _, _) = call.finish()?;
        let user = call_input(run.plan, shape, &fields)?;
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
    row.opened.extend(indices);
    true
}
