//! The fan-out launches that wait on the owner, as TASKS lead rows (OF-393):
//! a held launch's pause row with the resume door, and a launched cut's
//! width check with the ack door. A held ask's pause row is a held launch's.
//! Each row names its durable surface ref and the door's arguments verbatim;
//! the doors are the owner's alone, whoever reads the board.
use crate::entity_id::bytes_to_hex_lower;
use crate::task_verb::FanoutLaunchReceipt;

/// The most fan-out rows one board shows; one more row counts the rest.
const FANOUT_ACTION_ROWS_CAP: usize = 8;

/// The rows for `launches`: held launches first, then width checks, then
/// denied holds, each kind in the order given, at most
/// [`FANOUT_ACTION_ROWS_CAP`] of them. A launch that waits on nothing has
/// no row.
#[must_use]
pub fn fanout_action_rows(launches: &[FanoutLaunchReceipt]) -> Vec<String> {
    let mut ranked: Vec<(u8, String)> = launches.iter().filter_map(fanout_action_row).collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    let omitted = ranked.len().saturating_sub(FANOUT_ACTION_ROWS_CAP);
    let mut rows: Vec<String> = ranked
        .into_iter()
        .take(FANOUT_ACTION_ROWS_CAP)
        .map(|(_, row)| row)
        .collect();
    if omitted > 0 {
        rows.push(format!("fanout_rows_omitted: {omitted}"));
    }
    rows
}

/// One launch's row and its rank: 0 held, 1 width check, 2 denied.
fn fanout_action_row(launch: &FanoutLaunchReceipt) -> Option<(u8, String)> {
    let launch_ref = launch.launch_ref.to_hex();
    let digest = bytes_to_hex_lower(&launch.plan_digest);
    let tasks = launch.statement.task_count;
    if let Some(pause) = &launch.paused {
        let (rank, state) = if pause.denied {
            (2, "denied_parked")
        } else {
            (0, "paused")
        };
        return Some((
            rank,
            format!(
                "{} {state} tasks={tasks} resume=vault.fanout.resume launch_ref={launch_ref} \
                 plan_digest={digest} ruling=approve_once|approve_and_remember|deny by=owner",
                pause.surface_ref
            ),
        ));
    }
    let check = launch
        .check_row_ref
        .as_ref()
        .filter(|_| launch.choice_receipt_ref.is_none())?;
    Some((
        1,
        format!(
            "{check} dispatched tasks={tasks} ack=vault.fanout.ack launch_ref={launch_ref} \
             plan_digest={digest} answer=ack|ack_and_remember by=owner"
        ),
    ))
}
