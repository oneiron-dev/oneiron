//! The code `oneiron jobs` exits with: the job's own exit code, and `fleet run`'s codes where
//! fleet has the case (its source: /home/lexi/.local/bin/gpu on sel, read 28 Nov). The table is
//! docs/ops/jobs-booker.md's.

use oneiron::work_order::{CancelWhy, EndKind, GiveUpWhy, OrderState, WorkOrder};

/// Refused before anything was ordered: a flag, a host, a template, the pin's refusal or its
/// pending check-in, a Grant's refusal (clap's own usage code; chosen).
pub(super) const EXIT_REFUSED: i32 = 2;
/// The node lost the run (fleet `EXIT_BOX_LOST`, gpu:8213).
pub(super) const EXIT_LOST: i32 = 77;
/// Cancelled by someone else (fleet `EXIT_WITHDRAWN`, gpu:1425).
pub(super) const EXIT_WITHDRAWN: i32 = 78;
/// It never started (fleet `EXIT_NOT_ADMITTED`, gpu:1862).
pub(super) const EXIT_NOT_STARTED: i32 = 79;
/// The intent key made another order; nothing was ordered (fleet `EXIT_KEY_HELD`, gpu:2746).
pub(super) const EXIT_KEY_HELD: i32 = 80;
/// `--no-wait` and it could not run now, or its wait ran out (fleet `--no-wait`, gpu:10363).
pub(super) const EXIT_NO_ROOM: i32 = 75;
/// Stopped at its maximum (fleet `--timeout`, gpu:10291).
pub(super) const EXIT_TIME_LIMIT: i32 = 124;
/// Over its memory (fleet's 137, gpu:2137).
pub(super) const EXIT_MEMORY_LIMIT: i32 = 137;
/// The issuer stopped answering while the order lives on (sysexits `EX_IOERR`; chosen).
pub(super) const EXIT_UNREACHED: i32 = 74;
/// Any other end; the end line names it (chosen).
pub(super) const EXIT_OTHER: i32 = 1;

/// A signal this process took while it followed the order: it asked for the cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnStop {
    Terminate,
    Interrupt,
}

impl OwnStop {
    /// 128 plus the signal's number, as a shell reports it.
    pub(super) const fn code(self) -> i32 {
        match self {
            Self::Terminate => 128 + 15,
            Self::Interrupt => 128 + 2,
        }
    }
}

/// The exit code of an attempt's end, and its words for the end line.
pub(super) fn end_code(end: &EndKind) -> (i32, String) {
    match end {
        EndKind::Exited { code } => (
            if (0..=255).contains(code) {
                *code
            } else {
                EXIT_OTHER
            },
            format!("exited {code}"),
        ),
        EndKind::TimeLimit => (EXIT_OTHER, "time limit".to_owned()),
        EndKind::MemoryLimit => (EXIT_OTHER, "memory limit".to_owned()),
        EndKind::Lost => (EXIT_OTHER, "lost".to_owned()),
        EndKind::NeverStarted => (EXIT_OTHER, "never started".to_owned()),
        EndKind::Expired => (EXIT_OTHER, "start window expired".to_owned()),
        EndKind::DiskLimit => (EXIT_OTHER, "disk limit".to_owned()),
        EndKind::LaunchRefusedChanged => (
            EXIT_OTHER,
            "launch refused: the contract, the commit or the template changed".to_owned(),
        ),
        EndKind::Revoked => (EXIT_OTHER, "its authority was revoked".to_owned()),
        EndKind::Stopped => (EXIT_OTHER, "stopped".to_owned()),
        EndKind::WrittenOff => (EXIT_OTHER, "written off".to_owned()),
        EndKind::Closed => (EXIT_OTHER, "closed".to_owned()),
    }
}

/// The exit code of an order at an end, and its words; `None` while it is not at one.
/// `own_stop` is the signal this process cancelled it for, if any.
pub(super) fn order_code(order: &WorkOrder, own_stop: Option<OwnStop>) -> Option<(i32, String)> {
    let last_end = || {
        order
            .attempts
            .last()
            .and_then(|attempt| attempt.end.as_ref())
    };
    Some(match &order.state {
        OrderState::Open { .. } | OrderState::Running { .. } => return None,
        OrderState::Done => match last_end() {
            Some(end) => end_code(&end.kind),
            None => (0, "done".to_owned()),
        },
        OrderState::GivenUp { why } => match why {
            GiveUpWhy::Ended { end } => end_code(end),
            GiveUpWhy::WaitEnded { .. } => {
                (EXIT_NO_ROOM, "gave up: no room in its wait".to_owned())
            }
            GiveUpWhy::NeverFits { .. } => (
                EXIT_OTHER,
                "gave up: no allowed machine ever fits it".to_owned(),
            ),
            GiveUpWhy::WrittenOff => (EXIT_OTHER, "gave up: written off".to_owned()),
            GiveUpWhy::Upstream { .. } => (EXIT_OTHER, "gave up: its upstream order".to_owned()),
        },
        OrderState::Cancelled { why } => match (own_stop, why) {
            (Some(stop), _) => (stop.code(), "cancelled by this booker".to_owned()),
            (None, CancelWhy::Asked { .. }) => (EXIT_WITHDRAWN, "cancelled".to_owned()),
            (None, CancelWhy::AuthorityEnded) => {
                (EXIT_WITHDRAWN, "cancelled: its authority ended".to_owned())
            }
        },
    })
}
