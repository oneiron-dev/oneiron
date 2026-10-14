//! A compaction pass is bounded work: it outlives the call that started it,
//! so its thread holds a permit of its own until it ends. Past the bound a
//! pass waits its turn rather than being dropped, and one that waits past
//! its deadline never starts.

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use oneiron::engine_executor::CompactionSpawn;

use super::ThreadSpawn;
use crate::admission::{Admission, Crossing};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

const PATIENCE: Duration = Duration::from_secs(10);

fn spawner(bound: usize, wait: Duration) -> (ThreadSpawn, Arc<LimitQuestions>) {
    let questions = Arc::new(LimitQuestions::default());
    let passes = Admission::new(
        LimitRow::CompactionPasses,
        Arc::clone(&questions),
        bound,
        wait,
    );
    (
        ThreadSpawn {
            passes: Arc::new(passes),
        },
        questions,
    )
}

/// Spawns a pass that only reports it ran; the receiver hears it.
fn spawn_reporting(spawn: &ThreadSpawn) -> mpsc::Receiver<()> {
    let (ran, pass) = mpsc::channel();
    spawn.spawn(Box::new(move || {
        let _ = ran.send(());
    }));
    pass
}

/// Rule five at the compaction row: `callers` passes past a bound of one all
/// run, and the row asks.
pub(crate) fn cross_the_passes(callers: usize) -> Crossing {
    let (spawn, questions) = spawner(1, PATIENCE);
    let passes: Vec<_> = (0..callers)
        .map(|_| {
            let (ran, pass) = mpsc::channel();
            spawn.spawn(Box::new(move || {
                std::thread::sleep(Duration::from_millis(20));
                let _ = ran.send(());
            }));
            pass
        })
        .collect();
    let refused = passes
        .iter()
        .filter(|pass| pass.recv_timeout(PATIENCE * 4).is_err())
        .count();
    Crossing {
        refused,
        asked: questions.latest(LimitRow::CompactionPasses).is_some(),
    }
}

#[test]
fn a_pass_holds_its_permit_until_its_thread_ends_and_the_next_waits_for_it() {
    let (spawn, _) = spawner(1, PATIENCE);

    // The first pass runs, and keeps running after the spawn returns.
    let (release, released) = mpsc::channel::<()>();
    let (started, first) = mpsc::channel();
    spawn.spawn(Box::new(move || {
        let _ = started.send(());
        let _ = released.recv();
    }));
    first.recv_timeout(PATIENCE).expect("the first pass runs");

    // The next pass waits for the permit: it neither runs nor is dropped.
    let next = spawn_reporting(&spawn);
    assert_eq!(
        next.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout),
        "past the bound a pass waits its turn"
    );

    drop(release);
    next.recv_timeout(PATIENCE)
        .expect("the permit passes on once the first pass's thread ends");
}

#[test]
fn a_pass_that_waits_past_its_deadline_never_starts() {
    let (spawn, _) = spawner(1, Duration::from_millis(200));
    let (_release, released) = mpsc::channel::<()>();
    let (started, first) = mpsc::channel();
    spawn.spawn(Box::new(move || {
        let _ = started.send(());
        let _ = released.recv();
    }));
    first.recv_timeout(PATIENCE).expect("the first pass runs");

    // Dropped unrun at its deadline, which the run reads as a pass that
    // never ran; never before it.
    let started = std::time::Instant::now();
    assert_eq!(
        spawn_reporting(&spawn).recv_timeout(PATIENCE),
        Err(RecvTimeoutError::Disconnected)
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "a pass waits its deadline rather than being dropped at once"
    );
}
