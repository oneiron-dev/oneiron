//! A compaction pass is bounded work: it outlives the call that started it,
//! so its thread holds a permit of its own until it ends. Past the bound a
//! pass waits its turn rather than being dropped, and one that waits past
//! its deadline never starts.

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use oneiron::engine_executor::CompactionSpawn;
use tokio::runtime::Runtime;

use super::ThreadSpawn;
use crate::admission::{Admission, Crossing};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

const PATIENCE: Duration = Duration::from_secs(10);

/// One credential's spawner, the row's questions, and the runtime its
/// passes wait on, which must outlive them.
fn spawner(bound: usize, wait: Duration) -> (ThreadSpawn, Arc<LimitQuestions>, Runtime) {
    let questions = Arc::new(LimitQuestions::default());
    let passes = Admission::new(
        LimitRow::CompactionPasses,
        Arc::clone(&questions),
        bound,
        wait,
    );
    let runtime = runtime();
    let spawn = on_behalf_of(&Arc::new(passes), "a credential", &runtime);
    (spawn, questions, runtime)
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .expect("runtime")
}

/// A run's spawner on `passes`, its passes queued as `credential`'s.
fn on_behalf_of(
    passes: &Arc<Admission<String>>,
    credential: &str,
    runtime: &Runtime,
) -> ThreadSpawn {
    ThreadSpawn {
        passes: Arc::clone(passes),
        credential: credential.to_owned(),
        runtime: runtime.handle().clone(),
    }
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
    let (spawn, questions, _runtime) = spawner(1, PATIENCE);
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
    let (spawn, _, _runtime) = spawner(1, PATIENCE);

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
    let (spawn, _, _runtime) = spawner(1, Duration::from_millis(200));
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

/// Review r2 (Sol and Astra, P1): every pass queued under one key, so passes
/// waited first come, first served across every credential. A credential
/// with a backlog of passes held another's one pass back until its whole
/// backlog had run, and past its deadline that pass never ran at all.
#[test]
fn a_credentials_backlog_of_passes_never_holds_another_credentials_pass_back() {
    let passes = Arc::new(Admission::new(
        LimitRow::CompactionPasses,
        Arc::new(LimitQuestions::default()),
        1,
        PATIENCE,
    ));
    let runtime = runtime();
    let fleet = on_behalf_of(&passes, "a fleet's credential", &runtime);
    let other = on_behalf_of(&passes, "another credential", &runtime);

    // The fleet's first pass holds the only permit.
    let (release, released) = mpsc::channel::<()>();
    let (started, first) = mpsc::channel();
    fleet.spawn(Box::new(move || {
        let _ = started.send(());
        let _ = released.recv();
    }));
    first.recv_timeout(PATIENCE).expect("the first pass runs");

    // Three more of the fleet's passes queue, then the other credential's.
    let (ran, order) = mpsc::channel();
    let queue = |spawn: &ThreadSpawn, name: &'static str| {
        let before = passes.waiting();
        let ran = ran.clone();
        spawn.spawn(Box::new(move || {
            let _ = ran.send(name);
        }));
        while passes.waiting() == before {
            std::thread::yield_now();
        }
    };
    for name in ["fleet 2", "fleet 3", "fleet 4"] {
        queue(&fleet, name);
    }
    queue(&other, "other");

    drop(release);
    let served: Vec<_> = (0..4)
        .map(|_| {
            order
                .recv_timeout(PATIENCE)
                .expect("every queued pass runs")
        })
        .collect();
    assert_eq!(
        served,
        ["fleet 2", "other", "fleet 3", "fleet 4"],
        "turns go round the credentials, in order within one"
    );
}
