//! A compaction pass is bounded work: it outlives the call that started it,
//! so its thread holds a permit of its own until it ends, and past the bound a
//! pass is refused rather than started.

use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use oneiron::engine_executor::CompactionSpawn;

use super::ThreadSpawn;
use crate::admission::Admission;

const PATIENCE: Duration = Duration::from_secs(10);

/// Spawns a pass that only reports it ran, and says whether it did.
fn ran(spawn: &ThreadSpawn) -> Result<(), RecvTimeoutError> {
    let (ran, pass) = mpsc::channel();
    spawn.spawn(Box::new(move || {
        let _ = ran.send(());
    }));
    pass.recv_timeout(PATIENCE)
}

#[test]
fn a_pass_holds_its_permit_until_its_thread_ends() {
    let spawn = ThreadSpawn {
        passes: Arc::new(Admission::new(1, 1)),
    };

    // The first pass runs, and keeps running after the spawn returns.
    let (release, released) = mpsc::channel::<()>();
    let (started, first) = mpsc::channel();
    spawn.spawn(Box::new(move || {
        let _ = started.send(());
        let _ = released.recv();
    }));
    first.recv_timeout(PATIENCE).expect("the first pass runs");

    // A refused pass is dropped unrun, which the run reads as a refused pass.
    assert_eq!(
        ran(&spawn),
        Err(RecvTimeoutError::Disconnected),
        "past the bound a pass is refused, not started"
    );

    drop(release);
    let admitted = (0..500).any(|_| {
        let admitted = ran(&spawn).is_ok();
        if !admitted {
            std::thread::sleep(Duration::from_millis(10));
        }
        admitted
    });
    assert!(admitted, "the permit returns once the pass's thread ends");
}
