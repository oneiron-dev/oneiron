//! DESIGN 15-setting-primitive, stage 5c-2: the paced verb line is one armed row of the
//! schedule's runner, `runtime_hooks.paced_verb_line` (OPUS-SETTING's answer to ASK
//! SETTING-SCHEDULE-5C2-HOST-JOBS, point 2):
//! - a held call arms the row, or pulls it earlier, in its hold's own write, due at the earliest
//!   a held call's window opens or its deadline passes, and the row wakes the host then;
//! - only a process whose host installed its paced turn runner runs the row: a CLI or embedded
//!   pass steps over it, ends no turn and is not woken for it;
//! - a pass that runs the row takes the turns that are due and moves the row to the line's next
//!   window;
//! - a handle's first pass arms the row from the calls the vault holds, when it has none;
//! - the settler's door runs the due row alone, not before it is due, and runs nothing while a
//!   housekeeping pass holds the runner.
//!
//! Red before 5c-2: no row is ever armed, a housekeeping pass takes no turn, every process is
//! woken for the line on the gate-decision sweep's carrier, and the settler takes the turns
//! without the runner.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test paced_verb_line_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::housekeeping::HousekeepingBudget;
use oneiron::test_doors::schedule::{
    PACED_VERB_LINE, due_at, paced_verb_call_waits, plant_paced_verb_call,
    while_a_pass_holds_the_runner,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every test opens at, in vault-clock seconds.
const T0: u64 = 4_000_000_000;
/// A held call's deadline in these tests: far past every window they open.
const DEADLINE: u64 = T0 + 100_000;

/// A vault on a clock the test moves, opened as an embedded owner opens it.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        config.store_clock = clock.bundle();
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), config).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        Self {
            vault,
            clock,
            owner,
            _dir: dir,
        }
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// One housekeeping pass, as the host's tick runs it.
    fn pass(&self) {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping");
    }

    /// A call by the owner held in the line, its window opening at `window`.
    fn hold(&self, window: u64) -> [u8; 16] {
        plant_paced_verb_call(&self.vault, self.owner, window, DEADLINE).expect("hold a call")
    }

    fn waits(&self, call: [u8; 16]) -> bool {
        paced_verb_call_waits(&self.vault, call).expect("the line")
    }

    /// When the line's row is next due, or `None` when it is not armed.
    fn line_due(&self) -> Option<u64> {
        due_at(&self.vault, PACED_VERB_LINE, None).expect("schedule")
    }

    fn wake(&self) -> Option<u64> {
        self.vault.housekeeping_wake_at().expect("the wake time")
    }
}

#[test]
fn a_held_call_arms_the_line_at_its_window_and_wakes_the_host_that_runs_its_turns() {
    let fx = Fixture::open();
    fx.vault.install_paced_verb_turn_runner();
    let call = fx.hold(T0 + 100);
    assert_eq!(fx.line_due(), Some(T0 + 100), "the hold armed the line");
    assert_eq!(fx.wake(), Some(T0 + 100), "the line wakes its host then");
    assert!(fx.waits(call));
}

#[test]
fn a_process_that_runs_no_turns_steps_over_the_line_and_is_not_woken_for_it() {
    let fx = Fixture::open();
    let call = fx.hold(T0 + 7);
    assert_ne!(
        fx.wake(),
        Some(T0 + 7),
        "no turn runs here: the line wakes nothing"
    );
    fx.at(T0 + 10);
    fx.pass();
    assert!(fx.waits(call), "a pass with no turn runner ends no turn");
    assert_eq!(
        fx.line_due(),
        Some(T0 + 7),
        "the row stays due for the host"
    );
    assert_ne!(fx.wake(), Some(T0 + 7));
}

#[test]
fn a_pass_takes_the_due_turn_and_moves_the_line_to_its_next_window() {
    let fx = Fixture::open();
    fx.vault.install_paced_verb_turn_runner();
    let first = fx.hold(T0 + 100);
    let second = fx.hold(T0 + 500);
    assert_eq!(fx.line_due(), Some(T0 + 100));
    fx.at(T0 + 50);
    fx.pass();
    assert!(fx.waits(first), "no window opened yet");
    fx.at(T0 + 100);
    fx.pass();
    assert!(
        !fx.waits(first),
        "the turn ran, refused: this host installed no check"
    );
    assert!(fx.waits(second), "its window is not open");
    assert_eq!(
        fx.line_due(),
        Some(T0 + 500),
        "the line is due at its next window"
    );
}

#[test]
fn a_held_call_pulls_the_line_earlier_and_never_later() {
    let fx = Fixture::open();
    fx.vault.install_paced_verb_turn_runner();
    fx.hold(T0 + 1_000);
    assert_eq!(fx.line_due(), Some(T0 + 1_000));
    fx.hold(T0 + 200);
    assert_eq!(
        fx.line_due(),
        Some(T0 + 200),
        "a sooner window pulls the line"
    );
    fx.hold(T0 + 5_000);
    assert_eq!(fx.line_due(), Some(T0 + 200), "a later window leaves it");
}

#[test]
fn the_first_pass_arms_the_line_from_the_calls_the_vault_holds() {
    let fx = Fixture::open();
    fx.vault.install_paced_verb_turn_runner();
    let call = fx.hold(T0 + 300);
    assert!(
        oneiron::test_doors::schedule::disarm_as_engine(&fx.vault, PACED_VERB_LINE, None)
            .expect("disarm"),
        "the line was armed"
    );
    assert_eq!(
        fx.line_due(),
        None,
        "as a vault a build before the row held its calls in"
    );
    fx.pass();
    assert_eq!(
        fx.line_due(),
        Some(T0 + 300),
        "the first pass armed the line"
    );
    assert!(fx.waits(call));
}

#[test]
fn the_settler_door_runs_the_due_line_alone_and_waits_while_a_pass_holds_the_runner() {
    let fx = Fixture::open();
    fx.vault.install_paced_verb_turn_runner();
    let call = fx.hold(T0 + 100);
    fx.at(T0 + 50);
    fx.vault.run_due_paced_verb_line().expect("door");
    assert!(fx.waits(call), "not before its window");
    fx.at(T0 + 100);
    while_a_pass_holds_the_runner(&fx.vault, || {
        fx.vault.run_due_paced_verb_line().expect("door");
    });
    assert!(
        fx.waits(call),
        "the pass that holds the runner runs the row"
    );
    fx.vault.run_due_paced_verb_line().expect("door");
    assert!(!fx.waits(call), "the door took the turn");
    assert_eq!(fx.line_due(), None, "nothing waits: the row went");
}
