//! Row OWNER-CONFIRM-SHEET, the keystore's presence layer: one confirm opens
//! a 15-minute window that either clock or a screen lock ends, a refusal
//! opens nothing, a device with no prompt says so, acts that arrive
//! together share one prompt, a screen lock refuses the answer of a prompt
//! that was up when it came, and a clock reading from before a confirm never
//! ends the window that confirm opened.
//!
//! A device that must be asked for its screen lock (macOS): no act is
//! confirmed while its screen reads locked, a locked reading ends the
//! window, the watch ends the window when no act comes, and the watch stops
//! with its gate. Each LocalAuthentication error code keeps its own refusal.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use oneiron_keystore::{
    ManualPresenceClock, NoPromptPresence, PRESENCE_WINDOW_SECS, PresenceCapability, PresenceClock,
    PresenceConfirmation, PresenceError, PresenceGate, PresenceInstant, PresenceWindow,
    ScriptedPresence, UserPresence,
};

const WINDOW_MS: u64 = PRESENCE_WINDOW_SECS * 1000;
const WALL_START_MS: u64 = 1_000_000;
const MONOTONIC_START_MS: u64 = 5_000;
const REASON: &str = "confirm a change to your vault";

fn clock() -> Arc<ManualPresenceClock> {
    ManualPresenceClock::new(WALL_START_MS, MONOTONIC_START_MS)
}

/// A gate over a prompt that gives `answers` in order.
fn scripted_gate(
    answers: Vec<Result<(), PresenceError>>,
    clock: &Arc<ManualPresenceClock>,
) -> (PresenceGate, Arc<ScriptedPresence>) {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let gate = PresenceGate::new(presence.clone(), PresenceWindow::new(clock.clone()));
    (gate, presence)
}

#[test]
fn a_confirm_opens_a_window_and_a_second_act_inside_it_shows_no_prompt() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(())], &clock);
    assert_eq!(gate.capability(), PresenceCapability::DevicePrompt);
    assert!(
        !gate.window_is_open(),
        "no confirm yet: the window is closed"
    );

    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert_eq!(presence.reasons(), [REASON]);
    assert!(gate.window_is_open());

    clock.advance(WINDOW_MS - 1);
    assert_eq!(
        gate.confirm("another change"),
        Ok(PresenceConfirmation::WithinWindow),
        "one millisecond short of the window's end still needs no prompt"
    );
    assert_eq!(presence.prompts(), 1);
}

#[test]
fn the_window_ends_at_fifteen_minutes_on_either_clock() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(()), Ok(()), Ok(())], &clock);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    // Asleep: the wall clock moved on and the monotonic clock stood still.
    clock.set(WALL_START_MS + WINDOW_MS, MONOTONIC_START_MS);
    assert!(
        !gate.window_is_open(),
        "the wall clock alone ends the window"
    );
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    // Awake with the wall clock held back: the monotonic clock still counts.
    clock.set(WALL_START_MS + WINDOW_MS, MONOTONIC_START_MS + WINDOW_MS);
    assert!(
        !gate.window_is_open(),
        "the monotonic clock alone ends the window"
    );
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    clock.advance(WINDOW_MS - 1);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::WithinWindow));
    assert_eq!(presence.prompts(), 3);
}

#[test]
fn a_wall_clock_set_back_behind_the_confirm_ends_the_window_for_good() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(()), Ok(())], &clock);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    clock.set(WALL_START_MS - 1, MONOTONIC_START_MS + 1);
    assert!(
        !gate.window_is_open(),
        "a wall clock behind the confirm ends the window"
    );
    // The clock comes back inside the old window: the ended window stays ended.
    clock.set(WALL_START_MS + 1, MONOTONIC_START_MS + 2);
    assert!(!gate.window_is_open());
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert_eq!(presence.prompts(), 2);
}

#[test]
fn a_screen_lock_ends_the_window_at_once() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(()), Ok(())], &clock);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert!(gate.window_is_open());

    gate.end_window();
    assert!(!gate.window_is_open());
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert_eq!(presence.prompts(), 2);
}

#[test]
fn a_refused_prompt_opens_nothing_and_keeps_its_own_error() {
    let refusals = [
        PresenceError::Declined,
        PresenceError::NoAnswer,
        PresenceError::Platform("local authentication", -1004),
    ];
    let clock = clock();
    let mut answers: Vec<_> = refusals.into_iter().map(Err).collect();
    answers.push(Ok(()));
    let (gate, presence) = scripted_gate(answers, &clock);

    for refusal in refusals {
        assert_eq!(gate.confirm(REASON), Err(refusal));
        assert!(!gate.window_is_open(), "{refusal} opened the window");
    }
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert_eq!(presence.prompts(), 4, "every refused act asked again");
}

#[test]
fn a_device_with_no_prompt_says_so_and_never_opens_a_window() {
    const WHY: &str = "this keystore has no unlock prompt";
    let gate = PresenceGate::new(
        Arc::new(NoPromptPresence::new(WHY)),
        PresenceWindow::new(clock()),
    );
    assert_eq!(gate.capability(), PresenceCapability::NoPrompt(WHY));
    assert_eq!(gate.confirm(REASON), Err(PresenceError::NoPrompt(WHY)));
    assert!(!gate.window_is_open());

    // A Linux keystore, file or TPM, has no prompt: its platform gate must
    // refuse and never answer yes.
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        let platform = PresenceGate::platform();
        assert!(matches!(
            platform.capability(),
            PresenceCapability::NoPrompt(_)
        ));
        assert!(matches!(
            platform.confirm(REASON),
            Err(PresenceError::NoPrompt(_))
        ));
        assert!(!platform.window_is_open());
        assert!(matches!(
            oneiron_keystore::platform_user_presence().confirm(REASON),
            Err(PresenceError::NoPrompt(_))
        ));
    }
}

/// A prompt that stays up until the test answers it.
struct HeldPrompt {
    shown: Mutex<mpsc::Sender<()>>,
    answer: Mutex<mpsc::Receiver<()>>,
}

impl UserPresence for HeldPrompt {
    fn capability(&self) -> PresenceCapability {
        PresenceCapability::DevicePrompt
    }

    fn confirm(&self, _reason: &str) -> Result<(), PresenceError> {
        self.shown
            .lock()
            .expect("the shown channel")
            .send(())
            .expect("the test listens for each prompt");
        self.answer
            .lock()
            .expect("the answer channel")
            .recv()
            .map_err(|_| PresenceError::NoAnswer)
    }
}

#[test]
fn two_acts_at_once_show_one_prompt() {
    let (shown, prompts) = mpsc::channel();
    let (answer, answers) = mpsc::channel();
    let gate = Arc::new(PresenceGate::new(
        Arc::new(HeldPrompt {
            shown: Mutex::new(shown),
            answer: Mutex::new(answers),
        }),
        PresenceWindow::new(clock()),
    ));
    let start = Arc::new(Barrier::new(3));
    let spawn_act = || {
        let (gate, start) = (gate.clone(), start.clone());
        thread::spawn(move || {
            start.wait();
            gate.confirm(REASON)
        })
    };
    let acts = [spawn_act(), spawn_act()];
    start.wait();

    prompts.recv().expect("the first act's prompt shows");
    assert!(
        prompts.recv_timeout(Duration::from_millis(200)).is_err(),
        "the second act showed a prompt of its own while the first was up"
    );
    answer.send(()).expect("the prompt takes its answer");

    let mut outcomes = acts.map(|act| act.join().expect("the act ends"));
    outcomes.sort_by_key(|outcome| *outcome != Ok(PresenceConfirmation::Prompted));
    assert_eq!(
        outcomes,
        [
            Ok(PresenceConfirmation::Prompted),
            Ok(PresenceConfirmation::WithinWindow)
        ]
    );
    assert!(prompts.try_recv().is_err(), "one prompt served both acts");
}

#[test]
fn a_screen_lock_while_a_prompt_is_up_refuses_its_answer_and_opens_no_window() {
    let (shown, prompts) = mpsc::channel();
    let (answer, answers) = mpsc::channel();
    let gate = Arc::new(PresenceGate::new(
        Arc::new(HeldPrompt {
            shown: Mutex::new(shown),
            answer: Mutex::new(answers),
        }),
        PresenceWindow::new(clock()),
    ));
    let spawn_act = || {
        let gate = gate.clone();
        thread::spawn(move || gate.confirm(REASON))
    };

    let first = spawn_act();
    prompts.recv().expect("the first act's prompt shows");
    // A second act arrives while that prompt is up and waits behind it.
    let second = spawn_act();

    // The screen locks with the prompt still up, and the answer lands after.
    gate.end_window();
    answer.send(()).expect("the first prompt takes its answer");
    assert_eq!(
        first.join().expect("the first act ends"),
        Err(PresenceError::ScreenLocked),
        "an answer from before the lock confirmed the act"
    );
    assert!(
        !gate.window_is_open(),
        "an answer from before the lock opened the window"
    );

    // The act that waited does not ride on the refused answer: it asks for
    // itself, after the lock, and its confirm opens the window.
    prompts
        .recv()
        .expect("the second act shows a prompt of its own");
    answer.send(()).expect("the second prompt takes its answer");
    assert_eq!(
        second.join().expect("the second act ends"),
        Ok(PresenceConfirmation::Prompted)
    );
    assert!(gate.window_is_open());
    assert_eq!(
        gate.confirm(REASON),
        Ok(PresenceConfirmation::WithinWindow),
        "a confirm made after the lock serves the next act"
    );
    assert!(prompts.try_recv().is_err(), "two prompts in all");
}

/// How long [`HeldReadingClock`] keeps its first reading when nobody lets
/// it go.
const HELD_READING_MS: u64 = 500;

/// A clock whose first reading is taken at once and handed back late: when
/// the test lets it go, or after [`HELD_READING_MS`]. Every later reading
/// comes back at once.
struct HeldReadingClock {
    clock: Arc<ManualPresenceClock>,
    first_reading: Mutex<Option<HeldReading>>,
}

/// How the test learns the first reading was taken, and lets it go.
struct HeldReading {
    taken: mpsc::Sender<()>,
    let_go: mpsc::Receiver<()>,
}

impl PresenceClock for HeldReadingClock {
    fn now(&self) -> PresenceInstant {
        let reading = self.clock.now();
        let held = self
            .first_reading
            .lock()
            .expect("the first reading's channels")
            .take();
        if let Some(held) = held {
            held.taken
                .send(())
                .expect("the test waits for the first reading");
            // A timeout is the fixed window's path: the reader holds the
            // window's lock, so the confirm cannot run until it lets go.
            let _ = held
                .let_go
                .recv_timeout(Duration::from_millis(HELD_READING_MS));
        }
        reading
    }
}

#[test]
fn a_clock_reading_from_before_a_confirm_does_not_end_the_window_it_opened() {
    let manual = clock();
    let (taken, readings) = mpsc::channel();
    let (let_go, held) = mpsc::channel();
    let presence = Arc::new(ScriptedPresence::new(vec![Ok(())]));
    let gate = Arc::new(PresenceGate::new(
        presence.clone(),
        PresenceWindow::new(Arc::new(HeldReadingClock {
            clock: manual.clone(),
            first_reading: Mutex::new(Some(HeldReading {
                taken,
                let_go: held,
            })),
        })),
    ));

    // One act asks whether the window is open: its clock reading is taken
    // and not handed back yet.
    let reader = {
        let gate = gate.clone();
        thread::spawn(move || gate.window_is_open())
    };
    readings.recv().expect("the reader takes its clock reading");

    // Time passes, and another act's confirm opens the window after that
    // reading. On a window that reads the clock under its lock the confirm
    // waits here until the reader is done.
    manual.advance(1);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    // The reader may be done already: then nobody listens, which is fine.
    let _ = let_go.send(());
    reader.join().expect("the reader ends");

    assert!(
        gate.window_is_open(),
        "a clock reading from before the confirm ended the window it opened"
    );
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::WithinWindow));
    assert_eq!(presence.prompts(), 1, "the second act asked again");
}

#[test]
fn a_locked_screen_refuses_an_act_inside_an_open_window_and_ends_the_window() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(()), Ok(())], &clock);
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    presence.set_screen_locked(true);
    assert_eq!(
        gate.confirm(REASON),
        Err(PresenceError::ScreenLocked),
        "an act on a locked device was confirmed inside the window"
    );
    assert_eq!(presence.prompts(), 1, "a locked device showed a prompt");

    // The locked reading ended the window: after the unlock the next act
    // asks for itself.
    presence.set_screen_locked(false);
    assert!(!gate.window_is_open(), "the window outlasted the lock");
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert_eq!(presence.prompts(), 2);
}

/// A device whose screen locks while its prompt is up: the answer comes
/// back as a yes, with the screen still locked.
struct LocksWhilePrompting {
    locked: AtomicBool,
}

impl UserPresence for LocksWhilePrompting {
    fn capability(&self) -> PresenceCapability {
        PresenceCapability::DevicePrompt
    }

    fn confirm(&self, _reason: &str) -> Result<(), PresenceError> {
        self.locked.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn screen_is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
}

#[test]
fn an_answer_that_comes_with_the_screen_locked_is_refused_and_opens_no_window() {
    let presence = Arc::new(LocksWhilePrompting {
        locked: AtomicBool::new(false),
    });
    let gate = PresenceGate::new(presence.clone(), PresenceWindow::new(clock()));

    assert_eq!(
        gate.confirm(REASON),
        Err(PresenceError::ScreenLocked),
        "an answer taken on a locked screen confirmed the act"
    );
    presence.locked.store(false, Ordering::SeqCst);
    assert!(
        !gate.window_is_open(),
        "an answer taken on a locked screen opened the window"
    );
}

/// How often the tests' watch reads the screen lock.
const WATCH_EVERY: Duration = Duration::from_millis(5);
/// How long a test waits for the watch before it fails.
const WATCH_WAIT: Duration = Duration::from_secs(20);

/// Waits until the watch has read the screen lock `more` times more.
fn wait_for_screen_lock_reads(presence: &ScriptedPresence, more: usize) {
    let target = presence.screen_lock_reads() + more;
    let deadline = Instant::now() + WATCH_WAIT;
    while presence.screen_lock_reads() < target {
        assert!(
            Instant::now() < deadline,
            "the screen-lock watch stopped reading"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn the_screen_lock_watch_ends_the_window_when_no_act_comes() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(()), Ok(())], &clock);
    gate.watch_screen_lock(WATCH_EVERY)
        .expect("the watch starts");
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));

    // The screen locks and unlocks with no act in between. Each change waits
    // for two more reads: the first of them may have begun before it, and
    // the second begins only when the first has ended the window or left it.
    presence.set_screen_locked(true);
    wait_for_screen_lock_reads(&presence, 2);
    presence.set_screen_locked(false);
    wait_for_screen_lock_reads(&presence, 2);

    assert_eq!(
        gate.confirm(REASON),
        Ok(PresenceConfirmation::Prompted),
        "the window outlasted a lock that no act met"
    );
    assert_eq!(presence.prompts(), 2);
}

#[test]
fn the_screen_lock_watch_stops_when_its_gate_is_dropped() {
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![], &clock);
    gate.watch_screen_lock(WATCH_EVERY)
        .expect("the watch starts");
    wait_for_screen_lock_reads(&presence, 1);

    // The gate and the watch each hold the prompt; the test holds it too.
    drop(gate);
    let deadline = Instant::now() + WATCH_WAIT;
    while Arc::strong_count(&presence) > 1 {
        assert!(Instant::now() < deadline, "the watch outlived its gate");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn each_local_authentication_code_keeps_its_own_refusal() {
    let refusal = PresenceError::from_local_authentication_code;
    // authenticationFailed, userCancel, userFallback.
    for code in [-1, -2, -3] {
        assert_eq!(refusal(code), PresenceError::Declined, "code {code}");
    }
    // systemCancel, appCancel.
    for code in [-4, -9] {
        assert_eq!(refusal(code), PresenceError::NoAnswer, "code {code}");
    }
    // passcodeNotSet, notInteractive: the confirm belongs on another device.
    for code in [-5, -1004] {
        assert!(
            matches!(refusal(code), PresenceError::NoPrompt(_)),
            "code {code}: {:?}",
            refusal(code)
        );
    }
    assert_ne!(refusal(-5), refusal(-1004), "each says why it cannot ask");
    // Every other code is a fault by its number, the biometry ones too:
    // never a confirm, and never read as the user's own no.
    for code in [
        0,
        1,
        -6,
        -7,
        -8,
        -10,
        -11,
        -12,
        -13,
        -14,
        i64::MIN,
        i64::MAX,
    ] {
        assert_eq!(
            refusal(code),
            PresenceError::Platform("local authentication", code),
            "code {code}"
        );
    }
}
