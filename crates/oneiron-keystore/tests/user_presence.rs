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
//!
//! Windows: each Windows Hello answer keeps its own meaning, each
//! availability says whether the device can ask, and only an active session
//! that says it is unlocked reads as unlocked.
//!
//! Row OCS-OWNER-PIN, a device that asks for its device PIN: it opens no
//! window without the PIN, the right PIN opens the window, a wrong one opens
//! nothing and ends a window that was open, five wrong PINs in a row start
//! a wait that refuses even the right one, the wait counts on either clock,
//! each end of the window tells the backend once, and a screen lock while a
//! PIN is checked opens nothing.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use oneiron_keystore::{
    DEVICE_PIN_WAIT_SECS, DEVICE_PIN_WRONG_TRIES, ManualPresenceClock, NoPromptPresence,
    PRESENCE_WINDOW_SECS, PresenceCapability, PresenceClock, PresenceConfirmation, PresenceError,
    PresenceGate, PresenceInstant, PresenceWindow, ScriptedPresence, UserPresence,
    WindowsScreenSession,
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

#[test]
fn each_windows_hello_answer_keeps_its_own_meaning() {
    let answer = PresenceError::user_consent_verification;
    // Verified.
    assert_eq!(answer(0), Ok(()));
    // RetriesExhausted, Canceled.
    for result in [5, 6] {
        assert_eq!(
            answer(result),
            Err(PresenceError::Declined),
            "result {result}"
        );
    }
    // DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy: the confirm
    // belongs on another device.
    for result in [1, 2, 3] {
        assert!(
            matches!(answer(result), Err(PresenceError::NoPrompt(_))),
            "result {result}: {:?}",
            answer(result)
        );
    }
    assert_ne!(answer(1), answer(2), "each says why it cannot ask");
    assert_ne!(answer(2), answer(3), "each says why it cannot ask");
    // DeviceBusy, and a value Windows may add later: a fault by its number,
    // never a confirm, and never read as the user's own no.
    for result in [4, 7, -1, i32::MIN, i32::MAX] {
        assert_eq!(
            answer(result),
            Err(PresenceError::Platform(
                "user consent verification result",
                i64::from(result)
            )),
            "result {result}"
        );
    }
}

#[test]
fn each_windows_hello_availability_says_whether_the_device_can_ask() {
    let capability = PresenceCapability::from_user_consent_availability;
    // Available, DeviceBusy: the device has a prompt.
    for availability in [0, 4] {
        assert_eq!(
            capability(availability),
            PresenceCapability::DevicePrompt,
            "availability {availability}"
        );
    }
    // DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy, and a value
    // this build does not know: no prompt, never a silent yes.
    for availability in [1, 2, 3, 5, -1, i32::MAX] {
        assert!(
            matches!(capability(availability), PresenceCapability::NoPrompt(_)),
            "availability {availability}: {:?}",
            capability(availability)
        );
    }
    // The verifier's answer and its availability give one reason for one
    // cause.
    for cause in [1, 2, 3] {
        let Err(PresenceError::NoPrompt(asked)) = PresenceError::user_consent_verification(cause)
        else {
            panic!("result {cause} is not a device that cannot ask");
        };
        assert_eq!(capability(cause), PresenceCapability::NoPrompt(asked));
    }
}

#[test]
fn only_an_active_windows_session_that_says_unlocked_reads_as_unlocked() {
    const ACTIVE: i32 = 0;
    const LOCK: i32 = 0;
    const UNLOCK: i32 = 1;
    // WTS_SESSIONSTATE_UNKNOWN is every bit set.
    const UNKNOWN: i32 = -1;
    let session = WindowsScreenSession::from_session_info;

    assert_eq!(session(1, ACTIVE, UNLOCK), WindowsScreenSession::Unlocked);
    assert_eq!(session(1, ACTIVE, LOCK), WindowsScreenSession::Locked);
    // A lock state this build does not know is never read as unlocked.
    for flags in [UNKNOWN, 2, i32::MAX] {
        assert_eq!(
            session(1, ACTIVE, flags),
            WindowsScreenSession::Unreadable,
            "flags {flags}"
        );
    }
    // Connected, Disconnected, Idle, Down: no user at a screen, whatever
    // the lock state says.
    for connect_state in [1, 4, 5, 8, -1] {
        for flags in [LOCK, UNLOCK, UNKNOWN] {
            assert_eq!(
                session(3, connect_state, flags),
                WindowsScreenSession::OffScreen,
                "connect state {connect_state}, flags {flags}"
            );
        }
    }
    // Session 0 is the services session, whatever else it says.
    for connect_state in [ACTIVE, 4] {
        for flags in [LOCK, UNLOCK, UNKNOWN] {
            assert_eq!(
                session(0, connect_state, flags),
                WindowsScreenSession::Services,
                "connect state {connect_state}, flags {flags}"
            );
        }
    }
}

const PIN: &[u8] = b"quiet harbor seven lanterns";
const WRONG_PIN: &[u8] = b"quiet harbor seven lantern";
const WAIT_MS: u64 = DEVICE_PIN_WAIT_SECS * 1000;

/// A gate over a device that asks for its PIN: `pin` when one is set.
fn device_pin_gate(
    pin: Option<&[u8]>,
    clock: &Arc<ManualPresenceClock>,
) -> (PresenceGate, Arc<ScriptedPresence>) {
    let presence = Arc::new(ScriptedPresence::with_device_pin(pin));
    let gate = PresenceGate::new(presence.clone(), PresenceWindow::new(clock.clone()));
    (gate, presence)
}

/// Types `wrong` wrong PINs, each of which must answer `WrongPin`.
fn type_wrong_pins(gate: &PresenceGate, wrong: u32) {
    for entry in 1..=wrong {
        assert_eq!(
            gate.confirm_with_secret(WRONG_PIN),
            Err(PresenceError::WrongPin),
            "wrong PIN number {entry}"
        );
    }
}

#[test]
fn a_device_that_asks_for_its_pin_opens_no_window_without_it() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);
    assert_eq!(
        gate.capability(),
        PresenceCapability::DevicePin { set: true }
    );
    assert_eq!(gate.confirm(REASON), Err(PresenceError::PinRequired));
    assert!(!gate.window_is_open(), "an act with no PIN opened a window");
    assert_eq!(presence.prompts(), 0, "a PIN device showed a prompt");
    assert_eq!(presence.secrets_checked(), 0);

    // Before the owner has set a PIN the device cannot confirm at all.
    let (unset, unset_presence) = device_pin_gate(None, &clock);
    assert_eq!(
        unset.capability(),
        PresenceCapability::DevicePin { set: false }
    );
    assert!(matches!(
        unset.confirm(REASON),
        Err(PresenceError::NoPrompt(_))
    ));
    assert!(matches!(
        unset.confirm_with_secret(PIN),
        Err(PresenceError::NoPrompt(_))
    ));
    assert_eq!(
        unset_presence.secrets_checked(),
        0,
        "a device with no PIN set was handed a secret to check"
    );
    assert!(!unset.window_is_open());
}

#[test]
fn a_device_that_takes_no_typed_secret_refuses_one_and_keeps_its_window() {
    const WHY: &str = "this keystore has no unlock prompt";
    let no_prompt = PresenceGate::new(
        Arc::new(NoPromptPresence::new(WHY)),
        PresenceWindow::new(clock()),
    );
    assert_eq!(
        no_prompt.confirm_with_secret(PIN),
        Err(PresenceError::NoPrompt(WHY))
    );
    assert!(!no_prompt.window_is_open());

    // A device with its own prompt: a typed secret confirms nothing there,
    // and it does not end the window the prompt opened.
    let clock = clock();
    let (gate, presence) = scripted_gate(vec![Ok(())], &clock);
    assert!(matches!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::NoPrompt(_))
    ));
    assert!(!gate.window_is_open(), "a typed secret opened a window");
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::Prompted));
    assert!(matches!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::NoPrompt(_))
    ));
    assert!(
        gate.window_is_open(),
        "a typed secret ended the window of a device that takes none"
    );
    assert_eq!(presence.secrets_checked(), 0);
    assert_eq!(presence.window_ends(), 0);
}

#[test]
fn the_right_pin_opens_the_window_and_an_act_inside_it_asks_for_nothing() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);

    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert!(gate.window_is_open());
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::WithinWindow));

    clock.advance(WINDOW_MS - 1);
    assert_eq!(
        gate.confirm("another change"),
        Ok(PresenceConfirmation::WithinWindow),
        "one millisecond short of the window's end still asks for nothing"
    );
    assert_eq!(presence.window_ends(), 0, "the backend was told too early");

    clock.advance(1);
    assert_eq!(
        gate.confirm(REASON),
        Err(PresenceError::PinRequired),
        "an act after the window's end rode on the old PIN"
    );
    assert_eq!(presence.secrets_checked(), 1);
    assert_eq!(presence.prompts(), 0);
}

#[test]
fn a_wrong_pin_opens_nothing_and_ends_a_window_that_was_open() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);

    assert_eq!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::WrongPin)
    );
    assert!(!gate.window_is_open(), "a wrong PIN opened the window");
    assert_eq!(gate.confirm(REASON), Err(PresenceError::PinRequired));
    assert_eq!(presence.window_ends(), 0, "no window was open to end");

    // Each typed PIN starts over: a wrong one never rides on the window an
    // earlier right one opened.
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert!(gate.window_is_open());
    assert_eq!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::WrongPin)
    );
    assert!(
        !gate.window_is_open(),
        "a wrong PIN left the earlier window open"
    );
    assert_eq!(presence.window_ends(), 1);
    assert_eq!(gate.confirm(REASON), Err(PresenceError::PinRequired));

    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert_eq!(gate.confirm(REASON), Ok(PresenceConfirmation::WithinWindow));
}

#[test]
fn five_wrong_pins_in_a_row_start_a_wait_that_refuses_even_the_right_pin() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);

    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert_eq!(gate.typed_secret_wait_secs(), None);
    assert_eq!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS
        }),
        "the fifth wrong PIN in a row starts the wait"
    );
    assert_eq!(gate.typed_secret_wait_secs(), Some(DEVICE_PIN_WAIT_SECS));
    let checked = presence.secrets_checked();
    assert_eq!(checked, DEVICE_PIN_WRONG_TRIES as usize);

    // Inside the wait the device takes no PIN: the backend never sees the
    // right one.
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS
        })
    );
    clock.advance(1000);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS - 1
        })
    );
    clock.advance(WAIT_MS - 1001);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::TooManyTries { wait_secs: 1 }),
        "one millisecond short of the wait's end still takes no PIN"
    );
    assert_eq!(
        presence.secrets_checked(),
        checked,
        "a PIN typed inside the wait reached the backend"
    );
    assert!(!gate.window_is_open());

    clock.advance(1);
    assert_eq!(gate.typed_secret_wait_secs(), None);
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert!(gate.window_is_open());

    // The wait started the count over: four more wrong PINs start no wait.
    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert_eq!(gate.typed_secret_wait_secs(), None);
}

#[test]
fn a_right_pin_starts_the_count_of_wrong_pins_over() {
    let clock = clock();
    let (gate, _presence) = device_pin_gate(Some(PIN), &clock);

    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert_eq!(
        gate.typed_secret_wait_secs(),
        None,
        "eight wrong PINs with a right one between them started a wait"
    );
    assert!(matches!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::TooManyTries { .. })
    ));
}

#[test]
fn the_wait_counts_on_either_clock_and_a_wall_clock_set_back_changes_nothing() {
    let clock = clock();
    let (gate, _presence) = device_pin_gate(Some(PIN), &clock);
    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert!(matches!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::TooManyTries { .. })
    ));

    // The wall clock is set back behind the wait's start: it counts
    // nothing, and the monotonic clock still counts.
    clock.set(WALL_START_MS - 1, MONOTONIC_START_MS + WAIT_MS - 1);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::TooManyTries { wait_secs: 1 }),
        "a wall clock set back shortened the wait"
    );
    clock.set(WALL_START_MS - 1, MONOTONIC_START_MS + WAIT_MS);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Ok(()),
        "a wall clock set back lengthened the wait"
    );

    // Asleep: the wall clock moved on and the monotonic clock stood still.
    let asleep = self::clock();
    let (gate, _presence) = device_pin_gate(Some(PIN), &asleep);
    type_wrong_pins(&gate, DEVICE_PIN_WRONG_TRIES - 1);
    assert!(matches!(
        gate.confirm_with_secret(WRONG_PIN),
        Err(PresenceError::TooManyTries { .. })
    ));
    asleep.set(WALL_START_MS + WAIT_MS - 1, MONOTONIC_START_MS);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::TooManyTries { wait_secs: 1 })
    );
    asleep.set(WALL_START_MS + WAIT_MS, MONOTONIC_START_MS);
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Ok(()),
        "the time the device slept did not count toward the wait"
    );
}

#[test]
fn each_end_of_the_window_tells_the_backend_once() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);

    // The host hands over a lock signal.
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert_eq!(presence.window_ends(), 0);
    gate.end_window();
    assert_eq!(presence.window_ends(), 1);
    gate.end_window();
    assert_eq!(presence.window_ends(), 1, "a closed window ended again");

    // The screen reads locked when an act comes.
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    presence.set_screen_locked(true);
    assert!(!gate.window_is_open());
    assert_eq!(presence.window_ends(), 2);
    assert_eq!(gate.confirm(REASON), Err(PresenceError::ScreenLocked));
    let checked = presence.secrets_checked();
    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::ScreenLocked),
        "a PIN was taken on a locked device"
    );
    assert_eq!(presence.secrets_checked(), checked);
    assert_eq!(presence.window_ends(), 2);
    presence.set_screen_locked(false);

    // The window's time is over.
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    clock.advance(WINDOW_MS);
    assert!(!gate.window_is_open());
    assert_eq!(presence.window_ends(), 3);
    assert!(!gate.window_is_open());
    assert_eq!(presence.window_ends(), 3);

    // A second right PIN ends the window the first one opened, then opens
    // its own.
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert_eq!(presence.window_ends(), 4);
    assert!(gate.window_is_open());

    // The gate goes away with its window open.
    drop(gate);
    assert_eq!(
        presence.window_ends(),
        5,
        "a dropped gate left its backend holding the window"
    );
}

/// Waits until the device was told `ends` times that its window ended.
fn wait_for_window_ends(presence: &ScriptedPresence, ends: usize) {
    let deadline = Instant::now() + WATCH_WAIT;
    while presence.window_ends() < ends {
        assert!(
            Instant::now() < deadline,
            "the watch never told the backend that its window ended"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn the_watch_ends_a_window_whose_time_is_over_when_no_act_comes() {
    let clock = clock();
    let (gate, presence) = device_pin_gate(Some(PIN), &clock);
    gate.watch_screen_lock(WATCH_EVERY)
        .expect("the watch starts");
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));

    // The watch reads an open window and leaves it open.
    wait_for_screen_lock_reads(&presence, 2);
    assert_eq!(presence.window_ends(), 0);

    // The window's time passes with no act to read it.
    clock.advance(WINDOW_MS);
    wait_for_window_ends(&presence, 1);
    wait_for_screen_lock_reads(&presence, 2);
    assert_eq!(
        presence.window_ends(),
        1,
        "the watch told the backend of one end more than once"
    );
    assert_eq!(gate.confirm(REASON), Err(PresenceError::PinRequired));
}

#[test]
fn a_watched_gate_ends_its_window_on_a_screen_lock_that_no_act_meets() {
    let presence = Arc::new(ScriptedPresence::with_device_pin(Some(PIN)));
    let gate = PresenceGate::watched(presence.clone());
    assert_eq!(
        gate.capability(),
        PresenceCapability::DevicePin { set: true }
    );
    assert_eq!(gate.confirm_with_secret(PIN), Ok(()));
    assert!(gate.window_is_open());

    presence.set_screen_locked(true);
    wait_for_window_ends(&presence, 1);
    presence.set_screen_locked(false);
    assert_eq!(gate.confirm(REASON), Err(PresenceError::PinRequired));
}

/// A device whose PIN check stays open until the test lets it end.
struct HeldPinCheck {
    checking: Mutex<mpsc::Sender<()>>,
    let_go: Mutex<mpsc::Receiver<()>>,
    window_ends: AtomicUsize,
}

impl HeldPinCheck {
    /// The device, how the test hears that a check began, and how it lets
    /// the check end.
    fn with_channels() -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (checking, checks) = mpsc::channel();
        let (let_go, held) = mpsc::channel();
        let device = Arc::new(Self {
            checking: Mutex::new(checking),
            let_go: Mutex::new(held),
            window_ends: AtomicUsize::new(0),
        });
        (device, checks, let_go)
    }
}

impl UserPresence for HeldPinCheck {
    fn capability(&self) -> PresenceCapability {
        PresenceCapability::DevicePin { set: true }
    }

    fn confirm(&self, _reason: &str) -> Result<(), PresenceError> {
        Err(PresenceError::PinRequired)
    }

    fn confirm_with_secret(&self, secret: &[u8]) -> Result<(), PresenceError> {
        self.checking
            .lock()
            .expect("the checking channel")
            .send(())
            .expect("the test listens for each check");
        self.let_go
            .lock()
            .expect("the let-go channel")
            .recv()
            .map_err(|_| PresenceError::NoAnswer)?;
        if secret == PIN {
            Ok(())
        } else {
            Err(PresenceError::WrongPin)
        }
    }

    fn window_ended(&self) {
        self.window_ends.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_screen_lock_while_a_pin_is_checked_opens_no_window_and_tells_the_backend() {
    let (device, checks, let_go) = HeldPinCheck::with_channels();
    let gate = Arc::new(PresenceGate::new(
        device.clone(),
        PresenceWindow::new(clock()),
    ));
    let typing = {
        let gate = gate.clone();
        thread::spawn(move || gate.confirm_with_secret(PIN))
    };
    checks.recv().expect("the PIN check begins");

    // The screen locks with the check still open, and the check ends after.
    gate.end_window();
    assert_eq!(
        device.window_ends.load(Ordering::SeqCst),
        0,
        "no window was open when the lock came"
    );
    let_go.send(()).expect("the check takes its end");
    assert_eq!(
        typing.join().expect("the typing ends"),
        Err(PresenceError::ScreenLocked),
        "a PIN checked across a lock confirmed"
    );
    assert!(
        !gate.window_is_open(),
        "a PIN checked across a lock opened the window"
    );
    assert_eq!(
        device.window_ends.load(Ordering::SeqCst),
        1,
        "the backend took the PIN and was not told that no window opened"
    );
}

#[test]
fn an_act_that_arrives_while_a_pin_is_checked_rides_on_it() {
    let (device, checks, let_go) = HeldPinCheck::with_channels();
    let gate = Arc::new(PresenceGate::new(device, PresenceWindow::new(clock())));
    let typing = {
        let gate = gate.clone();
        thread::spawn(move || gate.confirm_with_secret(PIN))
    };
    checks.recv().expect("the PIN check begins");

    // The act finds the window closed and waits behind the check.
    let act = thread::spawn(move || gate.confirm(REASON));
    let_go.send(()).expect("the check takes its end");
    assert_eq!(typing.join().expect("the typing ends"), Ok(()));
    assert_eq!(
        act.join().expect("the act ends"),
        Ok(PresenceConfirmation::WithinWindow),
        "an act behind a right PIN asked for the PIN again"
    );
}

/// A device whose screen locks while its PIN check runs: the check comes
/// back as a yes, with the screen still locked.
struct LocksWhileChecking {
    locked: AtomicBool,
    window_ends: AtomicUsize,
}

impl UserPresence for LocksWhileChecking {
    fn capability(&self) -> PresenceCapability {
        PresenceCapability::DevicePin { set: true }
    }

    fn confirm(&self, _reason: &str) -> Result<(), PresenceError> {
        Err(PresenceError::PinRequired)
    }

    fn confirm_with_secret(&self, _secret: &[u8]) -> Result<(), PresenceError> {
        self.locked.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn window_ended(&self) {
        self.window_ends.fetch_add(1, Ordering::SeqCst);
    }

    fn screen_is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
}

#[test]
fn a_pin_check_that_ends_with_the_screen_locked_is_refused_and_opens_no_window() {
    let device = Arc::new(LocksWhileChecking {
        locked: AtomicBool::new(false),
        window_ends: AtomicUsize::new(0),
    });
    let gate = PresenceGate::new(device.clone(), PresenceWindow::new(clock()));

    assert_eq!(
        gate.confirm_with_secret(PIN),
        Err(PresenceError::ScreenLocked),
        "a PIN check that ended on a locked screen confirmed"
    );
    assert_eq!(device.window_ends.load(Ordering::SeqCst), 1);
    device.locked.store(false, Ordering::SeqCst);
    assert!(
        !gate.window_is_open(),
        "a PIN check that ended on a locked screen opened the window"
    );
}
