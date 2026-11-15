//! Row OWNER-CONFIRM-SHEET, the keystore's presence layer: one confirm opens
//! a 15-minute window that either clock or a screen lock ends, a refusal
//! opens nothing, a device with no prompt says so, and acts that arrive
//! together share one prompt.

use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use oneiron_keystore::{
    ManualPresenceClock, NoPromptPresence, PRESENCE_WINDOW_SECS, PresenceCapability,
    PresenceConfirmation, PresenceError, PresenceGate, PresenceWindow, ScriptedPresence,
    UserPresence,
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
