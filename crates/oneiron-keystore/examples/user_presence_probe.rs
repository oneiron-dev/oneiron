//! Probe of the presence layer on a real device (row OWNER-CONFIRM-SHEET).
//! It reads and changes no key slot.
//!
//! - With no argument it prints what this device can do and ends. Nobody
//!   needs to be at the device.
//! - With `--prompt` it shows the device's unlock prompt and prints the
//!   answer, asks again at once (which must show no prompt), then has the
//!   person lock and unlock the screen and asks once more (which must show
//!   the prompt again: the lock ended the window). The prompt is the macOS
//!   unlock sheet, or the Windows Hello dialog.
//!
//! `cargo run -p oneiron-keystore --example user_presence_probe -- --prompt`
//!
//! It ends with exit code 0 when every step went as it must, else 1.

use std::io::{self, BufRead};
use std::process::ExitCode;

use oneiron_keystore::{
    PRESENCE_PROMPT_SECS, PRESENCE_WINDOW_SECS, PresenceCapability, PresenceConfirmation,
    PresenceError, PresenceGate, SCREEN_LOCK_POLL_MS, platform_user_presence,
};

const REASON: &str = "confirm it's you, for the presence probe";

fn main() -> ExitCode {
    let gate = PresenceGate::platform();
    print_device(&gate);
    if !std::env::args().any(|argument| argument == "--prompt") {
        return ExitCode::SUCCESS;
    }
    if prompt_steps(&gate) {
        println!("PASS: the prompt, the window and the screen-lock watch went as they must");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_device(gate: &PresenceGate) {
    println!(
        "platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    match gate.capability() {
        PresenceCapability::DevicePrompt => println!("capability: this device shows a prompt"),
        PresenceCapability::DevicePin { set } => {
            println!("capability: this device asks for its device PIN (one is set: {set})");
        }
        PresenceCapability::NoPrompt(reason) => println!("capability: no prompt ({reason})"),
    }
    println!(
        "screen reads locked: {}",
        platform_user_presence().screen_is_locked()
    );
    println!("window open before any confirm: {}", gate.window_is_open());
    println!(
        "one confirm lasts {PRESENCE_WINDOW_SECS} s; a prompt waits {PRESENCE_PROMPT_SECS} s; \
         the screen lock is read every {SCREEN_LOCK_POLL_MS} ms"
    );
}

/// The steps a person runs. `true` when each one went as it must.
fn prompt_steps(gate: &PresenceGate) -> bool {
    println!("step 1: answer the prompt that shows now");
    if !step_is(gate.confirm(REASON), PresenceConfirmation::Prompted) {
        return false;
    }
    println!("step 2: a second act at once must show no prompt");
    if !step_is(gate.confirm(REASON), PresenceConfirmation::WithinWindow) {
        return false;
    }
    println!(
        "step 3: lock the screen, wait five seconds, unlock it, then press Return here. \
         The prompt must show again."
    );
    if let Err(error) = io::stdin().lock().read_line(&mut String::new()) {
        println!("FAIL: standard input could not be read: {error}");
        return false;
    }
    step_is(gate.confirm(REASON), PresenceConfirmation::Prompted)
}

fn step_is(
    answer: Result<PresenceConfirmation, PresenceError>,
    expected: PresenceConfirmation,
) -> bool {
    match answer {
        Ok(confirmation) if confirmation == expected => {
            println!("  ok: {confirmation:?}");
            true
        }
        Ok(confirmation) => {
            println!("FAIL: {confirmation:?}, where {expected:?} was due");
            false
        }
        Err(error) => {
            println!("FAIL: {error}");
            false
        }
    }
}
