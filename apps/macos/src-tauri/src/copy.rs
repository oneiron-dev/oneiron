//! Every user-facing string the recorder shows, in one place.
//!
//! The disclosure copy is the product's promise to the people in the room, so
//! it is not scattered across the webview, the menu bar, and the Rust core
//! where three wordings could drift apart. One file, one wording.

/// Menu-bar and window title.
pub const APP_NAME: &str = "Oneiron Recorder";

/// Heading of the disclosure panel.
pub const DISCLOSURE_TITLE: &str = "Before recording";

/// What the operator is affirming. It states what will be captured, where it
/// goes, and who is responsible for telling the room — plainly, because a
/// disclosure nobody reads is not a disclosure.
pub const DISCLOSURE_BODY: &str = "This Mac will record the microphone and the audio other apps are playing, in one-minute segments, into your own local vault. Nothing is recorded until you confirm below, and recording stops the moment you say stop.";

/// The affirmation itself.
pub const DISCLOSURE_AFFIRM: &str =
    "Everyone who can be heard has been told that this session is being recorded.";

/// Label of the button that performs the affirm.
pub const DISCLOSURE_AFFIRM_ACTION: &str = "I have told everyone present";

/// Shown while the gate is closed.
pub const DISCLOSURE_REQUIRED_HINT: &str = "Confirm the disclosure to unlock recording.";

/// Shown once the gate is open but nothing is recording yet.
pub const DISCLOSURE_AFFIRMED_HINT: &str = "Disclosure confirmed. Recording can start.";

/// Menu-bar title while idle.
pub const MENU_BAR_IDLE: &str = "Not recording";

/// Menu-bar title while recording. The menu bar never claims a state the
/// capture is not actually in.
pub const MENU_BAR_RECORDING: &str = "Recording";

/// Shown while a capture is running.
pub const RECORDING_HINT: &str =
    "Recording. Each segment lands in your vault as it closes; stop takes effect immediately.";

/// Menu item that starts a recording.
pub const MENU_ITEM_START: &str = "Start recording";

/// Menu item that stops one.
pub const MENU_ITEM_STOP: &str = "Stop recording";

/// Menu item that raises the window.
pub const MENU_ITEM_SHOW: &str = "Open Oneiron Recorder";

/// Menu item that quits.
pub const MENU_ITEM_QUIT: &str = "Quit";

/// Empty-state line under the segment list.
pub const SEGMENTS_EMPTY: &str = "No segments committed in this session yet.";

/// Refusal shown when a start is attempted without an affirm. It is a product
/// message about the gate, not an engine error.
pub const START_REFUSED_WITHOUT_DISCLOSURE: &str =
    "Recording is closed until the disclosure is confirmed.";
