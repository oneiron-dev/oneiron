//! A menu-bar voice recorder that is a vault **device node**, not a client of
//! one: the engine is embedded in-process, segments land locally, and the
//! ordinary device-sync path carries them to whichever node the vault elected
//! as home. This Mac never registers home-node candidacy, so the election can
//! never land on it and a laptop that walks out of the building takes no
//! home node with it.
//!
//! Three product laws hold the shape together:
//!
//! 1. **Nothing records before the disclosure affirm.** The gate is structural
//!    ([`disclosure`]), not a checked flag.
//! 2. **Both surfaces tell the same truth.** Menu bar and window render one
//!    [`session::SessionView`]; neither can claim a state the capture is not in.
//! 3. **A segment states what it actually got.** Route, channels, and
//!    echo-cancellation mode are derived from the capture, and the engine's
//!    claim family — not this app — decides whether the statement is legible.

#[cfg(feature = "asr-mlx")]
pub mod asr;
pub mod capture;
pub mod copy;
pub mod disclosure;
pub mod session;
pub mod vault_sink;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::{Vault, VaultConfig};
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Runtime};

use crate::capture::LiveCapture;
use crate::capture::route::SystemRoute;
use crate::session::{LoggingSink, RecorderSession, SegmentLog, SessionError, SessionView};
use crate::vault_sink::VaultSegmentSink;

/// Menu-bar item identity, so the running icon can be found again to retitle.
const TRAY_ID: &str = "recorder";
/// Menu item ids.
const MENU_START: &str = "start";
const MENU_STOP: &str = "stop";
const MENU_SHOW: &str = "show";
const MENU_QUIT: &str = "quit";
/// The single window's label, matching `tauri.conf.json`.
const MAIN_WINDOW: &str = "main";
/// Where the vault lives under the app's data directory.
const VAULT_DIR: &str = "vault";

/// The one piece of state the webview and the menu bar share.
struct AppState {
    session: Mutex<RecorderSession>,
}

/// Runs the recorder.
///
/// # Panics
///
/// If the app cannot start at all — no window, no vault, no menu bar. There is
/// nothing useful to degrade to: a recorder that cannot open its vault must
/// not sit in the menu bar looking ready.
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            let vault = open_vault(&handle)?;
            let log = SegmentLog::new();
            let sink = Arc::new(LoggingSink::new(VaultSegmentSink::new(vault), log.clone()));
            let launcher = LiveCapture::new(sink, Arc::new(SystemRoute));
            app.manage(AppState {
                session: Mutex::new(RecorderSession::new(Box::new(launcher), log)),
            });
            install_menu_bar(&handle)?;

            // A menu-bar app, not a Dock app: no icon bounces when a
            // recording starts.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            recorder_copy,
            session_state,
            affirm_disclosure,
            start_recording,
            stop_recording
        ])
        .run(tauri::generate_context!())
        .expect("the recorder could not start");
}

/// The disclosure panel's words, handed to the webview from the one constants
/// file so the promise to the room is never written down twice.
#[derive(serde::Serialize)]
struct RecorderCopy {
    app_name: &'static str,
    disclosure_title: &'static str,
    disclosure_body: &'static str,
    disclosure_affirm: &'static str,
    disclosure_affirm_action: &'static str,
    segments_empty: &'static str,
    start: &'static str,
    stop: &'static str,
}

/// Every fixed string the window shows.
#[tauri::command]
fn recorder_copy() -> RecorderCopy {
    RecorderCopy {
        app_name: copy::APP_NAME,
        disclosure_title: copy::DISCLOSURE_TITLE,
        disclosure_body: copy::DISCLOSURE_BODY,
        disclosure_affirm: copy::DISCLOSURE_AFFIRM,
        disclosure_affirm_action: copy::DISCLOSURE_AFFIRM_ACTION,
        segments_empty: copy::SEGMENTS_EMPTY,
        start: copy::MENU_ITEM_START,
        stop: copy::MENU_ITEM_STOP,
    }
}

/// The window asks for the current state on load and after every action.
#[tauri::command]
fn session_state(app: AppHandle) -> Result<SessionView, String> {
    act(&app, |_| Ok(()))
}

/// The affirm. This is the only door into a recording.
#[tauri::command]
fn affirm_disclosure(app: AppHandle) -> Result<SessionView, String> {
    act(&app, |session| {
        session.affirm(now_unix());
        Ok(())
    })
}

/// Starts recording, if the gate is open.
#[tauri::command]
fn start_recording(app: AppHandle) -> Result<SessionView, String> {
    act(&app, RecorderSession::start)
}

/// Stops recording, committing the segment that was open.
#[tauri::command]
fn stop_recording(app: AppHandle) -> Result<SessionView, String> {
    act(&app, RecorderSession::stop)
}

/// Runs one action against the session and republishes the resulting state to
/// the menu bar, so the two surfaces cannot drift apart.
fn act<R, F>(app: &AppHandle<R>, action: F) -> Result<SessionView, String>
where
    R: Runtime,
    F: FnOnce(&mut RecorderSession) -> Result<(), SessionError>,
{
    let state = app.state::<AppState>();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "the recorder state is unavailable".to_owned())?;
    let outcome = action(&mut session);
    let view = session.view();
    drop(session);

    retitle_menu_bar(app, &view);
    match outcome {
        Ok(()) => Ok(view),
        Err(err) => Err(err.to_string()),
    }
}

fn open_vault<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<Vault>, Box<dyn std::error::Error>> {
    let path = app.path().app_data_dir()?.join(VAULT_DIR);
    std::fs::create_dir_all(&path)?;
    Ok(Arc::new(Vault::open(&path, VaultConfig::device())?))
}

fn install_menu_bar<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let start = MenuItem::with_id(app, MENU_START, copy::MENU_ITEM_START, true, None::<&str>)?;
    let stop = MenuItem::with_id(app, MENU_STOP, copy::MENU_ITEM_STOP, true, None::<&str>)?;
    let show = MenuItem::with_id(app, MENU_SHOW, copy::MENU_ITEM_SHOW, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, copy::MENU_ITEM_QUIT, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&start, &stop, &separator, &show, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .title(copy::MENU_BAR_IDLE)
        .show_menu_on_left_click(true)
        .on_menu_event(on_menu_event)
        .build(app)?;
    Ok(())
}

fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        MENU_START => {
            // A refused start is not an error to swallow: the window is where
            // the disclosure lives, so raise it and let the operator decide.
            if act(app, RecorderSession::start).is_err() {
                show_window(app);
            }
        }
        MENU_STOP => {
            let _ = act(app, RecorderSession::stop);
        }
        MENU_SHOW => show_window(app),
        MENU_QUIT => {
            // Never walk away leaving a capture running.
            let _ = act(app, RecorderSession::stop);
            app.exit(0);
        }
        _ => {}
    }
}

fn retitle_menu_bar<R: Runtime>(app: &AppHandle<R>, view: &SessionView) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_title(Some(view.menu_bar));
    }
}

fn show_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
