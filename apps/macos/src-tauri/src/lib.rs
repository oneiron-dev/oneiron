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
pub mod root_rekey;
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
/// Hook (FIX 4730; CALLS "root-secret raw-open door (l02/rootdoor)"): the app
/// roots its own vault when this open created the store for a new
/// local-origin vault and its authority log is empty. A store that was there
/// already (it may be a replica awaiting its root) never roots here.
const DESKTOP_ROOTS_FRESH_LOCAL_VAULT: bool = true;
/// Hook (same row): where the host root secret comes from, first found wins.
const DESKTOP_ROOT_SECRET_SOURCE: &[RootSecretSource] = &[
    RootSecretSource::ServerConfig,
    RootSecretSource::RetainedSlot,
];
/// What the engine's log names this open.
const DESKTOP_OPEN: &str = "desktop app open";

/// One place the desktop may find its vault's host root secret.
#[derive(Clone, Copy)]
enum RootSecretSource {
    /// The `auth_secret` `oneiron serve` resolves for this vault: its config
    /// file, environment and defaults, through the server's own resolver.
    ServerConfig,
    /// This device's retained `HostRoot` keystore slot, filled with a fresh
    /// secret only when this open roots a new local-origin vault.
    RetainedSlot,
}

/// The one piece of state the webview and the menu bar share.
struct AppState {
    session: Mutex<RecorderSession>,
    /// This launch's open was given a host root that is not the vault's
    /// settled root, so it went unused: the vault opened under its settled
    /// root as before. A fact the window shows as a nonblocking warning
    /// ([`root_warning`], FIX 5346), never a refusal or a re-key.
    wrong_root: bool,
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
            let vault_dir = handle.path().app_data_dir()?.join(VAULT_DIR);
            let (vault, wrong_root) = open_vault(&vault_dir)?;
            let log = SegmentLog::new();
            let sink = Arc::new(LoggingSink::new(
                VaultSegmentSink::new(Arc::clone(&vault)),
                log.clone(),
            ));
            let launcher = LiveCapture::new(sink, Arc::new(SystemRoute));
            app.manage(AppState {
                session: Mutex::new(RecorderSession::new(Box::new(launcher), log)),
                wrong_root,
            });
            app.manage(root_rekey::RekeyState::new(vault, vault_dir));
            install_menu_bar(&handle)?;

            // A menu-bar app, not a Dock app: no icon bounces when a
            // recording starts.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            recorder_copy,
            root_warning,
            session_state,
            affirm_disclosure,
            start_recording,
            stop_recording,
            root_rekey::root_rekey_prepare,
            root_rekey::root_rekey_confirm
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

/// The wrong-root warning the window shows beside everything else, or `None`
/// when this launch's host root was the vault's own or none was given (FIX
/// 5346). It is fixed for the launch, blocks nothing and re-keys nothing.
#[tauri::command]
fn root_warning(app: AppHandle) -> Option<&'static str> {
    app.state::<AppState>()
        .wrong_root
        .then_some(copy::WRONG_ROOT_WARNING)
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

/// The recorder's vault at `path`, and whether its open reported the
/// wrong-root fact.
fn open_vault(path: &std::path::Path) -> Result<(Arc<Vault>, bool), Box<dyn std::error::Error>> {
    open_vault_at_with_host_root(
        path,
        DESKTOP_ROOT_SECRET_SOURCE,
        DESKTOP_ROOTS_FRESH_LOCAL_VAULT,
    )
}

/// [`open_vault_at`], then this install's own machine profile from the host
/// root secret the first of `sources` holds (FIX 4730), so the owner's acts
/// carry from this Mac. With `initialize_root`, a store this open created is
/// a new local-origin vault, rooted through the engine's own door. Every
/// failure is logged with its reason and the app opens as before. The
/// `bool` is the wrong-root fact ([`profile_from`]).
fn open_vault_at_with_host_root(
    path: &std::path::Path,
    sources: &[RootSecretSource],
    initialize_root: bool,
) -> Result<(Arc<Vault>, bool), Box<dyn std::error::Error>> {
    // Read before the open creates anything: only a store this open brings
    // into existence may root.
    let new_local_origin = initialize_root && Vault::is_unstarted_vault_dir(path);
    let vault = open_vault_at(path)?;
    let wrong_root = profile_install(&vault, path, sources, new_local_origin);
    Ok((vault, wrong_root))
}

/// Profiles `vault` from the first secret `sources` holds, or logs why not,
/// and says whether that secret was the wrong root ([`profile_from`]).
/// A source that fails stops the search: a secret the owner may have
/// configured is never stood in for by one made here.
fn profile_install(
    vault: &Vault,
    path: &std::path::Path,
    sources: &[RootSecretSource],
    new_local_origin: bool,
) -> bool {
    let profiled = with_effective_secret(
        vault,
        path,
        sources,
        new_local_origin,
        |found| match found {
            Some((_, secret)) => profile_from(vault, Some(secret), new_local_origin),
            None => profile_from(vault, None, false),
        },
    );
    match profiled {
        Ok(wrong_root) => wrong_root,
        Err(SourceFailure::ServerConfig(reason)) => {
            tracing::warn!(
                reason = %reason,
                "the server config did not resolve, so no host root secret is read; \
                 this install stays unprofiled and the app opens on"
            );
            false
        }
        Err(SourceFailure::RetainedSlot(error)) => {
            tracing::warn!(
                kind = ?error.kind(),
                reason = %error,
                "this device's keystore gave no host root secret for the vault; \
                 this install stays unprofiled and the app opens on"
            );
            false
        }
    }
}

/// Why the search for this Mac's host root secret stopped: the first source
/// that failed. A failure is never stood in for by a later source.
enum SourceFailure {
    /// The server config did not resolve; the reason keeps only its
    /// top-level context, which names the file and never its contents.
    ServerConfig(String),
    /// This device's keystore gave no answer for the retained slot.
    RetainedSlot(oneiron::Error),
}

/// Runs `use_secret` on the first host root secret `sources` holds, with
/// its source, or on `None` when none holds one: the one search the open
/// and a re-key's re-read ([`root_rekey`]) both make. `create_retained`
/// fills an empty retained slot first ([`Vault::retained_host_root_secret`]).
/// A source that fails stops the search with its failure. The secret lives
/// only for the call.
fn with_effective_secret<T>(
    vault: &Vault,
    path: &std::path::Path,
    sources: &[RootSecretSource],
    create_retained: bool,
    use_secret: impl FnOnce(Option<(RootSecretSource, &[u8])>) -> T,
) -> Result<T, SourceFailure> {
    for source in sources {
        match source {
            RootSecretSource::ServerConfig => match configured_auth_secret(path) {
                Ok(Some(secret)) => return Ok(use_secret(Some((*source, secret.as_bytes())))),
                Ok(None) => {}
                Err(reason) => return Err(SourceFailure::ServerConfig(reason)),
            },
            RootSecretSource::RetainedSlot => {
                match vault.retained_host_root_secret(create_retained) {
                    Ok(Some(secret)) => return Ok(use_secret(Some((*source, &secret[..])))),
                    Ok(None) => {}
                    Err(error) => return Err(SourceFailure::RetainedSlot(error)),
                }
            }
        }
    }
    Ok(use_secret(None))
}

/// The configured `auth_secret` for the vault at `path`, as `oneiron serve`
/// resolves it; an empty one is none. An error keeps only its top-level
/// context, which names the file and never its contents.
fn configured_auth_secret(path: &std::path::Path) -> Result<Option<String>, String> {
    oneiron_server::embedded::embedded_serve_config(path, None, None)
        .map(|config| config.auth_secret.filter(|secret| !secret.is_empty()))
        .map_err(|error| error.to_string())
}

/// The engine's profile door for this open; it logs its own outcome, and the
/// app opens whatever it says. `true` is the wrong-root fact: the secret is
/// not the vault's settled root and went unused, so the window warns (FIX
/// 5346); a refusal or a skip is `false`, as the open goes on either way.
fn profile_from(vault: &Vault, secret: Option<&[u8]>, new_local_origin: bool) -> bool {
    vault
        .profile_local_open_logged(secret, new_local_origin, DESKTOP_OPEN)
        .is_ok_and(oneiron::authority::LocalOpenProfile::wrong_root)
}

/// Opens the recorder's vault at `path`. Crash output never carries world
/// text (owner ruling 2026-10-14, fix 6), so the engine's panic hook goes in
/// before the vault opens. It never roots or profiles: a join, pair or
/// adoption flow opens its replica's store through here (FIX 4730).
fn open_vault_at(path: &std::path::Path) -> Result<Arc<Vault>, Box<dyn std::error::Error>> {
    oneiron::panic_report::install_panic_hook();
    std::fs::create_dir_all(path)?;
    let vault = Vault::open(path, VaultConfig::device())?;
    // Signing doors (delete receipts) need this install's keys from the keystore.
    vault.install_default_keystore(path);
    Ok(Arc::new(vault))
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

#[cfg(test)]
mod tests;
