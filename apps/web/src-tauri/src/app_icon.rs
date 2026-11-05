//! The running macOS Dock icon only. No bundle, Finder or engine mutation.

use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{NSAppearanceNameAqua, NSAppearanceNameDarkAqua, NSApplication, NSImage};
use objc2_foundation::{NSArray, NSBundle, NSData, NSProcessInfo, NSString, ns_string};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, Manager, State};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IconAppearance {
    Light,
    Dark,
    #[default]
    System,
}

#[derive(Deserialize, Serialize)]
struct Preferences {
    appearance: IconAppearance,
}

pub struct IconState {
    preference: Mutex<IconAppearance>,
    path: PathBuf,
}

fn use_dark_icon(preference: IconAppearance, system_dark: bool) -> bool {
    match preference {
        IconAppearance::Light => false,
        IconAppearance::Dark => true,
        IconAppearance::System => system_dark,
    }
}

fn load_preference(path: &Path) -> Result<IconAppearance, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Preferences>(&bytes)
            .map(|value| value.appearance)
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(IconAppearance::System),
        Err(error) => Err(error.to_string()),
    }
}

fn save_preference(path: &Path, preference: IconAppearance) -> Result<(), String> {
    let parent = path.parent().ok_or("app icon config has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec(&Preferences {
        appearance: preference,
    })
    .map_err(|error| error.to_string())?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

fn use_bundle_icon(preference: IconAppearance, macos_major: isize, has_catalog: bool) -> bool {
    preference == IconAppearance::System && macos_major >= 26 && has_catalog
}

fn has_layered_bundle_icon() -> bool {
    let bundle = NSBundle::mainBundle();
    let named_icon = bundle
        .objectForInfoDictionaryKey(ns_string!("CFBundleIconName"))
        .and_then(|value| {
            value
                .downcast_ref::<NSString>()
                .map(|name| name.to_string() == "Oneiron")
        })
        .unwrap_or(false);
    let catalog_exists = bundle.resourcePath().is_some_and(|directory| {
        Path::new(&directory.to_string())
            .join("Assets.car")
            .is_file()
    });
    // A cargo/tauri-dev executable must not clear its useful PNG override in
    // favor of a generic executable icon. The packaged catalog is build-validated.
    bundle.bundlePath().to_string().ends_with(".app") && named_icon && catalog_exists
}

fn icon_image(
    mtm: MainThreadMarker,
    preference: IconAppearance,
) -> Result<Option<objc2::rc::Retained<NSImage>>, String> {
    let major = NSProcessInfo::processInfo()
        .operatingSystemVersion()
        .majorVersion;
    if use_bundle_icon(preference, major, has_layered_bundle_icon()) {
        // nil restores the bundle's native iconstack. macOS owns its independent
        // icon/widget appearance and compositing, not the HTML or window theme.
        return Ok(None);
    }
    let app = NSApplication::sharedApplication(mtm);
    // These public AppKit constants exist on our macOS 12+ deployment target.
    let (light, dark) = unsafe { (NSAppearanceNameAqua, NSAppearanceNameDarkAqua) };
    let choices = NSArray::from_slice(&[light, dark]);
    let matched = app
        .effectiveAppearance()
        .bestMatchFromAppearancesWithNames(&choices);
    let system_dark = matched.as_deref() == Some(dark);
    let bytes: &[u8] = if use_dark_icon(preference, system_dark) {
        include_bytes!("../icons/app-icon-dark.png")
    } else {
        include_bytes!("../icons/app-icon-light.png")
    };
    NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(bytes))
        .map(Some)
        .ok_or_else(|| "bundled app icon could not be decoded".into())
}

fn apply_image(mtm: MainThreadMarker, image: Option<&NSImage>) {
    // SAFETY: main-thread marker proves AppKit thread affinity. Some is a valid
    // retained image from our bytes. Apple documents nil as restoring the bundle
    // icon; that path is used only for a present native catalog on macOS 26+.
    unsafe { NSApplication::sharedApplication(mtm).setApplicationIconImage(image) };
}

pub fn initialize(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let path = app
        .path()
        .app_config_dir()?
        .join("app-icon-appearance.json");
    let preference = load_preference(&path).unwrap_or_else(|error| {
        eprintln!("Could not read app icon preference; using System: {error}");
        IconAppearance::System
    });
    let mtm = MainThreadMarker::new().ok_or("app icon setup must run on the main thread")?;
    let image = icon_image(mtm, preference)?;
    apply_image(mtm, image.as_deref());
    app.manage(IconState {
        preference: Mutex::new(preference),
        path,
    });
    Ok(())
}

#[tauri::command]
pub fn get_app_icon_appearance(state: State<'_, IconState>) -> Result<IconAppearance, String> {
    state
        .preference
        .lock()
        .map(|value| *value)
        .map_err(|_| "app icon state unavailable".into())
}

#[tauri::command]
pub async fn set_app_icon_appearance(
    app: AppHandle,
    preference: IconAppearance,
) -> Result<IconAppearance, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let handle = app.clone();
    app.run_on_main_thread(move || {
        let result = (|| {
            let mtm =
                MainThreadMarker::new().ok_or("app icon update must run on the main thread")?;
            let image = icon_image(mtm, preference)?;
            let state = handle.state::<IconState>();
            let mut current = state
                .preference
                .lock()
                .map_err(|_| "app icon state unavailable")?;
            // Persist before reporting success. Serialization/main-thread dispatch
            // prevent concurrent selections from racing the file and Dock state.
            save_preference(&state.path, preference)?;
            apply_image(mtm, image.as_deref());
            *current = preference;
            Ok(preference)
        })();
        let _ = send.send(result);
    })
    .map_err(|error| error.to_string())?;
    receive
        .await
        .map_err(|_| "app icon update was interrupted".to_string())?
}

pub fn system_appearance_changed(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let Some(state) = handle.try_state::<IconState>() else {
            return;
        };
        let Ok(current) = state.preference.lock() else {
            return;
        };
        if *current != IconAppearance::System {
            return;
        }
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        match icon_image(mtm, *current) {
            Ok(image) => apply_image(mtm, image.as_deref()),
            Err(error) => eprintln!("Could not update the System app icon: {error}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_ignore_system_appearance_and_system_follows_it() {
        for system_dark in [false, true] {
            assert!(!use_dark_icon(IconAppearance::Light, system_dark));
            assert!(use_dark_icon(IconAppearance::Dark, system_dark));
            assert_eq!(
                use_dark_icon(IconAppearance::System, system_dark),
                system_dark
            );
        }
    }

    #[test]
    fn native_system_requires_modern_os_and_a_packaged_catalog() {
        assert!(use_bundle_icon(IconAppearance::System, 26, true));
        assert!(use_bundle_icon(IconAppearance::System, 27, true));
        assert!(!use_bundle_icon(IconAppearance::System, 25, true));
        assert!(!use_bundle_icon(IconAppearance::System, 27, false));
        assert!(!use_bundle_icon(IconAppearance::Light, 27, true));
        assert!(!use_bundle_icon(IconAppearance::Dark, 27, true));
    }

    #[test]
    fn preferences_round_trip_and_reject_unknown_values() {
        for appearance in [
            IconAppearance::Light,
            IconAppearance::Dark,
            IconAppearance::System,
        ] {
            let encoded = serde_json::to_vec(&Preferences { appearance }).unwrap();
            assert_eq!(
                serde_json::from_slice::<Preferences>(&encoded)
                    .unwrap()
                    .appearance,
                appearance
            );
        }
        assert!(serde_json::from_str::<Preferences>(r#"{"appearance":"/tmp/icon.png"}"#).is_err());
    }

    #[test]
    fn missing_preference_defaults_to_system_and_explicit_choice_persists() {
        let directory =
            std::env::temp_dir().join(format!("oneiron-icon-test-{}", std::process::id()));
        let path = directory.join("preference.json");
        assert_eq!(load_preference(&path).unwrap(), IconAppearance::System);
        save_preference(&path, IconAppearance::Dark).unwrap();
        assert_eq!(load_preference(&path).unwrap(), IconAppearance::Dark);
        fs::remove_dir_all(directory).unwrap();
    }
}
