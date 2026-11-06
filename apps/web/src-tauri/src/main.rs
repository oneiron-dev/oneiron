#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "macos")]
mod app_icon;
#[cfg(target_os = "macos")]
use tauri::Manager;

fn main() {
    // This process owns only the UI. No engine, sidecar, service or wake
    // assertion is started here, so closing/quitting cannot stop engine work.
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder
        .invoke_handler(tauri::generate_handler![
            app_icon::get_app_icon_appearance,
            app_icon::set_app_icon_appearance,
        ])
        .on_window_event(|window, event| {
            // Native appearance stays unset/follows macOS. HTML theme classes
            // never call set_theme, so the Dock preference is independent.
            if matches!(event, tauri::WindowEvent::ThemeChanged(_)) {
                app_icon::system_appearance_changed(window.app_handle());
            }
        });

    builder
        .setup(|app| {
            let config = &app.config().app.windows[0];
            let window = tauri::WebviewWindowBuilder::from_config(app, config)?;

            // Keep genuine macOS controls, over the app's existing material.
            // Other platforms retain the standard native titlebar and layout.
            #[cfg(target_os = "macos")]
            let window = window
                .title_bar_style(tauri::TitleBarStyle::Overlay)
                .hidden_title(true)
                .initialization_script(include_str!("macos-chrome.js"));

            window.build()?;
            #[cfg(target_os = "macos")]
            app_icon::initialize(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running the Oneiron desktop UI");
}
