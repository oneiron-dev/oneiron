fn main() {
    let manifest = tauri_build::AppManifest::new()
        .commands(&["get_app_icon_appearance", "set_app_icon_appearance"]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to build the desktop shell");
}
