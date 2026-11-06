//! Private real-CLI entry before Tokio is constructed. Library hosts do not register.
use std::path::PathBuf;
use std::sync::OnceLock;

mod entry;
pub(crate) mod sys;
pub(crate) mod wire;

static CLI: OnceLock<PathBuf> = OnceLock::new();

pub(crate) fn cli() -> Option<&'static std::path::Path> {
    CLI.get().map(PathBuf::as_path)
}

pub(crate) fn enter() -> Option<anyhow::Result<()>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_none_or(|arg| arg != wire::MARKER) {
        if let Ok(path) = std::env::current_exe() {
            let _ = CLI.set(path);
        }
        return None;
    }
    crate::logging::install_panic_hook();
    Some(entry::run(&args[2..]).map_err(Into::into))
}
