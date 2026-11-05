//! The renderer's selected scratch filesystem and its private directories.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use oneiron::EntityId;
use oneiron::origin::smart_http::SpillFloor;

use crate::machine::DiskFloor;

#[cfg(target_os = "linux")]
mod bounded;

/// An explicit process-level choice; absent means the existing vault spool.
const SCRATCH_ENV: &str = "ONEIRON_RENDER_SCRATCH";

/// One selected source and one shared set of disk claims per server.
#[derive(Default)]
pub(crate) struct RendererScratch {
    configured: OnceLock<std::result::Result<Option<Source>, String>>,
}

#[derive(Clone)]
pub(super) struct Source {
    pub(super) spool: PathBuf,
    pub(super) disk: DiskFloor,
    pin: Option<Arc<File>>,
}

impl Source {
    pub(super) fn is_bounded(&self) -> bool {
        self.pin.is_some()
    }
}

impl RendererScratch {
    pub(super) fn source(&self, disk: &DiskFloor) -> io::Result<Option<Source>> {
        let configured = self
            .configured
            .get_or_init(|| configured(disk).map_err(|err| err.to_string()));
        match configured {
            Ok(Some(source)) => Ok(Some(source.clone())),
            Ok(None) => Ok(disk.spool_dir().map(|spool| Source {
                spool,
                disk: disk.clone(),
                pin: None,
            })),
            Err(reason) => Err(io::Error::other(reason.clone())),
        }
    }
}

fn configured(disk: &DiskFloor) -> io::Result<Option<Source>> {
    let Some(path) = std::env::var_os(SCRATCH_ENV) else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    {
        bounded::source(Path::new(&path), disk).map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, disk);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "configured renderer scratch requires Linux",
        ))
    }
}

/// A private directory, with any configured mount held through child cleanup.
pub(super) struct Scratch {
    pub(super) path: PathBuf,
    cleanup: PathBuf,
    _root: Option<Arc<File>>,
    _directory: Option<File>,
}

impl Scratch {
    pub(super) fn new(source: &Source) -> io::Result<Self> {
        let cleanup = source
            .spool
            .join(format!("oneiron-slides-{}", EntityId::now().to_hex()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&cleanup)?;
        let mut scratch = Self {
            path: cleanup.clone(),
            cleanup,
            _root: source.pin.clone(),
            _directory: None,
        };
        #[cfg(target_os = "linux")]
        if source.pin.is_some() {
            let directory = bounded::directory(&scratch.cleanup)?;
            scratch.path = bounded::pinned_path(&directory);
            scratch._directory = Some(directory);
        }
        Ok(scratch)
    }

    pub(super) fn child_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        if let Some(directory) = &self._directory {
            return bounded::child_path(directory);
        }
        self.path.clone()
    }

    pub(super) fn command(&self, program: &Path) -> io::Result<Command> {
        #[cfg(target_os = "linux")]
        if let Some(directory) = &self._directory {
            return bounded::command(program, directory);
        }
        Ok(Command::new(program))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cleanup);
    }
}
