//! Public-name ingress for an already-held private preview, never a connector installer.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use tokio::net::UnixListener;
use tokio::task::JoinSet;

use super::{SharedPreview, http};
use crate::managed::preview_route::PreviewRouteClient;
use crate::managed::{ManagedError, ManagedShutdown};

/// A name index over the same held leases. Weak entries confer no lease lifetime.
pub(crate) struct PreviewRoutes {
    pub(super) client: PreviewRouteClient,
    pub(super) stopped: ManagedShutdown,
    entries: Mutex<BTreeMap<String, Weak<SharedPreview>>>,
}

impl PreviewRoutes {
    pub(crate) fn new(client: PreviewRouteClient) -> Self {
        Self {
            client,
            stopped: ManagedShutdown::new(),
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn insert(&self, shared: &Arc<SharedPreview>) -> anyhow::Result<()> {
        let Some(hosted) = shared.hosted() else {
            return Ok(());
        };
        let mut entries = self.entries.lock().expect("preview routes lock");
        anyhow::ensure!(
            !self.stopped.is_triggered() && shared.is_live(),
            "preview ingress stopped"
        );
        let authority = hosted.authority.to_ascii_lowercase();
        anyhow::ensure!(
            !entries
                .get(&authority)
                .and_then(Weak::upgrade)
                .is_some_and(|prior| !Arc::ptr_eq(&prior, shared) && prior.hosted_is_live()),
            "preview origin already bound"
        );
        entries.insert(authority, Arc::downgrade(shared));
        Ok(())
    }

    pub(super) fn remove(&self, authority: &str, shared: &SharedPreview) {
        let authority = authority.to_ascii_lowercase();
        let mut entries = self.entries.lock().expect("preview routes lock");
        if entries
            .get(&authority)
            .is_some_and(|entry| std::ptr::eq(entry.as_ptr(), shared))
        {
            entries.remove(&authority);
        }
    }

    fn stop(&self) {
        self.stopped.trigger();
        let leases: Vec<_> = {
            let mut entries = self.entries.lock().expect("preview routes lock");
            let leases = entries.values().filter_map(Weak::upgrade).collect();
            entries.clear();
            leases
        };
        for shared in leases {
            if let Some(hosted) = shared.hosted() {
                hosted.guard.close();
            }
        }
    }

    pub(super) fn resolve(&self, authority: &str) -> Option<Arc<SharedPreview>> {
        let shared = self
            .entries
            .lock()
            .expect("preview routes lock")
            .get(&authority.to_ascii_lowercase())
            .and_then(Weak::upgrade)?;
        shared.hosted_is_live().then_some(shared)
    }
}

/// The fixed per-vault native data socket. Its inode is removed on every exit,
/// including startup failure before the managed ready byte.
pub(crate) struct PreviewRouteListener {
    listener: Option<UnixListener>,
    path: PathBuf,
}

impl PreviewRouteListener {
    pub(crate) fn bind(path: &Path) -> Result<Self, ManagedError> {
        Ok(Self {
            listener: Some(crate::managed::listener::bind_unix_socket(path)?),
            path: path.to_path_buf(),
        })
    }

    pub(crate) async fn serve(
        mut self,
        routes: Arc<PreviewRoutes>,
        stop: ManagedShutdown,
    ) -> io::Result<()> {
        let listener = self.listener.take().expect("bound preview listener");
        let mut connections = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                () = stop.triggered() => break Ok(()),
                accepted = listener.accept() => {
                    let (socket, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(error),
                    };
                    connections.spawn(http::serve_hosted_connection(socket, Arc::clone(&routes), stop.clone()));
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        };
        drop(listener);
        routes.stop();
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        result
    }
}

impl Drop for PreviewRouteListener {
    fn drop(&mut self) {
        self.listener.take();
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.path.display(), "preview socket unlink failed");
        }
    }
}
