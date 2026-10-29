//! Served pack operations, including explicit default skill imports.

use std::sync::Arc;

use axum::Router;

use crate::server::SyncServer;

pub(super) mod defaults;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    defaults::routes()
}
