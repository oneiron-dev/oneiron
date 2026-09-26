//! Compile the exact host module as an isolated transport test. The server's
//! all-lib test target currently contains unrelated, stale disclosure fixtures;
//! this test keeps the Linear wire check independently runnable.
mod server {
    pub(crate) use oneiron_server::server::SyncServer;
}

#[path = "../src/linear_host.rs"]
mod linear_host;
