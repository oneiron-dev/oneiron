//! FIX SLOW-FACADE-CALLS-COORDINATION-08: the MCP surface registers once per
//! process, not on every request that reads it.
//!
//! `SyncServer::mcp_surface` built the whole surface on every read: a schema
//! for each of the 1437 tool-first tools, 742-815 ms per registration in the
//! E2E build (fleet job 1113-051216-6430). Each `tools/call` read it twice
//! and each `tools/list` once. The test reads each mode's served surface
//! through that accessor once, then times four more reads.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! mcp_surface_registration_latency`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::mcp::{MCP_READ_RESULT_TOOL, McpSurfaceMode, try_registered_surface};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_surface::{served_listing, served_tool_names};

/// Reads of one surface after the first, timed together.
const REPEATED_SURFACE_READS: usize = 4;

/// Their bound. A read after the first is a lookup; one registration took
/// 742-815 ms in the E2E build.
const REPEATED_SURFACE_READS_BOUND: Duration = Duration::from_millis(50);

/// A server with no code host: its surfaces carry no `execute_code` runtime.
fn server_without_code_host() -> (tempfile::TempDir, SyncServer) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in BEFORE the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("mcp-surface-registration".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    (dir, server)
}

#[tokio::test]
async fn mcp_surface_reads_after_the_first_do_not_register_again() {
    let (_dir, server) = server_without_code_host();
    for mode in McpSurfaceMode::ALL {
        let tools = served_tool_names(&server, mode).expect("the surface registers");
        let started = Instant::now();
        for _ in 0..REPEATED_SURFACE_READS {
            let again = served_tool_names(&server, mode).expect("the surface registers");
            assert_eq!(again.len(), tools.len(), "{mode:?}");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < REPEATED_SURFACE_READS_BOUND,
            "{mode:?}: {REPEATED_SURFACE_READS} surface reads after the first took {elapsed:?} \
             (bound {REPEATED_SURFACE_READS_BOUND:?}); a read must not register the surface again"
        );
    }
}

/// The served surface is the process registration, tool for tool and byte
/// for byte, and without a code host it registers no `read_result`.
#[tokio::test]
async fn mcp_surface_without_a_code_host_is_the_process_registration() {
    let (_dir, server) = server_without_code_host();
    for mode in McpSurfaceMode::ALL {
        let registered = try_registered_surface(mode).expect("the process registration");
        let served = served_tool_names(&server, mode).expect("the surface registers");
        assert_eq!(served, registered.tool_names(), "{mode:?}");
        assert!(
            !served.contains(&MCP_READ_RESULT_TOOL),
            "{mode:?}: read_result is registered only beside a verified code host"
        );
        let listing = served_listing(&server, mode).expect("the surface registers");
        assert_eq!(&listing, registered.listing(), "{mode:?}");
    }
}
