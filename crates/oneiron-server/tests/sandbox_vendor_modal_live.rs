//! A live smoke of the Modal client (L8-43): one sandbox on Modal's own API,
//! on a real key. The stand-ins of `tests/sandbox_vendor_modal.rs` prove our
//! reading of Modal's published proto; this run proves Modal's servers
//! answer that reading.
//!
//! The run makes one sandbox from a public image pinned by digest, with all
//! network access blocked. It writes a file into the sandbox, copies it with
//! one command, tries one outbound connection, reads the copy back, and
//! terminates the sandbox, which it also does when a step fails.
//!
//! It is ignored by default, and it needs the key: a token id and a token
//! secret joined by a colon, in the file `ONEIRON_MODAL_LIVE_KEY_FILE` names.
//! `/dev/stdin` takes the key from a pipe, so it is never on disk or in the
//! environment. Each run makes one CPU sandbox that lives at most
//! [`RUN_SECONDS`] plus a minute, which Modal bills to the key's workspace.
//!
//! `ONEIRON_MODAL_LIVE_KEY_FILE=/dev/stdin RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test sandbox_vendor_modal_live
//! -- --ignored --nocapture`.
#![cfg(all(oneiron_test_support, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "sandbox_vendor/fixture.rs"]
mod fixture;

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use fixture::VendorVault;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron::engine_executor::StepCancellation;
use oneiron_agent_runtime::code_sandbox::microvm::{VendorCallBound, VendorSandboxSpec};
use oneiron_server::test_doors::sandbox_vendor::modal_client;

/// `python:3.13-slim` (Debian), the OCI index Docker Hub served for that tag
/// on 15 Nov 2026.
const IMAGE: &str = "docker.io/library/python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90";
const API: &str = "https://api.modal.com";
const KEY_NAME: &str = "modal-live-smoke";
/// The run's whole wall clock, a first build of [`IMAGE`] included.
const RUN_SECONDS: u64 = 300;
const IN_PATH: &str = "/tmp/oneiron-live-in";
const OUT_PATH: &str = "/tmp/oneiron-live-out";
const PAYLOAD: &[u8] = b"oneiron modal live smoke\n\x00\x01\x02\xff binary tail\n";
/// Exits 3 when the connection fails, 0 when it opens.
const EGRESS_PROBE: &str = "import socket, sys\n\
try:\n    socket.create_connection(('1.1.1.1', 53), 5)\n\
except OSError:\n    sys.exit(3)\n";

fn key() -> String {
    let path = std::env::var("ONEIRON_MODAL_LIVE_KEY_FILE")
        .expect("ONEIRON_MODAL_LIVE_KEY_FILE names the file of the key (token id:token secret)");
    let text = std::fs::read_to_string(path).expect("the key file reads");
    text.trim().to_owned()
}

#[test]
#[ignore = "live: makes one Modal sandbox on the key in ONEIRON_MODAL_LIVE_KEY_FILE"]
fn a_modal_sandbox_takes_a_file_runs_commands_blocks_egress_and_gives_the_file_back() {
    let vault = VendorVault::new(SandboxVendor::Modal, KEY_NAME, &key());
    let client = modal_client(&vault.vault, KEY_NAME, API);
    let cancel = StepCancellation::new();
    let started = Instant::now();
    let bound = VendorCallBound {
        deadline: started + Duration::from_secs(RUN_SECONDS),
        cancel: &cancel,
    };
    let step = |what: &str| eprintln!("LIVE {what} at {:.1} s", started.elapsed().as_secs_f64());
    let sandbox = client
        .create(
            &VendorSandboxSpec {
                guest_image: IMAGE,
                budget: ExecutionBudget::new(RUN_SECONDS, 512, 64),
            },
            bound,
        )
        .expect("modal makes the sandbox");
    step(&format!("create ok, sandbox {}", sandbox.as_str()));
    // From here the sandbox is terminated whatever fails.
    let steps = catch_unwind(AssertUnwindSafe(|| {
        let body = SandboxProposalBody::from_bytes(PAYLOAD).expect("payload body");
        client
            .upload(&sandbox, IN_PATH, &body, bound)
            .expect("the upload lands");
        step("upload ok");
        let copied = client
            .execute(&sandbox, &["/bin/cp", IN_PATH, OUT_PATH], bound)
            .expect("the copy runs");
        step(&format!("execute cp exit {copied}"));
        assert_eq!(copied, 0, "cp exits 0");
        let probe = client
            .execute(
                &sandbox,
                &["/usr/local/bin/python3", "-c", EGRESS_PROBE],
                bound,
            )
            .expect("the egress probe runs");
        step(&format!("execute egress probe exit {probe}"));
        assert_eq!(
            probe, 3,
            "the outbound connection fails (exit 3); 0 means the sandbox has egress"
        );
        let mut copy = Vec::new();
        client
            .download(&sandbox, OUT_PATH, &mut copy, bound)
            .expect("the download ends");
        step(&format!("download ok, {} bytes", copy.len()));
        assert_eq!(copy, PAYLOAD, "the copy holds the uploaded bytes");
    }));
    let terminated = client.delete(&sandbox);
    step(&format!("delete ok={}", terminated.is_ok()));
    if let Err(panic) = steps {
        resume_unwind(panic);
    }
    terminated.expect("modal terminates the sandbox");
}
