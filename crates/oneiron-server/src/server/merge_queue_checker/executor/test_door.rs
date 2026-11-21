//! The isolated executor's door for the integration tests
//! (`--cfg oneiron_test_support`).

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::code_sandbox::microvm::MicroVmBackend;
use oneiron::merge_queue::{QueueCheckExecution, QueueCheckInputs, QueueCheckInvocation};
use oneiron_container::{EgressRelay, GuestSpec, SessionManifest};

use super::super::tree::{
    FRAME_DONE, FRAME_END, FRAME_INPUTS, Sent, read_frame, send_tree, write_frame,
};
use super::QueueCheckExecutor;
use crate::config::MergeQueueCheckerConfig;

/// A door for the integration tests (`--cfg oneiron_test_support`): runs one
/// isolated check with no commands on `lease`, a guest session the test
/// started and whose start `manifest` names, and answers what the run came
/// to. An in-process helper answers on the session's pipes as `checker.py`
/// does for an empty tree: the input digests and the terminal frame. Then
/// it reads on until its input closes, as a held container's launcher
/// does. The session goes only to a held start
/// (`start_session_until_stdin_closes`): a plain start is refused, so a
/// checker that does not ask for the hold does not complete.
///
/// # Errors
/// An engine failure of the run, or of the door's own pipes.
pub(crate) fn run_empty_isolated_check(
    lease: Box<dyn oneiron_container::SessionLease>,
    manifest: SessionManifest,
) -> oneiron::Result<QueueCheckExecution> {
    use oneiron::code_sandbox::microvm::{
        CredentialResolver, ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle,
        NoSandboxBackends, backend_error,
    };
    use oneiron::code_sandbox::{SandboxBoundaryContract, SandboxMountTable, SandboxProposalWrite};
    use oneiron::merge_queue::{QueueCheckFile, QueueCheckTreeSource};
    use oneiron_container::SessionTransport;
    use std::os::unix::net::UnixStream;

    struct EmptyTree;

    impl QueueCheckTreeSource for EmptyTree {
        fn files(&self) -> oneiron::Result<Vec<QueueCheckFile>> {
            Ok(Vec::new())
        }

        fn blob(&self, _oid: &str) -> oneiron::Result<Vec<u8>> {
            Err(oneiron::Error::InvalidConfig(
                "the empty tree holds no blob".to_owned(),
            ))
        }
    }

    /// Hands out the test's one session, once, to a held start.
    struct HandedSession(Mutex<Option<SessionTransport>>);

    impl MicroVmBackend for HandedSession {
        fn start_session(
            &self,
            _spec: &GuestSpec,
            _command: &[OsString],
            _relay: Arc<dyn EgressRelay>,
        ) -> oneiron::Result<SessionTransport> {
            Err(backend_error(
                self.name(),
                "a checker guest must outlive its helper until its input closes",
            ))
        }

        fn start_session_until_stdin_closes(
            &self,
            _spec: &GuestSpec,
            _command: &[OsString],
            _relay: Arc<dyn EgressRelay>,
        ) -> oneiron::Result<SessionTransport> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or_else(|| backend_error(self.name(), "the one session was handed out"))
        }

        fn name(&self) -> &'static str {
            "test-handed-session"
        }

        fn prepare(
            &self,
            _contract: &SandboxBoundaryContract,
            _mounts: &SandboxMountTable,
        ) -> oneiron::Result<MicroVmHandle> {
            Err(backend_error(self.name(), "sessions only"))
        }

        fn run(
            &self,
            _vm: &MicroVmHandle,
            _image: &GuestImage,
            _budget: ExecutionBudget,
        ) -> oneiron::Result<MicroVmExit> {
            Err(backend_error(self.name(), "sessions only"))
        }

        fn collect_overlay_delta(
            &self,
            _vm: &MicroVmHandle,
        ) -> oneiron::Result<Vec<SandboxProposalWrite>> {
            Err(backend_error(self.name(), "sessions only"))
        }

        fn cleanup(&self, _vm: &MicroVmHandle) {}

        fn proxy_credentials(
            &self,
            _vm: &MicroVmHandle,
            _resolver: &dyn CredentialResolver,
        ) -> oneiron::Result<()> {
            Err(backend_error(self.name(), "sessions only"))
        }
    }

    /// The helper's side: reads the header and the tree to its end frame,
    /// answers the digests and the terminal frame, then reads on until its
    /// input closes.
    fn answer_empty_check(mut input: UnixStream, mut output: UnixStream, digest: &str) {
        loop {
            match read_frame(&mut input) {
                Ok(Some((kind, _))) if kind == FRAME_END => break,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return,
            }
        }
        let digests = serde_json::json!({"before": digest, "after": digest}).to_string();
        if write_frame(&mut output, FRAME_INPUTS, digests.as_bytes()).is_err()
            || write_frame(&mut output, FRAME_DONE, &[]).is_err()
            || output.flush().is_err()
        {
            return;
        }
        while let Ok(Some(_)) = read_frame(&mut input) {}
    }

    let commit = "0".repeat(40);
    let tree = EmptyTree;
    let Sent::Tree(digest) = send_tree(&mut Vec::new(), &tree, &commit)? else {
        return Err(oneiron::Error::InvalidConfig(
            "the empty tree did not send".to_owned(),
        ));
    };
    let (input_host, input_guest) = UnixStream::pair()?;
    let (output_host, output_guest) = UnixStream::pair()?;
    let helper = std::thread::spawn(move || answer_empty_check(input_guest, output_guest, &digest));
    let transport = SessionTransport {
        reader: Box::new(output_host),
        writer: Box::new(input_host),
        manifest,
        lease,
    };
    let limits = serde_json::json!({
        "memory_mib": 256, "cpu_millis": 1000, "pids": 64, "tmpfs_mib": 64,
    });
    let inputs: QueueCheckInputs = serde_json::from_value(serde_json::json!({
        "store": "test-store",
        "repo": oneiron::EntityId::now(),
        "target": {"Baseline": {"commit": commit, "tree": "0".repeat(40), "phase": "Fast"}},
        "baseline_id": null,
        "plan_digest": "test-plan",
        "commands": [],
        "contract_outputs": {},
        "environment": {
            "backend": "isolated",
            "executor": "test-handed-session",
            "runtime": null,
            "image": concat!(
                "example.invalid/checker@sha256:",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "helper": [crate::config::merge_queue::ISOLATED_CHECK_HELPER],
            "toolchain": {},
            "limits": limits,
            "network": "deny",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
    }))
    .map_err(|error| oneiron::Error::InvalidConfig(format!("the door's inputs: {error}")))?;
    let mut executor = QueueCheckExecutor::new(
        MergeQueueCheckerConfig::default(),
        Arc::new(NoSandboxBackends),
    );
    executor.backend = Some(Box::new(HandedSession(Mutex::new(Some(transport)))));
    let invocation = QueueCheckInvocation {
        target: &inputs.target,
        tree: &tree,
    };
    // The run takes the backend: a session it never handed out closes its
    // pipes as the run returns, so the helper ends either way.
    let ran = executor.execute_isolated(&invocation, &inputs, &|| false);
    let _ = helper.join();
    ran
}
