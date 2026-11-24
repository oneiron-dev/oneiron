#![cfg(all(oneiron_test_support, feature = "mesh", unix))]
//! OF-575 between two of the owner's servers over the real mesh (pass 33
//! row R0: `post-untangle/fable/33-exec-node/DESIGN.md` section 11, T1 and
//! T2; owner ruling MESH). Until this file, no test ran an organ call
//! between two serving installs: `oneiron-organ-host/tests/mesh_ask_carried.rs`
//! runs both ends in one host over an in-process transport pair, and
//! `mesh_two_machine_peer_e2e.rs` covers sync alone.
//!
//! The fixture is the owner's home H and three devices of H, each a replica
//! of H's vault in its own directory with its own install identity,
//! enrolled as `oneiron device enrol` enrols a device (the enrolment of
//! `mesh_two_machine_peer_e2e.rs`), A and B paired for organ calls and C for
//! sync (a pairing covers the one protocol it names until MESH-PAIRING-CEILING
//! lands). Each device's server runs with its real mesh listener
//! (`handler::mesh::start`, serve's full route set: iroh on a loopback port
//! the system assigns, no relay), so every call below crosses the real
//! handshake, the listener's admission (the MACHINE row and its grant for
//! `oneiron/organ/1`, read live), the organ service, the staging of bytes
//! past the transport's 1 MiB message, and the listener's stop. Each replica
//! binds the other two devices' endpoints at the addresses their listeners
//! took, and grants A and B organ calls and C sync, never organ calls.
//!
//! - A asks. Its host has no organ installed, so its router (the one the
//!   image edit doors take) sends each call to the owner's other nodes.
//! - B serves: the probe organ is installed on its host, as the server
//!   installs an organ it names by its program.
//! - C is the owner's machine without the organ grant.
//!
//! The organ is `oneiron-organ-probe`, a bin of `oneiron-organ-host`, so
//! this package's tests have no `CARGO_BIN_EXE` for it. The test takes
//! `ONEIRON_TEST_ORGAN_PROBE`, else the bin in the profile dir its own
//! binary was built under, which one cargo invocation builds with the same
//! features when it also selects an `oneiron-organ-host` test. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! -p oneiron-organ-host --all-features --test organ_mesh_two_server_e2e
//! --test mesh_ask_carried`.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, MeshBindingIdentity, MeshEnrolment,
    MeshMachineAddress, PairingPrincipal, pairing_binding_transcript_pinned,
};
use oneiron::federation::Scope;
use oneiron::sync::mesh_path::{
    MESH_PATH_RECEIPTS_READ_MAX, MeshPathDirection, MeshPathOutcome, MeshPathReceipt, SYNC_ALPN,
};
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_organ_host::{
    AskHandlers, CallClass, HostError, LentInput, ORGAN_ALPN, OrganCall, OrganOutcome, OrganSpec,
    OrganState, RanOn, Routed,
};
use oneiron_organ_protocol::{Hash32, Value, touch_fold};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::embedded_peer_path::{MeshListener, start_mesh_listener};
use oneiron_server::test_doors::organ_mesh::{install_organ, organ_router, organ_status};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The organ every call names.
const PROBE: &str = "probe";
/// Where a runner names the probe's program.
const PROBE_ENV: &str = "ONEIRON_TEST_ORGAN_PROBE";
/// The probe's program name beside the test's own target dir.
const PROBE_BIN: &str = "oneiron-organ-probe";
/// The verbs B's install grants: the runtime's `organ.touch` (reads every
/// input byte and reports their length and fold), `probe.outputs` (answers
/// with outputs of a given size) and `probe.sleep` (a long call).
const PROBE_VERBS: [&str; 3] = ["organ.touch", "probe.outputs", "probe.sleep"];
const BIN: &str = "application/octet-stream";
/// Past the transport's 1 MiB message, and not a whole number of the
/// staging's pieces, so it crosses as several pieces, the last one short.
const BIG: usize = 2 * 1024 * 1024 + 4099;
/// The serving listener's drain grace (`commands/serve.rs` `DRAIN_GRACE`):
/// what an admitted call runs on for after the stop begins.
const DRAIN_GRACE: Duration = Duration::from_secs(10);
/// What the stop's cancel, the call's thread, its reply and the asking side
/// may add past the drain grace.
const STOP_MARGIN: Duration = Duration::from_secs(30);
/// The call the stop cuts short asks the probe to sleep this long.
const LONG_SLEEP_MS: u64 = 120_000;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The probe organ's program: `ONEIRON_TEST_ORGAN_PROBE`, else the bin in
/// the profile dir this test's binary sits under: `<target>/<profile>/deps/`
/// in cargo's old layout, `<target>/<profile>/build/<package>/<hash>/out/`
/// in its build-dir layout, the bin at `<target>/<profile>/oneiron-organ-probe`
/// in both. The nearest ancestor that holds the bin is that profile dir.
fn probe_program() -> TestResult<PathBuf> {
    if let Some(program) = std::env::var_os(PROBE_ENV).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(program));
    }
    let exe = std::env::current_exe()?;
    let found = exe
        .ancestors()
        .skip(1)
        .map(|dir| dir.join(PROBE_BIN))
        .find(|program| program.is_file());
    found.ok_or_else(|| {
        format!(
            "FIXTURE: no {PROBE_BIN} in any dir above {}: set {PROBE_ENV}, or build it in the \
             same cargo invocation (`cargo test -p oneiron-server -p oneiron-organ-host \
             --all-features --test organ_mesh_two_server_e2e --test mesh_ask_carried`)",
            exe.display()
        )
        .into()
    })
}

/// The owner's home H: a rooted carrier install the owner answered as his
/// own machine, as `oneiron serve` leaves a self-hosted home. It never runs.
struct Home {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: oneiron::consent::AuthenticatedOwner,
}

fn home() -> TestResult<Home> {
    let dir = tempfile::tempdir()?;
    let vault =
        steward::open_owner_carrier_vault(dir.path()).map_err(at("open the home's vault"))?;
    let owner = steward::owner(&vault).map_err(at("the home's owner proof"))?;
    let machine = vault
        .local_machine()
        .map_err(at("read the home's install"))?
        .ok_or("FIXTURE: the home's install has no machine")?
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers the home is his"))?;
    Ok(Home {
        _dir: dir,
        vault,
        owner,
    })
}

/// One device of H: a replica of H's vault with its own install identity,
/// enrolled on H.
struct Device {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    machine: EntityId,
    identity: MeshBindingIdentity,
    /// The pairing slip H minted for the device's mesh binding.
    mesh_pairing: [u8; 32],
}

impl Home {
    /// A device that copies H's vault and enrols on H as the owner's own
    /// machine, as `oneiron device enrol` does: H's owner makes the machine
    /// pairing link; the device redeems it with a holder key of its own
    /// (seeded by `holder_seed`), its enrolment request, its machine key's
    /// possession proof and its mesh identity; H enrols it, and binds and
    /// grants its endpoint on `alpn` in the same redemption. Its pairing
    /// covers `alpn` alone, so no replica can grant it another protocol.
    fn enrol(&self, holder_seed: u8, alpn: &[u8]) -> TestResult<Device> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::device())
            .map_err(at("open the device's vault"))?;
        vault
            .import_signed_authority_history(
                &self
                    .vault
                    .export_signed_authority_history()
                    .map_err(at("the home's authority history"))?,
            )
            .map_err(at("the device takes the home's authority history"))?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let vault_id = vault
            .authority_vault_id()
            .map_err(at("the device's vault id"))?
            .ok_or("FIXTURE: the device's copy has no vault id")?;
        let request = vault
            .machine_enrolment_request(
                vault_id,
                vault
                    .machine_encryption_key(vault_id)
                    .map_err(at("the device's encryption key"))?,
            )
            .map_err(at("the device's enrolment request"))?;
        let device_owner = steward::owner(&vault).map_err(at("the device's owner proof"))?;
        let identity = vault
            .mesh_binding_identity_as_owner(&device_owner)
            .map_err(at("the device's mesh identity"))?;
        let issuer = test_host_issuer();
        let link = self
            .vault
            .issue_machine_pairing_link(
                &issuer,
                &self.owner,
                ActSurface::ThisInstall,
                Scope::top(),
                3600,
                PairingPrincipal::default(),
                MachineOwnership::Yours,
            )
            .map_err(at("the owner's machine pairing link"))?;
        let holder = SigningKey::from_bytes(&[holder_seed; 32]);
        let binding_key = holder.verifying_key().to_bytes();
        let holder_ref = request.machine.to_hex();
        let transcript = pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )
        .map_err(at("the pairing transcript"))?;
        let possession = vault
            .machine_possession_proof(&request, &transcript)
            .map_err(at("the machine key's possession proof"))?;
        let redeemed = self
            .vault
            .redeem_pairing_link_with_mesh(
                &issuer,
                &link.code,
                &holder_ref,
                binding_key,
                &holder.sign(&transcript).to_bytes(),
                &request,
                Some(&possession),
                (&identity, alpn),
            )
            .map_err(at("the home redeems the device's enrolment"))?;
        let pairing_slip_id = match redeemed.mesh {
            Some(MeshEnrolment::Bound {
                pairing_slip_id, ..
            }) => pairing_slip_id,
            other => {
                return Err(format!("FIXTURE: the home did not bind the device: {other:?}").into());
            }
        };
        Ok(Device {
            _dir: dir,
            vault: Arc::new(vault),
            machine: request.machine,
            identity,
            mesh_pairing: pairing_slip_id,
        })
    }

    /// Every device takes H's authority history once all have enrolled, so
    /// each replica folds every machine and every slip H minted.
    fn share_history(&self, devices: &[&Device]) -> TestResult {
        let history = self
            .vault
            .export_signed_authority_history()
            .map_err(at("the home's authority history"))?;
        for device in devices {
            device
                .vault
                .import_signed_authority_history(&history)
                .map_err(at("a device takes the home's authority history"))?;
        }
        Ok(())
    }
}

impl Device {
    /// This vault binds `peer`'s endpoint at the loopback addresses its
    /// running listener bound (`listening`), on the pairing H minted for it.
    /// The listeners and dialers read the roster and the grants live, so a
    /// bind after the listener started counts.
    fn bind(&self, peer: &Device, listening: &Served) -> TestResult {
        self.vault
            .bind_mesh_machine(
                &test_host_issuer(),
                peer.machine,
                MeshMachineAddress {
                    endpoint_key: peer.identity.endpoint_key,
                    direct_addrs: listening.addresses.clone(),
                    relay_url: None,
                },
                peer.identity.device_key,
                peer.mesh_pairing,
                [
                    peer.identity.device_proof.as_slice(),
                    peer.identity.transport_proof.as_slice(),
                ],
            )
            .map_err(at("bind the peer's endpoint"))?;
        Ok(())
    }

    /// This vault grants `peer` the protocol `alpn`, as the owner does for a
    /// machine whose calls on it this one takes or makes.
    fn grant(&self, peer: &Device, alpn: &[u8]) -> TestResult {
        self.vault
            .set_mesh_alpn_grant(
                &test_host_issuer(),
                peer.machine,
                peer.identity.endpoint_key,
                alpn,
                true,
            )
            .map_err(at("grant the peer its protocol"))?;
        Ok(())
    }

    /// Starts this device's server as a device of H, with no models, and its
    /// mesh listener on a loopback port the system assigns as it binds: no
    /// other test of this binary (they run in parallel) can take that port
    /// between the choice and the bind.
    async fn serve(&self) -> TestResult<Served> {
        let server = SyncServer::new(Arc::clone(&self.vault), SyncServerConfig::default())
            .map_err(at("the device's server"))?;
        let (server, host) = AiHost::attach_device(server, None, true).await;
        let server = Arc::new(server);
        let app = oneiron_server::build_app(Arc::clone(&server));
        let listener = start_mesh_listener(
            Arc::clone(&server),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &app,
        )
        .await
        .map_err(at("the device's mesh listener"))?;
        let addresses = listener.direct_addrs();
        if addresses.is_empty() {
            return Err("FIXTURE: the device's mesh listener bound no direct address".into());
        }
        Ok(Served {
            server,
            _host: host,
            listener: Some(listener),
            addresses,
        })
    }
}

/// A device's running server and mesh listener.
struct Served {
    server: Arc<SyncServer>,
    _host: AiHost,
    /// `None` once a test stopped it.
    listener: Option<MeshListener>,
    /// The loopback addresses the listener bound.
    addresses: Vec<SocketAddr>,
}

impl Served {
    /// Stops the listener, if it still runs: its stop's drain and cancel.
    async fn stop(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
    }
}

/// One machine of the owner's: its replica and its running server.
struct Machine {
    device: Device,
    served: Served,
}

/// H, the asker A, the serving B and the ungranted C, all running.
struct Mesh {
    _home: Home,
    a: Machine,
    b: Machine,
    c: Machine,
}

impl Mesh {
    /// Enrols the three devices, starts each server and listener, writes
    /// the roster into every replica (the other two devices bound at the
    /// addresses their listeners took; A and B granted organ calls; C
    /// granted sync), and installs the probe on B's host alone.
    async fn start() -> TestResult<Self> {
        let probe = probe_program()?;
        let home = home()?;
        let a = home.enrol(0x0a, ORGAN_ALPN)?;
        let b = home.enrol(0x0b, ORGAN_ALPN)?;
        let c = home.enrol(0x0c, SYNC_ALPN)?;
        home.share_history(&[&a, &b, &c])?;
        let a = Machine {
            served: a.serve().await?,
            device: a,
        };
        let b = Machine {
            served: b.serve().await?,
            device: b,
        };
        let c = Machine {
            served: c.serve().await?,
            device: c,
        };
        // A replica holds no binding of its own install: it binds and
        // grants the other two.
        let roster = [(&a, ORGAN_ALPN), (&b, ORGAN_ALPN), (&c, SYNC_ALPN)];
        for (holder, _) in roster {
            for (peer, alpn) in roster {
                if peer.device.machine != holder.device.machine {
                    holder.device.bind(&peer.device, &peer.served)?;
                    holder.device.grant(&peer.device, alpn)?;
                }
            }
        }
        let mut spec = OrganSpec::first_party(PROBE, probe);
        spec.verbs = PROBE_VERBS.map(String::from).into();
        spec.media_types = vec![BIN.to_owned()];
        install_organ(&b.served.server, spec);
        Ok(Self {
            _home: home,
            a,
            b,
            c,
        })
    }

    async fn stop(mut self) {
        for machine in [&mut self.a, &mut self.b, &mut self.c] {
            machine.served.stop().await;
        }
    }
}

fn call(verb: &str, args: Value, deadline: Duration) -> OrganCall {
    OrganCall {
        organ: PROBE.into(),
        verb: verb.into(),
        schema: 1,
        args,
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline,
        grant: "g".into(),
    }
}

fn touch() -> OrganCall {
    call("organ.touch", Value::Nil, Duration::from_secs(60))
}

fn lent(bytes: Vec<u8>) -> Vec<LentInput> {
    vec![LentInput {
        media_type: BIN.to_owned(),
        bytes,
    }]
}

/// Runs `call` through `from`'s own router, on a blocking thread as the
/// server's callers do (the router blocks on the runtime it was built in).
async fn call_from(
    from: &Machine,
    call: OrganCall,
    lent: Vec<LentInput>,
) -> TestResult<Result<Routed, HostError>> {
    let router = organ_router(&from.served.server);
    let vault = Arc::clone(&from.device.vault);
    tokio::task::spawn_blocking(move || router.call_with(&vault, call, lent, &AskHandlers::none()))
        .await
        .map_err(at("the call's thread"))
}

/// The outcome of a call that ran, and where; a call that waits fails the
/// test with its reason.
fn ran(routed: Routed, step: &str) -> TestResult<(OrganOutcome, RanOn)> {
    match routed {
        Routed::Done { outcome, ran_on } => Ok((outcome, ran_on)),
        Routed::Waiting(wait) => Err(format!("{step}: the call waits: {}", wait.reason).into()),
    }
}

/// The reason of a call that waits; a call that ran fails the test.
fn waited(routed: Routed, step: &str) -> TestResult<String> {
    match routed {
        Routed::Waiting(wait) => Ok(wait.reason),
        Routed::Done { ran_on, .. } => {
            Err(format!("{step}: the call ran ({ran_on:?}) where it must wait").into())
        }
    }
}

fn report_u64(report: &Value, key: &str) -> Option<u64> {
    report
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))?
        .1
        .as_u64()
}

/// The inbound organ-call path receipts `vault` holds for `machine`.
fn organ_path_receipts(vault: &Vault, machine: EntityId) -> Vec<MeshPathReceipt> {
    let alpn = String::from_utf8_lossy(ORGAN_ALPN);
    let machine = machine.to_hex();
    vault
        .mesh_path_receipts(MESH_PATH_RECEIPTS_READ_MAX)
        .unwrap_or_default()
        .into_iter()
        .filter(|receipt| {
            receipt.direction == MeshPathDirection::Inbound
                && receipt.alpn == alpn
                && receipt.machine.as_deref() == Some(machine.as_str())
        })
        .collect()
}

/// Polls `probe` every 250 ms until it holds or `within` passes.
async fn eventually(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(within, async {
        while !probe() {
            // testkit-lint: allow(sleep) poll interval: the listener writes its path receipts and the host its organ status on tasks of their own, which offer no event to await
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .is_ok()
}

#[test]
fn an_organ_call_runs_on_the_owners_other_server_over_the_real_mesh() -> TestResult {
    on_engine_stack(organ_call_runs_on_the_other_server)
}

async fn organ_call_runs_on_the_other_server() -> TestResult {
    let mesh = Mesh::start().await?;
    assert!(
        organ_status(&mesh.a.served.server, PROBE).is_none(),
        "FIXTURE: the asking server must have no probe of its own"
    );

    // Bytes in: a lent input past the 1 MiB message, staged in pieces.
    let input: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
    let routed = call_from(&mesh.a, touch(), lent(input.clone()))
        .await?
        .map_err(at("A's touch"))?;
    let (touched, ran_on) = ran(routed, "A's touch")?;
    assert_eq!(
        ran_on,
        RanOn::Node(mesh.b.device.machine),
        "A's call must run on B, the one node granted and offering the probe"
    );
    assert_eq!(
        report_u64(&touched.report, "len"),
        Some(input.len() as u64),
        "the organ on B must read every byte A lent"
    );
    assert_eq!(
        report_u64(&touched.report, "fold"),
        Some(touch_fold(&input)),
        "the organ on B must read the very bytes A lent"
    );
    // B's receipt holds what B saw: it hashed the reassembled bytes again.
    assert_eq!(touched.receipt.organ.name, PROBE);
    assert_eq!(touched.receipt.verb, "organ.touch");
    assert_eq!(touched.receipt.inputs.len(), 1, "one input line");
    let line = &touched.receipt.inputs[0];
    assert!(line.lent, "the input line must say the bytes were lent");
    assert_eq!(line.len, input.len() as u64);
    assert_eq!(
        line.content_hash,
        Hash32::of(&input),
        "B's receipt must name the blake3 of the bytes A sent"
    );

    // Bytes out: an output past the 1 MiB message comes back in pieces, and
    // A takes it only as the output B's receipt names.
    let args = Value::Map(vec![
        ("count".into(), 1u64.into()),
        ("bytes".into(), (BIG as u64).into()),
    ]);
    let routed = call_from(
        &mesh.a,
        call("probe.outputs", args, Duration::from_secs(60)),
        Vec::new(),
    )
    .await?
    .map_err(at("A's outputs call"))?;
    let (made, ran_on) = ran(routed, "A's outputs call")?;
    assert_eq!(ran_on, RanOn::Node(mesh.b.device.machine));
    assert_eq!(made.outputs.len(), 1, "one output");
    assert_eq!(made.receipt.outputs.len(), 1, "one receipt output line");
    let output = &made.outputs[0];
    let expected = vec![0x5a_u8; BIG];
    assert_eq!(output.len(), BIG, "the whole output must come back");
    assert!(
        output[..] == expected[..],
        "the output A holds must be the bytes the organ made"
    );
    let receipt_line = &made.receipt.outputs[0];
    assert_eq!(output.content_hash, Hash32::of(&expected));
    assert_eq!(receipt_line.content_hash, output.content_hash);
    assert_eq!(receipt_line.len, BIG as u64);
    assert_eq!(receipt_line.name, output.name);

    // B's host ran it, and B's listener admitted A on the organ protocol.
    let b_status = organ_status(&mesh.b.served.server, PROBE).ok_or("B lost its probe")?;
    assert!(b_status.spawns >= 1, "B's host must have started the probe");
    let b_vault = Arc::clone(&mesh.b.device.vault);
    let a_machine = mesh.a.device.machine;
    let admitted = eventually(Duration::from_secs(15), || {
        organ_path_receipts(&b_vault, a_machine)
            .iter()
            .any(|receipt| receipt.outcome == MeshPathOutcome::Admitted)
    })
    .await;
    assert!(
        admitted,
        "B must hold an admitted inbound organ-call path receipt for A: {:?}",
        organ_path_receipts(&b_vault, a_machine)
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_machine_without_the_organ_grant_is_refused_at_the_handshake() -> TestResult {
    on_engine_stack(machine_without_the_organ_grant_is_refused)
}

async fn machine_without_the_organ_grant_is_refused() -> TestResult {
    let mesh = Mesh::start().await?;
    let b_hex = mesh.b.device.machine.to_hex();

    // C's replica names B (and A) as granted organ calls, so C dials them;
    // their replicas grant C sync alone.
    let routed = call_from(&mesh.c, touch(), lent(b"refused".to_vec()))
        .await?
        .map_err(at("C's touch"))?;
    let reason = waited(routed, "C's touch")?;
    assert!(
        reason.contains(&b_hex),
        "C's call must wait, naming B as tried: {reason}"
    );
    let b_vault = Arc::clone(&mesh.b.device.vault);
    let c_machine = mesh.c.device.machine;
    let refused = eventually(Duration::from_secs(15), || {
        organ_path_receipts(&b_vault, c_machine)
            .iter()
            .any(|receipt| receipt.outcome == MeshPathOutcome::Refused)
    })
    .await;
    assert!(
        refused,
        "B must hold a refused inbound organ-call path receipt for C: {:?}",
        organ_path_receipts(&b_vault, c_machine)
    );
    assert!(
        !organ_path_receipts(&b_vault, c_machine)
            .iter()
            .any(|receipt| receipt.outcome == MeshPathOutcome::Admitted),
        "B must never admit C on the organ protocol"
    );
    assert_eq!(
        organ_status(&mesh.b.served.server, PROBE).map(|status| status.spawns),
        Some(0),
        "B's host must start nothing for a machine it never admitted"
    );

    // The refusal is C's alone: A, granted, runs the same call on B.
    let routed = call_from(&mesh.a, touch(), lent(b"admitted".to_vec()))
        .await?
        .map_err(at("A's touch"))?;
    let (_, ran_on) = ran(routed, "A's touch")?;
    assert_eq!(ran_on, RanOn::Node(mesh.b.device.machine));
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_call_in_flight_when_the_serving_server_stops_is_cut_at_the_drain_deadline_and_waits()
-> TestResult {
    on_engine_stack(call_in_flight_when_the_server_stops)
}

async fn call_in_flight_when_the_server_stops() -> TestResult {
    let mut mesh = Mesh::start().await?;
    let b_hex = mesh.b.device.machine.to_hex();

    // A long call on B, under a deadline far past the stop.
    let args = Value::Map(vec![
        ("ms".into(), LONG_SLEEP_MS.into()),
        ("obey_cancel".into(), true.into()),
    ]);
    let router = organ_router(&mesh.a.served.server);
    let vault = Arc::clone(&mesh.a.device.vault);
    let sleeping = call("probe.sleep", args, Duration::from_secs(300));
    let in_flight = tokio::task::spawn_blocking(move || {
        router.call_with(&vault, sleeping, Vec::new(), &AskHandlers::none())
    });
    let b_server = Arc::clone(&mesh.b.served.server);
    let running = eventually(Duration::from_secs(60), || {
        organ_status(&b_server, PROBE)
            .is_some_and(|status| status.spawns >= 1 && matches!(status.state, OrganState::Warm))
    })
    .await;
    assert!(running, "B's host never started the probe for A's call");

    // B's listener stops: it admits nothing new, the admitted call runs on
    // until the drain deadline, then the stop cancels it.
    // testkit-lint: allow(wall-clock) the drain deadline runs on the listener's own clock: this measures it
    let stopping = std::time::Instant::now();
    let listener = mesh
        .b
        .served
        .listener
        .take()
        .ok_or("B's listener is gone")?;
    let stopped = tokio::spawn(listener.stop());
    let routed = in_flight
        .await
        .map_err(at("the call's thread"))?
        .map_err(at("A's sleep"))?;
    let ended_after = stopping.elapsed();
    let reason = waited(routed, "A's sleep")?;
    assert!(
        ended_after >= DRAIN_GRACE.saturating_sub(Duration::from_secs(2)),
        "the admitted call must run on until the drain deadline: it ended {ended_after:?} after the stop"
    );
    assert!(
        ended_after < DRAIN_GRACE + STOP_MARGIN,
        "the stop must cut the call at its drain deadline, not after its {LONG_SLEEP_MS} ms: it ended {ended_after:?} after the stop"
    );
    assert!(
        reason.contains(&b_hex) && reason.contains("interrupted by the host's stop"),
        "A's call must wait with B's word that its stop cut the call short: {reason}"
    );
    stopped.await.map_err(at("B's listener stop"))?;

    // Once B stopped, a new call from A reaches no node and waits.
    let routed = call_from(&mesh.a, touch(), lent(b"after the stop".to_vec()))
        .await?
        .map_err(at("A's touch after B's stop"))?;
    let reason = waited(routed, "A's touch after B's stop")?;
    assert!(
        reason.contains(&b_hex),
        "A's call after B's stop must wait, naming B as tried: {reason}"
    );
    mesh.stop().await;
    Ok(())
}
