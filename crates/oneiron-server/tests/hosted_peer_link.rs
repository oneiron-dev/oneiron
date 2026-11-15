//! L10-16 PR 2: the owner's link of a hosted peer and its unlink (plan
//! `lanes/post-untangle/plans/PLAN-L10-16.md`, Design 1-7; RULING
//! L10-16-UNLINK = A), the acts behind `/v1/owner/link`, over a control
//! plane the test scripts (`oneiron_server::test_doors::linked_peer`): no
//! test can pin an https issuer, so no registration is live, and an
//! in-process server binds no mesh listener. The routes' own gates are in
//! `tests/owner_link_routes.rs`.
//!
//! A link hands the control plane one hosted-node link at the origin the
//! peer redeems it at; its machine enrols as a hosted node, never mine, and
//! the status names it. An unlink revokes the peer here at once (machine
//! removed, the peer's slip and every slip of its machine revoked, its mesh
//! grant gone), asks the control plane to remove it, and says the control
//! plane erases the peer's copy and keys while backups age out; the local
//! vault is untouched. A removal the
//! control plane lost is asked again by the next unlink, and so is a machine
//! removal this install could not sign, while the control plane is still
//! asked. A link the control plane refuses, or one unlinked before it is
//! redeemed, can no longer be redeemed, and a peer that redeemed it before
//! the refusal is revoked as an unlink revokes it. The link keeps its
//! origin's path; an origin a hosted peer does not reach (not https, a
//! loopback or private address) or one with a query or a fragment is
//! refused before anything is minted. A vault holds one hosted peer at a
//! time.
//!
//! The peer's slip is for the owner's PERSON with no actor class (RULING
//! LINK-PEER-AUTHORITY = B): the peer redeems its link over HTTP, and its
//! slip is refused at the owner's link routes and at the pairing-link mint
//! (the mint's refusal needs main's owner check on that door, #8012). An
//! unlink revokes the peer's slip by its id, so a device of the owner's own,
//! whose slip has the same holder, keeps its slip.
//!
//! On unmodified main the file does not build: there is no
//! `test_doors::linked_peer`.
//!
//! Deterministic: in-process vault, a scripted control plane, no TCP ports,
//! no sleeps, no models.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test hosted_peer_link`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, FoldedMachine, HostSlipIssuer, MachineEnrolmentRequest, MachineRole,
    MeshBindingIdentity, MeshEnrolment, PairingRedeemed, pairing_binding_transcript,
    pairing_binding_transcript_pinned, parse_pinned_pairing_link,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::linked_peer::{self, ScriptedControlPlane};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Where the peer redeems: this server as the peer reaches it.
const ORIGIN: &str = "https://laptop.example";

/// The owner's link routes.
const LINK: &str = "/v1/owner/link";

/// The seed of the peer's pairing key: the key its slip is bound to.
const PEER_PAIRING_SEED: [u8; 32] = [0x2c; 32];

/// The ALPN the peer's mesh redeem asks a grant on.
const MESH_ALPN: &[u8] = b"oneiron/hosted-peer-link-test";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The person's own machine, serving the vault: rooted from its install's
/// keystore, its install profiled as a serving start leaves it (or not yet,
/// so it carries no owner act), with one row of its own.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    /// The server's routes, served in process.
    app: Router,
    issuer: HostSlipIssuer,
    /// The owner's PERSON, and his proof.
    person: EntityId,
    owner: AuthenticatedOwner,
    /// A row the local vault holds before any link.
    row: EntityId,
}

fn host() -> Host {
    serving_host(true)
}

fn serving_host(install_profiled: bool) -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("hosted-peer-link".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the owner's root slip");
    if install_profiled {
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("FIXTURE: this install's live machine profile");
    }
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    let row = EntityId::now();
    vault
        .put_entity(
            &row,
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"hosted peer link: a row of the local vault",
        )
        .expect("FIXTURE: a local row");
    let app = build_app(Arc::clone(&server));
    Host {
        _dir: dir,
        vault,
        server,
        app,
        issuer,
        person,
        owner,
        row,
    }
}

impl Host {
    fn link(&self, control: &ScriptedControlPlane) -> Result<Value, String> {
        linked_peer::link(&self.server, &self.owner, ORIGIN, control)
    }

    fn status(&self, control: &ScriptedControlPlane) -> Value {
        linked_peer::status(&self.server, &self.owner, control)
    }

    fn unlink(&self, control: &ScriptedControlPlane) -> Value {
        linked_peer::unlink(&self.server, &self.owner, Some(control)).expect("a linked peer")
    }

    fn fold_machine(&self, machine: EntityId) -> Option<FoldedMachine> {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .cloned()
    }

    fn slip_is_live(&self, slip: &CapabilitySlip) -> bool {
        self.slip_id_is_live(&slip.claims.slip_id)
    }

    fn slip_id_is_live(&self, slip: &[u8; 32]) -> bool {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .slip_is_live(slip)
    }

    /// The live, unexpired slips `holder` holds, by id: those a revoke by
    /// holder revokes.
    fn live_slips_held_by(&self, holder: EntityId) -> Vec<[u8; 32]> {
        let fold = self.vault.authority_fold().expect("authority fold");
        let now = self.vault.now_recorded_at();
        fold.slips
            .mints
            .iter()
            .filter(|(id, mint)| {
                mint.action.claims.holder_ref == holder.to_hex()
                    && now < mint.action.claims.expires_at
                    && fold.slip_is_live(id)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// A device of the owner's own, paired before any link: its slip is
    /// for the owner's PERSON, the holder the peer's slip names too.
    fn owner_device(&self) -> CapabilitySlip {
        let link = self
            .vault
            .issue_pairing_link(&self.issuer, Scope::top(), 3600)
            .expect("FIXTURE: a pairing link");
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let binding_key = key.verifying_key().to_bytes();
        let holder = self.person.to_hex();
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &holder)
            .expect("the binding transcript");
        self.vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder,
                binding_key,
                &key.sign(&transcript).to_bytes(),
            )
            .expect("FIXTURE: the owner's own device pairs")
    }

    /// The peer's binding proof for one request under `slip`, signed with
    /// its pairing key.
    fn peer_binding(&self, slip: &CapabilitySlip) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = slip
            .binding_transcript(challenge.as_bytes())
            .expect("the request transcript");
        let signature = SigningKey::from_bytes(&PEER_PAIRING_SEED).sign(&transcript);
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature.to_bytes())})
            .to_string()
    }

    /// `method` on `uri` over HTTP, under the peer's `slip` when one is
    /// given: the status and the answer, as text when it is not JSON.
    async fn call(
        &self,
        slip: Option<&CapabilitySlip>,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(slip) = slip {
            let token = slip.to_token().expect("the peer's token");
            request = request
                .header("authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", self.peer_binding(slip));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("the request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the answer");
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, answer)
    }
}

/// The hosted peer: its own install, which redeems the one-line link the
/// control plane was handed, as `oneiron device enrol` does.
struct Peer {
    install: Vault,
    _dir: tempfile::TempDir,
    machine: EntityId,
}

impl Peer {
    fn new(host: &Host) -> (Self, MachineEnrolmentRequest) {
        let dir = tempfile::tempdir().expect("temporary peer directory");
        let install = Vault::open(dir.path(), VaultConfig::device()).expect("the peer's install");
        install.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let vault_id = host
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("FIXTURE: a rooted vault");
        let key = install
            .machine_encryption_key(vault_id)
            .expect("FIXTURE: the peer's encryption key");
        let request = install
            .machine_enrolment_request(vault_id, key)
            .expect("FIXTURE: the peer's enrolment request");
        (
            Self {
                install,
                _dir: dir,
                machine: request.machine,
            },
            request,
        )
    }

    /// The peer's mesh endpoint key and the proofs that bind it to its
    /// machine, read as its install's owner, as `oneiron device enrol`
    /// reads them.
    fn mesh_identity(&self) -> MeshBindingIdentity {
        let person = self
            .install
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the peer install's owner");
        let owner = self
            .install
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: the peer install's owner proof");
        self.install
            .mesh_binding_identity_as_owner(&owner)
            .expect("FIXTURE: the peer's mesh identity")
    }
}

/// The peer redeems `line` with `request`, under a throwaway pairing key.
fn redeem(
    host: &Host,
    line: &str,
    request: &MachineEnrolmentRequest,
) -> oneiron::Result<CapabilitySlip> {
    redeem_at(&host.vault, &host.issuer, line, request)
}

/// [`redeem`] at `vault` under its `issuer`.
fn redeem_at(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    line: &str,
    request: &MachineEnrolmentRequest,
) -> oneiron::Result<CapabilitySlip> {
    let (origin, code, holder, pin) = parse_pinned_pairing_link(line)?;
    assert_eq!(
        origin, ORIGIN,
        "the link names the origin the peer redeems at"
    );
    let pairing_key = SigningKey::from_bytes(&PEER_PAIRING_SEED);
    let device_key = pairing_key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript_pinned(&code, &device_key, &holder, pin.as_ref())?;
    vault
        .redeem_machine_pairing_link(
            issuer,
            &code,
            &holder,
            device_key,
            &pairing_key.sign(&transcript).to_bytes(),
            request,
        )
        .map(|(slip, _)| slip)
}

/// [`redeem`] with the peer's mesh identity, as a peer whose mesh listener
/// runs redeems: its endpoint is bound and granted [`MESH_ALPN`].
fn redeem_with_mesh(
    host: &Host,
    line: &str,
    request: &MachineEnrolmentRequest,
    identity: &MeshBindingIdentity,
) -> PairingRedeemed {
    let (_, code, holder, pin) = parse_pinned_pairing_link(line).expect("the handed link parses");
    let pairing_key = SigningKey::from_bytes(&PEER_PAIRING_SEED);
    let device_key = pairing_key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript_pinned(&code, &device_key, &holder, pin.as_ref())
        .expect("the binding transcript");
    host.vault
        .redeem_pairing_link_with_mesh(
            &host.issuer,
            &code,
            &holder,
            device_key,
            &pairing_key.sign(&transcript).to_bytes(),
            request,
            None,
            (identity, MESH_ALPN),
        )
        .expect("the peer redeems with its mesh identity")
}

/// The one link the control plane was handed.
fn handed_link(control: &ScriptedControlPlane) -> String {
    let links = control.links.lock().expect("scripted links");
    assert_eq!(links.len(), 1, "the control plane was handed one link");
    links[0].clone()
}

#[test]
fn a_link_enrols_the_peer_as_a_hosted_node_and_its_status_names_it() {
    run_on_engine_stack("link-enrols-hosted-node", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        let row = host.link(&control).expect("the owner links a hosted peer");
        assert_eq!(row["peer_id"], "peer-1", "{row}");
        assert_eq!(row["cloud_origin"], "https://cloud.example", "{row}");
        assert_eq!(row["machine"], Value::Null, "{row}");

        let status = host.status(&control);
        assert_eq!(status["state"], "linked", "{status}");
        assert_eq!(status["machine"], Value::Null, "not redeemed yet: {status}");
        assert_eq!(status["cloud"]["state"], "provisioning", "{status}");

        let (peer, request) = Peer::new(&host);
        redeem(&host, &handed_link(&control), &request).expect("the peer redeems its link");
        control.enrolled.store(true, Ordering::SeqCst);

        let status = host.status(&control);
        assert_eq!(status["state"], "linked", "{status}");
        assert_eq!(status["peer"]["machine"], peer.machine.to_hex(), "{status}");
        let machine = &status["machine"];
        assert_eq!(machine["machine"], peer.machine.to_hex(), "{status}");
        assert_eq!(machine["hosted_node"], true, "{status}");
        assert_eq!(machine["live"], true, "{status}");
        assert_eq!(
            machine["mine"], false,
            "a hosted node is never mine: {status}"
        );
        assert_eq!(status["cloud"]["state"], "enrolled", "{status}");
    });
}

#[test]
fn an_unlink_revokes_the_peer_at_once_and_leaves_the_local_vault_whole() {
    run_on_engine_stack("unlink-revokes-at-once", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        let before = host.vault.get_raw(&host.row).expect("the local row");
        host.link(&control).expect("the owner links a hosted peer");
        let (peer, request) = Peer::new(&host);
        let slip = redeem(&host, &handed_link(&control), &request).expect("the peer redeems");
        assert!(
            host.slip_is_live(&slip),
            "the peer's slip is live once linked"
        );

        let receipt = host.unlink(&control);
        assert_eq!(
            receipt["machine"]["machine"],
            peer.machine.to_hex(),
            "{receipt}"
        );
        assert_eq!(receipt["machine"]["removed"], true, "{receipt}");
        assert_eq!(receipt["machine"]["live"], false, "{receipt}");
        assert_eq!(receipt["machine_removal"]["state"], "removed", "{receipt}");
        assert!(receipt["slips_revoked"].as_u64() >= Some(1), "{receipt}");
        assert_eq!(receipt["removal"]["state"], "accepted", "{receipt}");
        let erasure = receipt["erasure"]
            .as_str()
            .expect("the receipt says what is erased");
        assert!(erasure.contains("live copy and its keys"), "{erasure}");
        assert!(erasure.contains("90 days or less"), "{erasure}");

        assert!(
            !host.slip_is_live(&slip),
            "the peer's slip is revoked at once"
        );
        let folded = host.fold_machine(peer.machine).expect("the peer's machine");
        let roster = folded.roster.as_ref().expect("its roster chain");
        assert!(
            roster.removed && !roster.is_live(),
            "its machine is removed"
        );
        assert_eq!(
            *control.removals.lock().expect("scripted removals"),
            vec!["peer-1".to_owned()],
            "the control plane was asked to remove the peer"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
        assert_eq!(
            host.vault.get_raw(&host.row).expect("the local row"),
            before,
            "the local vault's own row is untouched"
        );
    });
}

#[test]
fn a_removal_the_control_plane_lost_is_asked_again_by_the_next_unlink() {
    run_on_engine_stack("unlink-removal-lost", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let (peer, request) = Peer::new(&host);
        let slip = redeem(&host, &handed_link(&control), &request).expect("the peer redeems");

        control.lose_remove.store(true, Ordering::SeqCst);
        let receipt = host.unlink(&control);
        assert_eq!(receipt["removal"]["state"], "failed", "{receipt}");
        assert!(
            !host.slip_is_live(&slip),
            "revoked here although the removal was lost"
        );
        let status = host.status(&control);
        assert_eq!(status["state"], "unlink_owed", "{status}");
        assert_eq!(status["machine"]["removed"], true, "{status}");
        assert_eq!(
            host.link(&control),
            Err("AlreadyLinked".to_owned()),
            "no new link while an unlink is owed"
        );

        control.lose_remove.store(false, Ordering::SeqCst);
        let receipt = host.unlink(&control);
        assert_eq!(receipt["removal"]["state"], "accepted", "{receipt}");
        assert_eq!(
            receipt["machine_removal"]["state"], "already_removed",
            "{receipt}"
        );
        assert_eq!(
            receipt["machine"]["machine"],
            peer.machine.to_hex(),
            "{receipt}"
        );
        assert_eq!(
            *control.removals.lock().expect("scripted removals"),
            vec!["peer-1".to_owned()]
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
    });
}

#[test]
fn a_link_the_control_plane_refuses_leaves_nothing_redeemable() {
    run_on_engine_stack("link-refused", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        control.refuse_create.store(true, Ordering::SeqCst);
        let refusal = host.link(&control).expect_err("the control plane refuses");
        assert!(refusal.starts_with("ControlPlane("), "{refusal}");
        assert!(refusal.contains("unlink_owed: false"), "{refusal}");
        assert_eq!(host.status(&control)["state"], "not_linked");
        let line = handed_link(&control);
        let (peer, request) = Peer::new(&host);
        assert!(
            redeem(&host, &line, &request).is_err(),
            "the refused link no longer redeems"
        );
        assert!(
            host.fold_machine(peer.machine).is_none(),
            "nothing enrolled"
        );
    });
}

#[test]
fn an_unlink_before_the_peer_redeems_spends_its_link() {
    run_on_engine_stack("unlink-before-redeem", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let receipt = host.unlink(&control);
        assert_eq!(receipt["machine"], Value::Null, "{receipt}");
        assert_eq!(
            receipt["machine_removal"]["state"], "no_machine",
            "{receipt}"
        );
        assert_eq!(receipt["removal"]["state"], "accepted", "{receipt}");
        let (peer, request) = Peer::new(&host);
        assert!(
            redeem(&host, &handed_link(&control), &request).is_err(),
            "the unlinked link no longer redeems"
        );
        assert!(
            host.fold_machine(peer.machine).is_none(),
            "nothing enrolled"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
    });
}

#[test]
fn a_vault_holds_one_hosted_peer_at_a_time() {
    run_on_engine_stack("one-hosted-peer", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        assert_eq!(host.link(&control), Err("AlreadyLinked".to_owned()));
        assert_eq!(control.links.lock().expect("scripted links").len(), 1);
    });
}

#[test]
fn a_machine_removal_this_install_cannot_sign_still_asks_the_control_plane_and_stays_owed() {
    run_on_engine_stack("unlink-removal-unsigned", || async {
        // No serving start profiled this install: the peer's redeem takes the
        // bootstrap arm, but the owner's removal has no carrier here.
        let host = serving_host(false);
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let (peer, request) = Peer::new(&host);
        let slip = redeem(&host, &handed_link(&control), &request).expect("the peer redeems");

        let receipt = host.unlink(&control);
        assert_eq!(receipt["machine_removal"]["state"], "refused", "{receipt}");
        let reason = receipt["machine_removal"]["reason"]
            .as_str()
            .expect("the refusal says why");
        assert!(reason.contains("no live machine profile"), "{reason}");
        assert_eq!(
            receipt["removal"]["state"], "accepted",
            "the control plane is asked all the same: {receipt}"
        );
        assert!(
            !host.slip_is_live(&slip),
            "the peer's slip is revoked at once all the same"
        );
        let status = host.status(&control);
        assert_eq!(status["state"], "unlink_owed", "{status}");
        assert_eq!(status["machine"]["removed"], false, "{status}");

        host.vault
            .ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered)
            .expect("FIXTURE: this install's live machine profile");
        let receipt = host.unlink(&control);
        assert_eq!(receipt["machine_removal"]["state"], "removed", "{receipt}");
        assert_eq!(
            receipt["machine"]["machine"],
            peer.machine.to_hex(),
            "{receipt}"
        );
        assert_eq!(receipt["machine"]["removed"], true, "{receipt}");
        assert_eq!(receipt["removal"]["state"], "accepted", "{receipt}");
        assert_eq!(
            *control.removals.lock().expect("scripted removals"),
            vec!["peer-1".to_owned(), "peer-1".to_owned()],
            "each unlink asked the control plane"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
    });
}

#[test]
fn a_link_keeps_its_origins_path_and_refuses_one_no_hosted_peer_reaches() {
    run_on_engine_stack("link-origin", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        for origin in [
            "https://laptop.example#pair",
            "https://laptop.example/?via=mail",
            "http://laptop.example",
            "http://127.0.0.1:8080",
            "https://localhost",
            "https://10.0.0.5",
            "https://[::1]",
        ] {
            assert_eq!(
                linked_peer::link(&host.server, &host.owner, origin, &control),
                Err("OriginNotRedeemable".to_owned()),
                "{origin}"
            );
        }
        assert!(
            control.links.lock().expect("scripted links").is_empty(),
            "nothing was handed to the control plane"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");

        linked_peer::link(
            &host.server,
            &host.owner,
            "https://laptop.example/oneiron/",
            &control,
        )
        .expect("the owner links a hosted peer");
        let (origin, ..) =
            parse_pinned_pairing_link(&handed_link(&control)).expect("the handed link parses");
        assert_eq!(origin, "https://laptop.example/oneiron");
    });
}

#[test]
fn a_peer_that_redeemed_before_its_create_was_refused_is_revoked() {
    run_on_engine_stack("early-redeem-revoked", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        let (peer, request) = Peer::new(&host);
        let redeemed = Arc::new(Mutex::new(None));
        {
            let vault = Arc::clone(&host.vault);
            let redeemed = Arc::clone(&redeemed);
            *control.on_create.lock().expect("scripted hook") =
                Some(Box::new(move |line: &str| {
                    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
                    let slip = redeem_at(&vault, &issuer, line, &request)
                        .expect("the peer redeems before the control plane answers");
                    *redeemed.lock().expect("the early slip") = Some(slip);
                }));
        }
        control.refuse_create.store(true, Ordering::SeqCst);

        let refusal = host.link(&control).expect_err("the control plane refuses");
        assert!(refusal.starts_with("ControlPlane("), "{refusal}");
        assert!(refusal.contains("unlink_owed: false"), "{refusal}");
        let slip = redeemed
            .lock()
            .expect("the early slip")
            .take()
            .expect("the peer redeemed its link");
        assert!(
            !host.slip_is_live(&slip),
            "the early peer's slip is revoked"
        );
        let folded = host.fold_machine(peer.machine).expect("the peer's machine");
        assert!(
            folded.roster.as_ref().is_some_and(|roster| roster.removed),
            "its machine is removed"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
    });
}

#[test]
fn a_refused_link_whose_cleanup_stays_owed_says_to_unlink() {
    run_on_engine_stack("link-refused-owed", || async {
        // No serving start profiled this install: the early peer's machine
        // removal has no carrier here, so the refused link's cleanup is owed.
        let host = serving_host(false);
        let control = ScriptedControlPlane::default();
        let (peer, request) = Peer::new(&host);
        {
            let vault = Arc::clone(&host.vault);
            *control.on_create.lock().expect("scripted hook") =
                Some(Box::new(move |line: &str| {
                    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
                    let _slip = redeem_at(&vault, &issuer, line, &request)
                        .expect("the peer redeems before the control plane answers");
                }));
        }
        control.refuse_create.store(true, Ordering::SeqCst);

        let refusal = host.link(&control).expect_err("the control plane refuses");
        assert!(refusal.contains("unlink_owed: true"), "{refusal}");
        assert_eq!(host.status(&control)["state"], "unlink_owed");
        assert_eq!(
            host.link(&control),
            Err("AlreadyLinked".to_owned()),
            "a new link waits for the unlink"
        );

        host.vault
            .ensure_serving_install_profile(&host.issuer, MachineRole::Unanswered)
            .expect("FIXTURE: this install's live machine profile");
        let receipt = host.unlink(&control);
        assert_eq!(receipt["machine_removal"]["state"], "removed", "{receipt}");
        assert_eq!(
            receipt["machine"]["machine"],
            peer.machine.to_hex(),
            "{receipt}"
        );
        assert_eq!(
            receipt["removal"]["state"], "nothing_to_remove",
            "{receipt}"
        );
        assert_eq!(host.status(&control)["state"], "not_linked");
    });
}

#[test]
fn the_peer_redeems_its_link_over_http() {
    run_on_engine_stack("peer-redeems-over-http", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let (peer, request) = Peer::new(&host);
        let (_, code, holder, pin) =
            parse_pinned_pairing_link(&handed_link(&control)).expect("the handed link parses");
        assert_eq!(
            holder,
            host.person.to_hex(),
            "the link names the owner's PERSON as its holder"
        );
        let pairing_key = SigningKey::from_bytes(&PEER_PAIRING_SEED);
        let binding_key = pairing_key.verifying_key().to_bytes();
        let transcript =
            pairing_binding_transcript_pinned(&code, &binding_key, &holder, pin.as_ref())
                .expect("the binding transcript");
        let body = json!({
            "code": code,
            "holder_ref": holder,
            "binding_key": hex(&binding_key),
            "signature": hex(&pairing_key.sign(&transcript).to_bytes()),
            "machine": {
                "vault_id": hex(&request.vault_id),
                "machine": request.machine.to_hex(),
                "machine_key": hex(&request.machine_key),
                "device_class": request.device_class,
                "encryption_suite": request.encryption_key.suite,
                "encryption_key": base64::engine::general_purpose::STANDARD
                    .encode(&request.encryption_key.key),
                "machine_proof": hex(&request.machine_proof),
            },
        });
        let (status, answer) = host
            .call(None, "POST", "/v1/core/pairing/redeem", Some(body))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the HTTP redeem admits the peer: {answer}"
        );
        assert!(
            answer["token"]
                .as_str()
                .is_some_and(|token| token.starts_with("v2.slip.")),
            "{answer}"
        );
        let status = host.status(&control);
        assert_eq!(
            status["machine"]["machine"],
            peer.machine.to_hex(),
            "{status}"
        );
        assert_eq!(status["machine"]["hosted_node"], true, "{status}");
        assert!(
            status["peer"]["slip"].is_string(),
            "the row names the peer's slip: {status}"
        );
    });
}

#[test]
fn the_peers_slip_is_refused_at_the_owner_link_routes() {
    run_on_engine_stack("peer-slip-owner-routes", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let (_peer, request) = Peer::new(&host);
        let slip = redeem(&host, &handed_link(&control), &request).expect("the peer redeems");
        assert_eq!(
            slip.claims.holder_ref,
            host.person.to_hex(),
            "the peer's slip is for the owner's PERSON"
        );
        assert_eq!(slip.claims.actor_class, None, "with no actor class");

        for (method, body) in [
            ("GET", None),
            ("DELETE", None),
            ("POST", Some(json!({"origin": ORIGIN}))),
        ] {
            let (status, answer) = host.call(Some(&slip), method, LINK, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {LINK}: {answer}");
        }
        assert_eq!(
            host.status(&control)["state"],
            "linked",
            "the peer did not unlink itself"
        );
        assert!(host.slip_is_live(&slip), "and its slip stands");
    });
}

#[test]
fn the_peers_slip_cannot_mint_a_pairing_link() {
    run_on_engine_stack("peer-slip-mint", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        let (_peer, request) = Peer::new(&host);
        let slip = redeem(&host, &handed_link(&control), &request).expect("the peer redeems");

        for body in [
            json!({"scope": Scope::top(), "lifetime_secs": 600}),
            json!({"scope": Scope::top(), "lifetime_secs": 600, "machine": "yours"}),
        ] {
            let (status, answer) = host
                .call(
                    Some(&slip),
                    "POST",
                    "/v1/core/pairing/links",
                    Some(body.clone()),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}: {answer}");
        }
    });
}

#[test]
fn an_unlink_leaves_none_of_the_peers_slips_or_mesh_grants_live() {
    run_on_engine_stack("unlink-slips-and-mesh", || async {
        let host = host();
        let control = ScriptedControlPlane::default();
        let own_device = host.owner_device();
        host.link(&control).expect("the owner links a hosted peer");
        let (peer, request) = Peer::new(&host);
        let identity = peer.mesh_identity();
        let redeemed = redeem_with_mesh(&host, &handed_link(&control), &request, &identity);
        let Some(MeshEnrolment::Bound {
            pairing_slip_id,
            endpoint_key,
            ..
        }) = redeemed.mesh
        else {
            panic!(
                "the peer's endpoint is bound with its pairing: {:?}",
                redeemed.mesh
            );
        };
        let peer_slip = redeemed.slip.claims.slip_id;
        assert_eq!(
            redeemed.slip.claims.holder_ref,
            host.person.to_hex(),
            "the peer's slip has the holder the owner's own device has"
        );
        assert!(
            host.vault
                .mesh_grant_permits(peer.machine, endpoint_key, MESH_ALPN)
                .expect("the mesh grant read"),
            "the peer's mesh grant admits it once linked"
        );
        let machine_slips = host.live_slips_held_by(peer.machine);
        assert!(
            machine_slips.contains(&pairing_slip_id),
            "the machine holds its mesh pairing"
        );
        let status = host.status(&control);
        assert_eq!(status["peer"]["slip"], hex(&peer_slip), "{status}");

        let receipt = host.unlink(&control);
        assert_eq!(
            receipt["slips_revoked"].as_u64(),
            u64::try_from(machine_slips.len() + 1).ok(),
            "the peer's slip and each live slip of its machine: {receipt}"
        );
        assert!(
            !host.slip_id_is_live(&peer_slip),
            "the peer's slip is revoked"
        );
        for slip in &machine_slips {
            assert!(
                !host.slip_id_is_live(slip),
                "no slip of its machine stays live"
            );
        }
        assert!(
            host.live_slips_held_by(peer.machine).is_empty(),
            "its machine holds no live slip"
        );
        assert!(
            !host
                .vault
                .mesh_grant_permits(peer.machine, endpoint_key, MESH_ALPN)
                .expect("the mesh grant read"),
            "no mesh grant admits the peer after the unlink"
        );
        assert!(
            host.slip_is_live(&own_device),
            "the owner's own device keeps its slip: the peer's goes by its id, never by holder"
        );
    });
}
