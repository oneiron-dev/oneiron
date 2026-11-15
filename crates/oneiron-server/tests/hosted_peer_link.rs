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
//! removed, every slip of its holder revoked), asks the control plane to
//! remove it, and says the control plane erases the peer's copy and keys
//! while backups age out; the local vault is untouched. A removal the
//! control plane lost is asked again by the next unlink, and so is a machine
//! removal this install could not sign, while the control plane is still
//! asked. A link the control plane refuses, or one unlinked before it is
//! redeemed, can no longer be redeemed. The link keeps its origin's path;
//! an origin with a query or a fragment is refused before anything is
//! minted. A vault holds one hosted peer at a time.
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

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, FoldedMachine, HostSlipIssuer, MachineRole, pairing_binding_transcript_pinned,
    parse_pinned_pairing_link,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::linked_peer::{self, ScriptedControlPlane};
use oneiron_server::{config::SyncServerConfig, server::SyncServer};
use serde_json::Value;

/// Where the peer redeems: this server as the peer reaches it.
const ORIGIN: &str = "https://laptop.example";

/// The person's own machine, serving the vault: rooted from its install's
/// keystore, its install profiled as a serving start leaves it (or not yet,
/// so it carries no owner act), with one row of its own.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    issuer: HostSlipIssuer,
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
    Host {
        _dir: dir,
        vault,
        server,
        issuer,
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
        self.vault
            .authority_fold()
            .expect("authority fold")
            .slip_is_live(&slip.claims.slip_id)
    }
}

/// The hosted peer: its own install, which redeems the one-line link the
/// control plane was handed, as `oneiron device enrol` does.
struct Peer {
    _dir: tempfile::TempDir,
    machine: EntityId,
}

impl Peer {
    fn new(host: &Host) -> (Self, oneiron::authority::MachineEnrolmentRequest) {
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
                _dir: dir,
                machine: request.machine,
            },
            request,
        )
    }
}

/// The peer redeems `line` with `request`, under a throwaway pairing key.
fn redeem(
    host: &Host,
    line: &str,
    request: &oneiron::authority::MachineEnrolmentRequest,
) -> oneiron::Result<CapabilitySlip> {
    let (origin, code, holder, pin) = parse_pinned_pairing_link(line)?;
    assert_eq!(
        origin, ORIGIN,
        "the link names the origin the peer redeems at"
    );
    let pairing_key = SigningKey::from_bytes(&[0x2c; 32]);
    let device_key = pairing_key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript_pinned(&code, &device_key, &holder, pin.as_ref())?;
    host.vault
        .redeem_machine_pairing_link(
            &host.issuer,
            &code,
            &holder,
            device_key,
            &pairing_key.sign(&transcript).to_bytes(),
            request,
        )
        .map(|(slip, _)| slip)
}

/// The one link the control plane was handed.
fn handed_link(control: &ScriptedControlPlane) -> String {
    let links = control.links.lock().expect("scripted links");
    assert_eq!(links.len(), 1, "the control plane was handed one link");
    links[0].clone()
}

#[test]
fn a_link_enrols_the_peer_as_a_hosted_node_and_its_status_names_it() {
    run_on_engine_stack(async {
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
    run_on_engine_stack(async {
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
    run_on_engine_stack(async {
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
    run_on_engine_stack(async {
        let host = host();
        let control = ScriptedControlPlane::default();
        control.refuse_create.store(true, Ordering::SeqCst);
        let refusal = host.link(&control).expect_err("the control plane refuses");
        assert!(refusal.starts_with("ControlPlane("), "{refusal}");
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
    run_on_engine_stack(async {
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
    run_on_engine_stack(async {
        let host = host();
        let control = ScriptedControlPlane::default();
        host.link(&control).expect("the owner links a hosted peer");
        assert_eq!(host.link(&control), Err("AlreadyLinked".to_owned()));
        assert_eq!(control.links.lock().expect("scripted links").len(), 1);
    });
}

#[test]
fn a_machine_removal_this_install_cannot_sign_still_asks_the_control_plane_and_stays_owed() {
    run_on_engine_stack(async {
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
fn a_link_keeps_its_origins_path_and_refuses_a_query_or_fragment() {
    run_on_engine_stack(async {
        let host = host();
        let control = ScriptedControlPlane::default();
        for origin in [
            "https://laptop.example#pair",
            "https://laptop.example/?via=mail",
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
