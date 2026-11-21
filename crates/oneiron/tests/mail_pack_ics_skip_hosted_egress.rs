//! [MAIL-PACK-ICS-SKIP-HOSTED-EGRESS]: the Mail & Calendar pack's ICS
//! subscription wire is built on the managed (hosted) node's egress guard
//! when a served host runs a sync step, so an owner-supplied ICS URL whose
//! host is an internal address is refused, by its hosted reason, before any
//! connect. A self-hosted node carries no guard: its wire fetches exactly
//! as before, loopback included.
//!
//! Public paths only. The guarded step is called as the served door calls
//! it (`vault.mail.sources.sync` with the server's hosted egress guard);
//! the unguarded step is the local device's own step.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test mail_pack_ics_skip_hosted_egress`

use std::collections::BTreeSet;
use std::io;
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::mail_pack::{
    ICS_CALENDAR_CONNECTOR_EFFECTOR, MailProvider, MailSourceConnectRequest, MailSourceKind,
    MailSyncBudget,
};
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::store::GateDecisionId;
use oneiron::web_fetch::HostedEgressGuard;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The custody record the test's ICS subscription URL is stored under.
const CUSTODY_REF: &str = "test-ics-subscription";
/// The calendar source's provider id, as a connect names it.
const CALENDAR: &str = "owner-ics-calendar";

/// A vault with the pack installed and the owner's own ICS calendar
/// connected, its subscription URL `url` held in custody as the source's
/// credential, as a connect through the owner secrets form leaves it.
struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    source: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture(url: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    // The pack installs as the embedded owner, whose proof needs the vault's
    // writer lease: open it owned, and start the host as a server does.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"mail pack ics hosted egress test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    oneiron::mail_pack::install_mail_calendar_pack_embedded(&memory)?;
    register_ics_credential(&vault, url)?;
    let connected = memory.mail_sources_connect(&MailSourceConnectRequest {
        provider: MailProvider::Ics,
        kind: MailSourceKind::Calendar,
        address: CALENDAR.to_owned(),
        provider_account: CALENDAR.to_owned(),
        custody_ref: CUSTODY_REF.to_owned(),
        members: Vec::new(),
        for_person: None,
        channel_identity_ref: None,
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
    })?;
    Ok(Fixture {
        vault,
        proof,
        source: EntityId::from_hex(&connected.source.source_ref)?,
        _dir: dir,
    })
}

/// Registers the ICS subscription URL `url` under [`CUSTODY_REF`], stored
/// for the owner and bound with read to the ICS calendar effector, as the
/// owner's custody door registers one.
fn register_ics_credential(vault: &Vault, url: &str) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (
            Value::from("effector"),
            Value::from(ICS_CALENDAR_CONNECTOR_EFFECTOR),
        ),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(vec![Value::from("read")]),
        ),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(CUSTODY_REF)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(url.as_bytes().to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// A managed node's guard with no operator origin excepted: every
/// infrastructure and private-network address is refused, as the server's
/// `hosted_egress_guard()` builds it for a node with none listed.
fn hosted_guard() -> Arc<HostedEgressGuard> {
    Arc::new(HostedEgressGuard::new(
        || BTreeSet::<std::net::IpAddr>::new(),
        BTreeSet::new(),
    ))
}

#[test]
fn hosted_sync_refuses_loopback_ics_url_before_any_connect() -> TestResult {
    // A listener on the very address the subscription names: a fetch that
    // connected would land in its backlog, refused before any connect or
    // not.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let fixture = fixture(&format!("https://127.0.0.1:{port}/feed.ics"))?;

    let outcome = fixture.vault.mail_source_sync_step_with_hosted_guard(
        &fixture.proof,
        fixture.source,
        MailSyncBudget::default(),
        Some(hosted_guard()),
    );
    let error = outcome.expect_err("a hosted node refuses a loopback ICS subscription");
    assert!(
        error.message.contains("hosted_infrastructure"),
        "the refusal names the hosted infrastructure reason: {error:?}"
    );
    assert!(
        !error.message.contains("ics_calendar_transport_failed"),
        "the refusal happens before the transport, not at it: {error:?}"
    );
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        other => panic!("the refused fetch made no connection: {other:?}"),
    }
    Ok(())
}

#[test]
fn hosted_sync_refuses_private_literal_ics_url_before_any_connect() -> TestResult {
    let fixture = fixture("https://10.0.0.1/feed.ics")?;

    let outcome = fixture.vault.mail_source_sync_step_with_hosted_guard(
        &fixture.proof,
        fixture.source,
        MailSyncBudget::default(),
        Some(hosted_guard()),
    );
    let error = outcome.expect_err("a hosted node refuses a private ICS subscription");
    assert!(
        error.message.contains("hosted_private_network"),
        "the refusal names the hosted private-network reason: {error:?}"
    );
    assert!(
        !error.message.contains("ics_calendar_transport_failed"),
        "the refusal happens before the transport, not at it: {error:?}"
    );
    Ok(())
}

#[test]
fn self_hosted_sync_still_fetches_a_loopback_ics_url_as_today() -> TestResult {
    // A listener that takes one connection and drops it at once: the wire's
    // TLS handshake then fails at the transport, as a fetch of a loopback
    // service that is not there fails today.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let fixture = fixture(&format!("https://127.0.0.1:{port}/feed.ics"))?;
    let (sent, heard) = mpsc::channel();
    let acceptor = std::thread::spawn(move || {
        let connected = listener.accept().is_ok();
        let _ = sent.send(connected);
    });

    let outcome = fixture.vault.mail_source_sync_step(
        &fixture.proof,
        fixture.source,
        MailSyncBudget::default(),
    );
    let error = outcome.expect_err("the dropped loopback connection fails the fetch");
    assert!(
        error.message.contains("ics_calendar_transport_failed"),
        "a self-hosted fetch reaches the transport, as before: {error:?}"
    );
    assert!(
        !error.message.contains("hosted_infrastructure")
            && !error.message.contains("hosted_private_network"),
        "no hosted refusal on a self-hosted node: {error:?}"
    );
    assert_eq!(
        heard.recv_timeout(Duration::from_secs(10)),
        Ok(true),
        "the self-hosted wire connected to the loopback service, as today"
    );
    acceptor.join().expect("the acceptor thread ends");
    Ok(())
}
