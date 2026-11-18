#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RESIDENCE-MEDIA-VECTORS-SERVER-TEST: `residence.media_vectors` serves a
//! proven own machine the text replica of a record it may read, and refuses
//! an unproved peer, an unreadable item and an undeclared space.
//!
//! The engine half (read the replica, land it) is engine-covered; this target
//! covers the door's admission and wire shape through the socket loop's own
//! dispatch. No red on main: the row asks for the missing coverage.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test residence_media_vectors_server_test`.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PeerMachine};
use oneiron::embed::{EmbeddingSpace, InputKind};
use oneiron::federation::{Scope, ScopeAxis, own_device_residence_scope};
use oneiron::memory::ClaimInput;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, encode_sync_selector};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::selector_grant::stand_selector_grant;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::residence::{media_vectors_reply, serve_window};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SPACE_ID: &str = "residence-media-vectors-test@r1@test";
const SPACE_DIMENSIONS: usize = 4;

/// The owner's holder-bound read slip and this install's machine proof over
/// it: the token, its binding fields, and the proven peer.
struct Credential {
    peer: PeerMachine,
    token: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

/// Mints the owner's read slip under `issuer` and proves this install's
/// machine over the slip's own binding, as a socket's upgrade proves it.
fn credential(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> TestResult<Credential> {
    let holder = SigningKey::from_bytes(&[0x52; 32]);
    let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
    claims.slip_id = *blake3::hash(b"residence-media-vectors-slip").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".into()]));
    let slip = vault.mint_capability_slip(issuer, claims)?;
    let token = slip.to_token()?;
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = holder
        .sign(&slip.binding_transcript(challenge.as_bytes())?)
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let (machine, machine_signature) = vault
        .machine_connection_proof(&token, timestamp, &nonce)?
        .expect("this install is a machine of its vault");
    let peer = vault.verify_machine_connection_proof(
        machine,
        &machine_signature,
        &token,
        timestamp,
        &nonce,
    )?;
    assert!(
        matches!(peer, PeerMachine::Proven { .. }),
        "the install's machine proof stands"
    );
    Ok(Credential {
        peer,
        token,
        timestamp,
        nonce,
        signature,
    })
}

/// The door's whole input: a rooted vault on its install's machine profile,
/// the owner's claim with a text vector in a bound space, the claim's served
/// window, and the owner's standing residence grant, selector and credential.
struct Fixture {
    server: Arc<SyncServer>,
    claim: EntityId,
    claim_raw: Vec<u8>,
    encoded_selector: String,
    credential: Credential,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        // Root under the unit-test host and provision this install, as
        // `oneiron::test_support::provision_engine_machines` does; that module
        // needs `test-support`, which this target does not enable.
        let issuer = HostSlipIssuer::from_secret(b"oneiron unit test host root")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.provision_engine_machine_identities(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        // The owner answers for this install, so its machine proves its key
        // (an Unanswered roster profile proves none).
        let machine = vault
            .local_machine()?
            .map(|local| local.id)
            .ok_or("this install enrolled no machine")?;
        vault.set_machine_role(
            &owner_proof,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("residence-media-vectors-server-test".to_owned()),
                ..Default::default()
            },
        )?);
        let claim = EntityId::now();
        let receipt = vault
            .memory(owner, EdgeActorClass::Human)
            .claim_upsert(&ClaimInput {
                id: Some(claim.to_hex()),
                predicate: "profile.name".to_owned(),
                subject_ref: owner.to_hex(),
                value: json!("Media Vector Residence"),
                confidence: 0.9,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            })?;
        assert_eq!(receipt.approval, "auto", "the fixture claim lands");
        let claim_raw = vault.get_raw(&claim)?.expect("the fixture claim is stored");
        vault.seed_embedding_space(EmbeddingSpace {
            id: SPACE_ID.to_owned(),
            dimensions: SPACE_DIMENSIONS,
            accepts: BTreeSet::from([InputKind::Text]),
            query_towers: BTreeSet::from([InputKind::Text]),
            evidence: None,
        })?;
        vault.seed_kind_slot(InputKind::Text, SPACE_ID)?;
        vault.put_media_vector(SPACE_ID, &claim, InputKind::Text, &[0.25, -0.5, 0.75, 1.0])?;
        let window = oneiron::sync::residence::residence_window_for_blob(&claim_raw)?;
        serve_window(&server, window.as_str()).await?;
        let grant_id = stand_selector_grant(
            &vault,
            own_device_residence_scope(),
            owner,
            vault.now_recorded_at(),
        )?;
        let selector = SyncSelector::new(grant_id, owner, SyncSelectorWorld::All, vec![], vec![]);
        let encoded_selector =
            base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector)?);
        let credential = credential(&vault, &issuer, owner)?;
        Ok(Self {
            server,
            claim,
            claim_raw,
            encoded_selector,
            credential,
            _dir: dir,
        })
    }

    /// One `residence.media_vectors` call for `peer`, under the fixture slip.
    fn call(&self, peer: PeerMachine, params: Value) -> TestResult<Value> {
        let credential = &self.credential;
        Ok(media_vectors_reply(
            &self.server,
            &credential.token,
            credential.timestamp,
            &credential.nonce,
            &credential.signature,
            peer,
            params,
        )?)
    }

    /// The call's params for `space` and `id`.
    fn params(&self, space: &str, id: EntityId) -> Value {
        json!({
            "selector": self.encoded_selector,
            "space": space,
            "id": id,
        })
    }
}

#[tokio::test]
async fn a_proven_own_machine_is_served_the_claims_text_replica() -> TestResult {
    let fixture = Fixture::new().await?;
    let reply = fixture.call(
        fixture.credential.peer,
        fixture.params(SPACE_ID, fixture.claim),
    )?;
    assert_eq!(reply["requestId"], 7);
    assert_eq!(reply["last"], true);
    // The wire shape the home's client decodes: one replica of this space,
    // sourced on the claim's exact stored bytes.
    let replicas: Vec<oneiron::embed::MediaVectorReplica> =
        serde_json::from_value(reply["result"].clone())?;
    assert_eq!(replicas.len(), 1, "one replica is served: {reply}");
    let replica = &replicas[0];
    assert_eq!(replica.space_id(), SPACE_ID);
    let digest = *blake3::hash(&fixture.claim_raw).as_bytes();
    assert_eq!(replica.sources(), [(fixture.claim, digest)].as_slice());
    Ok(())
}

#[tokio::test]
async fn an_unproved_peer_is_refused_before_any_read() -> TestResult {
    let fixture = Fixture::new().await?;
    let reply = fixture.call(
        PeerMachine::Unknown,
        fixture.params(SPACE_ID, fixture.claim),
    )?;
    assert_eq!(reply["error"]["code"], "NOT_FOUND", "{reply}");
    Ok(())
}

#[tokio::test]
async fn an_item_the_credential_does_not_read_is_not_found() -> TestResult {
    let fixture = Fixture::new().await?;
    let reply = fixture.call(
        fixture.credential.peer,
        fixture.params(SPACE_ID, EntityId::now()),
    )?;
    assert_eq!(reply["error"]["code"], "NOT_FOUND", "{reply}");
    Ok(())
}

#[tokio::test]
async fn an_undeclared_space_serves_no_replica() -> TestResult {
    let fixture = Fixture::new().await?;
    let reply = fixture.call(
        fixture.credential.peer,
        fixture.params("undeclared-space@r1@test", fixture.claim),
    )?;
    assert_eq!(reply["result"], json!([]), "{reply}");
    Ok(())
}
