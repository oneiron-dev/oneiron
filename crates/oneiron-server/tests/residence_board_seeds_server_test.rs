#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! PREDICTED-BOARD-SEED-SIGNAL (lead ruling = A, 21 Nov): a machine reports the items one board
//! showed, and the home records them in its touch log as prefetch seeds of that machine's
//! prediction; the signal is stored and erased like any vault row.
//!
//! - `residence.board_seeds` records each item the proved machine may hold, once, and leaves out
//!   one it may not; it refuses an unproved peer and a report of more than 64 items, and then
//!   records nothing.
//! - An erased item takes its touch rows under every machine, and an erased machine its log.
//! - The whole-vault export carries the touch log as retained rows, and no longer an erased
//!   item's.
//!
//! Red at the base (pin opus-worldfollow/board-seed-signal-red: main plus this file and its test
//! doors): the verb answers no record, the erase leaves the rows, the export carries none.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test residence_board_seeds_server_test`.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PeerMachine,
};
use oneiron::federation::{Scope, ScopeAxis, own_device_residence_scope};
use oneiron::memory::ClaimInput;
use oneiron::sync::{SyncSelector, SyncSelectorWorld, encode_sync_selector};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::predicted_residence::{exported_machine_touches, machine_touches};
use oneiron::test_doors::selector_grant::stand_selector_grant;
use oneiron::{DeleteReason, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::residence::{SlipProof, residence_reply};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The owner's holder-bound read slip and this install's machine proof over it: the token, its
/// binding fields, and the proven peer.
struct Credential {
    peer: PeerMachine,
    token: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

/// Mints the owner's read slip under `issuer` and proves this install's machine over the slip's
/// own binding, as a socket's upgrade proves it.
fn credential(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> TestResult<Credential> {
    let holder = SigningKey::from_bytes(&[0x53; 32]);
    let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
    claims.slip_id = *blake3::hash(b"residence-board-seeds-slip").as_bytes();
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

/// A rooted vault on its install's machine profile, answered as the owner's own machine, with two
/// owner claims, the owner's standing residence grant and selector, and the credential.
struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    machine: EntityId,
    first: EntityId,
    second: EntityId,
    encoded_selector: String,
    credential: Credential,
    _dir: tempfile::TempDir,
}

/// Lands an owner claim and answers its id.
fn owner_claim(vault: &Vault, owner: EntityId, value: &str) -> TestResult<EntityId> {
    let claim = EntityId::now();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.name".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
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
    Ok(claim)
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        // Root under the unit-test host and provision this install, as
        // `oneiron::test_support::provision_engine_machines` does; that module needs
        // `test-support`, which this target does not enable.
        let issuer = HostSlipIssuer::from_secret(b"oneiron unit test host root")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.provision_engine_machine_identities(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        // A carried `Owned(Yours)` stands only with an owner key's proof (row
        // CARRIER-OWNER-PROOF): enrol this install's owner signing key first.
        vault.enrol_device_owner_signing_key(
            &ActAuthority::Owner(owner_proof.clone(), ActSurface::ThisInstall),
            &issuer,
        )?;
        // The owner answers for this install, so its machine proves its key (an Unanswered
        // roster profile proves none).
        let machine = vault
            .local_machine()?
            .map(|local| local.id)
            .ok_or("this install enrolled no machine")?;
        let landing = vault.set_machine_role(
            &owner_proof,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )?;
        assert!(
            landing.held().is_none(),
            "the owner's answer stands, so the install's machine proof verifies"
        );
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("residence-board-seeds-server-test".to_owned()),
                ..Default::default()
            },
        )?);
        let first = owner_claim(&vault, owner, "Board Seed First")?;
        let second = owner_claim(&vault, owner, "Board Seed Second")?;
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
            vault,
            machine,
            first,
            second,
            encoded_selector,
            credential,
            _dir: dir,
        })
    }

    /// One `residence.board_seeds` report of `items` for `peer`, under the fixture slip.
    fn report(&self, peer: PeerMachine, items: &[EntityId]) -> TestResult<Value> {
        let credential = &self.credential;
        let slip = SlipProof {
            token: &credential.token,
            timestamp: credential.timestamp,
            nonce: &credential.nonce,
            signature: &credential.signature,
        };
        let items: Vec<String> = items.iter().map(EntityId::to_hex).collect();
        Ok(residence_reply(
            &self.server,
            &slip,
            peer,
            "residence.board_seeds",
            json!({ "selector": self.encoded_selector, "items": items }),
        )?)
    }

    /// The items the home's touch log holds for `machine`.
    fn touches(&self, machine: EntityId) -> TestResult<Vec<EntityId>> {
        Ok(machine_touches(&self.vault, machine)?)
    }

    /// Hard-erases `id`.
    fn erase(&self, id: EntityId) -> TestResult {
        self.vault
            .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
        Ok(())
    }
}

/// `ids` in the touch log's key order.
fn in_key_order(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_by_key(EntityId::to_hex);
    ids
}

#[tokio::test]
async fn a_board_report_records_each_item_the_machine_may_hold_once() -> TestResult {
    let fixture = Fixture::new()?;
    // Never stored, so this machine may not hold it.
    let absent = EntityId::now();
    let reply = fixture.report(
        fixture.credential.peer,
        &[fixture.first, absent, fixture.second, fixture.first],
    )?;
    assert_eq!(reply["requestId"], 7);
    assert_eq!(reply["result"]["recorded"], 2, "{reply}");
    assert_eq!(
        fixture.touches(fixture.machine)?,
        in_key_order(vec![fixture.first, fixture.second]),
        "the log holds each held item once, and not the absent one"
    );
    Ok(())
}

#[tokio::test]
async fn an_unproved_peer_reports_nothing() -> TestResult {
    let fixture = Fixture::new()?;
    let reply = fixture.report(PeerMachine::Unknown, &[fixture.first])?;
    assert_eq!(reply["error"]["code"], "UNAUTHORIZED", "{reply}");
    assert!(fixture.touches(fixture.machine)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_report_of_more_than_64_items_is_refused_whole() -> TestResult {
    let fixture = Fixture::new()?;
    let mut items = vec![fixture.first];
    items.extend((0..64).map(|_| EntityId::now()));
    assert_eq!(items.len(), 65);
    let reply = fixture.report(fixture.credential.peer, &items)?;
    assert_eq!(reply["error"]["code"], "BAD_REQUEST", "{reply}");
    assert!(
        fixture.touches(fixture.machine)?.is_empty(),
        "a refused report records nothing"
    );
    items.pop();
    let reply = fixture.report(fixture.credential.peer, &items)?;
    assert_eq!(
        reply["result"]["recorded"], 1,
        "64 items are one report: {reply}"
    );
    assert_eq!(fixture.touches(fixture.machine)?, vec![fixture.first]);
    Ok(())
}

#[tokio::test]
async fn an_erased_item_leaves_no_touch_row_under_any_machine() -> TestResult {
    let fixture = Fixture::new()?;
    let other_machine = EntityId::now();
    let vault = &fixture.vault;
    vault.record_machine_touch(fixture.machine, fixture.first)?;
    vault.record_machine_touch(fixture.machine, fixture.second)?;
    vault.record_machine_touch(other_machine, fixture.first)?;
    // The first claim's id in the machine half: the log an erased machine leaves.
    vault.record_machine_touch(fixture.first, fixture.second)?;
    fixture.erase(fixture.first)?;
    assert_eq!(
        fixture.touches(fixture.machine)?,
        vec![fixture.second],
        "the erased item's touch goes and the other item's stays"
    );
    assert!(
        fixture.touches(other_machine)?.is_empty(),
        "the erased item's touch goes under every machine"
    );
    assert!(
        fixture.touches(fixture.first)?.is_empty(),
        "an erased id's own log goes"
    );
    Ok(())
}

#[tokio::test]
async fn the_whole_vault_export_carries_the_touch_log_and_not_an_erased_items_rows() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = &fixture.vault;
    vault.record_machine_touch(fixture.machine, fixture.first)?;
    vault.record_machine_touch(fixture.machine, fixture.second)?;
    let mut expected = vec![
        (fixture.machine, fixture.first),
        (fixture.machine, fixture.second),
    ];
    expected.sort_by_key(|(machine, item)| (machine.to_hex(), item.to_hex()));
    let mut carried = exported_machine_touches(vault)?;
    carried.sort_by_key(|(machine, item)| (machine.to_hex(), item.to_hex()));
    assert_eq!(carried, expected, "the export carries both touch rows");
    fixture.erase(fixture.first)?;
    assert_eq!(
        exported_machine_touches(vault)?,
        vec![(fixture.machine, fixture.second)],
        "after the erase the export carries only the other item's row"
    );
    Ok(())
}
