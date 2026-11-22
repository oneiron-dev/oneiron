//! [E2E-KV-GET-PREFILTER]: the keyed store's own reader under a read
//! credential. A transport caller's handle is bound to the slip its request
//! was admitted on (`credential_memory` in oneiron-server), and the keyed
//! reader then cuts its heads to the rows that credential's lane reads
//! (OF-172 D2, FIX 642). That cut used the generic claim admission, which
//! never admits an exact-store claim, so on main every keyed read under a
//! credential answered absent: a committed owner `vault.kv.put` read back
//! as null.
//!
//! The cut still withholds what the credential does not cover: a credential
//! whose records caveat names other rows, and a revoked credential, never
//! read the head.
//!
//! This integration target builds the library and this file only, so it runs
//! independently of unrelated library test targets.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, VerifiedSlip};
use oneiron::memory::{KeyValueAddress, KeyValuePut, KeyValueSearch};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const CHALLENGE: &[u8] = b"oneiron-request:key-value-credential-read";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-key-value-credential").expect("issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    Fixture {
        _dir: dir,
        vault,
        issuer,
        owner,
    }
}

/// A credential minted for the owner as a `human`, from the host root's
/// claims (as oneiron-server's test credentials mint one), with `records`
/// as its records caveat, verified with its holder's signature.
fn owner_credential(
    fixture: &Fixture,
    seed: u8,
    records: BTreeSet<String>,
) -> (CapabilitySlip, VerifiedSlip) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("host root");
    let mut claims = root.claims;
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the owner credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    let verified = fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the owner credential");
    (slip, verified)
}

fn address() -> KeyValueAddress {
    KeyValueAddress {
        namespace: vec!["notes".to_owned(), "host".to_owned()],
        key: "preference".to_owned(),
    }
}

fn put_value(fixture: &Fixture, proof: &VerifiedSlip) -> serde_json::Value {
    let value = json!({"text": "the owner prefers short replies"});
    let address = address();
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(proof)
        .key_value_put(&KeyValuePut {
            namespace: address.namespace,
            key: address.key,
            value: value.clone(),
            request_id: "kv-credential-read-1".to_owned(),
            source: "user_stated".to_owned(),
        })
        .expect("the owner's user_stated put commits");
    value
}

#[test]
fn an_owner_bound_to_its_credential_reads_back_its_committed_value() {
    let fixture = fixture();
    let (_, proof) = owner_credential(&fixture, 0x11, BTreeSet::new());
    let value = put_value(&fixture, &proof);
    let memory = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);

    let item = memory
        .key_value_get(&address())
        .expect("the get answers")
        .expect("the committed value reads back under the owner's credential");
    assert_eq!(item.value, value);

    let found = memory
        .key_value_search(&KeyValueSearch {
            namespace_prefix: vec!["notes".to_owned()],
            filter: None,
            limit: 10,
            offset: 0,
        })
        .expect("the search answers");
    assert_eq!(found.len(), 1, "the search lists the committed head");
    assert_eq!(found[0].value, value);
}

#[test]
fn a_credential_whose_records_caveat_names_other_rows_never_reads_the_head() {
    let fixture = fixture();
    let (_, full) = owner_credential(&fixture, 0x21, BTreeSet::new());
    put_value(&fixture, &full);
    let other = EntityId::now().to_hex();
    let (_, narrow) = owner_credential(&fixture, 0x22, BTreeSet::from([other]));

    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&narrow)
        .key_value_get(&address());
    assert!(
        !matches!(read, Ok(Some(_))),
        "a credential that does not cover the head read it: {read:?}"
    );
}

#[test]
fn a_revoked_credential_never_reads_the_head() {
    let fixture = fixture();
    let (slip, proof) = owner_credential(&fixture, 0x31, BTreeSet::new());
    put_value(&fixture, &proof);
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, slip.claims.slip_id)
        .expect("revoke the owner credential");

    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof)
        .key_value_get(&address());
    assert!(
        !matches!(read, Ok(Some(_))),
        "a revoked credential read the head: {read:?}"
    );
}
