//! Engine ruling 2026-10-13: a vault seeded before canon's critical classes
//! shipped takes the shipped manifest on open, and what waited on its old
//! policy is re-gated, never stranded.

use super::*;
use crate::claim::encode_claim_body;

fn stored(vault: &crate::Vault) -> Vec<u8> {
    let id = crate::gate::default_policy_manifest_id().expect("default manifest id");
    let raw = vault.get_raw(&id).expect("read").expect("seeded manifest");
    raw[ENTITY_METADATA_HEADER_LEN..].to_vec()
}

fn frontier(vault: &crate::Vault) -> [u8; 32] {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::gate::resolve_policy_manifest(&vault.store, &txn)
        .expect("policy")
        .read_frontier_hash()
        .expect("frontier")
}

fn declares_critical(vault: &crate::Vault, predicate: &str) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::gate::resolve_policy_manifest(&vault.store, &txn)
        .expect("policy")
        .declares_predicate_critical(predicate)
}

fn reopen(dir: &tempfile::TempDir) -> crate::Vault {
    crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen vault")
}

/// The old manifest with `residence.` declared critical, as a stand-in for
/// a policy under which a residence correction was held.
fn before_with_residence_critical() -> Vec<u8> {
    let old = crate::Vault::policy_manifest_before_critical_classes_for_test().expect("old");
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut old.as_slice()).expect("decode")
    else {
        panic!("manifest map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("rules")
            && let Value::Array(rules) = value
        {
            rules.push(Value::Map(vec![
                (Value::from("prefix"), Value::from("residence.")),
                (
                    Value::from("axes"),
                    Value::Map(vec![
                        (Value::from("criticality"), Value::from("critical")),
                        (Value::from("sensitivity"), Value::from("normal")),
                    ]),
                ),
            ]));
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode");
    bytes
}

/// Lisbon, then Porto correcting it: the replacement waits on its deferred
/// closure. Returns (Lisbon, Porto).
fn residence_correction(vault: &crate::Vault) -> (EntityId, EntityId) {
    let facade = facade_for(vault, put_person(vault, 0x81));
    let subject = put_person(vault, 0x82);
    let first = facade
        .claim_upsert(&claim_input(
            "residence.city",
            &subject,
            "observed",
            serde_json::json!("Lisbon"),
        ))
        .expect("Lisbon");
    let mut input = claim_input(
        "residence.city",
        &subject,
        "observed",
        serde_json::json!("Porto"),
    );
    input.learned_at = Some(200);
    input.occurred_at = Some(200);
    let second = facade.claim_upsert(&input).expect("Porto");
    let old = facade.resolve_ref(&first.claim_short_id).unwrap();
    let new = facade.resolve_ref(&second.claim_short_id).unwrap();
    assert_eq!(vault.pending_claim_supersession(&new).unwrap(), Some(old));
    (old, new)
}

/// Every waiting consent: (claim, predicate, reasons, frontier).
fn waiting(vault: &crate::Vault) -> Vec<(EntityId, String, Vec<String>, [u8; 32])> {
    let txn = vault.store.env.read_txn().expect("read txn");
    let rows = vault
        .store
        .pending_gate_consents_in_txn(&txn, usize::MAX)
        .expect("pending consents");
    drop(txn);
    rows.into_iter()
        .map(|row| {
            let id = EntityId::from_bytes(row.claim_id).expect("claim id");
            let predicate = vault
                .get_claim(&id)
                .expect("read claim")
                .map_or_else(String::new, |body| body.predicate);
            (id, predicate, row.reason_codes, row.read_frontier_hash)
        })
        .collect()
}

fn approve(vault: &crate::Vault, id: &EntityId) -> crate::Result<()> {
    let body = vault.get_claim(id)?.expect("waiting claim");
    vault
        .approve_inbox_member_with_edit_at(id, &encode_claim_body(&body)?, 300)
        .map(|_| ())
}

/// Check 4 and the install: the untouched seeded default takes the shipped
/// manifest on the first open, stays marked seeded, declares canon's
/// classes critical, and a second open changes nothing.
#[test]
fn an_untouched_seeded_manifest_takes_the_shipped_one_once() {
    let (dir, vault) = open_vault();
    let old = crate::Vault::policy_manifest_before_critical_classes_for_test().unwrap();
    let shipped = crate::gate::default_policy_manifest().unwrap();
    assert_ne!(old, shipped);
    vault
        .install_seeded_policy_manifest_for_test(old.clone())
        .unwrap();
    assert_eq!(stored(&vault), old);
    assert!(!declares_critical(&vault, "health.allergy"));
    drop(vault);

    let vault = reopen(&dir);
    assert_eq!(stored(&vault), shipped);
    {
        let txn = vault.store.env.read_txn().unwrap();
        let id = crate::gate::default_policy_manifest_id().unwrap();
        assert!(
            crate::gate::manifest_authenticity::manifest_is_seeded_default(
                &vault.store,
                &txn,
                &id,
                &shipped
            )
            .unwrap(),
            "the upgraded manifest stays marked seeded"
        );
    }
    for predicate in [
        "health.allergy",
        "safety.recall",
        "legal.contract",
        "boundary.topic",
        "decision.settled",
    ] {
        assert!(declares_critical(&vault, predicate), "{predicate}");
    }
    for predicate in ["residence.city", "decision.made", "profile.name"] {
        assert!(!declares_critical(&vault, predicate), "{predicate}");
    }
    let id = crate::gate::default_policy_manifest_id().unwrap();
    let raw = vault.get_raw(&id).unwrap();
    let frontier_after = frontier(&vault);
    drop(vault);

    let vault = reopen(&dir);
    assert_eq!(
        vault.get_raw(&id).unwrap(),
        raw,
        "a second open changes nothing"
    );
    assert_eq!(frontier(&vault), frontier_after);
}

/// Check 2: a manifest the owner re-authored is never touched, even when its
/// bytes are an older build's seed.
#[test]
fn a_re_authored_manifest_is_left_byte_identical() {
    let (dir, vault) = open_vault();
    let old = crate::Vault::policy_manifest_before_critical_classes_for_test().unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &old,
    )
    .unwrap();
    assert_eq!(stored(&vault), old);
    drop(vault);

    let vault = reopen(&dir);
    assert_eq!(stored(&vault), old);
    assert!(!declares_critical(&vault, "health.allergy"));
}

/// Check 3a and the measure: every consent staged before the upgrade (the
/// critical confirm attached to an Auto claim, a deferred correction, an
/// inbox proposal) re-binds to the new frontier under the verdict it waited
/// under, and the owner's approve then lands. Before, all of them refused as
/// stale.
#[test]
fn waiting_consents_re_bind_and_stay_approvable() {
    let (_dir, vault) = open_vault();
    let old = crate::Vault::policy_manifest_before_critical_classes_for_test().unwrap();
    vault.install_seeded_policy_manifest_for_test(old).unwrap();
    let (lisbon, porto) = residence_correction(&vault);
    // No rule names `pet.name`, so its critical default pends a proposal
    // for the owner under either manifest.
    let facade = facade_for(&vault, put_person(&vault, 0x83));
    let pet = facade
        .claim_upsert(&claim_input(
            "pet.name",
            &put_person(&vault, 0x84),
            "inferred",
            serde_json::json!("Biscuit"),
        ))
        .expect("inferred pet name");
    let pet = facade.resolve_ref(&pet.claim_short_id).unwrap();
    let before = frontier(&vault);
    let rows = waiting(&vault);
    for id in [porto, pet] {
        assert!(rows.iter().any(|row| row.0 == id), "{} waits", id.to_hex());
    }
    assert!(rows.iter().all(|row| row.3 == before));

    let regate = vault.upgrade_seeded_policy_manifest().unwrap();
    assert_eq!(
        regate,
        Some(crate::gate::ConsentRegate {
            rebound: rows.len(),
            restaged: 0,
            stale: 0
        }),
        "the rows that waited: {rows:?}"
    );
    let after = frontier(&vault);
    assert_ne!(after, before);
    let rebound = waiting(&vault);
    assert_eq!(
        rebound
            .iter()
            .map(|row| (row.0, row.2.clone()))
            .collect::<Vec<_>>(),
        rows.iter()
            .map(|row| (row.0, row.2.clone()))
            .collect::<Vec<_>>(),
        "every row keeps the reasons it waited under"
    );
    assert!(rebound.iter().all(|row| row.3 == after));
    assert_eq!(
        vault.get_claim(&porto).unwrap().unwrap().approval,
        ClaimApprovalStatus::Proposed
    );

    approve(&vault, &porto).expect("the owner's approve lands the correction");
    assert_eq!(
        vault.get_claim(&lisbon).unwrap().unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    approve(&vault, &pet).expect("the owner's approve lands the proposal");
    assert_eq!(
        vault.get_claim(&pet).unwrap().unwrap().approval,
        ClaimApprovalStatus::Approved
    );
}

/// Check 3b: a correction held under a policy that declared its class
/// critical, whose verdict the shipped policy changes, is re-staged under
/// the fresh verdict with nothing applied; its later grant then lands it.
#[test]
fn a_held_correction_whose_verdict_changed_is_re_staged_and_its_grant_lands() {
    let (_dir, vault) = open_vault();
    vault
        .install_seeded_policy_manifest_for_test(before_with_residence_critical())
        .unwrap();
    let (lisbon, porto) = residence_correction(&vault);
    assert!(matches!(
        vault.grant_deferred_claim_auto(&porto, 250),
        Err(Error::Gate(_))
    ));

    let rows = waiting(&vault);
    assert!(rows.iter().any(|row| row.0 == porto));

    let regate = vault.upgrade_seeded_policy_manifest().unwrap();
    assert_eq!(
        regate,
        Some(crate::gate::ConsentRegate {
            rebound: rows.len() - 1,
            restaged: 1,
            stale: 0
        }),
        "the rows that waited: {rows:?}"
    );
    let restaged = waiting(&vault);
    for (before, after) in rows.iter().zip(&restaged) {
        assert_eq!(before.0, after.0);
        assert_eq!(
            before.2 == after.2,
            before.0 != porto,
            "only the correction's verdict changed"
        );
    }
    assert_eq!(
        vault.get_claim(&porto).unwrap().unwrap().approval,
        ClaimApprovalStatus::Proposed,
        "the upgrade applies nothing"
    );
    assert_eq!(
        vault.get_claim(&lisbon).unwrap().unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.pending_claim_supersession(&porto).unwrap(),
        Some(lisbon)
    );

    vault
        .grant_deferred_claim_auto(&porto, 260)
        .expect("the grant lands under the new frontier");
    assert_eq!(
        vault.get_claim(&porto).unwrap().unwrap().approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(
        vault.get_claim(&lisbon).unwrap().unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}
