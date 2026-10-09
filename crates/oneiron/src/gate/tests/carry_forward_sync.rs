//! Current-head CRDT replay does not depend on a receiver's local lifecycle history.
use super::*;
use crate::Vault;
use crate::gate::carry_forward_policy::DEFAULT_CARE as CARE_CONFIDENCE_FLOOR;
use crate::sync::{bridge, loro_support, quarantine, schema, types::WindowKey, window};
use crate::write_envelope::carry_forward::{CarryForwardClaim, CarryForwardKind};
use std::sync::Arc;

// Every body below was authored and resolved by THIS build, not hand-crafted
// to make replay pass. The raw blobs are the current entities-map values.
struct SourceHeads {
    _dir: tempfile::TempDir,
    vault: Vault,
    heads: Vec<(EntityId, Vec<u8>)>,
    before_demotion: Vec<u8>,
}

fn source_heads() -> Result<SourceHeads> {
    let (dir, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0x70), &policy)?;
    let approved = test_id(0x30);
    let rejected = test_id(0x31);
    let weakened = test_id(0x32);
    for (id, subject, run) in [
        (approved, test_id(0x50), "carry-sync-approve"),
        (rejected, test_id(0x51), "carry-sync-decline"),
    ] {
        super::carry_forward::park_forward_care(&vault, id, subject, run)?;
    }
    let reviewer = WriteActor::new(test_id(0x40), EdgeActorClass::Agent);
    let owner = consent_bundle_owner(&vault, test_id(0x60))?;
    for (run, action) in [
        ("carry-sync-approve", GateConsentBundleAction::Approve),
        ("carry-sync-decline", GateConsentBundleAction::Decline),
    ] {
        let bundle = vault.review_gate_consent_bundle(&reviewer, run)?;
        vault.resolve_gate_consent_bundle(&owner, bundle.bundle_id, run, action, 9)?;
    }
    let (subject, envelope) =
        super::carry_forward::forward_envelope(&vault, ClaimApprovalStatus::Auto)?;
    vault.put_carry_forward_claim(
        &weakened,
        CarryForwardClaim {
            kind: CarryForwardKind::CareCheckIn,
            subject,
            detail: "follow up after the visit".into(),
            confidence: CARE_CONFIDENCE_FLOOR,
        },
        &envelope,
        test_time(3),
        3,
    )?;
    let before_demotion = vault
        .get_raw(&weakened)?
        .expect("initial high-confidence head");
    vault.apply_claim_demotion(
        &weakened,
        crate::claim::ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.1,
        },
        10,
    )?;
    // A weakening supersedes: the old head closes and a successor carries
    // the lower confidence, so both rows are part of the final state.
    let successor = vault
        .apply_claim_demotion(
            &weakened,
            crate::claim::ClaimDemotionAction::Weaken {
                new_confidence: 0.8,
            },
            11,
        )?
        .claim;
    let final_heads = [approved, rejected, weakened, successor]
        .into_iter()
        .map(|id| Ok((id, vault.get_raw(&id)?.expect("source current head"))))
        .collect::<Result<Vec<_>>>()?;
    Ok(SourceHeads {
        _dir: dir,
        vault,
        heads: final_heads,
        before_demotion,
    })
}

fn same_final_heads(source: &Vault, target: &Vault, heads: &[(EntityId, Vec<u8>)]) -> Result<()> {
    for (id, _) in heads {
        assert_eq!(
            target.get_claim(id)?,
            source.get_claim(id)?,
            "same final CLAIM body at {id:?}"
        );
    }
    assert!(
        quarantine::quarantined_records(target)?.is_empty(),
        "valid current heads are not quarantined"
    );
    Ok(())
}

#[test]
fn fresh_peer_and_forward_rematerialization_accept_final_care_heads() -> Result<()> {
    let fixture = source_heads()?;
    let source = &fixture.vault;
    let heads = &fixture.heads;
    assert_eq!(
        source.get_claim(&heads[0].0)?.expect("approved").approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        source.get_claim(&heads[1].0)?.expect("declined").approval,
        ClaimApprovalStatus::Rejected
    );
    assert_eq!(
        source.get_claim(&heads[2].0)?.expect("weakened").lifecycle,
        crate::ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        source
            .get_claim(&heads[3].0)?
            .expect("successor")
            .confidence,
        0.8
    );
    let key = WindowKey::new("1970-01");
    let doc = schema::create_window_doc("remote", &key);
    let (peer_dir, peer) = temp_vault();
    let peer = Arc::new(peer);
    let materializer = Arc::new(bridge::Materializer::new());
    let _subscription = bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let entities = doc.get_map("entities");
    for (id, blob) in heads {
        loro_support::map_insert_bytes(&entities, &id.to_hex(), blob)?;
    }
    doc.commit(); // Observer B sees only current heads, no local proposal history.
    same_final_heads(source, &peer, heads)?;
    let (_reopen_dir, reopened) = temp_vault();
    assert_eq!(
        window::forward_rematerialize(&reopened, &doc, &bridge::Materializer::new(), &key)?,
        heads.len() as u32
    );
    same_final_heads(source, &reopened, heads)?;
    drop(peer_dir);
    Ok(())
}

#[test]
fn incremental_peer_can_skip_intermediate_demotion_states() -> Result<()> {
    let fixture = source_heads()?;
    let source = &fixture.vault;
    let heads = &fixture.heads;
    let id = heads[2].0;
    let key = WindowKey::new("1970-01");
    let doc = schema::create_window_doc("remote", &key);
    let (_peer_dir, peer) = temp_vault();
    let peer = Arc::new(peer);
    let materializer = Arc::new(bridge::Materializer::new());
    let _subscription = bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    let entities = doc.get_map("entities");
    loro_support::map_insert_bytes(&entities, &id.to_hex(), &fixture.before_demotion)?;
    doc.commit();
    assert_eq!(
        peer.get_claim(&id)?.expect("initial").confidence,
        CARE_CONFIDENCE_FLOOR
    );
    // The peer misses the Decayed state and receives only the final blobs:
    // the closed head and the successor that carries the lower confidence.
    for (head, blob) in &heads[2..] {
        loro_support::map_insert_bytes(&entities, &head.to_hex(), blob)?;
    }
    doc.commit();
    same_final_heads(source, &peer, &heads[2..])?;
    Ok(())
}
