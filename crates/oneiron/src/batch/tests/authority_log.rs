//! Authority log, first-seen fold, eviction and identity topology.

use super::*;

#[cfg(feature = "sync")]
fn authority_test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(feature = "sync")]
fn authority_key_from_signing(signing: &SigningKey) -> crate::authority::AuthorityKey {
    crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

#[cfg(feature = "sync")]
fn authority_test_device(key: crate::authority::AuthorityKey) -> crate::authority::DeviceAuthority {
    crate::authority::DeviceAuthority {
        key,
        transport_key_binding: [0; 32],
        attestation: crate::authority::AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: crate::authority::AuthorityTier::Software,
        roles: crate::authority::ROLE_OWNER,
    }
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: authority_test_device(key.clone()),
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_enroll_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: authority_test_device(new_key),
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_first_seen_for_test(vault: &Vault, key: &str) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key)?
        .and_then(|raw| crate::authority::decode_authority_first_seen_secs(&raw)))
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_sidecar_drives_live_fold() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = authority_test_key(74);
    let genesis = authority_genesis_fixture(74);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 75, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(75));

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let enroll_id = vault.put_authority_log_entry(&enroll, test_time_range(2, 2), 2)?;

    let first_seen = authority_first_seen_for_test(&vault, &enroll_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    let fold = vault.authority_fold()?;
    assert!(fold.pending_widens.contains_key(&enroll_hash));
    assert!(!fold.roster.contains_key(&enroll_key));

    let replayed_id = vault.put_authority_log_entry(&enroll, test_time_range(3, 3), 999_999)?;
    assert_eq!(
        replayed_id, enroll_id,
        "a byte-identical replay must land on the same content-derived store key"
    );
    assert_eq!(
        authority_first_seen_for_test(&vault, &enroll_sidecar)?,
        Some(first_seen),
        "metadata-only rewrites must not move local first-seen"
    );

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_sidecar_fold = vault.authority_fold()?;
    assert_eq!(
        missing_sidecar_fold
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None,
        "missing local first-seen data must fail closed instead of trusting entity metadata"
    );
    assert!(!missing_sidecar_fold.roster.contains_key(&enroll_key));
    Ok(())
}

/// ONE-1604-D1 T4: the write door derives the store key from the entry's
/// content hash and returns it; the row is readable under exactly that id.
#[cfg(feature = "sync")]
#[test]
fn put_authority_log_entry_returns_derived_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(90);
    let hash = crate::authority::authority_entry_hash(&genesis)?;

    let id = vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;

    assert_eq!(
        id.as_bytes(),
        &hash[..16],
        "the store key must be the first 16 bytes of the entry hash"
    );
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));
    Ok(())
}

/// ONE-1604-D1 T1: the ONE-1604 regression — an existing AUTHORITY_LOG row can no
/// longer be body-replaced at its store key. A replicated write carrying a
/// DIFFERENT valid signed body for an occupied derived id is rejected (the
/// divergent body derives a different key, so the bind refuses it); the
/// stored bytes and the fold are unchanged. This is the LWW hole closing:
/// before the keystone this same write silently overwrote folded history.
#[cfg(feature = "sync")]
#[test]
fn authority_log_body_divergent_overwrite_rejected_at_store_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(91);
    let id = vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let stored = vault.get_raw(&id)?.expect("authority row must be stored");
    let vault_id_before = vault.authority_fold()?.vault_id;

    // A different, independently valid signed entry — divergent bytes staged
    // at the FIRST entry's occupied store key.
    let divergent = authority_genesis_fixture(92);
    let divergent_body = crate::authority::encode_authority_log_entry_body(&divergent)?;
    let err = vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &divergent_body,
        )
        .commit()
        .expect_err("body-divergent overwrite of a AUTHORITY_LOG row must be rejected");

    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert_eq!(
        vault.get_raw(&id)?,
        Some(stored),
        "local bytes must be kept"
    );
    assert_eq!(vault.authority_fold()?.vault_id, vault_id_before);
    Ok(())
}

/// ONE-1604-D1 T2: a valid entry offered under a NON-derived id is refused at
/// the chokepoint, and nothing is stored under either key.
#[cfg(feature = "sync")]
#[test]
fn authority_log_store_key_mismatch_rejected() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(95);
    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let owner = authority_test_key(95);
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 96, 1);
    let enroll_body = crate::authority::encode_authority_log_entry_body(&enroll)?;
    let derived = crate::authority::authority_log_entity_id(&enroll)?;
    let wrong_id = EntityId::now();

    let err = vault
        .batch()
        .put_replicated(
            &wrong_id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &enroll_body,
        )
        .commit()
        .expect_err("a AUTHORITY_LOG row under a non-derived id must be rejected");

    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert!(!vault.entity_exists(&wrong_id)?);
    assert!(!vault.entity_exists(&derived)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 1, P2-a — chokepoint half): the local write door
/// applies the same dominance as the replicated one. A cross-type squatter at
/// a derived AUTHORITY_LOG key is evicted WITH its indexes — a stale type_index or
/// short-id row pointing at an authority body would corrupt reads — and the
/// same-type append-only rule is untouched by the change.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_cross_type_squatter_and_its_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(97);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    vault.put_entity(
        &derived,
        crate::registry::ENTITY_TYPE_EVENT,
        test_time_range(1, 1),
        1,
        b"squatter",
    )?;
    assert!(vault.entity_exists(&derived)?);

    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis.clone()));

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(crate::registry::ENTITY_TYPE_EVENT, &id)
            )?
            .is_none(),
        "the evicted squatter must leave no type_index row behind"
    );
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(ENTITY_TYPE_AUTHORITY_LOG, &id)
            )?
            .is_some(),
        "the authority row must own the type_index entry at its derived key"
    );
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "the squatter's short-id rows must not survive the eviction"
    );
    drop(rtxn);

    // Same-type append-only is unchanged: a divergent body still cannot
    // overwrite an admitted authority row (it derives a different key).
    let divergent = authority_genesis_fixture(98);
    let divergent_body = crate::authority::encode_authority_log_entry_body(&divergent)?;
    let err = vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(3, 3),
            3,
            &divergent_body,
        )
        .commit()
        .expect_err("dominance must not weaken the same-type append-only guard");
    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, LMDB door): evicting a squatter's ENTITY row is
/// only half the eviction — its incident EDGES are keyed independently
/// (`src|kind|tgt`), so an entity-only eviction would leave a revoked
/// squatter traversable through the graph at a key the authority substrate
/// took over. `deindex_entity` → `delete_related_edges` already sweeps both
/// directions; this pins that guarantee against a future narrowing of the
/// eviction, and is the LMDB twin of the reverse-remat edge sweep.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_cross_type_squatter_incident_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(101);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC1; 16])?;

    for (id, body) in [(&derived, b"squatter"), (&neighbor, b"neighbor")] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_EVENT,
            test_time_range(1, 1),
            1,
            body.as_slice(),
        )?;
    }
    // Both directions: the squatter as edge SOURCE and as edge TARGET.
    vault
        .batch()
        .edge(&derived, EdgeKind::Mentions, &neighbor, 1.0)
        .edge(&neighbor, EdgeKind::Mentions, &derived, 1.0)
        .commit()?;
    assert_eq!(vault.edges_out(&derived)?.len(), 1);
    assert_eq!(vault.edges_in(&derived)?.len(), 1);

    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    assert!(
        vault.edges_out(&derived)?.is_empty(),
        "the squatter's outbound edge rows must not survive the eviction"
    );
    assert!(
        vault.edges_in(&derived)?.is_empty(),
        "the squatter's inbound edge rows must not survive the eviction"
    );
    // The mirrored rows on the NEIGHBOUR's side are the ones a one-sided
    // sweep would strand — they still name the evicted id.
    assert!(
        vault.edges_out(&neighbor)?.is_empty() && vault.edges_in(&neighbor)?.is_empty(),
        "the neighbour's mirrored edge rows must not keep the evicted id reachable"
    );
    Ok(())
}

/// Plants a type-76 (IDENTITY_TOPOLOGY_EVENT) row through the shared write
/// chokepoint, the way the sync ingest door stores a replicated record.
#[cfg(feature = "sync")]
fn put_identity_topology_event_for_test(
    vault: &Vault,
    id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    let data = crate::identity_topology::encode_identity_topology_event_body(record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            occurred: test_time_range(1, 1),
            learned_at: 1,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Plants a type-76 record at `id` through the REPLICATED INGEST door, so the
/// full ARCH-0055 shell reconciliation runs exactly as it does for an honest
/// peer record — the only way to get a squatter that has really installed
/// participant edges.
#[cfg(feature = "sync")]
fn ingest_replicated_identity_topology_event_for_test(
    vault: &Vault,
    id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    let body = crate::identity_topology::encode_identity_topology_event_body(record)?;
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    blob.push(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT);
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&body);
    let header = EntityMetadataHeader::parse(&blob).expect("blob header");
    vault.with_write_txn(|wtxn| {
        crate::sync::bridge::ingest_replicated_identity_topology_event_in_txn(
            vault, wtxn, id, &header, &blob, &body, 7,
        )
        .map(|_| ())
    })
}

/// A structural (mergeable) participant row materialized at `id`.
#[cfg(feature = "sync")]
fn put_topology_participant_for_test(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    vault.put_entity(id, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, body)
}

/// Asserts BOTH halves of the canonical shell pair agree with `present` — a
/// one-sided sweep leaves the mirrored `edges_in` row naming a peer with no
/// ledger writer, which is the residue these regressions exist to catch.
#[cfg(feature = "sync")]
fn assert_shell_edge_pair(
    vault: &Vault,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    present: bool,
    context: &str,
) -> Result<()> {
    assert_eq!(
        vault.edge_exists(src, kind, tgt)?,
        present,
        "{context}: outbound {kind:?} edge presence"
    );
    assert_eq!(
        vault
            .edges_in(tgt)?
            .iter()
            .any(|edge| edge.kind == kind && edge.target == *src),
        present,
        "{context}: inbound {kind:?} mirror presence"
    );
    Ok(())
}

/// ONE-1604-D1 PRECEDENCE PIN (fix-leg 3): authority dominance outranks
/// delete protection. `registry::is_delete_protected_engine_record` covers
/// type-76 IDENTITY_TOPOLOGY_EVENT, and every ordinary delete door refuses
/// that kind — but a type-76 row squatting a validated AUTHORITY_LOG row's
/// CONTENT-DERIVED store key is evicted anyway. It has to be: the key is a
/// pure function of fully-validated authority bytes, so a type-76 body can
/// never legitimately hash there; the eviction UNWINDS the squatter's induced
/// shell effects via explicit-source reconciliation (fix-leg 4, pinned by
/// `authority_dominance_unwinds_evicted_type_76_participant_shell_edges`), so
/// for a copied row it is curative; and exempting the protected band would
/// hand a squatter a protected band to suppress a pending RevokeDevice from —
/// the D1 attack dominance exists to close.
///
/// If someone later narrows the eviction to spare delete-protected kinds,
/// THIS TEST MUST FAIL. That is its job: the precedence is a ratified design
/// decision (`gseal-wave2-p1-adjudication`), so changing it needs a design
/// conversation, not a silent edit.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_delete_protected_squatter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(103);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;
    let survivor = EntityId::from_bytes([0xD1; 16])?;
    let loser = EntityId::from_bytes([0xD2; 16])?;
    let squatter_record = crate::identity_topology::StoredIdentityOpEvent {
        seq: 50,
        at: 1,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: crate::identity_topology::StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };

    // The squatter is a REAL delete-protected row at the derived key.
    put_identity_topology_event_for_test(&vault, &derived, &squatter_record)?;
    assert_eq!(
        vault.identity_topology_event(&derived)?.as_ref(),
        Some(&squatter_record),
        "fixture must plant a genuine type-76 row at the derived authority key"
    );

    // Dominance wins: the protected occupant is evicted and the authority
    // row owns its content-derived key.
    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2).expect(
        "authority dominance must evict a delete-protected squatter; if this now fails the eviction was narrowed to exempt protected kinds — that reopens the D1 revocation-suppression squat",
    );
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, &id)
            )?
            .is_none(),
        "the evicted type-76 squatter must leave no type_index row behind"
    );
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(ENTITY_TYPE_AUTHORITY_LOG, &id)
            )?
            .is_some(),
        "the authority row must own the type_index entry at its derived key"
    );
    // Curative, not destructive: the ledger fold no longer sees the copied
    // event, so a replayed type-76 body cannot be counted twice.
    assert!(
        vault.identity_topology_events_in_txn(&rtxn)?.is_empty(),
        "the evicted copy must leave the type-76 ledger family empty"
    );
    drop(rtxn);

    // Control: delete protection for type-76 is genuinely LIVE at an
    // ordinary id — the eviction above is a scoped precedence rule, not a
    // hole in `is_delete_protected_engine_record`.
    let protected = EntityId::from_bytes([0xD3; 16])?;
    put_identity_topology_event_for_test(&vault, &protected, &squatter_record)?;
    let err = vault
        .batch()
        .delete(&protected)
        .commit()
        .expect_err("type-76 rows must stay delete-protected at their own ids");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
    assert!(vault.entity_exists(&protected)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4): evicting a type-76 squatter must UNWIND the shell
/// edges the reconciler installed FROM it.
///
/// The pin above argued eviction "orphans no legitimate structure" because a
/// type-76 event's shell edges name its own id. That is false in the one case
/// that matters. A squatter arriving through the replicated-ingest door is
/// enumerated by `reconcile_identity_topology_edges_in_txn` like any ledger
/// event, so by eviction time it has installed REAL `merged_into` edges on
/// live PARTICIPANT entities — ids the squatter merely names. `deindex_entity`
/// removes only edges incident to the EVENT id, and once the event row is
/// gone it is no longer enumerable, so the full reconciler (touched set
/// derived from SURVIVING events) can never repair those participant edges.
///
/// Left standing they are shell edges with no ledger writer: the ARCH-0055
/// wedge — participant undo hits `EntityNotFound`, the loser stays
/// permanently redirected — reached through authority dominance, i.e. exactly
/// the state type-76 delete protection exists to prevent.
///
/// MUTATION PROBE: drop the explicit-source reconciliation at the end of
/// `apply_ops` and this test fails on the surviving `loser -> survivor` edge.
#[cfg(feature = "sync")]
#[test]
fn authority_dominance_unwinds_evicted_type_76_participant_shell_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(104);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    // Structural participants must be MATERIALIZED, else the reconciler
    // defers and no shell edge is ever installed (the bug needs a real one).
    let survivor = EntityId::from_bytes([0xE1; 16])?;
    let loser = EntityId::from_bytes([0xE2; 16])?;
    put_topology_participant_for_test(&vault, &survivor, b"survivor")?;
    put_topology_participant_for_test(&vault, &loser, b"loser___")?;

    let squatter_record = crate::identity_topology::StoredIdentityOpEvent {
        seq: 50,
        at: 1,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: crate::identity_topology::StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    ingest_replicated_identity_topology_event_for_test(&vault, &derived, &squatter_record)?;

    // PRECONDITION: the induced participant edge genuinely EXISTS. Without
    // it the test proves nothing about unwinding.
    assert!(
        vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "fixture precondition: the squatter must induce a real shell edge on the participants"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        crate::identity_topology::EntityLifecycleState::Merged
    );

    // Admit the authority row; dominance evicts the squatter.
    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    // The event's own edges were never the problem — these are the
    // PARTICIPANT edges the event induced on ids it merely named.
    assert!(
        !vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "the evicted event's induced shell edge must be unwound, not left dangling"
    );
    assert!(
        vault.edges_out(&loser)?.is_empty() && vault.edges_in(&survivor)?.is_empty(),
        "no half of the shell pair may survive its ledger justification"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "with its event gone the loser must fold back to Active"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&survivor)?,
        crate::identity_topology::EntityLifecycleState::Active
    );

    // The ARCH-0055 wedge itself: with the edge gone, the participants are
    // ordinary Active entities again — a fresh merge applies instead of
    // rejecting `NotActive`, and its undo resolves instead of wedging.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    let op =
        crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![loser],
            survivor,
            evidence: crate::identity_topology::IdentityOpEvidence::default(),
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        });
    let event = match vault.apply_identity_topology_op(&op, &write, 3)? {
        crate::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("a post-eviction merge must apply, got {other:?}"),
    };
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    vault
        .undo_identity_topology_event(&event, &write, 4)
        .expect("undo must resolve, not hit EntityNotFound on an orphaned shell");
    assert!(!vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5), direction 1 — evicting an APPLY event UNLOCKS a
/// later merge, so an edge must be CREATED on a participant the evicted event
/// never named.
///
/// Fold shape: squatter apply `T([A] -> B)` shells `A`, which makes the later
/// honest merge `M([A, C] -> D)` fold to REJECTED (`A` is not Active), so `C`
/// carries no edge. Dominance then evicts `T`. `A` folds back to Active, `M`
/// becomes effective, and BOTH `A -> D` and `C -> D` are now mandated — but
/// `C` is not in `T`'s captured source set, so leg 4's explicit-source-only
/// pass never visits it.
///
/// Leg 4's pass alone leaves `C` Active with no edge while the ledger says
/// Merged: the fold and the edge witness disagree, so an undo of `M` is
/// rejected `NotCurrent` and `C`'s topology is permanently stuck.
#[cfg(feature = "sync")]
#[test]
fn evicting_an_apply_creates_unlocked_merge_edges_on_undirect_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(105);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    let a = EntityId::from_bytes([0x51; 16])?;
    let b = EntityId::from_bytes([0x52; 16])?;
    let c = EntityId::from_bytes([0x53; 16])?;
    let d = EntityId::from_bytes([0x54; 16])?;
    put_topology_participant_for_test(&vault, &a, b"aaaaaaaa")?;
    put_topology_participant_for_test(&vault, &b, b"bbbbbbbb")?;
    put_topology_participant_for_test(&vault, &c, b"cccccccc")?;
    put_topology_participant_for_test(&vault, &d, b"dddddddd")?;

    // T: the squatter apply, at the authority row's derived key.
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &derived,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 40,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a],
                survivor: b,
            },
        },
    )?;
    // M: a LATER multi-participant merge sharing only `A` with T. It folds
    // rejected while T stands, so neither of its sources is shelled.
    let m = EntityId::from_bytes([0x11; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &m,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 41,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a, c],
                survivor: d,
            },
        },
    )?;

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, true, "precondition T")?;
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        false,
        "precondition M",
    )?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "precondition: M is rejected while T shells A, so C is untouched"
    );

    // Dominance evicts T. The replay makes M effective.
    assert_eq!(
        vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?,
        derived
    );

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, false, "T unwound")?;
    assert_shell_edge_pair(
        &vault,
        &a,
        EdgeKind::MergedInto,
        &d,
        true,
        "M direct source",
    )?;
    // THE FINDING: C is only reachable through the SURVIVING family.
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        true,
        "M's other source, never named by the evicted event",
    )?;
    for shelled in [&a, &c] {
        assert_eq!(
            vault.entity_lifecycle_state(shelled)?,
            crate::identity_topology::EntityLifecycleState::Merged,
            "the unlocked merge must shell BOTH of its sources"
        );
    }

    // The fold and the edge witness must agree well enough that the follow-up
    // undo of M resolves rather than rejecting NotCurrent.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    vault
        .undo_identity_topology_event(&m, &write, 3)
        .expect("undoing the unlocked merge must resolve for BOTH sources");
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, false, "M undone")?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5), direction 2 — evicting an UNDO event RE-LOCKS the
/// event it reverted, so an edge must be REMOVED from a participant the
/// evicted undo never named. This is the finder's exact shape and the
/// MUTATION PROBE: drop the surviving-family half of
/// `reconcile_shell_edges_after_eviction_in_txn` and this test fails on the
/// surviving `C -> D` edge.
///
/// Fold shape: honest merge `T([A] -> B)`; squatter undo `U(T)` at the
/// authority row's derived key, which reverts T and lets the later honest
/// merge `M([A, C] -> D)` apply, shelling `A` and `C`. Dominance evicts `U`.
/// T is effective again, so `M` folds to REJECTED and BOTH `A -> D` and
/// `C -> D` must go. `U` names only `A` (through the one-hop walk to T), so
/// leg 4's capture reaches `A` and stops — `C` keeps a `merged_into D` edge
/// no surviving ledger event justifies, which is the ARCH-0055 wedge one hop
/// out from where leg 4 closed it.
#[cfg(feature = "sync")]
#[test]
fn evicting_an_undo_removes_relocked_merge_edges_on_undirect_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(106);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    let a = EntityId::from_bytes([0x61; 16])?;
    let b = EntityId::from_bytes([0x62; 16])?;
    let c = EntityId::from_bytes([0x63; 16])?;
    let d = EntityId::from_bytes([0x64; 16])?;
    put_topology_participant_for_test(&vault, &a, b"aaaaaaaa")?;
    put_topology_participant_for_test(&vault, &b, b"bbbbbbbb")?;
    put_topology_participant_for_test(&vault, &c, b"cccccccc")?;
    put_topology_participant_for_test(&vault, &d, b"dddddddd")?;

    let t = EntityId::from_bytes([0x22; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &t,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 40,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a],
                survivor: b,
            },
        },
    )?;
    // U: the squatter, an UNDO of T, parked at the authority row's key.
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &derived,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 41,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Undo { target: t },
        },
    )?;
    // M: applies only because U reverted T.
    let m = EntityId::from_bytes([0x33; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &m,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 42,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a, c],
                survivor: d,
            },
        },
    )?;

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, false, "T reverted")?;
    assert_shell_edge_pair(
        &vault,
        &a,
        EdgeKind::MergedInto,
        &d,
        true,
        "M direct source",
    )?;
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, true, "M other source")?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Merged
    );

    // Dominance evicts U. The replay re-locks T and rejects M.
    assert_eq!(
        vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?,
        derived
    );

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, true, "T re-locked")?;
    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &d, false, "M rejected")?;
    // THE FINDING / MUTATION PROBE: C is neither U's direct source nor
    // reachable through U's one-hop walk to T.
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        false,
        "M's other source must lose the edge no surviving event justifies",
    )?;
    assert_eq!(
        vault.entity_lifecycle_state(&a)?,
        crate::identity_topology::EntityLifecycleState::Merged,
        "A is shelled by the re-locked T, not by the rejected M"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "with M rejected, C must fold back to Active"
    );

    // C is an ordinary Active entity again: a fresh merge applies instead of
    // rejecting NotActive, and its undo resolves instead of wedging.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    let op =
        crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![c],
            survivor: d,
            evidence: crate::identity_topology::IdentityOpEvidence::default(),
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        });
    let event = match vault.apply_identity_topology_op(&op, &write, 3)? {
        crate::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("a post-eviction merge on C must apply, got {other:?}"),
    };
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, true, "fresh merge")?;
    vault
        .undo_identity_topology_event(&event, &write, 4)
        .expect("undo must resolve, not hit a stranded shell");
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, false, "fresh undo")?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_write_does_not_mark_legacy_backfill_complete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(86);

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(
                &rtxn,
                crate::authority::authority_first_seen_backfill_sync_key(),
            )?
            .is_none(),
        "a single authority write must not suppress the legacy sidecar scan"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_ignores_future_learned_at_metadata() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(87);
    let genesis_hash = crate::authority::authority_entry_hash(&genesis)?;
    let genesis_sidecar = crate::authority::authority_first_seen_sync_key(&genesis_hash);
    let future_learned_at = crate::unix_seconds_now()
        .saturating_add(crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS);

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), future_learned_at)?;

    let first_seen = authority_first_seen_for_test(&vault, &genesis_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    assert!(
        first_seen < future_learned_at,
        "local first-seen must come from local observation time, not future learned_at metadata"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_fold_backfills_legacy_missing_first_seen_sidecars_once() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    // Make wall/authority clock skew deterministic without sleeps. This local
    // time is still past learned_at (2) + the 86_400-second widening delay.
    let clock_domain = vault.store.authority_clock_domain;
    assert_eq!(
        crate::authority::authority_observation_secs_for_domain(clock_domain, 0, 1_000_000),
        1_000_000
    );
    let owner = authority_test_key(84);
    let genesis = authority_genesis_fixture(84);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 85, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(85));

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    vault.put_authority_log_entry(&enroll, test_time_range(2, 2), 2)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        vault.store.sync_state.delete(
            wtxn,
            crate::authority::authority_first_seen_backfill_sync_key(),
        )?;
        Ok(())
    })?;

    // The authority clock is already anchored; deleting sidecars does not reset
    // it. Bracket migration in that same clock domain, not raw wall time, which
    // can cross a second before the anchor does.
    let clock_key = crate::authority::authority_first_seen_clock_sync_key();
    let previous_floor = authority_first_seen_for_test(&vault, clock_key)?
        .expect("authority writes must persist the observation clock");
    let observed_before = crate::authority::authority_observation_secs_for_domain(
        clock_domain,
        previous_floor,
        crate::unix_seconds_now(),
    );
    let backfilled_fold = vault.authority_fold()?;
    let observed_after = authority_first_seen_for_test(&vault, clock_key)?
        .expect("the fold must persist the observation clock");
    // fix-leg 4: the migration dates a legacy row at LOCAL OBSERVATION time, not
    // at the peer-written `learned_at` in its header. Trusting the header let a
    // sidecar-less `EnrollDevice` claiming `learned_at = 0` present as matured
    // before it arrived. The consequence here is that the migrated enrollment
    // starts its delay now, so it stays PENDING and its key stays out of the
    // roster — a legacy widen serves its window once rather than skipping it.
    let migrated = authority_first_seen_for_test(&vault, &enroll_sidecar)?
        .expect("migration must write a sidecar");
    assert!(
        (observed_before..=observed_after).contains(&migrated),
        "migrated first-seen ({migrated}) must be in the local observation interval \
         {observed_before}..={observed_after}, not learned_at (2)"
    );
    assert!(
        backfilled_fold.pending_widens.contains_key(&enroll_hash),
        "an enrollment first observed at migration time is inside its delay"
    );
    assert_eq!(
        backfilled_fold
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        Some(migrated),
        "the fold must use the migrated local observation"
    );
    assert!(!backfilled_fold.roster.contains_key(&enroll_key));

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_after_marker = vault.authority_fold()?;
    assert!(
        !missing_after_marker.roster.contains_key(&enroll_key),
        "after migration, a missing sidecar must still fail closed"
    );
    assert_eq!(
        missing_after_marker
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_authority_log_rejects_foreign_vault_root() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let local = authority_genesis_fixture(72);
    vault.put_authority_log_entry(&local, test_time_range(1, 1), 1)?;

    // The row carries its own CORRECT content-derived id, so the store-key
    // bind passes and the foreign-root rejection is what is actually under
    // test (ONE-1604-D1 checks precede the vault-id fold check).
    let foreign = authority_genesis_fixture(73);
    let foreign_body = crate::authority::encode_authority_log_entry_body(&foreign)?;
    let foreign_id = crate::authority::authority_log_entity_id(&foreign)?;
    let err = vault
        .batch()
        .put_replicated(
            &foreign_id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &foreign_body,
        )
        .commit()
        .expect_err("foreign authority log must not enter replicated storage");

    assert_eq!(err.kind(), ErrorKind::InvalidAuthorityLogBody);
    Ok(())
}
