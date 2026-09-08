//! Session/resume serialization, basic entity CRUD, short-ID alias and vault identity.

use super::*;

#[test]
fn resume_budget_invariant_uses_meter_delta() {
    let bundle = sample_resume_bundle(400, 1_000);
    assert_eq!(bundle.budget.tokens_used, 400);
    assert_eq!(bundle.budget.tokens_limit, 1_000);
    assert_eq!(bundle.budget.tokens_remaining, 600);
}

#[test]
fn resume_budget_saturates_when_used_exceeds_limit() {
    let budget = ResumeBudget::from_meter(1_200, 1_000);
    assert_eq!(budget.tokens_used, 1_200);
    assert_eq!(budget.tokens_limit, 1_000);
    assert_eq!(budget.tokens_remaining, 0);
}

#[test]
fn resume_bundle_serde_top_level_keys_are_exact() {
    let value = serde_json::to_value(sample_resume_bundle(400, 1_000)).unwrap();
    let object = value
        .as_object()
        .expect("resume bundle should be an object");
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from(["budget", "notifications", "session", "unprocessed"])
    );
}

#[test]
fn resume_bundle_empty_surfaces_serialize_as_empty_arrays() {
    let bundle = ResumeBundle::new(
        SessionContext {
            api_version: "v1".to_owned(),
            counts: BTreeMap::new(),
            last_activity: None,
            rag_state: EiriSessionRagState::new("default"),
        },
        Vec::new(),
        Vec::new(),
        ResumeBudget::from_meter(0, 0),
    );

    assert_eq!(bundle.notifications, Vec::<NotificationItem>::new());
    assert_eq!(bundle.unprocessed, Vec::<UnprocessedItem>::new());

    let json = String::from_utf8(crate::serialize::serialize_resume_bundle(&bundle)).unwrap();
    assert!(
        json.contains("\"notifications\":[]"),
        "notifications must serialize as an empty array: {json}"
    );
    assert!(
        json.contains("\"unprocessed\":[]"),
        "unprocessed must serialize as an empty array: {json}"
    );
}

#[test]
fn session_context_deserializes_legacy_without_rag_state() {
    let session: SessionContext = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "counts": {},
        "last_activity": null
    }))
    .expect("legacy session context should deserialize");

    assert_eq!(session.rag_state, EiriSessionRagState::default());
}

#[test]
fn encode_edge_key_has_exact_layout() {
    let src = EntityId::from_bytes_unchecked([0x11; 16]);
    let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
    let kind = EdgeKind::DerivedFrom;

    let key = Store::encode_edge_key(&src, kind, &tgt);

    assert_eq!(key.len(), 33);
    assert_eq!(&key[..16], src.as_bytes());
    assert_eq!(key[16], kind as u8);
    assert_eq!(&key[17..], tgt.as_bytes());
}

#[test]
fn open_put_get_delete_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"entity-payload";

    vault.put_entity(&id, 1, test_time_range(10, 20), 30, data)?;
    let got = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(got, data);

    assert!(vault.delete_entity(&id)?);
    assert!(vault.get(&id)?.is_none());
    assert!(!vault.delete_entity(&id)?);

    Ok(())
}

/// The ticket-pinned `mx01` sample: a LEGACY presentation id installed as an
/// alias for a real MACHINE.
///
/// `mx` is deliberately NOT a namespace — it is absent from the entity registry
/// and from `ID_NAMESPACE_REGISTRY`, MACHINE keeps its canonical `mc`, and no
/// phantom production MACHINE is seeded. The literal only resolves because an
/// EXACT alias row for the full id exists, which is precisely the distinction
/// between "declared prefix" and "aliased id".
#[test]
fn mx01_resolves_to_machine_alias() -> Result<()> {
    use crate::registry::id_namespace_for_prefix;

    let (_dir, vault) = open_test_vault();
    let machine = crate::test_util::entity(0x6d);
    vault
        .batch()
        .put_replicated(
            &machine,
            ENTITY_TYPE_MACHINE,
            test_time_range(1, 1),
            2,
            b"workstation",
        )
        .commit()?;

    let (canonical_short_id, content_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, machine.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (short_id, hash) = crate::batch::parse_short_id_value(&value)?;
        (short_id.to_owned(), hash)
    };
    assert!(
        canonical_short_id.starts_with("mc"),
        "MACHINE keeps its canonical prefix, got {canonical_short_id}"
    );

    // Before the alias, `mx01` is a well-formed presentation id that resolves
    // to nothing — parse succeeds, resolution fails. Same for `zz9`.
    for absent in ["mx01", "zz9"] {
        crate::entity_id::parse_presentation_id(absent)
            .unwrap_or_else(|_| panic!("{absent} must PARSE"));
        assert_eq!(
            id_namespace_for_prefix(&absent[..2]),
            None,
            "{absent} must name no declared namespace"
        );
        assert!(
            vault.hydrate_short_id(absent, content_hash)?.is_none(),
            "{absent} must resolve to nothing before any alias exists"
        );
    }

    vault.alias_short_id_to_entity("mx01", &machine)?;

    let hydrated = vault
        .hydrate_short_id("mx01", content_hash)?
        .expect("mx01 resolves through its exact alias row");
    assert_eq!(hydrated.id, machine);
    assert_eq!(hydrated.entity_type, ENTITY_TYPE_MACHINE);

    // The alias admitted ONE id, not a namespace: `mx02` still resolves to
    // nothing, and `mx` is still absent from every registry.
    assert!(vault.hydrate_short_id("mx02", content_hash)?.is_none());
    assert_eq!(id_namespace_for_prefix("mx"), None);
    assert!(
        !crate::registry::ENTITY_TYPE_REGISTRY
            .iter()
            .any(|entry| entry.answers_to_prefix("mx")),
        "mx must never become a canonical or legacy entity prefix"
    );

    // `zz9` stays unresolvable through the same two-layer path — the alias row
    // is the only thing that distinguishes them.
    assert!(vault.hydrate_short_id("zz9", content_hash)?.is_none());
    Ok(())
}

/// ONE-1930 item 6 is WORDING-ONLY. The vault identity algorithm is untouched:
/// genesis derives its vault id from the same BLAKE3 authority-entry hash, at
/// the same 32-byte width. `vtN` is a slug that resolves to this; it is never
/// an input to it.
#[test]
fn blake3_vault_identity_algorithm_unchanged() -> Result<()> {
    use crate::authority::{
        AUTHORITY_HASH_LEN, AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp,
        AuthoritySignature, AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
        authority_entry_hash, authority_transcript, genesis_vault_id,
    };
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [0x41; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    entry.signer.signature = signing
        .sign(&authority_transcript(&entry)?)
        .to_bytes()
        .to_vec();

    let vault_id = genesis_vault_id(&entry)?;
    assert_eq!(
        vault_id,
        authority_entry_hash(&entry)?,
        "genesis_vault_id must remain exactly the authority entry hash"
    );
    assert_eq!(vault_id.len(), AUTHORITY_HASH_LEN);
    assert_eq!(AUTHORITY_HASH_LEN, 32);
    Ok(())
}
