//! NOTE body ABI: the pinned four keys, the closed kind, and the negative
//! set the decoder must fail closed on.

use rmpv::Value;

use super::*;
use crate::error::{Error, RecordError};

fn actor(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("actor id")
}

fn take(markdown: &str) -> NoteBody {
    NoteBody {
        kind: NoteKind::parse("opinion/take").expect("shipped kind"),
        author_ref: NoteActor::Actor(actor(0x7a)),
        markdown: markdown.to_owned(),
        source_revision_ref: [0x42; 16],
    }
}

/// Encodes an arbitrary map so the negative cases can express bodies the
/// public encoder refuses to produce.
fn encode_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode map");
    out
}

#[test]
fn decode_rejects_every_abi_deviation() {
    let author = actor(0x7a);

    // Trailing bytes after an otherwise valid map.
    let mut trailing = encode_note_body(&take("solid")).expect("encode");
    trailing.push(0xC0);
    assert!(decode_note_body(&trailing).is_err(), "trailing bytes");

    // Not MessagePack at all, and MessagePack that is not a map.
    assert!(decode_note_body(&[0xFF, 0xFF, 0xFF]).is_err(), "garbage");
    let mut not_a_map = Vec::new();
    rmpv::encode::write_value(&mut not_a_map, &Value::from("opinion/take")).expect("encode");
    assert!(decode_note_body(&not_a_map).is_err(), "non-map body");

    // Unknown key alongside the pinned four.
    let unknown_key = encode_map(vec![
        (Value::from("kind"), Value::from("opinion/take")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
        (Value::from("author_display"), Value::from("Ada")),
    ]);
    assert!(decode_note_body(&unknown_key).is_err(), "unknown key");

    // Duplicate key — last-write-wins would let a writer smuggle a second
    // author past a reader that stops at the first.
    let duplicate = encode_map(vec![
        (Value::from("kind"), Value::from("opinion/take")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("author_ref"), Value::from(actor(0x7b).to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
    ]);
    assert!(decode_note_body(&duplicate).is_err(), "duplicate key");

    // Non-string key.
    let int_key = encode_map(vec![(Value::from(1), Value::from("opinion/take"))]);
    assert!(decode_note_body(&int_key).is_err(), "non-string key");

    // Unknown kind on the wire.
    let unknown_kind = encode_map(vec![
        (Value::from("kind"), Value::from("not_registered")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
    ]);
    assert!(decode_note_body(&unknown_kind).is_err(), "unknown kind");

    // Invalid actor bytes: wrong length, non-hex, and wrong MessagePack type.
    for bad_actor in [
        Value::from("deadbeef"),
        Value::from("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        Value::Binary(author.as_bytes().to_vec()),
    ] {
        let body = encode_map(vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), bad_actor.clone()),
            (Value::from("markdown"), Value::from("solid")),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]);
        assert!(decode_note_body(&body).is_err(), "actor {bad_actor:?}");
    }

    // Blank markdown, on both the decode and the encode side.
    for blank in ["", "   ", "\n\t "] {
        let body = encode_map(vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from(blank)),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]);
        assert!(decode_note_body(&body).is_err(), "blank {blank:?} decode");
        assert!(
            encode_note_body(&take(blank)).is_err(),
            "blank {blank:?} encode"
        );
    }

    // Missing keys in an inline core are rejected.
    for omit in ["kind", "author_ref", "markdown", "source_revision_ref"] {
        let entries = vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from("solid")),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]
        .into_iter()
        .filter(|(key, _)| key.as_str() != Some(omit))
        .collect();
        assert!(
            decode_note_body(&encode_map(entries)).is_err(),
            "missing {omit}"
        );
    }
}

#[test]
fn brief_kind_round_trip_is_person_stamped_and_fail_closed() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let actor = actor(0x61);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let contract = memory.bless_brief_kind().unwrap();
    assert_eq!(contract.person(), actor);
    assert_eq!(contract.extraction, NoteExtractionDefault::Disabled);
    assert_eq!(contract.context, NoteContextDefault::RelationshipScoped);
    assert_eq!(contract.retention, NoteRetentionDefault::Durable);
    assert_eq!(vault.brief_kind_contract().unwrap(), Some(contract.clone()));
    assert_eq!(
        BriefKindContract::decode(&contract.encode().unwrap()).unwrap(),
        contract
    );
    let value: serde_json::Value = serde_json::from_slice(&contract.encode().unwrap()).unwrap();
    for (field, invalid) in [
        ("version", serde_json::json!(2)),
        ("person", serde_json::json!("not-an-entity-id")),
        ("extraction", serde_json::json!("allowed")),
        ("context", serde_json::json!("global")),
        ("retention", serde_json::json!("ephemeral")),
        ("grant", serde_json::json!("owner")),
    ] {
        let mut malformed = value.clone();
        malformed[field] = invalid;
        assert!(matches!(
            BriefKindContract::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
    }
    for field in ["version", "person", "extraction", "context", "retention"] {
        let mut malformed = value.clone();
        malformed.as_object_mut().unwrap().remove(field);
        assert!(matches!(
            BriefKindContract::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
    }
    for tag in ["brief", "unknown.pack"] {
        let body = NoteBody {
            kind: NoteKind::Plugin(tag.into()),
            author_ref: NoteActor::Actor(actor),
            markdown: "authored".into(),
            source_revision_ref: [0x42; 16],
        };
        assert_eq!(
            decode_note_body(&encode_note_body(&body).unwrap()).unwrap(),
            body
        );
    }
    assert_eq!(
        NOTE_BODY_KEYS,
        ["kind", "author_ref", "markdown", "source_revision_ref"]
    );
}

/// Roots `vault` with a single-key authority and binds `owner` as its human
/// owner, so the owner mints delegating `diary.read` grants.
fn diary_owner_binding(vault: &crate::Vault, seed: u8, owner: EntityId) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        let transcript =
            crate::authority::authority_transcript(&entry).expect("authority transcript");
        entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        entry
    };
    let genesis = sign(AuthorityLogEntry {
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
            genesis_nonce: [seed.wrapping_add(10); 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    });
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let bind = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq: 1,
        parent_hashes: vec![
            crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
        ],
        op: AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: owner,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 101,
    });
    let time = |at: u64| crate::TimeRange { start: at, end: at };
    vault
        .put_authority_log_entries(&[(genesis, time(1), 1), (bind, time(2), 2)])
        .expect("atomic genesis owner-binding");
}

#[test]
fn diary_round_trip_and_revision_are_required() {
    use crate::memory::{DiaryReadOutcome, DiaryReadsRequest};

    // LABEL-05 (ARCH-0032 #private-reads): author-only is the DEFAULT for a
    // diary, not a lock. By default only the author reads; an Owner's grant
    // widens who reads, through the reason-logged door.
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let author = actor(0x7a);
    let stranger = actor(0x7b);
    let note_id = actor(0x7c);
    let diary = NoteBody {
        kind: NoteKind::parse("diary").expect("shipped kind"),
        author_ref: NoteActor::Actor(author),
        markdown: "private journal".to_owned(),
        source_revision_ref: [0x42; 16],
    };
    // The logical projection round-trips.
    let body_bytes = encode_note_body(&diary).expect("encode diary");
    assert_eq!(decode_note_body(&body_bytes).expect("decode diary"), diary);
    // The stored row round-trips.
    let core_bytes = encode_note_core(&diary.core()).expect("encode diary core");
    assert_eq!(
        decode_note_core(&core_bytes).expect("decode diary core"),
        diary.core()
    );
    let txn = vault.store.env.read_txn().unwrap();
    let readable = |id: &EntityId, bytes: &[u8], reader: Option<&EntityId>| {
        note_body_readable(&vault.store, &txn, id, bytes, reader).unwrap()
    };
    // By default only the author reads.
    assert!(!readable(&note_id, &core_bytes, None));
    assert!(!readable(&note_id, &core_bytes, Some(&stranger)));
    assert!(readable(&note_id, &core_bytes, Some(&author)));
    // An invalid revision fails closed: the logical projection refuses it
    // and it reads to no one, not even the author.
    for revision in [
        Value::Nil,
        Value::Binary(vec![1; 15]),
        Value::Binary(vec![1; 17]),
        Value::from("opaque"),
    ] {
        let bytes = encode_map(vec![
            (Value::from("kind"), Value::from("diary")),
            (
                Value::from("author_ref"),
                Value::from(diary.author_ref.to_wire()),
            ),
            (Value::from("markdown"), Value::from("private")),
            (Value::from("source_revision_ref"), revision),
        ]);
        assert!(matches!(
            decode_note_body(&bytes),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
        assert!(!readable(&note_id, &bytes, Some(&author)));
    }
    // ... and the stored row refuses an invalid revision too.
    for revision in [
        Value::Nil,
        Value::Binary(vec![1; 15]),
        Value::Binary(vec![1; 17]),
        Value::from("opaque"),
    ] {
        let bytes = encode_map(vec![
            (Value::from("kind"), Value::from("diary")),
            (
                Value::from("author_ref"),
                Value::from(diary.author_ref.to_wire()),
            ),
            (Value::from("source_revision_ref"), revision),
        ]);
        assert!(matches!(
            decode_note_core(&bytes),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
        assert!(!readable(&note_id, &bytes, Some(&author)));
    }
    drop(txn);

    // An Owner's grant widens the default: the grantee then reads through
    // the reason-logged door. Owning the vault alone reads nothing.
    let grant_dir = tempfile::tempdir().unwrap();
    let grant_vault = crate::Vault::open(grant_dir.path(), crate::VaultConfig::default()).unwrap();
    let put_person = |seed: u8| {
        let id = actor(seed);
        grant_vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
        id
    };
    let agent = put_person(0xA1);
    let reader = put_person(0xA2);
    let owner = grant_vault.ensure_embedded_owner_actor().unwrap();
    let receipt = grant_vault
        .memory(agent, crate::edge::EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: agent },
            markdown: "private journal entry".to_owned(),
            source_revision_ref: [0xA3; 16],
            mask: None,
        })
        .unwrap();
    let entry = EntityId::from_hex(&receipt.id_hex).unwrap();
    diary_owner_binding(&grant_vault, 0xA4, owner);
    let owner_proof = grant_vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let agent_proof = grant_vault
        .authenticate_owner(
            agent,
            &agent.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    // The author reads its own diary, with no grant and no log row.
    match grant_vault
        .memory(agent, crate::edge::EdgeActorClass::Human)
        .read_agent_diary(Some(&agent_proof), agent, "self review")
        .unwrap()
    {
        DiaryReadOutcome::Granted { read, entries } => {
            assert!(read.is_none());
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, entry);
            assert_eq!(entries[0].markdown, "private journal entry");
        }
        other => panic!("the author reads its own diary, got {other:?}"),
    }
    // Before any grant no one else reads, not even the vault's owner.
    assert!(matches!(
        grant_vault
            .memory(owner, crate::edge::EdgeActorClass::Human)
            .read_agent_diary(Some(&owner_proof), agent, "owner audit")
            .unwrap(),
        DiaryReadOutcome::NotCovered
    ));
    assert!(matches!(
        grant_vault
            .memory(reader, crate::edge::EdgeActorClass::Agent)
            .read_agent_diary(None, agent, "owner audit")
            .unwrap(),
        DiaryReadOutcome::NotCovered
    ));
    // The Owner's grant widens the diary to its named reader.
    grant_vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .grant_diary_read(
            &owner_proof,
            crate::WriteActor::new(reader, crate::edge::EdgeActorClass::Agent),
            agent,
            &[],
        )
        .unwrap();
    match grant_vault
        .memory(reader, crate::edge::EdgeActorClass::Agent)
        .read_agent_diary(None, agent, "owner audit")
        .unwrap()
    {
        DiaryReadOutcome::Granted { read, entries } => {
            assert!(read.is_some());
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, entry);
            assert_eq!(entries[0].markdown, "private journal entry");
        }
        other => panic!("the grantee reads the diary, got {other:?}"),
    }
    // The granted read lands in the agent's log with its reason.
    let log = grant_vault
        .memory(agent, crate::edge::EdgeActorClass::Human)
        .diary_reads(&DiaryReadsRequest {
            limit: None,
            include_used: false,
        })
        .unwrap();
    assert_eq!(log.reads.len(), 1);
    assert_eq!(log.reads[0].reader, reader);
    assert_eq!(log.reads[0].reason, "owner audit");
    assert_eq!(log.reads[0].entries, vec![entry]);
}

fn facet_stamps(vault: &crate::Vault, id: EntityId) -> Vec<EntityId> {
    vault
        .edges_out(&id)
        .unwrap()
        .into_iter()
        .filter(|edge| edge.kind == crate::edge::EdgeKind::FacetOf)
        .map(|edge| edge.target)
        .collect()
}

fn owner_fixture() -> (tempfile::TempDir, crate::Vault, crate::WriteActor) {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let actor = crate::WriteActor::new(owner, crate::edge::EdgeActorClass::Human);
    (dir, vault, actor)
}

fn put_facet(vault: &crate::Vault, seed: u8) -> EntityId {
    let facet = actor(seed);
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .unwrap();
    facet
}

#[test]
fn fork_to_facet_births_a_linked_note_under_the_new_facet() {
    let (_dir, vault, owner) = owner_fixture();
    let note = vault.create_note("research", "origin", owner).unwrap();
    let facet = put_facet(&vault, 0x53);
    let fork = vault.fork_to_facet(note, facet, true, owner).unwrap();
    let out: Vec<_> = vault
        .edges_out(&fork)
        .unwrap()
        .into_iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();

    assert!(
        out.contains(&(crate::edge::EdgeKind::FacetOf, facet))
            && out.contains(&(crate::edge::EdgeKind::DerivedFrom, note))
            && out.contains(&(crate::edge::EdgeKind::Supersedes, note))
    );
}

#[test]
fn fork_to_facet_leaves_the_origin_stamp_unchanged() {
    let (_dir, vault, owner) = owner_fixture();
    let note = vault.create_note("research", "origin", owner).unwrap();
    let default = vault.default_facet().unwrap();
    let facet = put_facet(&vault, 0x54);
    vault.fork_to_facet(note, facet, true, owner).unwrap();

    assert_eq!(facet_stamps(&vault, note), vec![default]);
}

/// Greptile #1336 repro: an owner's fork of a raw claim keeps the claim's
/// citations where the support check reads them. Once a claim's cited source
/// is erased, the claim and the fork that moves it to a facet are both
/// unsupported, and neither recall nor a point read returns the fork. The
/// fork of a claim whose source is live still reads.
#[test]
fn a_fork_keeps_the_support_its_claim_needs() {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    };
    use crate::dreamer_consolidation::{
        ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
    };
    use crate::memory::{Effort, RecallScope};
    let (_dir, vault, owner) = owner_fixture();
    let facet = put_facet(&vault, 0x55);
    let claim = |source: EntityId, text: &str| {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(owner.entity_ref()),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.source = Some(ClaimSource::UserStated);
        body.evidence = Some(encode_consolidation_evidence(
            &ConsolidationEvidenceEnvelope {
                refs: vec![source],
                chain: Vec::new(),
                source_meet: ClaimSource::UserStated,
            },
        ));
        vault
            .put_claim(&id, &body, crate::TimeRange { start: 10, end: 10 }, 10)
            .unwrap();
        id
    };
    let erased = vault
        .create_note("research", "erased source", owner)
        .unwrap();
    let live = vault.create_note("research", "live source", owner).unwrap();
    let unsupported = claim(erased, "aurora erased citation");
    let supported = claim(live, "aurora live citation");
    vault
        .delete_entity_with_options(
            &erased,
            crate::deletion::DeleteEntityOptions { purge: true },
        )
        .unwrap();
    let forks = [unsupported, supported]
        .map(|origin| vault.fork_to_facet(origin, facet, true, owner).unwrap());
    for (id, text) in [
        (forks[0], "aurora erased citation"),
        (forks[1], "aurora live citation"),
    ] {
        vault.batch().text(&id, &[("body", text)]).commit().unwrap();
    }
    let support = {
        let txn = vault.store.env.read_txn().unwrap();
        [unsupported, supported, forks[0], forks[1]].map(|id| {
            let body = vault.get_claim_in_txn(&txn, &id).unwrap().expect("claim");
            crate::claim::has_live_support_in_txn(&vault.store, &txn, &body).unwrap()
        })
    };
    assert_eq!(support, [false, true, false, true]);
    let memory = vault.memory(owner.entity_ref(), owner.actor_class());
    let pack = memory
        .recall(
            "aurora",
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .unwrap();
    let recalled: Vec<_> = pack
        .items
        .iter()
        .filter_map(|item| crate::memory::resolve_entity_ref(&vault, &item.short_id).ok())
        .collect();
    assert!(recalled.contains(&forks[1]), "{recalled:?}");
    assert!(!recalled.contains(&forks[0]), "{recalled:?}");
    let read = |id: EntityId| memory.get_entity(&id.to_hex()).unwrap().value;
    assert!(read(forks[1]).is_some());
    assert!(read(forks[0]).is_none());
}
