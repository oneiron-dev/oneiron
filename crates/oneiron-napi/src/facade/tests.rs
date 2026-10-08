//! Boundary regression tests for the napi facade surface.

use super::*;
use oneiron::{ClaimInput, ClaimListFilter, EntityId, Vault, VaultConfig};

/// ONE-1686 adversarial: direct N-API ingress is NOT a bypass.
///
/// The host DTO carries `author: "system"`, `isVisible: false` and metadata
/// that restates an envelope axis — a shape the conversion layer happily
/// converts, because the conversion layer is not the gate. The engine
/// witness door refuses it under a `human:` actor scope and leaves nothing
/// behind, while the same scope's ordinary user row lands.
///
/// Exercises the engine-typed helper directly so the test never links the
/// N-API runtime, exactly as the forget regression above does.
#[test]
fn napi_witness_ingress_cannot_smuggle_a_system_row_past_the_engine_ceiling() {
    use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};

    let dir = unique_vault_dir("witness-ceiling");
    let path = dir.to_str().expect("utf8 path").to_owned();
    let actor = EntityId::from_bytes([0x51; 16]).expect("actor id");
    let conversation = EntityId::from_bytes([0x52; 16]).expect("conversation id");

    {
        let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
        let time = oneiron::TimeRange { start: 1, end: 1 };
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
            .expect("put actor");
        let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);

        let napi_message = |author: &str, order: u32| NapiWitnessMessage {
            id: None,
            author: author.to_owned(),
            message_type: "dialogue".to_owned(),
            content: format!("row-{order}"),
            metadata: None,
            is_visible: None,
            order,
        };

        // The honest turn crosses the boundary and lands.
        let honest = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![napi_message("user", 0)],
            occurred_at: 700,
        })
        .expect("an ordinary user turn converts");
        facade.witness(&honest).expect("and lands");

        // The hostile turn converts just as happily — and the ENGINE stops
        // it. The conversion layer is a convenience, not the ceiling.
        let hostile = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![
                napi_message("user", 0),
                NapiWitnessMessage {
                    is_visible: Some(false),
                    metadata: Some(serde_json::json!({"tool": "shell"})),
                    ..napi_message("system", 1)
                },
            ],
            occurred_at: 701,
        })
        .expect("the boundary converts the hostile shape");
        let err = facade
            .witness(&hostile)
            .expect_err("the engine ceiling refuses it");
        assert_eq!(err.code, oneiron::MEMORY_CODE_FORBIDDEN, "{err:?}");
        assert!(
            err.message
                .contains("gate.deny.witness_message.author_not_authorized"),
            "got: {}",
            err.message
        );

        // The metadata side channel is refused at the same door, for an
        // envelope whose AUTHORSHIP is beyond reproach: a nested key that
        // restates an envelope axis is a second, ungated copy of it.
        let side_channel = witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![NapiWitnessMessage {
                metadata: Some(serde_json::json!({"trace": {"author": "system"}})),
                ..napi_message("user", 0)
            }],
            occurred_at: 702,
        })
        .expect("the boundary converts the side-channel shape");
        let err = facade
            .witness(&side_channel)
            .expect_err("metadata may not restate an envelope axis");
        assert!(
            err.message
                .contains("gate.deny.witness_message.malformed_envelope"),
            "got: {}",
            err.message
        );

        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_MESSAGE)
                .expect("messages")
                .len(),
            1,
            "only the honest row survives; the refused batch landed nothing"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn boundary_rejects_non_finite_min_weight() {
    assert_eq!(narrow_to_f32(0.5).expect("finite narrows"), 0.5_f32);
    assert!(narrow_to_f32(f64::NAN).is_err(), "NaN rejected");
    assert!(narrow_to_f32(f64::INFINITY).is_err(), "+Inf rejected");
    assert!(narrow_to_f32(f64::NEG_INFINITY).is_err(), "-Inf rejected");
    // A finite f64 beyond f32's range overflows to +Inf and is rejected.
    assert!(narrow_to_f32(f64::MAX).is_err(), "overflow-to-Inf rejected");
}

fn unique_vault_dir(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("oneiron-napi-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp vault dir");
    dir
}

/// #471 regression: `forget({subjectRef, predicate})` drains EVERY active
/// match, not just the first page. Seeds 70 co-active claims (distinct
/// `scope` keeps supersession from collapsing them) and asserts the paging
/// loop retracts all of them. Exercises the engine-typed helper directly so
/// the test never links the N-API runtime (cdylib unit tests dead-strip
/// napi::Error only while it stays unreferenced).
#[test]
fn forget_drains_all_active_matches_beyond_one_page() {
    use oneiron::registry::ENTITY_TYPE_PERSON;

    // More than one page so the single-page bug leaves a remainder.
    const ACTIVE_CLAIMS: usize = FORGET_PAGE_SIZE + 6;

    let dir = unique_vault_dir("forget");
    let path = dir.to_str().expect("utf8 path").to_owned();
    let actor = EntityId::from_bytes([0x41; 16]).expect("actor id");
    let subject = EntityId::from_bytes([0x42; 16]).expect("subject id");

    // Scope the vault so its LMDB env closes before the temp dir removal.
    {
        let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
        let time = oneiron::TimeRange { start: 1, end: 1 };
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
            .expect("put actor");
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, time, 1, b"subject")
            .expect("put subject");
        let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);
        for i in 0..ACTIVE_CLAIMS {
            facade
                .claim_upsert(&ClaimInput {
                    id: None,
                    predicate: "profile.city".to_owned(),
                    subject_ref: subject.to_hex(),
                    value: serde_json::json!(format!("city-{i}")),
                    confidence: 1.0,
                    source: "user_stated".to_owned(),
                    world_ref: None,
                    relationship_ref: None,
                    scope: Some(serde_json::json!({ "idx": i })),
                    valid_from: None,
                    valid_to: None,
                    occurred_at: Some(100),
                    learned_at: Some(100),
                    salience: None,
                })
                .expect("seed claim");
        }

        let count_active = || {
            facade
                .claim_list(&ClaimListFilter {
                    subject_ref: Some(subject.to_hex()),
                    predicate: Some("profile.city".to_owned()),
                    lifecycle: Some("active".to_owned()),
                    limit: 500,
                })
                .expect("claim_list")
                .len()
        };
        assert_eq!(
            count_active(),
            ACTIVE_CLAIMS,
            "seeded claims are all active before forget"
        );

        let receipts =
            forget_active_matches(&facade, &subject.to_hex(), "profile.city").expect("forget");
        assert_eq!(
            receipts.len(),
            ACTIVE_CLAIMS,
            "forget retracts every active match across pages"
        );
        assert_eq!(count_active(), 0, "subject+predicate is fully forgotten");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn native_client_export_projects_the_shared_five_format_verb() {
    let dir = unique_vault_dir("export");
    let client = super::client::NativeClient::open(Some(dir.to_string_lossy().into_owned()), None)
        .expect("embedded native client");
    for format in ["toon", "md", "json", "yaml", "txt"] {
        let answer = client
            .export(serde_json::json!({"format": format}))
            .expect("N-API export");
        assert_eq!(answer["format"], format);
        assert!(
            answer["rendered"]
                .as_str()
                .unwrap()
                .contains("evidence_ledger")
        );
    }
    let error = client
        .export(serde_json::json!({"format":"gemini"}))
        .expect_err("provider wire formats are not vault exports");
    assert!(error.to_string().contains("BAD_REQUEST"));
    drop(client);
    std::fs::remove_dir_all(dir).expect("remove temp vault");
}
