//! A light recall keeps every TURN its query matched before the rows only
//! the effort's now anchor found (RECALL-NOW-ANCHOR-UNGATED-FILLS-SLOTS).
//! At limit 10 a pack holds 5 claims, 1 turn, 2 summaries, 1 facet and 1
//! other; the room an empty kind leaves goes to the kinds with more rows.
//! Fresh claims the query never named counted as such rows, so they took
//! that room and the pack cut a matching turn. The spare room a matched row
//! needs now comes first; a fresh unmatched row still fills room no match
//! needs.
//!
//! `cargo test --locked -p oneiron --all-features --test recall_now_anchor_query_slots`

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::memory::{
    ClaimInput, Effort, Memory, MemoryPack, RecallScope, WitnessAssertions, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MATCHED_TURN_LABELS: [&str; 4] = ["kestrel", "heron", "plover", "curlew"];
const UNMATCHED_CLAIMS: usize = 7;
const LIMIT: usize = 10;

fn owner_vault() -> Result<(tempfile::TempDir, Vault, EntityId), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((directory, vault, owner))
}

/// One witnessed turn, now, in a conversation of its own.
fn witness(memory: &Memory<'_>, content: String) -> TestResult {
    let occurred_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content,
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at,
        assertions: WitnessAssertions::default(),
    })?;
    Ok(())
}

/// Fresh, normal, base-world claims about the owner that the query never
/// names: the now anchor finds them, the query does not.
fn unmatched_claims(memory: &Memory<'_>, owner: EntityId) -> TestResult {
    for index in 0..UNMATCHED_CLAIMS {
        let receipt = memory.claim_upsert(&ClaimInput {
            id: Some(EntityId::now().to_hex()),
            predicate: format!("profile.now_anchor_probe_{index}"),
            subject_ref: owner.to_hex(),
            value: serde_json::json!(format!("unrelated ledger entry {index}")),
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
        assert_eq!(receipt.approval, "auto", "the owner's claim lands");
    }
    Ok(())
}

fn light(
    memory: &Memory<'_>,
    query: &str,
    scope: &RecallScope,
) -> Result<MemoryPack, Box<dyn std::error::Error>> {
    Ok(memory.recall(query, Effort::Light, scope, LIMIT, None, None)?)
}

fn holds_turn(pack: &MemoryPack, words: &str) -> bool {
    pack.items.iter().any(|item| {
        matches!(item.kind.as_str(), "TURN" | "MESSAGE") && item.value_text.contains(words)
    })
}

fn kinds(pack: &MemoryPack) -> Vec<&str> {
    pack.items.iter().map(|item| item.kind.as_str()).collect()
}

#[test]
fn light_recall_keeps_every_matching_turn_beside_fresh_unmatched_claims() -> TestResult {
    let (_directory, vault, owner) = owner_vault()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let query = format!("anchorslots{}", EntityId::now().to_hex());
    for label in MATCHED_TURN_LABELS {
        witness(&memory, format!("{query} {label}"))?;
    }
    unmatched_claims(&memory, owner)?;

    let turns_only = RecallScope {
        kinds: Some(vec!["TURN".to_owned()]),
        ..RecallScope::default()
    };
    let sanity = light(&memory, &query, &turns_only)?;
    for label in MATCHED_TURN_LABELS {
        assert!(
            holds_turn(&sanity, label),
            "fixture: a TURN-only recall finds the {label} turn ({:?})",
            kinds(&sanity)
        );
    }

    let pack = light(&memory, &query, &RecallScope::default())?;
    let missing: Vec<_> = MATCHED_TURN_LABELS
        .into_iter()
        .filter(|label| !holds_turn(&pack, label))
        .collect();
    assert!(
        missing.is_empty(),
        "every turn the query matched must stand before the fresh unmatched rows; \
         missing {missing:?}, pack kinds {:?}",
        kinds(&pack)
    );
    Ok(())
}

#[test]
fn light_recall_still_fills_spare_room_with_a_fresh_unmatched_turn() -> TestResult {
    let (_directory, vault, owner) = owner_vault()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let query = format!("anchorslots{}", EntityId::now().to_hex());
    witness(&memory, format!("{query} booked the aisle seat"))?;
    witness(&memory, "the harbour lights were out".to_owned())?;

    let pack = light(&memory, &query, &RecallScope::default())?;
    assert!(
        holds_turn(&pack, "aisle seat"),
        "the matching turn ({:?})",
        kinds(&pack)
    );
    assert!(
        holds_turn(&pack, "harbour lights"),
        "a fresh turn the query did not match still fills room no match needs ({:?})",
        kinds(&pack)
    );
    Ok(())
}
