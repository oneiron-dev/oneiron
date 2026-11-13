//! A selector's born-with Prompt carries no relationship text its member
//! does not read (OPUS-LEAKS, SELECTOR-BORN-WITH-PROMPT-LABEL).
//!
//! A member has a live Member federation grant with unrestricted read Scope,
//! but no grant or membership in relationship R. The owner witnesses an R
//! MESSAGE and an open MESSAGE. An open stated CLAIM has a birth naming both
//! MESSAGEs as Prompt inputs, and the owner explicitly lets Prompt travel.
//!
//! The ordinary row filter withholds the R MESSAGE. An export to an unknown
//! peer must also omit its words from the open CLAIM's row_born_with Prompt,
//! without withholding the CLAIM or the open prompt's words. The peer-aware
//! export is essential: plain filtered_window_doc does not carry born-with.
//!
//! A second test uses an Owner-role grant and requires the R prompt's words
//! to travel, guarding the co-Owner exemption against over-refusal.
//!
//! FIXTURE assertions establish the setup. The final LEAK assertion checks
//! the disclosure, and the final OVER-REFUSAL assertion checks the exemption.
//!
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron --all-features
//! --test selector_born_with_prompt_label
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::{LoroValue, ValueOrContainer};
use oneiron::authority::{ActSurface, MachineRole, PeerMachine};
use oneiron::edge::EdgeActorClass;
use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::provenance::birth::RowBirth;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::share_travel::{BornWith, BornWithField, TravelChoice};
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity_with_birth};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector,
    filtered_window_doc_for_peer, put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::test_support::test_host_issuer;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig, WriteActor,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

const SHARED_VAULT_ID: u64 = 7;
const RELATIONSHIP_PROMPT_TEXT: &str = "orchid observatory shutters close before sunrise";
const OPEN_PROMPT_TEXT: &str = "cobalt archive windows remain open after midday";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// Witnesses one MESSAGE through the owner's real write lane. Each source
/// gets its own turn, and only the R source names a relationship. A new
/// MESSAGE keeps its words inline in its row (FIX 4840), and a born-with
/// Prompt reads only a source's document text, so the owner then moves the
/// words into the MESSAGE's document, as a later edit does.
fn prompt_message(
    vault: &Vault,
    owner: EntityId,
    authorization: &DocAuthorization<'_>,
    relationship: Option<EntityId>,
    content: &str,
    now: u64,
) -> EntityId {
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: relationship
                    .map(|relationship| serde_json::json!({ "rel": relationship.to_hex() })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: WitnessAssertions::default(),
        })
        .expect("FIXTURE: the owner witnesses a prompt MESSAGE");
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".to_owned()),
            WriteActor::new(owner, EdgeActorClass::Human),
            authorization,
        )
        .expect("FIXTURE: the owner moves the MESSAGE's words into its document");
    vault
        .entity_document_head(&message)
        .expect("FIXTURE: the prompt MESSAGE owns a document head");
    assert_eq!(
        vault.entity_text(&message).expect("FIXTURE: MESSAGE text"),
        content,
        "FIXTURE: the prompt source has authoritative nonempty text"
    );
    message
}

/// Replays an open CLAIM with its immutable Rule A birth, using the public
/// replay-with-birth door. The CLAIM has its own open body and read scope;
/// its Prompt sources are recorded only in its birth, never in its value.
fn open_record_with_prompts(
    vault: &Vault,
    owner: EntityId,
    subject: EntityId,
    prompts: [EntityId; 2],
    now: u64,
) -> EntityId {
    let row = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    assert!(
        body.rel.is_none() && body.world.is_none(),
        "FIXTURE: the output CLAIM itself names no relationship or world"
    );
    let body_bytes = encode_claim_body(&body).expect("FIXTURE: encode the open CLAIM");
    let prompt_rows: Vec<Vec<u8>> = prompts
        .iter()
        .map(|prompt| {
            vault
                .get(prompt)
                .expect("FIXTURE: read the prompt row")
                .expect("FIXTURE: the prompt row exists")
        })
        .collect();
    let prompt_bytes: Vec<&[u8]> = prompt_rows.iter().map(Vec::as_slice).collect();
    let birth = RowBirth {
        made_by: MadeBy {
            inputs: prompts
                .into_iter()
                .map(|row| MadeByInput {
                    row,
                    role: MadeByInputRole::Prompt,
                })
                .collect(),
            process: MadeByProcess {
                actor: owner,
                class: MadeByClass::Stated,
                identity: "selector.prompt_fixture".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: now,
            trigger: None,
        },
        content_hash: RowBirth::content_hash_of(&prompt_bytes),
        withheld: Vec::new(),
        room_evidence: None,
    };
    replay_entity_with_birth(
        vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: at(now),
            learned_at: now,
            row_version: 0,
            body: &body_bytes,
        },
        Some(&birth),
        ImportTier::OwnDevice,
    )
    .expect("FIXTURE: replay the open CLAIM with its birth");
    // Replay keeps a row even when it refuses a malformed birth. The call
    // succeeding is not enough: both Prompt inputs must actually land.
    assert_eq!(
        vault.row_birth(&row).expect("FIXTURE: read the row birth"),
        Some(birth),
        "FIXTURE: the open CLAIM retains the exact birth with both Prompt inputs"
    );
    row
}

struct Export {
    prompt: String,
}

/// Exports the same fixture for a Member or a co-Owner. Only the role/preset
/// and Member-only read/row-denial checks differ between the two tests.
fn export_through(
    role: FederationGrantRole,
    preset: FederationGrantPreset,
    check_read_lane: bool,
) -> Export {
    let dir = tempfile::tempdir().expect("FIXTURE: tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("FIXTURE: member vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let (owner, proof) = embedded_owner(&vault).expect("FIXTURE: authenticated owner");
    // Engine MACHINE provisioning alone does not profile this install as a
    // carrier of signed owner acts. The real grant-travel door needs both.
    vault
        .ensure_serving_install_profile(&test_host_issuer(), MachineRole::Unanswered)
        .expect("FIXTURE: a live serving-install profile for the owner's travel act");

    let now = vault.now_recorded_at();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("FIXTURE: a relationship");
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "Yuki" }))
                .expect("FIXTURE: member body"),
        )
        .expect("FIXTURE: a member outside the relationship");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("FIXTURE: the live federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector).expect("FIXTURE: the selector is authorized");

    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Prompt]),
    };
    let effective = vault
        .set_federation_grant_travel_as(
            &proof,
            ActSurface::ThisInstall,
            &grant_id,
            Some(choice.clone()),
            None,
            now,
        )
        .expect("FIXTURE: the owner signs the grant's Prompt travel choice");
    assert_eq!(
        effective.map(|bound| bound.travel),
        Some(choice.clone()),
        "FIXTURE: the owner's Prompt travel choice is effective"
    );
    assert_eq!(
        vault
            .federation_grant_travel(&grant_id)
            .expect("FIXTURE: read the stored travel choice")
            .map(|bound| bound.travel),
        Some(choice),
        "FIXTURE: the export will read the stored Prompt travel choice"
    );

    let authorization = DocAuthorization::Owner(&proof);
    let relationship_prompt = prompt_message(
        &vault,
        owner,
        &authorization,
        Some(relationship),
        RELATIONSHIP_PROMPT_TEXT,
        now,
    );
    let open_prompt = prompt_message(&vault, owner, &authorization, None, OPEN_PROMPT_TEXT, now);
    let open_claim = open_record_with_prompts(
        &vault,
        owner,
        member,
        [relationship_prompt, open_prompt],
        now,
    );
    let owner_text = vault
        .born_with_text(&open_claim, None)
        .expect("FIXTURE: the owner's born-with read");
    let owner_prompt = owner_text
        .get(&BornWithField::Prompt)
        .expect("FIXTURE: the birth provides a Prompt field");
    assert!(
        owner_prompt.contains(RELATIONSHIP_PROMPT_TEXT) && owner_prompt.contains(OPEN_PROMPT_TEXT),
        "FIXTURE: the owner's born-with Prompt reads both MESSAGE contents"
    );

    if check_read_lane {
        let reads = |id: EntityId| {
            vault
                .memory(member, EdgeActorClass::Human)
                .get_entity(&id.to_hex())
                .expect("FIXTURE: the member's own read lane")
                .value
                .is_some()
        };
        assert!(
            reads(open_claim),
            "FIXTURE: the member reads the open CLAIM"
        );
        assert!(
            reads(open_prompt),
            "FIXTURE: the member reads the open prompt MESSAGE"
        );
        assert!(
            !reads(relationship_prompt),
            "FIXTURE: the member's own read lane does not read the R prompt MESSAGE"
        );
    }

    let key = WindowKey::from_timestamp(now);
    let source = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &source, &key).expect("FIXTURE: the window pack");
    for id in [open_claim, relationship_prompt, open_prompt] {
        assert!(
            source.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    let selected = filtered_window_doc_for_peer(
        &vault,
        &source,
        &key,
        scope,
        &selector,
        PeerMachine::Unknown,
    )
    .expect("FIXTURE: the selector export to another vault");
    assert!(
        selected
            .get_map("entities")
            .get(&open_claim.to_hex())
            .is_some(),
        "FIXTURE: the open CLAIM rides the selector window"
    );
    assert!(
        selected
            .get_map("entities")
            .get(&open_prompt.to_hex())
            .is_some(),
        "FIXTURE: the open prompt MESSAGE rides the selector window"
    );
    if check_read_lane {
        assert!(
            selected
                .get_map("entities")
                .get(&relationship_prompt.to_hex())
                .is_none(),
            "FIXTURE: round 2 withholds the R prompt MESSAGE itself"
        );
    }

    let entry = selected
        .get_map("row_born_with")
        .get(&open_claim.to_hex())
        .expect("FIXTURE: the open CLAIM has a row_born_with entry");
    let ValueOrContainer::Value(LoroValue::Binary(bytes)) = entry else {
        panic!("FIXTURE: row_born_with stores binary MessagePack");
    };
    let born_with: BornWith =
        rmp_serde::from_slice(bytes.as_ref()).expect("FIXTURE: decode BornWith");
    let prompt = born_with
        .get(&BornWithField::Prompt)
        .cloned()
        .expect("FIXTURE: the carried open CLAIM still has a Prompt field");
    assert!(
        prompt.contains(OPEN_PROMPT_TEXT),
        "FIXTURE: readable prompt words still travel in the same row_born_with entry"
    );
    Export { prompt }
}

#[test]
fn a_members_born_with_prompt_omits_unreadable_relationship_words() {
    let export = export_through(
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
        true,
    );
    let travelled: Vec<&str> = [RELATIONSHIP_PROMPT_TEXT, OPEN_PROMPT_TEXT]
        .into_iter()
        .filter(|text| export.prompt.contains(*text))
        .collect();
    assert!(
        !export.prompt.contains(RELATIONSHIP_PROMPT_TEXT),
        "LEAK: the open CLAIM's row_born_with Prompt carries R words to a member who does not read R; travelled={travelled:?}; prompt={:?}",
        export.prompt
    );
}

#[test]
fn a_co_owners_born_with_prompt_keeps_relationship_words() {
    let export = export_through(
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
        false,
    );
    let travelled: Vec<&str> = [RELATIONSHIP_PROMPT_TEXT, OPEN_PROMPT_TEXT]
        .into_iter()
        .filter(|text| export.prompt.contains(*text))
        .collect();
    assert!(
        export.prompt.contains(RELATIONSHIP_PROMPT_TEXT),
        "OVER-REFUSAL: the open CLAIM's row_born_with Prompt withholds R words from a co-Owner; travelled={travelled:?}; prompt={:?}",
        export.prompt
    );
}
