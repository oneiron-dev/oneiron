//! The general disclosure clamp follows a summary's words to their sources
//! (census L5-13; ILDF2 P7, one-1592 `#p7-room-built`).
//!
//! A scope summary's words are those of every record and MESSAGE it was
//! written from. A room's P7 rule disclosed it only with each of them, but
//! the clamp a context pack for any other non-owner audience applies,
//! `DisclosureContext::admits`, followed only an epoch summary's sources:
//! it admitted a scope summary on its own stamp. So a contact whose
//! clearance takes SUMMARY rows but not the conversation they summarise read
//! the summary, and so did any contact once one of its sources was marked
//! Tier A. The owner alone is admitted everything, as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test disclosure_summary_word_sources`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_owner_alone, clamp_admits_with_contact, mark_tier_a, seed_cleared_contact,
};
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The contact the clamp is asked under.
const COUNTERPARTY: &str = "owen@example.com";

/// A rooted default vault, a two-record trunk the owner wrote, and a scope
/// summary minted over it as the Dreamer writes one. The vault closes before
/// its directory goes.
struct Fixture {
    vault: Vault,
    trunk: [EntityId; 2],
    summary: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    // The server roots its vault and provisions the engine's MACHINE writers
    // on every open; the summary is minted under the Dreamer's authority.
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let (conversation, trunk) = {
        let host = vault.memory(owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "the plan"))?;
        let second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "the first step",
        ))?;
        (
            conversation,
            [
                EntityId::from_hex(&first.id)?,
                EntityId::from_hex(&second.id)?,
            ],
        )
    };
    let summary = mint_scope_summary(
        &vault,
        &ScopeSelector {
            conversation,
            session: None,
            path: ScopePath::Canonical,
            include_forks: false,
        },
        "The plan, and its first step.",
    )?;
    Ok(Fixture {
        vault,
        trunk,
        summary,
        _dir: dir,
    })
}

/// One trunk record that advances HEAD from `parent`.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// A contact cleared to `clearance`, created in `vault`.
fn cleared_contact(vault: &Vault, clearance: Scope) -> TestResult<EntityId> {
    let contact = EntityId::now();
    seed_cleared_contact(vault, contact, COUNTERPARTY, clearance)?;
    Ok(contact)
}

/// A clearance whose kind band takes SUMMARY rows and nothing else: the
/// summary's own stamp, but none of the records it summarises.
fn summaries_only() -> Scope {
    let mut clearance = Scope::top();
    clearance.bands = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_SUMMARY]));
    clearance
}

#[test]
fn a_summary_is_refused_to_a_contact_whose_clearance_takes_it_but_not_its_sources() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let contact = cleared_contact(vault, summaries_only())?;
    for source in fixture.trunk {
        assert!(
            !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &source)?,
            "the clearance takes none of the summarised records"
        );
    }
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &fixture.summary)?,
        "the summary carries the words of records the contact may not read"
    );
    Ok(())
}

#[test]
fn a_summary_is_refused_to_a_contact_once_one_of_its_sources_is_tier_a() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let contact = cleared_contact(vault, Scope::top())?;
    assert!(
        clamp_admits_with_contact(vault, contact, COUNTERPARTY, &fixture.summary)?,
        "a contact cleared for every source reads the summary"
    );
    let [_, step] = fixture.trunk;
    mark_tier_a(vault, &step)?;
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &step)?,
        "a Tier-A record reaches no one but the owner"
    );
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &fixture.summary)?,
        "the summary carries a Tier-A record's words"
    );
    Ok(())
}

#[test]
fn the_owner_alone_is_admitted_a_summary_and_its_sources_whatever_they_hold() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let [_, step] = fixture.trunk;
    mark_tier_a(vault, &step)?;
    for id in fixture.trunk.iter().chain([&fixture.summary]) {
        assert!(
            clamp_admits_owner_alone(vault, id)?,
            "the owner reads every record"
        );
    }
    Ok(())
}
