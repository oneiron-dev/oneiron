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
//! A claim served at another revision than its live row (a pinned hydration,
//! a history ledger) carries that revision's words, so the clamp follows the
//! served body's sources, not the live row's (Sol review of #7513).
//!
//! A reply TURN that copies a summary, and the `merge.summary` header that
//! names one, carry the summary's own words: the clamp judges the summary's
//! row too (its Tier A, its stamp), not only the records it was written
//! from (Sol review of #7692).
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
    clamp_admits_claim_revision_with_contact, clamp_admits_owner_alone, clamp_admits_with_contact,
    install_shipped_policy_with_ordinary_predicate, mark_tier_a, seed_cleared_contact,
};
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The contact the clamp is asked under.
const COUNTERPARTY: &str = "owen@example.com";

/// A rooted default vault, a two-record trunk the owner wrote, and a scope
/// summary minted over it as the Dreamer writes one. The vault closes before
/// its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
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
        owner,
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

/// Lands the fixture's summary on the first trunk record as the owner asks,
/// with its trunk reply: the `merge.summary` header claim, and the reply
/// TURN that copies the summary's words.
fn land_with_reply(fixture: &Fixture) -> TestResult<(EntityId, EntityId)> {
    let [plan, _] = fixture.trunk;
    let landed = fixture.vault.land_header(
        &fixture.summary,
        &plan,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    Ok((landed.claim, reply))
}

/// A contact cleared to `clearance`, created in `vault`.
fn cleared_contact(vault: &Vault, clearance: Scope) -> TestResult<EntityId> {
    let contact = EntityId::now();
    seed_cleared_contact(vault, contact, COUNTERPARTY, clearance)?;
    Ok(contact)
}

/// A `conversation.summary` claim about `owner` whose words came from
/// `covered`, the shape a summariser writes.
fn conversation_summary(owner: EntityId, text: &str, covered: EntityId) -> TestResult<ClaimBody> {
    Ok(ClaimBody::new(
        "conversation.summary",
        ClaimSubject::Entity(owner),
        Value::Map(vec![
            ("text".into(), text.into()),
            (
                "covers".into(),
                Value::Array(vec![Value::Binary(covered.as_bytes().to_vec())]),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?)
}

/// Puts `body` as the claim `id` now, by the vault's clock.
fn put_claim_now(vault: &Vault, id: &EntityId, body: &ClaimBody) -> TestResult {
    let at = vault.now_recorded_at();
    vault.put_claim(id, body, TimeRange { start: at, end: at }, at)?;
    Ok(())
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

#[test]
fn a_claim_revision_served_is_judged_on_the_sources_of_its_own_words() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let [plan, step] = fixture.trunk;
    // The engine lands its summaries through its own writer; this test writes
    // two revisions through the raw claim door, which the shipped policy parks
    // at the criticality floor for an undeclared predicate.
    install_shipped_policy_with_ordinary_predicate(vault, "conversation.summary")?;
    let claim = EntityId::now();
    let served = conversation_summary(fixture.owner, "The plan.", plan)?;
    put_claim_now(vault, &claim, &served)?;
    put_claim_now(
        vault,
        &claim,
        &conversation_summary(fixture.owner, "The first step.", step)?,
    )?;
    let contact = cleared_contact(vault, Scope::top())?;
    assert!(
        clamp_admits_claim_revision_with_contact(vault, contact, COUNTERPARTY, &claim, &served)?,
        "a contact cleared for every source reads the earlier revision"
    );
    mark_tier_a(vault, &plan)?;
    assert!(
        clamp_admits_with_contact(vault, contact, COUNTERPARTY, &claim)?,
        "the live revision's words come from the step alone"
    );
    assert!(
        !clamp_admits_claim_revision_with_contact(vault, contact, COUNTERPARTY, &claim, &served)?,
        "the earlier revision carries the Tier-A plan's words"
    );
    Ok(())
}

#[test]
fn a_reply_copying_a_summary_is_refused_once_the_summary_is_tier_a() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let (_, reply) = land_with_reply(&fixture)?;
    let contact = cleared_contact(vault, Scope::top())?;
    assert!(
        clamp_admits_with_contact(vault, contact, COUNTERPARTY, &reply)?,
        "a contact cleared for every source reads the reply"
    );
    mark_tier_a(vault, &fixture.summary)?;
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &fixture.summary)?,
        "a Tier-A summary reaches no one but the owner"
    );
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &reply)?,
        "the reply carries the Tier-A summary's words"
    );
    Ok(())
}

#[test]
fn a_merge_header_naming_a_summary_is_refused_once_the_summary_is_tier_a() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let (header, _) = land_with_reply(&fixture)?;
    let contact = cleared_contact(vault, Scope::top())?;
    assert!(
        clamp_admits_with_contact(vault, contact, COUNTERPARTY, &header)?,
        "a contact cleared for every source reads the header"
    );
    mark_tier_a(vault, &fixture.summary)?;
    assert!(
        !clamp_admits_with_contact(vault, contact, COUNTERPARTY, &header)?,
        "the header serves the Tier-A summary's words"
    );
    Ok(())
}
