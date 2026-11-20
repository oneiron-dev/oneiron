//! UC-13 PR 1: `vault.mail.inbox` and the conversation transcript take the
//! same `{at}:{id}` cursor texts before and after they share one codec
//! (`oneiron_contracts::cursor_text`). Each reads its cursor before it reads
//! the vault, so a text it refuses fails with its own bad request, and a
//! text it takes goes on to the read.
//!
//! Public paths only. Green on main and on the head.

use oneiron::mail_pack::MailInboxRequest;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: &str = "0123456789abcdef0123456789abcdef";
const INBOX_REFUSAL: &str = "the inbox cursor is not one this inbox gave";
const TRANSCRIPT_REFUSAL: &str = "invalid transcript cursor";

/// Each cursor text, and whether the inbox and transcript take it.
fn table() -> Vec<(String, bool)> {
    let upper = ID.to_uppercase();
    vec![
        (format!("1700000000:{ID}"), true),
        (format!("0:{ID}"), true),
        (format!("{}:{ID}", u64::MAX), true),
        (format!("1700000000:{upper}"), true),
        (
            "1700000000:0123456789ABCDEF0123456789abcdef".to_owned(),
            true,
        ),
        (format!("+5:{ID}"), true),
        (format!("007:{ID}"), true),
        (format!("18446744073709551616:{ID}"), false),
        (format!("-1:{ID}"), false),
        (format!(" 5:{ID}"), false),
        (format!("5:{ID} "), false),
        (format!(":{ID}"), false),
        ("5:".to_owned(), false),
        ("5".to_owned(), false),
        (String::new(), false),
        (format!("5:{ID}:6"), false),
        (format!("5:{}", &ID[..31]), false),
        (format!("5:{}g", &ID[..31]), false),
        (format!("5;{ID}"), false),
        ("5:00000000000000000000000000000000".to_owned(), false),
        ("5:ffffffffffffffffffffffffffffffff".to_owned(), false),
    ]
}

fn refused_with<T>(result: &MemoryResult<T>, refusal: &str) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|error: &MemoryError| error.message == refusal)
}

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn put_person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person",
    )?;
    Ok(id)
}

#[test]
fn mail_inbox_takes_the_same_cursor_texts() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = put_person(&vault)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for (text, taken) in table() {
        let page = memory.mail_inbox(&MailInboxRequest {
            cursor: Some(text.clone()),
            ..MailInboxRequest::default()
        });
        assert_eq!(
            !refused_with(&page, INBOX_REFUSAL),
            taken,
            "{text:?}: {:?}",
            page.as_ref().err()
        );
    }
    Ok(())
}

#[test]
fn conversation_transcript_takes_the_same_cursor_texts() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = put_person(&vault)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::now();
    for (text, taken) in table() {
        let page = memory.conversation_transcript(&conversation, Some(&text), 10);
        assert_eq!(
            !refused_with(&page, TRANSCRIPT_REFUSAL),
            taken,
            "{text:?}: {:?}",
            page.as_ref().err()
        );
    }
    Ok(())
}
