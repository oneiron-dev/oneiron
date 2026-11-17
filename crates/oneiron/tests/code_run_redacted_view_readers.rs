#![cfg(oneiron_test_support)]

//! Readers that take a code-run result's bytes outside its `more` facets (a
//! raw chunk, a summary member) read a tainted body through its redacted
//! view, each secret span blanked, and refuse only a body no view shows
//! (ARCH-0069 `#result-bodies`; READER-REDACTED-VIEW-SCOPE = A).

use std::fmt::Write as _;
use std::ops::Range;

use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::secret_lease::SecretTaintRef;
use oneiron::test_doors::code_run_result_body as doors;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_store::file_secret_marks::FILLER;

// The public BIP39 vector already marked by batch/secret_scan/tests.rs.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CUSTODY_NAME: &str = "redacted-view-readers-fixture";
const CUSTODY_VALUE: &str = "Q7m2R9v4L6n8C3x5B1z0D4f6H8j2K9p3";

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    run_id: EntityId,
    occurrence: EntityId,
    body: Vec<u8>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(body: Vec<u8>) -> Self {
        let directory = oneiron::test_support::restore_tempdir();
        let vault = Vault::open(directory.path().join("vault"), VaultConfig::device())
            .expect("open a fresh device vault");
        oneiron::test_doors::provenance_body_checkpoint::install_memory_keystore(&vault);
        vault.ensure_vault_key().expect("mint the vault data key");
        let owner = oneiron::test_doors::steward::owner(&vault).expect("authenticate owner");
        let run_id = EntityId::now();
        let occurrence = doors::store_code_run_result_body(&vault, run_id, "log", &body)
            .expect("publish a result through its scanning sink");
        Self {
            vault,
            owner,
            run_id,
            occurrence,
            body,
            _directory: directory,
        }
    }

    /// A clean log with the phrase on one line in its middle, and where.
    fn with_phrase() -> (Self, Range<usize>) {
        let head = clean_lines();
        let body = format!("{head}{PHRASE}\n{}", clean_lines()).into_bytes();
        let secret = head.len()..head.len() + PHRASE.len();
        (Self::new(body), secret)
    }

    fn chunk(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        doors::shown_result_range(
            &self.vault,
            self.run_id,
            self.occurrence,
            u64::try_from(offset).expect("offset"),
            len,
        )
        .expect("read the shown range")
    }

    fn member(&self, start: usize, end: usize) -> Result<String, String> {
        doors::summary_member_text(
            &self.vault,
            self.run_id,
            self.occurrence,
            u64::try_from(start).expect("start"),
            u64::try_from(end).expect("end"),
        )
        .expect("read the summary member")
    }

    fn mark(&self) -> Option<String> {
        doors::stored_result_mark(&self.vault, self.run_id, self.occurrence)
            .expect("read the occurrence's stored mark")
    }
}

fn clean_lines() -> String {
    let mut lines = String::new();
    for index in 0..256 {
        writeln!(lines, "line {index:04} build step ok").expect("write fixture lines");
    }
    lines
}

fn masked(body: &[u8], secret: &Range<usize>) -> Vec<u8> {
    let mut bytes = body.to_vec();
    bytes[secret.clone()].fill(FILLER);
    bytes
}

fn assert_no_phrase_word(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    assert!(!text.contains("abandon"), "a phrase word leaked: {text}");
}

#[test]
fn a_raw_chunk_of_a_marked_body_reads_its_redacted_view() {
    let (fixture, secret) = Fixture::with_phrase();
    assert!(fixture.mark().is_some(), "the scan marked the phrase");
    let expected = masked(&fixture.body, &secret);
    let start = secret.start - 32;
    let end = secret.end + 32;
    let chunk = fixture
        .chunk(start, end - start)
        .expect("a marked body's chunk reads through its view");
    assert_eq!(chunk, expected[start..end]);
    assert_no_phrase_word(&chunk);
    let whole = fixture
        .chunk(0, fixture.body.len())
        .expect("the whole view reads");
    assert_eq!(whole, expected);
}

#[test]
fn a_summary_member_reads_through_the_redacted_view() {
    let (fixture, secret) = Fixture::with_phrase();
    let expected = masked(&fixture.body, &secret);
    let whole = fixture
        .member(0, fixture.body.len())
        .expect("a marked member reads through its view");
    assert_eq!(whole.as_bytes(), expected.as_slice());
    assert_no_phrase_word(whole.as_bytes());
    let (start, end) = (secret.start - 10, secret.end + 10);
    let part = fixture
        .member(start, end)
        .expect("a member range over the phrase reads through its view");
    assert_eq!(part.as_bytes(), &expected[start..end]);
}

#[test]
fn a_body_no_view_shows_feeds_no_chunk_and_no_member() {
    let erased = Fixture::new(b"build output ready\n".to_vec());
    doors::withdraw_result_body(&erased.vault, erased.run_id, erased.occurrence)
        .expect("withdraw the exact owned occurrence");
    assert_eq!(erased.mark().as_deref(), Some("response_erased"));
    assert!(erased.chunk(0, erased.body.len()).is_none());
    assert_eq!(
        erased.member(0, erased.body.len()),
        Err("tainted".to_owned())
    );

    let unplaced = Fixture::new(format!("{}{}", "[".repeat(200), "]".repeat(200)).into_bytes());
    assert_eq!(
        unplaced.mark().as_deref(),
        Some("gate.secret_scan.json_depth_over_127")
    );
    assert!(unplaced.chunk(0, unplaced.body.len()).is_none());
    assert_eq!(
        unplaced.member(0, unplaced.body.len()),
        Err("tainted".to_owned())
    );
}

#[test]
fn a_clean_body_reads_as_stored_through_both_readers() {
    let fixture = Fixture::new(clean_lines().into_bytes());
    assert!(fixture.mark().is_none(), "a clean body takes no mark");
    let len = fixture.body.len();
    assert_eq!(
        fixture.chunk(0, len).as_deref(),
        Some(fixture.body.as_slice())
    );
    assert_eq!(
        fixture.chunk(100, 50).as_deref(),
        Some(&fixture.body[100..150])
    );
    assert_eq!(
        fixture.member(0, len).as_deref().map(str::as_bytes),
        Ok(fixture.body.as_slice())
    );
    assert_eq!(fixture.member(len, len + 1), Err("member_gone".to_owned()));
}

#[test]
fn a_lease_tainted_body_blanks_the_known_value_in_a_chunk_and_a_member() {
    let head = clean_lines();
    let body = format!("{head}{CUSTODY_VALUE}\n{}", clean_lines()).into_bytes();
    let secret = head.len()..head.len() + CUSTODY_VALUE.len();
    let fixture = Fixture::new(body);
    assert!(fixture.mark().is_none(), "the token matches no text rule");
    let registered = fixture
        .vault
        .register_secret_as_owner(
            &fixture.owner,
            &OwnerSecretRegistration {
                name: CUSTODY_NAME,
                class: CustodyClass::CustodyPortable,
                device_only: true,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: CUSTODY_VALUE.as_bytes(),
            },
            fixture.vault.now_recorded_at() / 1_000,
        )
        .expect("register custody only after the plaintext body was stored");
    doors::mark_result_body_with_lease_refs(
        &fixture.vault,
        fixture.run_id,
        fixture.occurrence,
        &[SecretTaintRef {
            secret_ref: registered.name,
            generation: registered.rotation_generation,
        }],
    )
    .expect("attach the registered secret's lease taint");
    let expected = masked(&fixture.body, &secret);
    let len = fixture.body.len();
    let chunk = fixture
        .chunk(0, len)
        .expect("a lease-tainted body's chunk reads through its view");
    assert_eq!(chunk, expected);
    assert!(!String::from_utf8_lossy(&chunk).contains(CUSTODY_VALUE));
    let member = fixture
        .member(0, len)
        .expect("a lease-tainted member reads through its view");
    assert_eq!(member.as_bytes(), expected.as_slice());
}
