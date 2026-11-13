#![cfg(oneiron_test_support)]

//! Retained result reads blank secret spans without changing their stored body.

use std::fmt::Write as _;
use std::ops::Range;

use oneiron::code_run::ResultFacet;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::result_doors::{
    ResultByteSelection, ResultOccurrenceRequest, ResultReadView, ResultSlicePage,
    ResultSliceRequest, ResultSliceSelection, ResultSliceView, ResultTaintState,
};
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::secret_lease::SecretTaintRef;
use oneiron::test_doors::code_run_result_body as doors;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::file_secret_marks::FILLER;
use serde_json::{Value, json};

// The public BIP39 vector already marked by batch/secret_scan/tests.rs.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CLEAN_BYTES: usize = 4 * 1024;
const CUSTODY_NAME: &str = "result-redaction-fixture";
const CUSTODY_VALUE: &str = "Q7m2R9v4L6n8C3x5B1z0D4f6H8j2K9p3";

struct ResultBodyFixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    run_id: EntityId,
    occurrence: EntityId,
    body: Vec<u8>,
    secret: Range<usize>,
    _directory: tempfile::TempDir,
}

impl ResultBodyFixture {
    fn new(body: Vec<u8>, secret: Range<usize>) -> Self {
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
            secret,
            _directory: directory,
        }
    }

    fn phrase() -> Self {
        Self::with_phrase(&clean_lines())
    }

    fn with_phrase(head: &str) -> Self {
        let body = format!("{head}{PHRASE}\n{}", clean_lines()).into_bytes();
        let secret = head.len()..head.len() + PHRASE.len();
        Self::new(body, secret)
    }

    fn reference(&self) -> String {
        format!("occurrence:{}", self.occurrence.to_hex())
    }

    fn raw(&self, reference: &str, facet: Option<ResultFacet>, input: Value) -> Value {
        let reply = self
            .vault
            .read_code_run_result(self.run_id, reference, facet, input, |_| Ok(false))
            .expect("read the raw result reply");
        assert!(reply.get("denied").is_none(), "unexpected refusal: {reply}");
        reply.get("output").expect("result output envelope").clone()
    }

    fn slice(&self, start: usize, end: usize) -> Value {
        self.raw(
            &self.reference(),
            Some(ResultFacet::Slice),
            json!({"bytes": [start, end]}),
        )
    }

    fn typed_slice(&self) -> ResultSliceView {
        let actor = self.owner.revalidate(&self.vault).expect("owner actor");
        self.vault
            .memory(actor, EdgeActorClass::Human)
            .result_slice_as_owner(
                &self.owner,
                ResultSliceRequest {
                    run_id: self.run_id,
                    occurrence: self.occurrence,
                    selection: ResultSliceSelection::Bytes(ResultByteSelection {
                        bytes: vec![0, u64::try_from(self.body.len()).expect("fixture length")],
                    }),
                },
            )
            .expect("read the typed owner slice")
    }

    fn masked(&self) -> Vec<u8> {
        let mut bytes = self.body.clone();
        bytes[self.secret.clone()].fill(FILLER);
        bytes
    }

    fn mark(&self) -> Option<String> {
        doors::stored_result_mark(&self.vault, self.run_id, self.occurrence)
            .expect("read the occurrence's stored mark")
    }

    fn preflight(&self) -> Value {
        doors::result_read_preflight(&self.vault, self.run_id, self.occurrence)
            .expect("read result preflight")
    }
}

fn clean_lines() -> String {
    let mut lines = String::new();
    for index in 0..256 {
        writeln!(lines, "line {index:04} build step ok").expect("write fixture lines");
    }
    lines.truncate(CLEAN_BYTES - 1);
    lines.push('\n');
    lines
}

fn assert_redacted_slice(output: &Value, start: usize, end: usize, expected: &[u8]) {
    assert!(
        output.get("withheld").is_none(),
        "unexpected withholding: {output}"
    );
    assert_eq!(output["redacted"], true, "{output}");
    assert_eq!(output["start"], json!(start));
    assert_eq!(output["end"], json!(end));
    let text = output["text"].as_str().expect("slice has text");
    assert_eq!(text.as_bytes(), expected);
    assert_eq!(text.len(), end - start);
    assert_eq!(
        output["done"], true,
        "fixture must fit in one reply: {output}"
    );
    assert!(output.get("next").is_none());
}

fn assert_withheld(fixture: &ResultBodyFixture, reason: &str) {
    let output = fixture.slice(0, fixture.body.len());
    assert_eq!(output["withheld"], "tainted_live", "{output}");
    assert_eq!(output["taint"]["secret"], reason);
    assert!(output.get("text").is_none());
    assert!(output.get("redacted").is_none());
    let preflight = fixture.preflight();
    assert_eq!(preflight["can"], false, "{preflight}");
    assert_eq!(preflight["reason"], "tainted");
    assert!(preflight.get("redacted").is_none());
}

#[test]
fn slice_over_clean_bytes_returns_them_and_blanks_only_the_phrase() {
    let fixture = ResultBodyFixture::phrase();
    let expected = fixture.masked();
    // Even after JSON escaping, this ASCII fixture is far below one reply.
    assert!(
        serde_json::to_vec(&json!(fixture.body))
            .expect("encode fixture")
            .len()
            < oneiron::engine_executor::RESULT_REPLY_INLINE_BYTES / 2
    );
    assert_redacted_slice(
        &fixture.slice(0, fixture.body.len()),
        0,
        fixture.body.len(),
        &expected,
    );
    let ResultSliceView::Available { manifest, page } = fixture.typed_slice() else {
        panic!("the owner's slice must be available");
    };
    assert!(matches!(
        manifest.taint.state,
        ResultTaintState::TaintedLive
    ));
    assert!(manifest.taint.secret.is_some());
    eprintln!("stored scan reason: {:?}", manifest.taint.secret);
    let ResultSlicePage::Content(page) = page else {
        panic!("a redacted body must return a content page");
    };
    assert_eq!(
        page.text.as_deref().map(str::as_bytes),
        Some(expected.as_slice())
    );
    assert_eq!(page.start, 0);
    assert_eq!(
        page.end,
        u64::try_from(fixture.body.len()).expect("fixture length")
    );
    assert!(page.done);
    assert!(page.next.is_none());
}

#[test]
fn a_slice_that_cuts_the_phrase_blanks_its_part_too() {
    let fixture = ResultBodyFixture::phrase();
    let start = fixture.secret.start + "abandon ".len() * 5;
    let end = fixture.secret.end + 100;
    let expected = fixture.masked();
    let output = fixture.slice(start, end);
    assert_redacted_slice(&output, start, end, &expected[start..end]);
    let text = output["text"].as_str().expect("slice text").as_bytes();
    let blanked = fixture.secret.end - start;
    assert!(text[..blanked].iter().all(|byte| *byte == FILLER));
    assert_eq!(&text[blanked..], &fixture.body[fixture.secret.end..end]);

    // A range ref uses offsets relative to its window, not the whole body.
    let range_ref = format!("{}#{start}-{end}", fixture.reference());
    let ranged = fixture.raw(
        &range_ref,
        Some(ResultFacet::Slice),
        json!({"bytes": [0, end - start]}),
    );
    assert_redacted_slice(&ranged, 0, end - start, &expected[start..end]);
    assert_eq!(ranged["ref"], range_ref);
}

#[test]
fn the_stored_bytes_and_the_mark_stay_as_stored() {
    let fixture = ResultBodyFixture::phrase();
    let before = fixture.mark().expect("the scan marked the phrase");
    assert_redacted_slice(
        &fixture.slice(0, fixture.body.len()),
        0,
        fixture.body.len(),
        &fixture.masked(),
    );
    let stored = doors::stored_result_bytes(&fixture.vault, fixture.run_id, fixture.occurrence)
        .expect("read bytes without a redacted view");
    assert_eq!(stored, fixture.body);
    let ResultSliceView::Available { manifest, .. } = fixture.typed_slice() else {
        panic!("the owner's redacted slice must be available");
    };
    assert_eq!(blake3::hash(&stored).to_hex().as_str(), manifest.blake3);
    assert_eq!(
        manifest.bytes,
        u64::try_from(stored.len()).expect("fixture length")
    );
    assert_eq!(manifest.taint.secret.as_deref(), Some(before.as_str()));
    assert_eq!(fixture.mark().as_deref(), Some(before.as_str()));
}

#[test]
fn the_card_previews_and_preflight_admits_a_redacted_body() {
    let fixture = ResultBodyFixture::with_phrase("build output ready\n");
    assert!(fixture.secret.end < 256);
    let card = fixture.raw(&fixture.reference(), None, json!({}));
    assert_eq!(card["redacted"], true, "{card}");
    let preview = card["preview"].as_str().expect("card preview");
    assert!(preview.contains('*'));
    for word in PHRASE.split_whitespace() {
        assert!(
            !preview.contains(word),
            "preview leaked a phrase word: {preview}"
        );
    }
    assert!(card.get("shape").is_some_and(|shape| !shape.is_null()));
    assert_eq!(card["taint"]["state"], "tainted_live");
    assert_eq!(card["taint"]["secret"].as_str(), fixture.mark().as_deref());
    let actor = fixture
        .owner
        .revalidate(&fixture.vault)
        .expect("owner actor");
    let typed = fixture
        .vault
        .memory(actor, EdgeActorClass::Human)
        .result_read_as_owner(
            &fixture.owner,
            ResultOccurrenceRequest {
                run_id: fixture.run_id,
                occurrence: fixture.occurrence,
            },
        )
        .expect("read the typed owner card");
    let ResultReadView::Available { card: typed, .. } = typed else {
        panic!("the owner's redacted card must be available");
    };
    assert_eq!(typed.preview, preview);
    let preflight = fixture.preflight();
    assert_eq!(preflight["can"], true, "{preflight}");
    assert_eq!(preflight["redacted"], true);
}

#[test]
fn an_erased_result_stays_withheld_whole() {
    let fixture = ResultBodyFixture::new(b"build output ready\n".to_vec(), 0..0);
    assert!(fixture.mark().is_none());
    doors::withdraw_result_body(&fixture.vault, fixture.run_id, fixture.occurrence)
        .expect("withdraw the exact owned occurrence");
    assert_eq!(fixture.mark().as_deref(), Some("response_erased"));
    assert_withheld(&fixture, "response_erased");
}

#[test]
fn a_lease_tainted_log_blanks_the_known_value() {
    assert_eq!(CUSTODY_VALUE.len(), 32);
    let head = clean_lines();
    let body = format!("{head}{CUSTODY_VALUE}\n{}", clean_lines()).into_bytes();
    let secret = head.len()..head.len() + CUSTODY_VALUE.len();
    let fixture = ResultBodyFixture::new(body, secret);
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
    let ResultSliceView::Available { manifest, page } = fixture.typed_slice() else {
        panic!("the lease-tainted result must be available through its view");
    };
    assert!(matches!(
        manifest.taint.state,
        ResultTaintState::TaintedLive | ResultTaintState::TaintedStale
    ));
    assert!(manifest.taint.secret.is_none());
    assert!(matches!(page, ResultSlicePage::Content(_)));
    assert_redacted_slice(
        &fixture.slice(0, fixture.body.len()),
        0,
        fixture.body.len(),
        &fixture.masked(),
    );
    assert_eq!(
        doors::stored_result_bytes(&fixture.vault, fixture.run_id, fixture.occurrence)
            .expect("known-value masking did not rewrite the stored bytes"),
        fixture.body,
    );
    assert!(fixture.mark().is_none());
}

#[test]
fn a_mark_no_rule_places_stays_withheld_whole() {
    let body = format!("{}{}", "[".repeat(200), "]".repeat(200)).into_bytes();
    let fixture = ResultBodyFixture::new(body, 0..0);
    let reason = "gate.secret_scan.json_depth_over_127";
    assert_eq!(fixture.mark().as_deref(), Some(reason));
    assert_withheld(&fixture, reason);
}
