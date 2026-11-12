//! INQUIRE-1 PR 1 (federation.md #inquiry, ruled 2026-11-11; Engine ruling
//! INQUIRE-SHAPE = A): the inquiry records and their one wire shape, the
//! member vault's "Asked about you" log, the asking side's `inquiry` receipt
//! and the company setting `inquiry_keep`.
//! - an answer crosses as statement text and source only, and fields this
//!   build does not know never land;
//! - `no_answer` has one shape whatever its reason, and a wire answer that
//!   breaks its outcome is refused;
//! - the log keeps the inquiry, its answer and who decided, and a repeat of
//!   the inquiry returns its current answer;
//! - the receipt keeps the asker, the task, the question, the time and the
//!   outcome of each send, never answer text;
//! - an actor's erase leaves the log rows and receipts without that actor;
//! - `inquiry_keep` reads `task` until the Owner's manifest names `copy`.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_records`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryAsker, InquiryDecider, InquiryKeep, InquiryKeepSetting,
    InquiryKeepSource, InquiryOutcome, InquiryStatement, InquiryTask, StatementSource,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::inquiry as door;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// The instant every test opens at, in the vault clock's seconds.
const T0: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
/// The asking company vault's authority id.
const COMPANY_VAULT: &str = "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac";
/// The member's word that answers the Thursday question.
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("open vault");
        Self {
            vault,
            clock,
            _dir: dir,
        }
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    fn owner(&self) -> AuthenticatedOwner {
        let owner = self.vault.ensure_embedded_owner_actor().expect("owner");
        self.vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof")
    }

    /// Installs an Owner manifest whose only row beside the header is
    /// `inquiry`.
    fn install(&self, inquiry_row: Value) -> oneiron::error::Result<()> {
        let policy = json!({
            "schema_version": "1.2",
            "pack_id": "inquiry-records",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [],
            "actor_ceilings": [],
            "inquiry": inquiry_row,
        });
        self.vault.install_owner_policy_manifest(
            &self.owner(),
            EntityId::now(),
            rmp_serde::to_vec_named(&policy).expect("encode"),
            self.vault.now_recorded_at(),
        )
    }

    /// Every `inquiry` receipt of `inquiry`, in the order they were written.
    fn receipts(&self, inquiry: &Inquiry) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::Inquiry].into();
        query.job_ref = Some(inquiry.id.to_hex());
        let mut receipts = self.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }
}

fn inquiry(question: &str) -> Inquiry {
    Inquiry {
        id: EntityId::now(),
        from: InquiryAsker {
            vault: COMPANY_VAULT.to_owned(),
            actor: EntityId::now(),
            role: "agent".to_owned(),
        },
        task: InquiryTask {
            id: EntityId::now(),
            purpose: "Find a time for the review with owen".to_owned(),
        },
        question: question.to_owned(),
        keep: InquiryKeep::Task,
        expires_at: T0 + DAY,
    }
}

fn said(text: &str, source: StatementSource) -> InquiryStatement {
    InquiryStatement::new(text, source).expect("statement")
}

fn answered(asked: &Inquiry) -> InquiryAnswer {
    InquiryAnswer::answered(
        asked,
        vec![said(OUT_THURSDAY, StatementSource::MemberWord)],
        T0 + 2 * DAY,
    )
    .expect("answer")
}

fn wire(answer: &InquiryAnswer) -> Value {
    serde_json::from_slice(&answer.encode_wire().expect("encode")).expect("json")
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect()
}

const ANSWER_KEYS: [&str; 5] = ["inquiry_id", "keep", "outcome", "statements", "valid_until"];

#[test]
fn an_answer_crosses_as_text_and_source_only() {
    let asked = inquiry("Is owen free on Thursday?");
    let answer = InquiryAnswer::answered(
        &asked,
        vec![
            said(OUT_THURSDAY, StatementSource::MemberWord),
            said("busy Thursday", StatementSource::CompanionOfMember),
        ],
        T0 + 2 * DAY,
    )
    .expect("answer");
    let json = wire(&answer);
    assert_eq!(keys(&json), BTreeSet::from(ANSWER_KEYS));
    assert_eq!(json["inquiry_id"], asked.id.to_hex());
    assert_eq!(json["outcome"], "answered");
    assert_eq!(json["keep"], "task");
    assert_eq!(json["valid_until"], T0 + 2 * DAY);
    let statements = json["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 2);
    for statement in statements {
        assert_eq!(keys(statement), BTreeSet::from(["source", "text"]));
    }
    assert_eq!(statements[0]["text"], OUT_THURSDAY);
    assert_eq!(statements[0]["source"], "member_word");
    assert_eq!(statements[1]["source"], "companion_of_member");
    let back = InquiryAnswer::decode_wire(&answer.encode_wire().expect("encode")).expect("decode");
    assert_eq!(back, answer);

    // A score, a vector or a record id a sender adds never lands.
    let mut padded = json.clone();
    padded["score"] = json!(0.93);
    padded["statements"][0]["record_id"] = json!(EntityId::now().to_hex());
    padded["statements"][0]["vector"] = json!([0.1, 0.2]);
    let landed =
        InquiryAnswer::decode_wire(&serde_json::to_vec(&padded).expect("bytes")).expect("decode");
    assert_eq!(landed, answer);
    assert_eq!(wire(&landed), json);
}

#[test]
fn no_answer_has_one_shape_whatever_its_reason() {
    let asked = inquiry("Why is owen out?");
    let shape = InquiryAnswer::no_answer(&asked)
        .encode_wire()
        .expect("encode");
    let json: Value = serde_json::from_slice(&shape).expect("json");
    assert_eq!(keys(&json), BTreeSet::from(ANSWER_KEYS));
    assert_eq!(json["outcome"], "no_answer");
    assert_eq!(json["statements"], json!([]));
    assert_eq!(json["valid_until"], Value::Null);

    // The member said no, a standing row said never, nobody answered in
    // time: the member's vault sends the same bytes.
    let fixture = Fixture::open();
    let deciders = [
        InquiryDecider::Member {
            principal: Some(EntityId::now()),
        },
        InquiryDecider::StandingRow {
            row_ref: "never-answer-acme".to_owned(),
        },
        InquiryDecider::LetGo,
    ];
    for decided_by in deciders {
        let edge = EntityId::now();
        door::receive(&fixture.vault, edge, &asked).expect("log");
        let entry = door::settle(
            &fixture.vault,
            edge,
            asked.id,
            InquiryAnswer::no_answer(&asked),
            decided_by,
        )
        .expect("settle");
        assert_eq!(entry.answer.encode_wire().expect("encode"), shape);
    }

    // Pending and unavailable carry no statements either.
    for (answer, outcome) in [
        (InquiryAnswer::pending(&asked), "pending"),
        (InquiryAnswer::unavailable(&asked), "unavailable"),
    ] {
        let json = wire(&answer);
        assert_eq!(keys(&json), BTreeSet::from(ANSWER_KEYS));
        assert_eq!(json["outcome"], outcome);
        assert_eq!(json["statements"], json!([]));
        assert_eq!(json["valid_until"], Value::Null);
    }
}

#[test]
fn a_wire_answer_that_breaks_its_outcome_is_refused() {
    let asked = inquiry("Is owen free on Thursday?");
    assert!(InquiryAnswer::answered(&asked, Vec::new(), T0 + DAY).is_err());
    assert!(
        InquiryAnswer::answered(
            &asked,
            vec![said(OUT_THURSDAY, StatementSource::MemberWord)],
            0
        )
        .is_err()
    );
    assert!(InquiryStatement::new("  ", StatementSource::MemberWord).is_err());

    let statement = json!({ "text": OUT_THURSDAY, "source": "member_word" });
    let refused = [
        // A no_answer that carries a statement, or a valid_until.
        json!({ "outcome": "no_answer", "statements": [statement], "valid_until": null }),
        json!({ "outcome": "no_answer", "statements": [], "valid_until": T0 + DAY }),
        // An answer with no statements, or no valid_until.
        json!({ "outcome": "answered", "statements": [], "valid_until": T0 + DAY }),
        json!({ "outcome": "answered", "statements": [statement], "valid_until": null }),
        // A statement with no text, or a source this build does not know.
        json!({ "outcome": "answered", "statements": [{ "text": "", "source": "member_word" }],
                "valid_until": T0 + DAY }),
        json!({ "outcome": "answered", "statements": [{ "text": "x", "source": "the_hr_file" }],
                "valid_until": T0 + DAY }),
        // An outcome this build does not know.
        json!({ "outcome": "refused", "statements": [], "valid_until": null }),
    ];
    for mut body in refused {
        body["inquiry_id"] = json!(asked.id.to_hex());
        body["keep"] = json!("task");
        let bytes = serde_json::to_vec(&body).expect("bytes");
        assert!(
            InquiryAnswer::decode_wire(&bytes).is_err(),
            "refused: {body}"
        );
    }
}

#[test]
fn an_inquiry_checks_its_fields_and_crosses_whole() {
    let asked = inquiry("Is owen free on Thursday?");
    asked.validate().expect("valid");
    let back = Inquiry::decode_wire(&asked.encode_wire().expect("encode")).expect("decode");
    assert_eq!(back, asked);

    let broken: [fn(&mut Inquiry); 6] = [
        |inquiry| inquiry.from.vault = COMPANY_VAULT.to_uppercase(),
        |inquiry| inquiry.from.vault = COMPANY_VAULT[1..].to_owned(),
        |inquiry| inquiry.from.role = String::new(),
        |inquiry| inquiry.task.purpose = "Find a time\nand book it".to_owned(),
        |inquiry| inquiry.question = " ".to_owned(),
        |inquiry| inquiry.expires_at = 0,
    ];
    for (at, break_it) in broken.into_iter().enumerate() {
        let mut inquiry = asked.clone();
        break_it(&mut inquiry);
        assert!(inquiry.validate().is_err(), "rule {at}");
        assert!(inquiry.encode_wire().is_err(), "rule {at}");
        let bytes = serde_json::to_vec(&inquiry).expect("bytes");
        assert!(Inquiry::decode_wire(&bytes).is_err(), "rule {at}");
    }
}

#[test]
fn statement_sources_name_the_member_or_the_companion() {
    assert_eq!(StatementSource::MemberWord.label("owen"), "owen");
    assert!(!StatementSource::MemberWord.is_provisional());
    assert_eq!(
        StatementSource::CompanionOfMember.label("owen"),
        "companion of owen"
    );
    assert!(StatementSource::CompanionOfMember.is_provisional());
}

#[test]
fn the_log_keeps_the_inquiry_its_answer_and_who_decided() {
    let fixture = Fixture::open();
    let edge = EntityId::now();
    let asked = inquiry("Is owen free on Thursday?");
    let logged = door::receive(&fixture.vault, edge, &asked).expect("log");
    assert_eq!(logged.edge, edge);
    assert_eq!(logged.inquiry, asked);
    assert_eq!(logged.received_at, T0);
    assert_eq!(logged.answer, InquiryAnswer::pending(&asked));
    assert_eq!(logged.decided_by, None);

    // A repeat returns the row as it stands; the same id with another
    // question is refused.
    fixture.at(T0 + 60);
    assert_eq!(
        door::receive(&fixture.vault, edge, &asked).expect("repeat"),
        logged
    );
    let mut changed = asked.clone();
    changed.question = "Why is owen out?".to_owned();
    assert!(door::receive(&fixture.vault, edge, &changed).is_err());

    // The member answers.
    fixture.at(T0 + HOUR);
    let member = EntityId::now();
    let answer = answered(&asked);
    let settled = door::settle(
        &fixture.vault,
        edge,
        asked.id,
        answer.clone(),
        InquiryDecider::Member {
            principal: Some(member),
        },
    )
    .expect("settle");
    assert_eq!(settled.answer, answer);
    assert_eq!(
        settled.decided_by,
        Some(InquiryDecider::Member {
            principal: Some(member)
        })
    );
    assert_eq!(settled.decided_at, Some(T0 + HOUR));
    assert_eq!(
        fixture
            .vault
            .inquiry_log_entry(&edge, &asked.id)
            .expect("read"),
        Some(settled.clone())
    );
    // The repeat now returns the answer, and the wire names no decider.
    let repeat = door::receive(&fixture.vault, edge, &asked).expect("repeat");
    assert_eq!(repeat.answer, answer);
    assert_eq!(keys(&wire(&repeat.answer)), BTreeSet::from(ANSWER_KEYS));
    // A settled row does not change again.
    assert!(
        door::settle(
            &fixture.vault,
            edge,
            asked.id,
            InquiryAnswer::no_answer(&asked),
            InquiryDecider::LetGo,
        )
        .is_err()
    );

    // A member's vault settles as answered or no_answer, for the inquiry
    // and keep it logged.
    let other = inquiry("Can owen take the Friday slot?");
    door::receive(&fixture.vault, edge, &other).expect("log");
    let mut copy = other.clone();
    copy.keep = InquiryKeep::Copy;
    for wrong in [
        InquiryAnswer::pending(&other),
        InquiryAnswer::unavailable(&other),
        InquiryAnswer::no_answer(&asked),
        InquiryAnswer::no_answer(&copy),
    ] {
        assert!(
            door::settle(
                &fixture.vault,
                edge,
                other.id,
                wrong,
                InquiryDecider::Companion
            )
            .is_err()
        );
    }
    assert!(
        door::settle(
            &fixture.vault,
            EntityId::now(),
            other.id,
            InquiryAnswer::no_answer(&other),
            InquiryDecider::Companion,
        )
        .is_err(),
        "no row over that edge"
    );

    // The same inquiry id over another edge is its own row; the log reads
    // newest first.
    fixture.at(T0 + 2 * HOUR);
    let edge_two = EntityId::now();
    let fresh = door::receive(&fixture.vault, edge_two, &asked).expect("log");
    assert_eq!(fresh.answer, InquiryAnswer::pending(&asked));
    let order: Vec<(EntityId, EntityId)> = fixture
        .vault
        .inquiry_log()
        .expect("log")
        .into_iter()
        .map(|entry| (entry.edge, entry.inquiry.id))
        .collect();
    assert_eq!(
        order,
        vec![(edge_two, asked.id), (edge, other.id), (edge, asked.id)]
    );
}

#[test]
fn the_receipt_keeps_each_send_and_no_answer_text() {
    let fixture = Fixture::open();
    let member = EntityId::now();
    let asked = inquiry("Is owen free on Thursday?");
    let first =
        door::record_send(&fixture.vault, &asked, &member, InquiryOutcome::Pending).expect("send");
    fixture.at(T0 + HOUR);
    let answer = answered(&asked);
    let second =
        door::record_send(&fixture.vault, &asked, &member, answer.outcome()).expect("send");
    let hex = asked.id.to_hex();
    assert_eq!(first.receipt_id, format!("inquiry:{hex}:000000"));
    assert_eq!(second.receipt_id, format!("inquiry:{hex}:000001"));

    let receipts = fixture.receipts(&asked);
    assert_eq!(receipts, vec![first, second]);
    let outcomes: Vec<&str> = receipts.iter().map(|r| r.outcome.as_str()).collect();
    assert_eq!(outcomes, ["pending", "answered"]);
    for receipt in &receipts {
        assert_eq!(receipt.receipt_kind, ReceiptKind::Inquiry);
        assert_eq!(receipt.actor, Some(asked.from.actor.to_hex()));
        assert_eq!(receipt.job_ref, Some(hex.clone()));
        assert_eq!(receipt.trigger_ref, Some(asked.task.id.to_hex()));
        let names: BTreeSet<&str> = receipt.fields.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            BTreeSet::from(["expires_at", "keep", "member", "purpose", "question"])
        );
        assert_eq!(receipt.fields["member"], member.to_hex());
        assert_eq!(receipt.fields["question"], asked.question);
        assert_eq!(receipt.fields["purpose"], asked.task.purpose);
        assert_eq!(receipt.fields["keep"], "task");
        let text = serde_json::to_string(receipt).expect("json");
        assert!(!text.contains("Out Thursday") && !text.contains("Back Friday"));
    }
    assert_eq!(receipts[0].occurred_at, T0);
    assert_eq!(receipts[1].occurred_at, T0 + HOUR);

    // The receipt family reads the kind, newest first.
    let mut query = ReceiptQuery::new(10);
    query.kinds = [ReceiptKind::Inquiry].into();
    let family = fixture.vault.receipts(query).expect("receipts");
    let ids: Vec<&str> = family.iter().map(|r| r.receipt_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            receipts[1].receipt_id.as_str(),
            receipts[0].receipt_id.as_str()
        ]
    );
    assert_eq!(ReceiptKind::parse("inquiry"), Some(ReceiptKind::Inquiry));
    assert_eq!(ReceiptKind::Inquiry.as_str(), "inquiry");
}

#[test]
fn an_erase_leaves_the_rows_without_the_actor() {
    let fixture = Fixture::open();
    let edge = EntityId::now();
    let principal = EntityId::now();
    let member = EntityId::now();
    let asked = inquiry("Is owen free on Thursday?");
    door::receive(&fixture.vault, edge, &asked).expect("log");
    door::settle(
        &fixture.vault,
        edge,
        asked.id,
        answered(&asked),
        InquiryDecider::Member {
            principal: Some(principal),
        },
    )
    .expect("settle");
    door::record_send(&fixture.vault, &asked, &member, InquiryOutcome::Answered).expect("send");

    // The member who decided: the decision stands without them.
    assert_eq!(
        door::erase_actor_in_inquiry_tables(&fixture.vault, &principal).expect("erase"),
        2,
        "both inquiry tables register a scrub"
    );
    let entry = fixture
        .vault
        .inquiry_log_entry(&edge, &asked.id)
        .expect("read")
        .expect("row");
    assert_eq!(
        entry.decided_by,
        Some(InquiryDecider::Member { principal: None })
    );
    assert_eq!(entry.answer, answered(&asked));

    // The asker and the member asked about: the send stands without them.
    door::erase_actor_in_inquiry_tables(&fixture.vault, &asked.from.actor).expect("erase");
    door::erase_actor_in_inquiry_tables(&fixture.vault, &member).expect("erase");
    let receipts = fixture.receipts(&asked);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].actor, None);
    assert!(!receipts[0].fields.contains_key("member"));
    assert_eq!(receipts[0].fields["question"], asked.question);
    assert_eq!(receipts[0].outcome, "answered");
}

#[test]
fn inquiry_keep_reads_task_until_the_owner_names_copy() {
    let fixture = Fixture::open();
    let default = InquiryKeepSetting {
        keep: InquiryKeep::Task,
        source: InquiryKeepSource::Default,
    };
    assert_eq!(fixture.vault.inquiry_keep().expect("keep"), default);

    // A row this build cannot read is refused at install, and changes
    // nothing.
    for row in [
        json!({ "version": 2, "keep": "copy" }),
        json!({ "version": 1, "keep": "forever" }),
        json!({ "version": 1 }),
        json!({ "version": 1, "keep": "copy", "until": T0 + DAY }),
        json!("copy"),
    ] {
        assert!(fixture.install(row.clone()).is_err(), "refused: {row}");
        assert_eq!(fixture.vault.inquiry_keep().expect("keep"), default);
    }

    fixture
        .install(json!({ "version": 1, "keep": "copy" }))
        .expect("the owner installs the row");
    assert_eq!(
        fixture.vault.inquiry_keep().expect("keep"),
        InquiryKeepSetting {
            keep: InquiryKeep::Copy,
            source: InquiryKeepSource::Row,
        }
    );
}
