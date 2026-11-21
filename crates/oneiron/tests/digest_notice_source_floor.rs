//! A digest's inbox notice is a derived row (RECIPIENT-NOTICE-READ-BY-ANY-READER, owner half;
//! Engine ANSWER 21 Nov 06:28: "the owner reads a member's notice body exactly when he can read
//! the sources it came from"). The Dreamer's proactivity digest notice is born from the records
//! its reader's kept proposals draw their words from, and a published weave period's notice from
//! the rows the period reads, so each reads to a reader of those rows and to no one else: the
//! source-audience walk judges the notice as it judges them.
//!
//! Each test holds one row of the owner's own mailbox, read by him alone, and a fact learnt from
//! it. The notice of a digest that carries the fact reads to the owner and not to a person named
//! by no source policy.
//!
//! Red on the base (#10176's head): both notices are born with no sources, so that person reads
//! them.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test digest_notice_source_floor`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{
    WeaveDigestCadence, WeaveDigestReader, WeaveDigestSchedule, WeaveSectionKind, WeaveSectionSpec,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::curator_finding::emit_retract_finding;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, Vault, VaultConfig,
};

/// The proactivity digest's notice producer, as the digest names it.
const DIGEST_PRODUCER: &str = "dreamer.digest";

/// The weave period's notice producer, as the weave names it.
const WEAVE_PRODUCER: &str = "weave.digest";

/// The predicate of the fact the owner's weave section reads.
const WEAVE_PREDICATE: &str = "project.note";

/// A vault with its embedded owner, one row of his own mailbox read by him
/// alone, and a person no source policy names. The vault closes before its
/// directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    row: EntityId,
    stranger: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        Self::open_with(|_| {})
    }

    /// [`Self::open`] in a vault whose Dreamer signs its findings as a
    /// MACHINE, as `tests/conflict_settle_restriction.rs` provisions it: an
    /// unsigned MACHINE write is refused.
    fn with_machine_signers(secret: &[u8]) -> Self {
        Self::open_with(|vault| {
            let issuer = HostSlipIssuer::from_secret(secret).expect("FIXTURE: the host issuer");
            vault
                .ensure_host_root_slip(&issuer)
                .expect("FIXTURE: the host root binds the owner");
            vault
                .provision_engine_machine_identities(&issuer)
                .expect("FIXTURE: the engine's machine signers");
        })
    }

    fn open_with(provision: impl FnOnce(&Vault)) -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
        let vault =
            Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("FIXTURE: this install's signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner");
        provision(&vault);
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: the owner's proof");
        let (row, _policy) = bound_row(&vault, owner).expect("FIXTURE: a row of his own mailbox");
        Self {
            vault,
            owner,
            proof,
            row,
            stranger: EntityId::now(),
            _dir: dir,
        }
    }

    /// An open CLAIM about the owner under `predicate`, learnt from his
    /// mailbox's row: its birth names the row, so its floor is the row's.
    fn fact_from_the_mailbox(&self, predicate: &str) -> EntityId {
        let at = self.vault.now_recorded_at();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from("The harbour survey's lantern list is kept in the owner's mail."),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("FIXTURE: an open CLAIM body");
        body.source = Some(ClaimSource::UserStated);
        let fact = EntityId::now();
        put_claim_made_by(
            &self.vault,
            fact,
            &body,
            MadeBy {
                inputs: vec![MadeByInput {
                    row: self.row,
                    role: MadeByInputRole::Input,
                }],
                process: MadeByProcess {
                    actor: self.owner,
                    class: MadeByClass::Stated,
                    identity: "digest_notice_source_floor.fixture".to_owned(),
                    version: "1".to_owned(),
                    params_hash: "0".repeat(64),
                },
                at,
                trigger: None,
            },
        )
        .expect("FIXTURE: the fact and its birth");
        assert!(
            reads(&self.vault, fact, &[self.owner]).expect("the owner's read"),
            "FIXTURE: the owner reads the fact learnt from his own mailbox"
        );
        assert!(
            !reads(&self.vault, fact, &[self.stranger]).expect("the stranger's read"),
            "FIXTURE: a person named by no source policy does not read the fact"
        );
        fact
    }

    /// The one notice of `producer` in the owner's inbox.
    fn owners_notice(&self, producer: &str) -> EntityId {
        let page = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .inbox_list(None, 500)
            .expect("the owner's inbox");
        let notices: Vec<_> = page
            .rows
            .iter()
            .filter(|row| row.source.producer == producer)
            .collect();
        assert_eq!(
            notices.len(),
            1,
            "FIXTURE: the owner's inbox holds one {producer} notice: {:?}",
            page.rows
        );
        EntityId::from_hex(&notices[0].id).expect("an inbox row names its id")
    }

    /// The notice `notice` reads to the owner, a reader of every row it came
    /// from, and not to a person no source policy names.
    fn assert_reads_only_to_the_owner(&self, notice: EntityId, what: &str) {
        assert!(
            reads(&self.vault, notice, &[self.owner]).expect("the owner's read"),
            "the owner reads his own {what}"
        );
        assert!(
            !reads(&self.vault, notice, &[self.stranger]).expect("the stranger's read"),
            "a person named by no source policy reads the {what} of a digest that carries a \
             fact learnt from the owner's own mailbox: the notice was born with no sources"
        );
    }
}

/// The Dreamer's finding over a fact learnt from the owner's own mailbox
/// rides his digest; the digest's notice is born from the finding and the
/// fact its words are drawn from, so it reads to him and to no one his
/// mailbox does not name.
#[test]
fn a_proactivity_digest_notice_reads_only_to_the_readers_of_its_proposals_words() {
    let fixture = Fixture::with_machine_signers(b"digest-notice-source-floor");
    let fact = fixture.fact_from_the_mailbox("profile.preference");
    let finding =
        emit_retract_finding(&fixture.vault, fact).expect("FIXTURE: the Dreamer's finding");
    let digest = fixture
        .vault
        .proactivity_digest(&fixture.proof, fixture.vault.now_recorded_at(), None)
        .expect("the owner's digest assembles")
        .expect("FIXTURE: a digest is due");
    assert!(
        digest
            .groups
            .values()
            .flatten()
            .any(|proposal| proposal.claim_ref == finding),
        "FIXTURE: the owner's digest carries the finding: {:?}",
        digest.groups
    );
    let notice = fixture.owners_notice(DIGEST_PRODUCER);
    fixture.assert_reads_only_to_the_owner(notice, "digest notice");
}

/// The owner's scheduled weave period reads a fact learnt from his own
/// mailbox; the period's notice, which the deadline timer records as it
/// publishes the period, is born from the rows the period reads.
#[test]
fn a_weave_period_notice_reads_only_to_the_readers_of_the_rows_its_period_reads() {
    let fixture = Fixture::open();
    fixture.fact_from_the_mailbox(WEAVE_PREDICATE);
    let reader = WeaveDigestReader::Owner(fixture.owner);
    fixture
        .vault
        .set_weave_digest_schedule(
            &fixture.proof,
            &WeaveDigestSchedule {
                reader,
                cadence: WeaveDigestCadence::Daily,
                next_due_at: 1,
                recipe: vec![WeaveSectionSpec {
                    kind: WeaveSectionKind::Digest,
                    predicates: vec![WEAVE_PREDICATE.to_owned()],
                    edge_kinds: Vec::new(),
                }],
            },
        )
        .expect("FIXTURE: the owner schedules his daily weave");
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let node = runner
        .local_home_node_candidate(false, false, false)
        .expect("FIXTURE: the local node")
        .node_id;
    let now = fixture.vault.now_recorded_at();
    runner
        .elect_home_node(&[DreamerHomeNodeCandidate::always_on_local(node)], now)
        .expect("FIXTURE: the home election runs");
    fixture
        .vault
        .serve_due_weave_digests(now, node)
        .expect("the timer serves the owner's schedule");
    let schedule = fixture
        .vault
        .weave_digest_schedule(&fixture.proof, reader)
        .expect("the owner's schedule reads")
        .expect("the owner keeps his schedule");
    assert!(
        schedule.next_due_at > 1,
        "FIXTURE: the timer published the period and moved the schedule on, rather than \
         holding a due notice: {schedule:?}"
    );
    let notice = fixture.owners_notice(WEAVE_PRODUCER);
    fixture.assert_reads_only_to_the_owner(notice, "weave period notice");
}
