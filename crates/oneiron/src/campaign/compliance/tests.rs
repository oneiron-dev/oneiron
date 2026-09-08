//! Compliance behaviour: seed shape, evaluator verdicts, hydration, and amendment.

use super::*;

use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::config::VaultConfig;
use crate::gate::{ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor};
use crate::temporal::TimeRange;
use crate::test_util::entity;

/// The counterparty PERSON every vault-backed arm addresses.
const SUBJECT_SEED: u8 = 0xC1;
/// A second PERSON, for the cross-subject evidence-binding arm.
const OTHER_SUBJECT_SEED: u8 = 0xC2;
/// The dispatch-evidence claim.
const EVIDENCE_SEED: u8 = 0xC3;
/// The list-provenance record.
const PROVENANCE_SEED: u8 = 0xC4;
/// The publication-context record.
const PUBLICATION_SEED: u8 = 0xC5;
/// The sending channel identity.
const IDENTITY_SEED: u8 = 0xC6;
/// The message-element configuration claim.
const ELEMENTS_SEED: u8 = 0xC7;
/// A record of the wrong kind, cited on purpose.
const WRONG_KIND_SEED: u8 = 0xC8;
/// A provenance record whose stored class contradicts the claim.
const WRONG_CLASS_SEED: u8 = 0xC9;
/// A provenance record bound to the other subject.
const FOREIGN_SEED: u8 = 0xCA;
/// The amendment proposer / owner.
const ACTOR_SEED: u8 = 0xCB;
/// A second live evidence head that contradicts the first.
const SECOND_EVIDENCE_SEED: u8 = 0xCC;
/// A second live evidence head that agrees with the first.
const TWIN_EVIDENCE_SEED: u8 = 0xCD;

/// The seed's verification date; every row shares it.
const SEED_VERIFIED_AT: u64 = 1_784_505_600;
/// A clock comfortably inside the seed's freshness window.
const FRESH_NOW: u64 = SEED_VERIFIED_AT + 1_000;

fn pack() -> CompliancePack {
    embedded_seed_pack().expect("seed pack parses")
}

/// Facts that satisfy every seeded pole. Each arm below spoils exactly one
/// axis, so a block can only come from the axis under test.
fn facts(jurisdiction: Option<&str>, channel: &str) -> DispatchComplianceFacts {
    DispatchComplianceFacts {
        counterparty: entity(SUBJECT_SEED),
        jurisdiction: jurisdiction.map(str::to_owned),
        jurisdiction_confidence_millis: Some(1_000),
        channel: channel.to_owned(),
        legal_form: Some("corporate".to_owned()),
        list_provenance: Some(HydratedListProvenance {
            record_ref: entity(PROVENANCE_SEED),
            claimed_class: "double_opt_in".to_owned(),
        }),
        jp_publication: Some(HydratedJpPublicationFacts {
            record_ref: entity(PUBLICATION_SEED),
            published_by_recipient: true,
            in_course_of_business: true,
            no_marketing_statement_attached: true,
        }),
        sender_identity_present: true,
        physical_address_present: true,
        optout_mechanism_present: true,
        commercial_marking_present: true,
        now_utc: FRESH_NOW,
    }
}

fn reason(verdict: &ComplianceVerdict) -> Option<ComplianceBlockReason> {
    match verdict {
        ComplianceVerdict::Allow => None,
        ComplianceVerdict::Block { reason, .. } => Some(*reason),
    }
}

fn verdict(facts: &DispatchComplianceFacts) -> ComplianceVerdict {
    evaluate_dispatch_compliance(&pack(), facts)
}

// -- seed integrity ----------------------------------------------------

#[test]
fn campaign_compliance_seed_rows_match_arch_0059() {
    let pack = pack();
    assert_eq!(pack.pack_id, CAMPAIGN_COMPLIANCE_PACK_ID);
    assert!(
        !pack.warning.trim().is_empty(),
        "the caveat ships with the pack"
    );
    for jurisdiction in ["UK", "JP", "EU", "EU/DE", "EU/FR", "US", JURISDICTION_NONE] {
        assert!(
            pack.rows.iter().any(|row| row.jurisdiction == jurisdiction),
            "{jurisdiction} has no seeded rows"
        );
    }
    // The four headline consent-class rows carry their primary source.
    for jurisdiction in ["UK", "JP", "EU", "US"] {
        let row = pack
            .rows
            .iter()
            .find(|row| {
                row.jurisdiction == jurisdiction
                    && row.rule_kind == ComplianceRuleKind::ConsentClass
                    && row.channel == "email"
            })
            .expect("headline consent-class row");
        assert!(!row.requirement.trim().is_empty());
        assert!(!row.source.citation.trim().is_empty());
        assert!(!row.source.url.trim().is_empty());
        assert!(!row.penalty_note.trim().is_empty());
        assert_eq!(row.verified_at, SEED_VERIFIED_AT);
        assert_eq!(row.version, 1);
    }
    // JP's publication exemption is bound to the three-fact check, and US
    // seeds the source-hygiene refusal.
    assert_eq!(
        pack.exemption_evidence("JP"),
        Some(ComplianceExemptionEvidence::PublicationContext)
    );
    assert!(pack.rows.iter().any(|row| {
        row.jurisdiction == "US" && row.rule_kind == ComplianceRuleKind::SourceHygiene
    }));
}

#[test]
fn campaign_compliance_pack_validation_rejects_malformed_packs() {
    let mut duplicated = pack();
    let first = duplicated.rows[0].clone();
    duplicated.rows.push(first);
    assert!(
        validate_compliance_pack(&duplicated).is_err(),
        "a duplicate (jurisdiction, channel, rule_kind) key must be rejected"
    );

    let mut no_disposition = pack();
    no_disposition
        .rows
        .retain(|row| row.jurisdiction != JURISDICTION_NONE);
    assert!(validate_compliance_pack(&no_disposition).is_err());

    let mut unbound = pack();
    unbound
        .conditional_exemption_evidence
        .retain(|binding| binding.jurisdiction != "JP");
    assert!(
        validate_compliance_pack(&unbound).is_err(),
        "a conditional row with no declared evidence cannot be applied"
    );
}

// -- selection and composition ----------------------------------------

#[test]
fn campaign_compliance_strictest_matching_rows_win() {
    // Germany seeds no content-marking row of its own; the EU floor's row
    // still governs, so the absence of a national row cannot relax it.
    let mut german = facts(Some("EU/DE"), "email");
    german.commercial_marking_present = false;
    assert_eq!(
        verdict(&german),
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::MissingRequiredMessageElement,
            jurisdiction: Some("EU".to_owned()),
            rule_kind: Some(ComplianceRuleKind::ContentMarking),
        }
    );

    // The same spoiled axis under the UK, which composes no EU floor,
    // still blocks on the UK's own row — composition is per-chain.
    let mut uk = facts(Some("UK"), "email");
    uk.commercial_marking_present = false;
    assert_eq!(
        verdict(&uk),
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::MissingRequiredMessageElement,
            jurisdiction: Some("UK".to_owned()),
            rule_kind: Some(ComplianceRuleKind::ContentMarking),
        }
    );

    // A jurisdiction that seeds no postal-address row does not inherit
    // one: rows are the only source of requirements.
    let mut no_address = facts(Some("UK"), "email");
    no_address.physical_address_present = false;
    assert_eq!(verdict(&no_address), ComplianceVerdict::Allow);
}

#[test]
fn campaign_compliance_unknown_jurisdiction_uses_strict_pole() {
    // Absent jurisdiction is NOT an automatic deny: facts that satisfy the
    // pole allow.
    assert_eq!(verdict(&facts(None, "email")), ComplianceVerdict::Allow);

    // A requirement the pole states still blocks, and names the pole's row.
    let mut spoiled = facts(None, "email");
    spoiled.optout_mechanism_present = false;
    assert_eq!(
        verdict(&spoiled),
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::MissingRequiredMessageElement,
            jurisdiction: Some("EU".to_owned()),
            rule_kind: Some(ComplianceRuleKind::OptoutMechanism),
        }
    );

    // An unseeded token and a below-floor confidence take the same road.
    assert_eq!(
        verdict(&facts(Some("ZZ"), "email")),
        ComplianceVerdict::Allow
    );
    let mut low_confidence = facts(Some("US"), "email");
    low_confidence.jurisdiction_confidence_millis = Some(100);
    low_confidence.list_provenance = None;
    assert_eq!(
        verdict(&low_confidence),
        ComplianceVerdict::Allow,
        "a distrusted US observation must not apply the US source-hygiene row"
    );
}

#[test]
fn campaign_compliance_platform_dm_scope_is_row_local() {
    // Japan: the publication exemption exists on email and not on the
    // platform lane, so the same missing context decides differently.
    let mut jp_email = facts(Some("JP"), "email");
    jp_email.jp_publication = None;
    assert_eq!(
        reason(&verdict(&jp_email)),
        Some(ComplianceBlockReason::MissingPublicationContext)
    );
    let mut jp_dm = facts(Some("JP"), "linkedin");
    jp_dm.jp_publication = None;
    assert_eq!(verdict(&jp_dm), ComplianceVerdict::Allow);

    // The UK carries its subscriber-class question onto the platform lane;
    // the US does not carry its opt-out regime's consent question anywhere.
    let mut uk_dm = facts(Some("UK"), "linkedin");
    uk_dm.legal_form = None;
    assert_eq!(
        reason(&verdict(&uk_dm)),
        Some(ComplianceBlockReason::UnknownLegalForm)
    );
    let mut us_dm = facts(Some("US"), "linkedin");
    us_dm.legal_form = None;
    assert_eq!(verdict(&us_dm), ComplianceVerdict::Allow);

    // Germany's platform row is its own, not a global DM rule.
    let mut de_dm = facts(Some("EU/DE"), "linkedin");
    de_dm.legal_form = None;
    assert_eq!(
        reason(&verdict(&de_dm)),
        Some(ComplianceBlockReason::UnknownLegalForm)
    );

    // A jurisdiction's duties reach only the lanes its own rows claim. The
    // Act's Art. 4 display duties are scoped to 特定電子メール, so the
    // platform lane Japan puts outside the Act is not refused for want of
    // the postal address the Act asks for.
    let mut jp_dm_no_address = facts(Some("JP"), "linkedin");
    jp_dm_no_address.physical_address_present = false;
    assert_eq!(verdict(&jp_dm_no_address), ComplianceVerdict::Allow);

    // Same for CAN-SPAM's harvested-list refusal, which the US platform
    // row places outside the federal regime along with the rest of it.
    let mut us_dm_unknown_list = facts(Some("US"), "linkedin");
    us_dm_unknown_list.list_provenance = None;
    assert_eq!(verdict(&us_dm_unknown_list), ComplianceVerdict::Allow);

    // And the converse, which is what makes this row-local rather than a
    // blanket DM carve-out: the UK reads reg 22 onto the platform lane, so
    // the UK's own cease-address duty follows the DM there.
    let mut uk_dm_no_optout = facts(Some("UK"), "linkedin");
    uk_dm_no_optout.optout_mechanism_present = false;
    assert_eq!(
        reason(&verdict(&uk_dm_no_optout)),
        Some(ComplianceBlockReason::MissingRequiredMessageElement)
    );

    // A channel no row covers cannot be evaluated, so it fails closed.
    assert_eq!(
        reason(&verdict(&facts(Some("JP"), "whatsapp"))),
        Some(ComplianceBlockReason::RuleViolation)
    );
}

// -- per-axis walls ----------------------------------------------------

#[test]
fn campaign_compliance_unknown_legal_form_blocks_exemption() {
    let mut unknown = facts(Some("UK"), "email");
    unknown.legal_form = None;
    assert_eq!(
        verdict(&unknown),
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::UnknownLegalForm,
            jurisdiction: Some("UK".to_owned()),
            rule_kind: Some(ComplianceRuleKind::ConsentClass),
        }
    );
    assert_eq!(
        verdict(&facts(Some("UK"), "email")),
        ComplianceVerdict::Allow
    );
}

#[test]
fn campaign_compliance_jp_publication_exemption_requires_context() {
    assert_eq!(
        verdict(&facts(Some("JP"), "email")),
        ComplianceVerdict::Allow
    );
    for spoil in 0..3usize {
        let mut partial = facts(Some("JP"), "email");
        let publication = partial.jp_publication.as_mut().expect("seeded publication");
        match spoil {
            0 => publication.published_by_recipient = false,
            1 => publication.in_course_of_business = false,
            _ => publication.no_marketing_statement_attached = false,
        }
        assert_eq!(
            reason(&verdict(&partial)),
            Some(ComplianceBlockReason::MissingPublicationContext),
            "each of the three Art. 3(1)(iv) facts is load-bearing"
        );
    }
}

#[test]
fn campaign_compliance_us_unknown_list_provenance_blocks() {
    let mut unknown = facts(Some("US"), "email");
    unknown.list_provenance = None;
    assert_eq!(
        verdict(&unknown),
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::UnknownListProvenance,
            jurisdiction: Some("US".to_owned()),
            rule_kind: Some(ComplianceRuleKind::SourceHygiene),
        }
    );

    // A KNOWN-bad provenance is a violation, not an unknown.
    let mut harvested = facts(Some("US"), "email");
    harvested.list_provenance = Some(HydratedListProvenance {
        record_ref: entity(PROVENANCE_SEED),
        claimed_class: "harvested".to_owned(),
    });
    assert_eq!(
        reason(&verdict(&harvested)),
        Some(ComplianceBlockReason::RuleViolation)
    );
}

#[test]
fn campaign_compliance_required_message_elements_block() {
    type SpoilOneAxis = fn(&mut DispatchComplianceFacts);
    let axes: [(SpoilOneAxis, ComplianceRuleKind); 4] = [
        (
            |facts| facts.sender_identity_present = false,
            ComplianceRuleKind::SenderId,
        ),
        (
            |facts| facts.physical_address_present = false,
            ComplianceRuleKind::PhysicalAddress,
        ),
        (
            |facts| facts.optout_mechanism_present = false,
            ComplianceRuleKind::OptoutMechanism,
        ),
        (
            |facts| facts.commercial_marking_present = false,
            ComplianceRuleKind::ContentMarking,
        ),
    ];
    for (spoil, rule_kind) in axes {
        let mut spoiled = facts(Some("US"), "email");
        spoil(&mut spoiled);
        assert_eq!(
            verdict(&spoiled),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::MissingRequiredMessageElement,
                jurisdiction: Some("US".to_owned()),
                rule_kind: Some(rule_kind),
            }
        );
    }
}

#[test]
fn campaign_compliance_stale_verified_at_blocks_dispatch() {
    let pack = pack();
    let mut stale = facts(Some("US"), "email");
    stale.now_utc = SEED_VERIFIED_AT + pack.verified_at_max_age_secs + 1;
    assert_eq!(
        reason(&evaluate_dispatch_compliance(&pack, &stale)),
        Some(ComplianceBlockReason::StaleRule),
        "staleness blocks; it never degrades to warn-and-send"
    );

    // One second earlier the same row is still fresh.
    let mut fresh = stale;
    fresh.now_utc = SEED_VERIFIED_AT + pack.verified_at_max_age_secs;
    assert_eq!(
        evaluate_dispatch_compliance(&pack, &fresh),
        ComplianceVerdict::Allow
    );
}

#[test]
fn campaign_compliance_future_verified_at_is_not_verification() {
    let base = pack();
    let mut future = base.clone();
    future.pack_version = 2;
    for row in &mut future.rows {
        row.verified_at = u64::MAX;
    }

    // Nothing verifies a row after now. A row dated forward — a unit
    // mistype, or a proposal reaching for an immortal row — is refused,
    // not trusted until the end of time.
    assert_eq!(
        reason(&evaluate_dispatch_compliance(
            &future,
            &facts(Some("US"), "email")
        )),
        Some(ComplianceBlockReason::StaleRule),
        "a forward-dated row must not outlive the verification-age dial"
    );

    // This is the evaluator's wall to hold because the classifier cannot:
    // verified_at is provenance, so moving it is a metadata refresh, and a
    // metadata refresh auto-activates.
    assert_eq!(
        classify_compliance_amendment(&base, &future).expect("classified"),
        ComplianceAmendmentClass::MetadataRefresh
    );
}

#[test]
fn campaign_compliance_post_send_rows_never_block_dispatch() {
    // Opt-out deadlines and retention are obligations that begin after the
    // send. They ship as data and are never a dispatch wall.
    assert!(!ComplianceRuleKind::OptoutDeadline.is_dispatch_enforced());
    assert!(!ComplianceRuleKind::Records.is_dispatch_enforced());
    assert_eq!(
        verdict(&facts(Some("US"), "email")),
        ComplianceVerdict::Allow
    );
    assert_eq!(
        verdict(&facts(Some("EU/DE"), "email")),
        ComplianceVerdict::Allow
    );
}

// -- hydration ---------------------------------------------------------

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault =
        Vault::open_unseeded_for_test(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone()))
            .collect(),
    )
}

fn put_person(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"compliance fixture",
        )
        .expect("person");
    id
}

fn put_claim(vault: &Vault, seed: u8, predicate: &str, subject: EntityId, value: Value) {
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&entity(seed), &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("claim write");
}

fn gate_effect(channel_identity_ref: Option<EntityId>) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: None,
            delegation_grant_ref: None,
        },
        provenance: crate::gate::GateProvenanceHandles::default(),
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        channel_identity_ref,
        counterparty: Some("kenji@example.com".to_owned()),
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

fn hydrate(vault: &Vault, subject: EntityId) -> DispatchComplianceFacts {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    hydrate_dispatch_compliance_facts(
        &vault.store,
        &rtxn,
        &gate_effect(Some(entity(IDENTITY_SEED))),
        subject,
        FRESH_NOW,
    )
    .expect("hydration")
}

/// Writes the evidence claim citing `provenance_ref` as `class`.
fn put_evidence(vault: &Vault, subject: EntityId, provenance_ref: EntityId, class: &str) {
    put_claim(
        vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        subject,
        map(&[
            ("legal_form", Value::from("corporate")),
            (
                "list_provenance",
                map(&[
                    ("ref", Value::from(provenance_ref.to_hex())),
                    ("class", Value::from(class)),
                ]),
            ),
        ]),
    );
}

#[test]
fn campaign_compliance_evidence_refs_are_hydrated_and_class_validated() {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, SUBJECT_SEED);
    let other = put_person(&vault, OTHER_SUBJECT_SEED);

    // 1. A reference that resolves to nothing is not evidence.
    put_evidence(&vault, subject, entity(PROVENANCE_SEED), "double_opt_in");
    assert!(hydrate(&vault, subject).list_provenance.is_none());

    // 2. A reference to an unrelated record is not evidence either.
    put_claim(
        &vault,
        WRONG_KIND_SEED,
        PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
        subject,
        map(&[("published_by_recipient", Value::from(true))]),
    );
    put_evidence(&vault, subject, entity(WRONG_KIND_SEED), "double_opt_in");
    assert!(hydrate(&vault, subject).list_provenance.is_none());

    // 3. A provenance record whose own class contradicts the claimed one
    //    is rejected: the claim cannot name the class it likes.
    put_claim(
        &vault,
        WRONG_CLASS_SEED,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
        subject,
        map(&[("class", Value::from("harvested"))]),
    );
    put_evidence(&vault, subject, entity(WRONG_CLASS_SEED), "double_opt_in");
    assert!(hydrate(&vault, subject).list_provenance.is_none());

    // 4. A record bound to ANOTHER counterparty cannot authorize this one.
    put_claim(
        &vault,
        FOREIGN_SEED,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
        other,
        map(&[("class", Value::from("double_opt_in"))]),
    );
    put_evidence(&vault, subject, entity(FOREIGN_SEED), "double_opt_in");
    assert!(hydrate(&vault, subject).list_provenance.is_none());

    // 5. The matching record on this subject hydrates.
    put_claim(
        &vault,
        PROVENANCE_SEED,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
        subject,
        map(&[("class", Value::from("double_opt_in"))]),
    );
    put_evidence(&vault, subject, entity(PROVENANCE_SEED), "double_opt_in");
    let hydrated = hydrate(&vault, subject);
    assert_eq!(
        hydrated.list_provenance,
        Some(HydratedListProvenance {
            record_ref: entity(PROVENANCE_SEED),
            claimed_class: "double_opt_in".to_owned(),
        })
    );
    assert_eq!(hydrated.legal_form.as_deref(), Some("corporate"));
}

#[test]
fn campaign_compliance_disagreeing_evidence_heads_take_the_strict_path() {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, SUBJECT_SEED);
    put_claim(
        &vault,
        PROVENANCE_SEED,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
        subject,
        map(&[("class", Value::from("double_opt_in"))]),
    );

    // Two live evidence heads that disagree: one carries the legal form
    // and cites no provenance, the other cites the provenance and states
    // no legal form. Both are ACTIVE and neither is newer.
    put_claim(
        &vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        subject,
        map(&[("legal_form", Value::from("corporate"))]),
    );
    put_claim(
        &vault,
        SECOND_EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        subject,
        map(&[(
            "list_provenance",
            map(&[
                ("ref", Value::from(entity(PROVENANCE_SEED).to_hex())),
                ("class", Value::from("double_opt_in")),
            ]),
        )]),
    );

    // Exactly one of these would have hydrated had the reader taken a head
    // and run — and whichever it took, the surviving fact answers a wall
    // the other head does not vouch for. Contested evidence is no
    // evidence, so both walls take the strict path.
    let contested = hydrate(&vault, subject);
    assert_eq!(contested.legal_form, None);
    assert_eq!(contested.list_provenance, None);

    // An identical twin — a re-import, an offline-minted duplicate — is
    // one truth restated, not a second one, and still hydrates.
    vault
        .retract_claim(&entity(SECOND_EVIDENCE_SEED), 2)
        .expect("retract the contradicting head");
    put_claim(
        &vault,
        TWIN_EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        subject,
        map(&[("legal_form", Value::from("corporate"))]),
    );
    assert_eq!(
        hydrate(&vault, subject).legal_form.as_deref(),
        Some("corporate")
    );
}

#[test]
fn campaign_compliance_message_elements_come_from_the_sending_identity() {
    let (_dir, vault) = test_vault();
    let subject = put_person(&vault, SUBJECT_SEED);
    let identity = put_person(&vault, IDENTITY_SEED);

    // With no configuration row, no element is established.
    let bare = hydrate(&vault, subject);
    assert!(!bare.sender_identity_present);
    assert!(!bare.optout_mechanism_present);

    put_claim(
        &vault,
        ELEMENTS_SEED,
        PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
        identity,
        map(&[
            ("sender_identity", Value::from(true)),
            ("physical_address", Value::from(true)),
            ("optout_mechanism", Value::from(true)),
            ("commercial_marking", Value::from(true)),
        ]),
    );
    let configured = hydrate(&vault, subject);
    assert!(configured.sender_identity_present);
    assert!(configured.physical_address_present);
    assert!(configured.optout_mechanism_present);
    assert!(configured.commercial_marking_present);

    // A send with no bound identity discloses nothing, whatever a row says.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let unbound = hydrate_dispatch_compliance_facts(
        &vault.store,
        &rtxn,
        &gate_effect(None),
        subject,
        FRESH_NOW,
    )
    .expect("hydration");
    assert!(!unbound.sender_identity_present);
}

// -- amendment ---------------------------------------------------------

fn tightened(base: &CompliancePack) -> CompliancePack {
    let mut proposed = base.clone();
    proposed.pack_version = base.pack_version + 1;
    let mut added = base
        .rows
        .iter()
        .find(|row| row.rule_kind == ComplianceRuleKind::SourceHygiene)
        .expect("a source-hygiene row to copy")
        .clone();
    added.jurisdiction = "UK".to_owned();
    proposed.rows.push(added);
    proposed
}

#[test]
fn campaign_compliance_tightening_auto_applies_with_notice() {
    let (_dir, vault) = test_vault();
    let base = load_active_compliance_pack(&vault).expect("seed bootstraps the active pack");
    assert_eq!(base, pack(), "an empty vault reads the embedded seed");

    let proposed = tightened(&base);
    assert_eq!(
        classify_compliance_amendment(&base, &proposed).expect("classified"),
        ComplianceAmendmentClass::Tightening
    );
    let outcome = propose_compliance_amendment(&vault, entity(ACTOR_SEED), proposed.clone())
        .expect("tightening applies");
    assert_eq!(
        outcome,
        ComplianceAmendmentOutcome::Applied {
            pack_version: 2,
            notice: match &outcome {
                ComplianceAmendmentOutcome::Applied { notice, .. } => notice.clone(),
                ComplianceAmendmentOutcome::PendingOwnerStamp { .. } => String::new(),
            },
        }
    );
    assert_eq!(
        load_active_compliance_pack(&vault)
            .expect("active")
            .pack_version,
        2
    );
    let notices = compliance_amendment_notices(&vault).expect("notices");
    assert_eq!(notices.len(), 1, "the activation left a durable notice");
    assert!(notices[0].contains("tightening"));

    // A citation-and-date-only revision is a metadata refresh.
    let mut refreshed = proposed;
    refreshed.pack_version = 3;
    for row in &mut refreshed.rows {
        row.verified_at += 1;
    }
    assert_eq!(
        classify_compliance_amendment(
            &load_active_compliance_pack(&vault).expect("active"),
            &refreshed
        )
        .expect("classified"),
        ComplianceAmendmentClass::MetadataRefresh
    );
}

#[test]
fn campaign_compliance_loosening_waits_for_owner_stamp() {
    let (_dir, vault) = test_vault();
    let base = load_active_compliance_pack(&vault).expect("active");
    let mut relaxed = base.clone();
    relaxed.pack_version = 2;
    relaxed
        .rows
        .retain(|row| row.rule_kind != ComplianceRuleKind::SourceHygiene);
    assert_eq!(
        classify_compliance_amendment(&base, &relaxed).expect("classified"),
        ComplianceAmendmentClass::LooseningOrAmbiguous
    );

    let outcome =
        propose_compliance_amendment(&vault, entity(ACTOR_SEED), relaxed.clone()).expect("staged");
    let ComplianceAmendmentOutcome::PendingOwnerStamp { proposal_hash } = outcome else {
        panic!("a row deletion must not auto-apply");
    };
    assert_eq!(
        load_active_compliance_pack(&vault)
            .expect("active")
            .pack_version,
        1,
        "nothing activates before the stamp"
    );

    // A hash over different rows does not bind this proposal.
    let other_rows = compliance_proposal_hash(&tightened(&base)).expect("hash");
    assert!(stamp_compliance_amendment(&vault, entity(ACTOR_SEED), other_rows).is_err());
    // Nor does the same rows at a different version.
    let mut other_version = relaxed.clone();
    other_version.pack_version = 3;
    let other_version_hash = compliance_proposal_hash(&other_version).expect("hash");
    assert_ne!(other_version_hash, proposal_hash);
    assert!(stamp_compliance_amendment(&vault, entity(ACTOR_SEED), other_version_hash).is_err());
    assert_eq!(
        load_active_compliance_pack(&vault)
            .expect("active")
            .pack_version,
        1
    );

    let stamped =
        stamp_compliance_amendment(&vault, entity(ACTOR_SEED), proposal_hash).expect("stamped");
    assert_eq!(stamped.pack_version, 2);
    assert_eq!(
        load_active_compliance_pack(&vault).expect("active"),
        relaxed,
        "the stamped version activates"
    );
    // The staged slot is consumed, so one stamp cannot activate twice.
    assert!(stamp_compliance_amendment(&vault, entity(ACTOR_SEED), proposal_hash).is_err());
}

#[test]
fn campaign_compliance_ambiguous_change_is_not_auto_applied() {
    let (_dir, vault) = test_vault();
    let base = load_active_compliance_pack(&vault).expect("active");

    // Free-text requirement edits cannot be ordered, so they are not
    // guessed safe — even one that reads stricter to a human.
    let mut reworded = base.clone();
    reworded.pack_version = 2;
    reworded.rows[0]
        .requirement
        .push_str(" This is now mandatory.");
    assert_eq!(
        classify_compliance_amendment(&base, &reworded).expect("classified"),
        ComplianceAmendmentClass::LooseningOrAmbiguous
    );
    assert!(matches!(
        ingest_published_compliance_update(&vault, reworded).expect("staged"),
        ComplianceAmendmentOutcome::PendingOwnerStamp { .. }
    ));
    assert_eq!(
        load_active_compliance_pack(&vault)
            .expect("active")
            .pack_version,
        1
    );

    // So is a widened trust window, and so is moving the strict pole.
    let mut widened = base.clone();
    widened.pack_version = 2;
    widened.verified_at_max_age_secs += 1;
    assert_eq!(
        classify_compliance_amendment(&base, &widened).expect("classified"),
        ComplianceAmendmentClass::LooseningOrAmbiguous
    );
    let mut moved_pole = base.clone();
    moved_pole.pack_version = 2;
    moved_pole.strict_pole_jurisdiction = "UK".to_owned();
    assert_eq!(
        classify_compliance_amendment(&base, &moved_pole).expect("classified"),
        ComplianceAmendmentClass::LooseningOrAmbiguous
    );

    // A proposal that does not advance the version is rejected outright.
    let mut stale_version = base.clone();
    stale_version.verified_at_max_age_secs -= 1;
    assert!(classify_compliance_amendment(&base, &stale_version).is_err());
}

#[test]
fn campaign_compliance_new_jurisdiction_rows_wait_for_owner_stamp() {
    let base = pack();
    let mut seeded_zz = base.clone();
    seeded_zz.pack_version = 2;
    let mut added = base
        .rows
        .iter()
        .find(|row| row.jurisdiction == "US" && row.rule_kind == ComplianceRuleKind::ConsentClass)
        .expect("a consent-class row to copy")
        .clone();
    added.jurisdiction = "ZZ".to_owned();
    seeded_zz.rows.push(added);

    // Every current row survives byte-identically and one row is added, so
    // the row set reads additive. It is not: seeding a jurisdiction the
    // pack did not hold REMOVES that token from the unknown disposition.
    assert_eq!(
        classify_compliance_amendment(&base, &seeded_zz).expect("classified"),
        ComplianceAmendmentClass::LooseningOrAmbiguous,
        "a row that seeds a NEW jurisdiction is not provably additive"
    );

    // The escape it would otherwise auto-activate, spelled out: the same
    // facts the strict pole refuses sail through the newly seeded token,
    // which now governs itself with exactly the one row the proposal wrote.
    let mut spoiled = facts(Some("ZZ"), "email");
    spoiled.optout_mechanism_present = false;
    assert_eq!(
        reason(&evaluate_dispatch_compliance(&base, &spoiled)),
        Some(ComplianceBlockReason::MissingRequiredMessageElement),
        "an unseeded token takes the strict pole"
    );
    assert_eq!(
        evaluate_dispatch_compliance(&seeded_zz, &spoiled),
        ComplianceVerdict::Allow,
        "a seeded token governs itself — which is why this needs the stamp"
    );

    // Adding a row under an ALREADY-seeded jurisdiction stays additive, so
    // the ordinary tightening path is not collateral damage.
    assert_eq!(
        classify_compliance_amendment(&base, &tightened(&base)).expect("classified"),
        ComplianceAmendmentClass::Tightening
    );
}
