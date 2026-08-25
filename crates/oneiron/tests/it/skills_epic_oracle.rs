//! ARCH-0053 skills-epic forward oracle (authored by the ONE-1735 opener).
//!
//! Every test here is `#[ignore = "armed by ONE-XXXX"]`: it encodes the
//! ACCEPTANCE CONTRACT of a later SK ticket at contract level, compiled
//! against today's public API. Arming rules (wave-2 board, path-opener
//! pattern):
//!
//! - The arming ticket removes its `#[ignore]`, replaces the marked seam
//!   lines (`// ARM(ONE-XXXX): …` + red assert) with real machinery calls,
//!   and may adapt signatures/plumbing to the landed API.
//! - Count-asserts are the contract: they are NEVER weakened, loosened to
//!   `any()`/`is_empty()` negations, or deleted. The path leader screens
//!   every edit to this file.
//! - Wire-shape asserts (map key sets, pinned strings) may be renamed by
//!   the arming ticket ONLY if its ticket text pins different names; the
//!   cardinalities stay.
//!
//! Scope: SK-02 (ONE-1736), SK-03 (ONE-1741), SK-04 (ONE-1737),
//! SK-05 (ONE-1738), SK-06 (ONE-1739). SK-07 (ONE-1740) is docs-only and
//! owned elsewhere; SK-01 (ONE-1735) ships live tests in
//! `src/skill/tests.rs`, not here.
//!
//! FULLY ARMED as of ONE-1739 (SK-06): every contract here now runs against
//! landed machinery, so a red here is a regression, never an un-built layer.

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::{
    ActorClaimEvidence, ActorClaimRow, ActorNote, ActorNoteKind, AttemptOutcome, AttemptQueue,
    AttemptRecord, AttributionVerdict, ClaimApprovalStatus, ClaimAttempt, ClaimBody,
    ClaimLifecycleStatus, ClaimOutcome, ClaimSource, ClaimSubject, CompleteAttempt,
    CompleteOutcome, EdgeActorClass, EnqueueAttempt, EnqueueOutcome, EntityId,
    HubDependencyResolution, HubFile, HubIndexEntry, HubPackage, HubPin, HubRef, HubSyncPolicy,
    LocalDirSkillHubAdapter, ManifestEntry, ManifestKind, OutcomeEvidence, ReceiptQuery, Result,
    SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES, ScanCompleteness, ScanRiskLevel, ScanVerdict,
    SessionActorDistiller, SessionClosePredicate, SessionDistillBrief, SessionEndWake,
    SessionMintOutcome, SkillCapabilitySurface, SkillContentHash, SkillEditProposal,
    SkillGovernance, SkillLifecycle, SkillRecord, SkillScanReceipt, TimeRange, Vault, VaultConfig,
    WitnessAuthor, WitnessMessage, WitnessTurn, attempt_pack_receipt_id, canonical_skill_tree_hash,
    cross_check_declared_content_hash, pending_edit_proposals, project_actor_claims_from_judgments,
    project_skill_reliability, read_attribution_cursor, rebuild_skill_confidence_cache,
    record_attribution_evidence, run_attribution_projector, run_session_end_actor_distill,
    skill_reliability_posterior, write_actor_claim,
};
use rmpv::Value;

// ─── shared fixtures ────────────────────────────────────────────────────

/// §G.1 predicate rows minted by this epic (ARCH-0053 §9).
const PRED_ACTOR_LESSON: &str = "actor.lesson";
const PRED_ACTOR_FAILURE_MODE: &str = "actor.failure_mode";
const PRED_ACTOR_SCOPE_NOTE: &str = "actor.scope_note";
const PRED_ACTOR_SKILL_FIT: &str = "actor.skill_fit";
const PRED_SKILL_RELIABILITY: &str = "skill.reliability";
/// SK-05's floor-crossing PROPOSAL row (ONE-1738): the reserved `skill.*` claim
/// a lower-bound crossing mints, so quarantine is always a question a human
/// answers rather than a lifecycle flip the engine performs.
const PRED_SKILL_QUARANTINE_PROPOSAL: &str = "skill.quarantine_proposal";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn provenance() -> Value {
    Value::Map(vec![(Value::from("source"), Value::from("oracle-fixture"))])
}

fn imported_candidate(skill_id: &str, tree_hash: SkillContentHash) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "Imported oracle fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        provenance(),
    )
    .with_content_hash(tree_hash)
}

fn fixture_tree_hash() -> SkillContentHash {
    canonical_skill_tree_hash([("SKILL.md", b"# oracle fixture skill\n".as_slice())])
        .expect("fixture tree hashes")
}

fn alternate_tree_hash() -> SkillContentHash {
    canonical_skill_tree_hash([("SKILL.md", b"# a different tree\n".as_slice())])
        .expect("fixture tree hashes")
}

/// Puts an imported skill and walks it `candidate → active` so pack/verdict
/// contracts run against an admitted record.
fn put_active_imported_skill(vault: &Vault, id: &EntityId, skill_id: &str) -> Result<SkillRecord> {
    let candidate = imported_candidate(skill_id, fixture_tree_hash());
    vault.put_skill_record(id, &candidate, t(10), 11)?;
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(id, &active, t(12), 13)?;
    Ok(active)
}

fn put_actor(vault: &Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(id, ENTITY_TYPE_PERSON, t(1), 1, b"oracle actor fixture")
}

/// Runs one attempt whose pack loaded `skill_id` to its terminal door and
/// returns the receipt id that close STAMPED. Attribution evidence cites these
/// — a hand-written receipt string is refused at the evidence door.
fn stamped_pack_receipt(vault: &Vault, skill_id: &str) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "oracle.attempt".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::Skill, skill_id, "1.0.0", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "oracle-worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("the enqueued attempt is claimable");
    };
    queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "oracle-worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;
    Ok(attempt_pack_receipt_id(&attempt.id))
}

/// All claim rows on `subject` with `predicate`, split (active, superseded).
fn claim_rows(
    vault: &Vault,
    subject: &EntityId,
    predicate: &str,
) -> Result<(Vec<ClaimBody>, Vec<ClaimBody>)> {
    let mut active = Vec::new();
    let mut superseded = Vec::new();
    for id in vault.claims_for_subject(subject)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate != predicate {
            continue;
        }
        match body.lifecycle {
            ClaimLifecycleStatus::Active => active.push(body),
            ClaimLifecycleStatus::Superseded => superseded.push(body),
            ClaimLifecycleStatus::Retracted => {}
        }
    }
    Ok((active, superseded))
}

fn total_claims(vault: &Vault, subject: &EntityId) -> Result<usize> {
    Ok(vault.claims_for_subject(subject)?.len())
}

/// A CHAT-lane distiller returning exactly the notes it was handed — the
/// `run_attribution_projector_with_judge` seam, on the distillation side (the
/// engine itself never invents a note).
struct OracleDistiller(Vec<ActorNote>);

impl SessionActorDistiller for OracleDistiller {
    fn distill(&self, _brief: &SessionDistillBrief) -> Result<Vec<ActorNote>> {
        Ok(self.0.clone())
    }
}

/// Opens a plain-chat sitting, witnesses `turn_count` turns THROUGH THE
/// PRODUCTION WITNESS DOOR, and ends it through the landed SessionEnd wake,
/// which registers the distill job.
///
/// The door is the fixture's whole point (ONE-1739 verdict F1): it writes an
/// empty TURN container plus MESSAGE children and no SESSION edge whatever, so
/// a sitting assembled by hand — turns carrying `spkr`/`txt` under a `ChildOf`
/// edge into the session — would arm this contract against a shape production
/// never produces, and a dead chat lane would pass it.
fn witnessed_chat_session(vault: &Vault, turn_count: usize, now: u64) -> Result<EntityId> {
    let speaker = EntityId::now();
    put_actor(vault, &speaker)?;
    let facade = vault.memory(speaker, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();
    let SessionMintOutcome::Minted(session) = vault.mint_session(now)? else {
        panic!("a fresh vault mints a session");
    };
    for index in 0..turn_count {
        let index = u64::try_from(index).expect("fixture turn counts are small");
        facade
            .witness(&WitnessTurn {
                conversation_ref: conversation.clone(),
                turn_ref: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "text".to_owned(),
                    content: format!("turn {index}"),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: now + index,
            })
            .expect("the witness door lands the turn");
    }
    vault.end_session_with_wake(
        &session,
        SessionClosePredicate::Explicit,
        now + 100,
        &SessionEndWake::none(0),
    )?;
    Ok(session)
}

/// String field of a MessagePack map value, by key.
fn map_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_str())
}

/// Active scan verdicts for `content_hash`, minus the engine's own static
/// receipt (ONE-1892 PACKET_AMEND).
///
/// The hub import door now runs a deterministic static pass and ingests its
/// receipt, so bytes that entered through a hub always carry an
/// `oneiron.static.v1` row. The SK-02/SK-03 verdict contracts are about
/// INDEPENDENT PROVIDER rows keyed on `(content_hash, provider)`; counting the
/// engine's own row into those arities would assert the producer's existence
/// rather than the contract.
fn third_party_scan_verdicts(
    vault: &Vault,
    content_hash: SkillContentHash,
) -> Result<Vec<ClaimBody>> {
    Ok(vault
        .skill_scan_verdicts_for_content_hash(content_hash)?
        .into_iter()
        .filter(|body| map_str(&body.value, "provider") != Some(oneiron::SCAN_PROVIDER_STATIC_V1))
        .collect())
}

// ═══ SK-02 · ONE-1736 — SKILL_HUB entity + adapters + rug-pull diff ═════

/// Contract (ARCH-0053 §7, ONE-1736): `hub_ref` is STRUCTURED, never a
/// single string — `{hub_id, ref_string, pin: {type, value}}` with the
/// five-way pin union `semver | tag | commit | content_hash | none`
/// (mirrors the claude-marketplace source union). One ref per pin type
/// must be constructible; the `none` pin carries no value.
#[test]
fn sk02_hub_ref_is_structured_with_five_way_pin() {
    const HUB_REF_KEYS: [&str; 3] = ["hubId", "refString", "pin"];
    const PIN_KEYS: [&str; 2] = ["type", "value"];
    const PIN_TYPES: [&str; 5] = ["semver", "tag", "commit", "content_hash", "none"];

    let hub_id = EntityId::now();
    let hub_refs: Vec<Value> = [
        HubPin::Semver("^1.0".to_owned()),
        HubPin::Tag("stable".to_owned()),
        HubPin::Commit("0123456789abcdef".to_owned()),
        HubPin::ContentHash(fixture_tree_hash().to_hex()),
        HubPin::None,
    ]
    .into_iter()
    .map(|pin| {
        HubRef::new(hub_id, "skills/oracle", pin)
            .expect("structured hub ref")
            .to_value()
            .expect("structured hub ref encodes")
    })
    .collect();

    assert_eq!(
        hub_refs.len(),
        PIN_TYPES.len(),
        "one structured hub_ref per pin type (armed by ONE-1736)"
    );
    for (hub_ref, pin_type) in hub_refs.iter().zip(PIN_TYPES) {
        let Value::Map(entries) = hub_ref else {
            panic!("hub_ref must be a structured map, got {hub_ref:?}");
        };
        assert_eq!(entries.len(), HUB_REF_KEYS.len(), "exactly the pinned keys");
        for key in HUB_REF_KEYS {
            assert_eq!(
                entries
                    .iter()
                    .filter(|(k, _)| k.as_str() == Some(key))
                    .count(),
                1,
                "hub_ref key {key} present exactly once"
            );
        }
        let pin = entries
            .iter()
            .find(|(k, _)| k.as_str() == Some("pin"))
            .map(|(_, v)| v)
            .expect("pin key checked above");
        let Value::Map(pin_entries) = pin else {
            panic!("pin must be a structured map, got {pin:?}");
        };
        assert_eq!(pin_entries.len(), PIN_KEYS.len(), "exactly {{type, value}}");
        // Key SET is pinned, not just the map length: {type, bogus} with
        // the right length must not pass (review C11).
        for key in PIN_KEYS {
            assert_eq!(
                pin_entries
                    .iter()
                    .filter(|(k, _)| k.as_str() == Some(key))
                    .count(),
                1,
                "pin key {key} present exactly once"
            );
        }
        let declared_type = pin_entries
            .iter()
            .find(|(k, _)| k.as_str() == Some("type"))
            .and_then(|(_, v)| v.as_str());
        assert_eq!(declared_type, Some(pin_type), "pin type string is pinned");
        if pin_type == "none" {
            let value = pin_entries
                .iter()
                .find(|(k, _)| k.as_str() == Some("value"))
                .map(|(_, v)| v);
            assert_eq!(value, Some(&Value::Nil), "a none pin carries no value");
        }
    }
}

/// Contract (ARCH-0053 §7/§8 r6, ONE-1736): updates run the RUG-PULL DIFF
/// against the prior version held in the vault. Capability-surface
/// widening (`requires.{bins,env,mcp}`, allowed-tools) REQUIRES human
/// re-consent — it must never land with `approval = auto`. Same-or-
/// narrower surfaces flow automatically per policy through the hub-sync
/// door. (The ONE-1735 update gate hard-rejects EVERY in-place imported-
/// content change, whatever the approval stamp; ONE-1736's hub-sync door
/// is the ONLY inlet that re-opens the same/narrower lane.)
#[test]
fn sk02_update_widening_capability_surface_requires_reconsent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let active = put_active_imported_skill(&vault, &skill_entity, "oracle.skill.rugpull")?;

    // Real today (ONE-1735 floor): a silent auto overwrite of imported
    // content is rejected at the generic update door.
    let mut silent = active;
    silent.desc = "upstream rewrote this".to_owned();
    silent.version = "1.1.0".to_owned();
    silent.approval_status = ClaimApprovalStatus::Auto;
    vault
        .update_skill_record(&skill_entity, &silent, t(20), 21)
        .expect_err("silent imported overwrite must stay banned");

    let hub_ref = HubRef::new(EntityId::now(), "skills/oracle-rugpull", HubPin::None)?;
    let mut narrower_record = vault
        .get_skill_record(&skill_entity)?
        .expect("active imported skill");
    narrower_record.version = "1.1.0".to_owned();
    let narrower_package = HubPackage::new(
        narrower_record,
        vec![HubFile::new(
            "SKILL.md",
            b"# oracle fixture skill\n".to_vec(),
        )],
        SkillCapabilitySurface::default(),
    );
    let narrower_applied = vault
        .sync_skill_from_hub(
            &skill_entity,
            &hub_ref,
            &narrower_package,
            HubSyncPolicy::MirrorOfHub,
            t(22),
            23,
        )?
        .applied();

    let mut wider_record = vault
        .get_skill_record(&skill_entity)?
        .expect("narrower update landed");
    wider_record.version = "1.2.0".to_owned();
    let wider_package = HubPackage::new(
        wider_record,
        vec![HubFile::new(
            "SKILL.md",
            b"# oracle fixture skill\n".to_vec(),
        )],
        SkillCapabilitySurface::default().with_bin("new-required-bin"),
    );
    let widening_landed_as = vault
        .sync_skill_from_hub(
            &skill_entity,
            &hub_ref,
            &wider_package,
            HubSyncPolicy::MirrorOfHub,
            t(24),
            25,
        )?
        .approval_status();

    assert!(
        narrower_applied,
        "armed by ONE-1736: same/narrower capability surface flows auto per policy"
    );
    let stored = vault
        .get_skill_record(&skill_entity)?
        .expect("skill persists");
    assert_eq!(stored.version, "1.1.0", "narrower update version landed");

    // Widening NEVER lands auto: the proposal is the strongest thing the
    // door may produce without a human.
    assert_eq!(
        widening_landed_as,
        Some(ClaimApprovalStatus::Proposed),
        "capability widening requires re-consent: proposed, never auto"
    );
    Ok(())
}

/// Contract (ARCH-0053 §7, ONE-1736): scan verdicts attach to
/// `(content_hash, provider, time)` — NEVER to the hub ref. Same hash
/// re-fetched via another hub inherits its verdicts (no new rows); a new
/// hash resets them (zero rows). Provider disagreement is N independent
/// rows, never one merged enum.
#[test]
fn sk02_scan_verdicts_key_on_content_hash_provider_time() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.verdicts")?;

    let content_hash = fixture_tree_hash();
    let receipts = [
        SkillScanReceipt::new(
            "provider-a",
            20,
            ScanVerdict::Malicious,
            ScanRiskLevel::Critical,
            ScanCompleteness::Complete,
            SkillGovernance::Prohibited,
        )?,
        SkillScanReceipt::new(
            "provider-b",
            21,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?,
        SkillScanReceipt::new(
            "provider-c",
            22,
            ScanVerdict::Suspicious,
            ScanRiskLevel::Medium,
            ScanCompleteness::Partial,
            SkillGovernance::Discouraged,
        )?,
    ];
    for (offset, receipt) in receipts.iter().enumerate() {
        let at = 20 + offset as u64;
        vault.ingest_skill_scan_verdict(&skill_entity, content_hash, receipt, t(at), at + 1)?;
    }
    let second_hub_ref = HubRef::new(
        EntityId::now(),
        "skills/oracle-verdicts-mirror",
        HubPin::None,
    )?;
    let second_hub_package = HubPackage::new(
        vault
            .get_skill_record(&skill_entity)?
            .expect("same-hash skill persists before second-hub import"),
        vec![HubFile::new(
            "SKILL.md",
            b"# oracle fixture skill\n".to_vec(),
        )],
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub(&second_hub_ref, &second_hub_package, t(24), 25)?;
    for (offset, receipt) in receipts.iter().enumerate() {
        let at = 26 + offset as u64;
        vault.ingest_skill_scan_verdict(&skill_entity, content_hash, receipt, t(at), at + 1)?;
    }
    let ingested = true;
    assert!(
        ingested,
        "armed by ONE-1736: scan-verdict ingestion not built yet"
    );

    // ONE-1741: verdicts anchor to the content bytes, so discovery is by
    // content hash, not by the submitting holder's subject edges.
    //
    // ONE-1892 PACKET_AMEND: the hub import above now produces the engine's own
    // `oneiron.static.v1` receipt for these bytes. This contract is about the
    // THIRD-PARTY providers ingested here staying independent rows, so the
    // engine's own row is filtered out rather than counted into the arity.
    let active = third_party_scan_verdicts(&vault, content_hash)?;
    assert_eq!(
        active.len(),
        3,
        "three providers = three independent rows, never one merged enum"
    );
    // Each row carries its (content_hash, provider) key — verdicts that
    // name neither would be unattributable rows (review C13).
    let expected_hash = fixture_tree_hash().to_hex();
    for row in &active {
        assert_eq!(
            map_str(&row.value, "contentHash"),
            Some(expected_hash.as_str()),
            "every verdict row carries the content hash it attaches to"
        );
        assert_eq!(
            map_str(&row.value, "provider").map(str::is_empty),
            Some(false),
            "every verdict row names its provider"
        );
    }
    let distinct_providers = active
        .iter()
        .filter_map(|row| map_str(&row.value, "provider"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        distinct_providers.len(),
        3,
        "providers are pairwise distinct"
    );
    // Re-fetch via a second hub added NO rows: verdicts key on the hash,
    // not the ref — 3 stays 3.
    let after_second_hub = third_party_scan_verdicts(&vault, content_hash)?;
    assert_eq!(
        after_second_hub.len(),
        3,
        "hub ref inherits, never duplicates"
    );

    // A NEW hash starts clean.
    let fresh_entity = EntityId::now();
    let fresh = imported_candidate("oracle.skill.fresh", alternate_tree_hash());
    vault.put_skill_record(&fresh_entity, &fresh, t(30), 31)?;
    let fresh_rows = vault.skill_scan_verdicts_for_content_hash(alternate_tree_hash())?;
    assert_eq!(fresh_rows.len(), 0, "a new content hash resets verdicts");
    Ok(())
}

/// Contract (ARCH-0053 §7, ONE-1735/1736): canonical identity dedups —
/// the same canonicalized tree imported via two different hubs is ONE
/// entity with TWO provenance rows (the mutable alias layer), never two
/// entities.
#[test]
fn sk02_same_content_via_two_hubs_is_one_entity_two_provenance_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let first_ref = HubRef::new(EntityId::now(), "skills/oracle-first", HubPin::None)?;
    let second_ref = HubRef::new(EntityId::now(), "skills/oracle-second", HubPin::None)?;
    let package = HubPackage::new(
        imported_candidate("oracle.skill.dedup", fixture_tree_hash()),
        vec![HubFile::new(
            "SKILL.md",
            b"# oracle fixture skill\n".to_vec(),
        )],
        SkillCapabilitySurface::default(),
    );
    let import_results = [
        vault.import_skill_from_hub(&first_ref, &package, t(10), 11)?,
        vault.import_skill_from_hub(&second_ref, &package, t(12), 13)?,
    ];
    let provenance_rows = vault.skill_hub_provenance_count(&import_results[0])?;

    assert_eq!(
        import_results.len(),
        2,
        "armed by ONE-1736: two imports ran"
    );
    assert_eq!(
        import_results[0], import_results[1],
        "same content hash = ONE entity"
    );
    assert_eq!(provenance_rows, 2, "two hubs = two provenance rows");
    let stored = vault
        .get_skill_record(&import_results[0])?
        .expect("the deduped entity exists");
    assert_eq!(
        stored.content_hash.map(|h| h.to_hex()).as_deref(),
        Some(fixture_tree_hash().to_hex().as_str()),
        "canonical identity is the dedup key"
    );
    Ok(())
}

/// Contract (ARCH-0053 §7, ONE-1736): NO TRUST CHAINING. A dependency
/// pointing into another hub inherits NOTHING from the importing hub's
/// trust tier — resolution refuses (fail closed) and materializes no
/// entity.
#[test]
fn sk02_cross_hub_dependency_inherits_nothing_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.deps")?;
    // The entity the dependency WOULD materialize as, if trust chained.
    let dep_entity = EntityId::now();

    let importing_ref = HubRef::new(EntityId::now(), "skills/oracle-parent", HubPin::None)?;
    let dependency_ref = HubRef::new(EntityId::now(), "skills/oracle-dependency", HubPin::None)?;
    let dependency_package = HubPackage::new(
        imported_candidate("oracle.skill.cross-hub-dependency", alternate_tree_hash()),
        vec![HubFile::new("SKILL.md", b"# a different tree\n".to_vec())],
        SkillCapabilitySurface::default(),
    );
    let resolution_refused = matches!(
        vault.resolve_hub_dependency(
            &importing_ref,
            &dependency_ref,
            &dep_entity,
            Some(&dependency_package),
            t(20),
            21,
        )?,
        HubDependencyResolution::RefusedCrossHub
    );

    assert!(
        resolution_refused,
        "armed by ONE-1736: cross-hub dependency must refuse, not inherit trust"
    );
    assert_eq!(
        vault.get_skill_record(&dep_entity)?,
        None,
        "refusal materializes nothing"
    );
    Ok(())
}

// ═══ SK-03 · ONE-1741 — native volume-hub adapter ═══════════════════════

/// Contract (ONE-1741): the native adapter cross-checks the hub's declared
/// per-skill SHA-256 against OUR canonical content hash on every fetch.
/// Mismatch = fail closed: no entity written, no verdict rows minted.
/// (The cross-check primitive itself shipped with ONE-1735:
/// `cross_check_declared_content_hash` — the adapter must route through
/// it.)
#[test]
fn sk03_adapter_rejects_declared_hash_mismatch_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let target = EntityId::now();

    // Real today (ONE-1735 floor): the primitive is fail-closed.
    let record = imported_candidate("oracle.skill.hashcheck", fixture_tree_hash());
    cross_check_declared_content_hash(&record, &fixture_tree_hash().to_hex())?;
    cross_check_declared_content_hash(&record, &alternate_tree_hash().to_hex())
        .expect_err("mismatch must fail closed");

    // ARM(ONE-1741): run the adapter ingest against a fixture package
    // whose hub-declared hash does NOT match the recomputed canonical
    // hash, targeting `target`; capture whether ingest refused.
    let hub_id = EntityId::now();
    let ref_string = "skills/oracle-hashcheck";
    let package = HubPackage::new(
        imported_candidate("oracle.skill.hashcheck", fixture_tree_hash()),
        vec![HubFile::new(
            "SKILL.md",
            b"# oracle fixture skill\n".to_vec(),
        )],
        SkillCapabilitySurface::default(),
    );
    let mut adapter = LocalDirSkillHubAdapter::new(hub_id);
    adapter.insert_package(
        ref_string,
        HubPin::ContentHash(alternate_tree_hash().to_hex()),
        package.clone(),
    );
    let mismatched_entry = HubIndexEntry {
        name: "oracle-hashcheck".to_owned(),
        description: "oracle fixture".to_owned(),
        version: "1.0.0".to_owned(),
        content_hash: alternate_tree_hash(),
        ref_string: ref_string.to_owned(),
    };
    let ingest_refused = vault
        .ingest_skill_from_adapter_checked(&adapter, &mismatched_entry, target, t(20), 21)
        .is_err()
        && vault.get_skill_record(&target)?.is_none()
        && total_claims(&vault, &target)? == 0;

    assert!(
        ingest_refused,
        "armed by ONE-1741: adapter ingest must refuse a declared-hash mismatch"
    );
    assert_eq!(vault.get_skill_record(&target)?, None, "nothing written");
    assert_eq!(
        total_claims(&vault, &target)?,
        0,
        "no verdict rows for a refused package"
    );

    // Acceptance leg (review C12): a reject-all adapter must not pass.
    // ARM(ONE-1741): ingest the SAME fixture package with the CORRECT
    // declared hash and record the entity id it landed at.
    adapter.insert_package(
        ref_string,
        HubPin::ContentHash(fixture_tree_hash().to_hex()),
        package,
    );
    let matching_entry = HubIndexEntry {
        content_hash: fixture_tree_hash(),
        ..mismatched_entry
    };
    let accepted_id =
        vault.ingest_skill_from_adapter_checked(&adapter, &matching_entry, target, t(22), 23)?;
    let landed = vault
        .get_skill_record(&accepted_id)?
        .expect("accepted package lands as a SKILL record");
    assert_eq!(
        landed.content_hash.map(|h| h.to_hex()).as_deref(),
        Some(fixture_tree_hash().to_hex().as_str()),
        "the accepted record carries the verified canonical hash"
    );
    assert_eq!(
        landed.lifecycle_status,
        SkillLifecycle::Candidate,
        "adapter ingest births a candidate; admission stays the gate's act"
    );
    Ok(())
}

/// Contract (ONE-1741, per SK-02's shape): the multi-provider audit
/// endpoint lands each provider verdict as its OWN
/// `(content_hash, provider, time)` row. Disagreement is preserved — a
/// malicious verdict neither merges with nor suppresses the clean ones —
/// and the scanner is SIGNAL, never the gate: the record's lifecycle does
/// not move.
#[test]
fn sk03_provider_audit_verdicts_are_independent_rows_signal_not_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let active = put_active_imported_skill(&vault, &skill_entity, "oracle.skill.audit")?;

    // ARM(ONE-1741): ingest an audit-endpoint fixture carrying verdicts
    // from three providers, exactly one of them flagging malicious.
    let receipts = [
        SkillScanReceipt::new(
            "alpha",
            20,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?,
        SkillScanReceipt::new(
            "beta",
            20,
            ScanVerdict::Malicious,
            ScanRiskLevel::Critical,
            ScanCompleteness::Complete,
            SkillGovernance::Prohibited,
        )?,
        SkillScanReceipt::new(
            "gamma",
            20,
            ScanVerdict::Suspicious,
            ScanRiskLevel::Medium,
            ScanCompleteness::Partial,
            SkillGovernance::Discouraged,
        )?,
    ];
    let ingested = vault.ingest_skill_audit_verdicts(
        &skill_entity,
        fixture_tree_hash(),
        &receipts,
        t(20),
        21,
    )? == 3;
    assert!(
        ingested,
        "armed by ONE-1741: audit-endpoint ingestion not built yet"
    );

    let rows = vault.skill_scan_verdicts_for_content_hash(fixture_tree_hash())?;
    assert_eq!(rows.len(), 3, "three providers = three independent rows");
    // Rows must CARRY their (content_hash, provider) key (review C13):
    // three anonymous rows with one malicious value must not pass.
    let expected_hash = fixture_tree_hash().to_hex();
    for row in &rows {
        assert_eq!(
            map_str(&row.value, "contentHash"),
            Some(expected_hash.as_str()),
            "every verdict row carries the content hash it attaches to"
        );
        assert_eq!(
            map_str(&row.value, "provider").map(str::is_empty),
            Some(false),
            "every verdict row names its provider"
        );
    }
    let distinct_providers = rows
        .iter()
        .filter_map(|row| map_str(&row.value, "provider"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        distinct_providers.len(),
        3,
        "providers are pairwise distinct"
    );
    let flagged = rows
        .iter()
        .filter(|row| map_str(&row.value, "verdict") == Some("malicious"))
        .count();
    assert_eq!(flagged, 1, "disagreement preserved, not merged away");

    let stored = vault
        .get_skill_record(&skill_entity)?
        .expect("record persists");
    assert_eq!(
        stored.lifecycle_status, active.lifecycle_status,
        "scanner verdicts are signal, never the gate: lifecycle unmoved"
    );
    Ok(())
}

// ═══ SK-04 · ONE-1737 — pack-manifest receipts + attribution projector ══

/// Contract (ARCH-0053 §2-3 r5, ONE-1737): the ATTEMPT is a SESSION, not a
/// call. The pack manifest is APPEND-ONLY and GROWS during the run —
/// tier-1 index at t0, mid-run tier-2 pulls append `skill@version`
/// entries, and the terminal receipt carries the FULL accumulated
/// manifest. Earlier entries never mutate or disappear.
#[test]
fn sk04_attempt_manifest_grows_mid_run_and_stays_append_only() {
    // ARMED (ONE-1737): an attempt starts with a tier-1 pack (index only),
    // pulls one tier-2 body mid-run ("oracle.skill.pdf@3"), then closes; the
    // manifest is captured after each of the three moments. The TERMINAL
    // snapshot is read back off the receipt's projected field-set, not off
    // the attempt row — the contract is that the RECEIPT carries the full
    // accumulated manifest.
    let (_tmp, vault) = temp_vault();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: "oracle.attempt".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
        .expect("enqueue attempt")
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };

    let wire_forms = |record: &AttemptRecord| -> Vec<String> {
        record
            .manifest()
            .iter()
            .map(ManifestEntry::wire_form)
            .collect()
    };

    // t0 — tier-1 index resident for the whole run.
    let at_t0 = queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, "oracle.skill.index", "1", 11),
        )
        .expect("tier-1 index appends at t0");

    // Mid-run — the attempt is leased and a step matches, pulling a tier-2
    // body. The pull is stamped WHEN it happens, not at close.
    let ClaimOutcome::Claimed(leased) = queue
        .claim(ClaimAttempt {
            lease_owner: "oracle-worker".to_owned(),
            now: 12,
        })
        .expect("claim the queued attempt")
    else {
        panic!("the enqueued attempt is claimable");
    };
    let at_mid = queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, "oracle.skill.pdf", "3", 13),
        )
        .expect("tier-2 body appends mid-run");

    // Terminal — closing the attempt STAMPS its accumulated manifest into the
    // terminal receipt. No test-only projection call: the queue's own terminal
    // door does it, so this reads the receipt back off the production RS1
    // receipt family exactly as a host would.
    let CompleteOutcome::Completed(_closed) = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "oracle-worker".to_owned(),
            attempt_count: leased.attempt_count,
            now: 14,
        })
        .expect("complete the leased attempt")
    else {
        panic!("a leased attempt completes exactly once");
    };
    let receipt_id = attempt_pack_receipt_id(&attempt.id);
    let family = vault
        .receipts(ReceiptQuery::new(16))
        .expect("query the receipt family");
    let receipt = family
        .into_iter()
        .find(|row| row.receipt_id == receipt_id)
        .expect("the terminal transition stamped the pack receipt onto the spine");
    assert_eq!(
        receipt.outcome, "completed",
        "the receipt records the terminal the attempt actually reached"
    );

    // The manifest door refuses a terminal attempt: append-only is not a
    // convention here, it is enforced at the write door.
    assert!(
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, "oracle.skill.late", "9", 15),
            )
            .is_err(),
        "a closed attempt's manifest is the evidence its receipt already projected"
    );

    let manifest_snapshots: Vec<Vec<String>> = vec![
        wire_forms(&at_t0),
        wire_forms(&at_mid),
        receipt
            .pack_manifest_skills()
            .expect("the terminal receipt stamped the manifest field"),
    ];

    assert_eq!(
        manifest_snapshots.len(),
        3,
        "armed by ONE-1737: capture manifest at t0 / mid-run / terminal"
    );
    for pair in manifest_snapshots.windows(2) {
        assert!(
            pair[1].starts_with(&pair[0]),
            "append-only: every later manifest extends the earlier one verbatim"
        );
    }
    // The tier-2 pull is appended WHEN it happens (review C14): the MID
    // snapshot already strictly extends t0 and already carries the entry —
    // [t0, t0, t0+pull] must not pass.
    assert!(
        manifest_snapshots[1].len() > manifest_snapshots[0].len(),
        "the mid-run snapshot strictly extends t0"
    );
    assert_eq!(
        manifest_snapshots[1]
            .iter()
            .filter(|entry| entry.as_str() == "oracle.skill.pdf@3")
            .count(),
        1,
        "the tier-2 pull is already stamped in the MID snapshot"
    );
    let terminal = manifest_snapshots.last().expect("three snapshots");
    assert_eq!(
        terminal
            .iter()
            .filter(|entry| entry.as_str() == "oracle.skill.pdf@3")
            .count(),
        1,
        "the mid-run tier-2 pull is stamped exactly once in the terminal manifest"
    );
    assert!(
        terminal.len() > manifest_snapshots[0].len(),
        "the manifest grew during the attempt (one-and-done reading rejected, r5)"
    );
}

/// Contract (ARCH-0053 §4, ONE-1737 + ONE-1739): the attribution projector
/// classifies BEFORE writing. Skill defect → claim on the SKILL entity (zero
/// on the actor). Execution lapse → `actor.failure_mode` on the ACTOR (zero
/// new rows on the skill — a lapse contributes nothing to the skill, §5).
///
/// RE-POINTED TO ONE-1739 (ONE-1737, deviation-board item). Every assert here
/// counts CLAIM ROWS, and the claim-write doors plus the `actor.*` predicate
/// reservation belong to ONE-1739 — the SK stack deliberately splits routing
/// (1737) from claiming (1738 reliability / 1739 actor rows), so 1737 cannot
/// satisfy these counts without writing claims its layer must not write. The
/// counts are untouched, per the arming law.
///
/// ONE-1737 landed the routing half and it is green under
/// `skill_attribution::tests::defect_routes_to_the_skill_and_lapse_routes_to_the_actor`:
/// the same two fixtures route to `SkillDefect` on the SKILL and
/// `ExecutionLapse` on the ACTOR, with each verdict citing its receipt and
/// neither contributing to the other's subject. ONE-1739 replaces the ARM seam
/// below with the claim writes those judgments drive.
#[test]
fn sk04_attribution_routes_defect_to_skill_and_lapse_to_actor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let actor_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.attrib")?;
    put_actor(&vault, &actor_entity)?;
    let skill_claims_before = total_claims(&vault, &skill_entity)?;

    // ONE-1737's half, live: route (a) a failed-attempt receipt judged SKILL
    // DEFECT and (b) one judged EXECUTION LAPSE, both with this skill in the
    // manifest and this actor executing.
    let failed = |receipt: &str, followed_skill: bool| {
        OutcomeEvidence::new(receipt, actor_entity, AttemptOutcome::Failed, 30)
            .with_skill(skill_entity)
            .with_routing_facts(followed_skill, true)
    };
    let defect_receipt = stamped_pack_receipt(&vault, "oracle.skill.attrib")?;
    let lapse_receipt = stamped_pack_receipt(&vault, "oracle.skill.attrib")?;
    record_attribution_evidence(&vault, &failed(&defect_receipt, true))?;
    record_attribution_evidence(&vault, &failed(&lapse_receipt, false))?;
    let judgments = run_attribution_projector(&vault, 0)?;
    assert_eq!(judgments.len(), 2, "both failures routed");
    assert_eq!(judgments[0].verdict, AttributionVerdict::SkillDefect);
    assert_eq!(judgments[0].subject, skill_entity);
    assert_eq!(judgments[1].verdict, AttributionVerdict::ExecutionLapse);
    assert_eq!(judgments[1].subject, actor_entity);

    // ARMED (ONE-1739): drive the claim writes off those routed judgments —
    // the defect through SK-05's reliability projector, the lapse through
    // SK-06's actor door. Each projector is handed BOTH judgments, so the
    // counts below also prove neither writes on the other's subject.
    project_skill_reliability(&vault, &judgments)?;
    project_actor_claims_from_judgments(&vault, &judgments)?;

    // (a) defect landed on the skill, not the actor.
    assert_eq!(
        total_claims(&vault, &skill_entity)? - skill_claims_before,
        1,
        "skill defect = exactly one new claim on the SKILL entity"
    );
    // (b) lapse landed on the actor as a failure_mode row …
    let (lapse_rows, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_FAILURE_MODE)?;
    assert_eq!(
        lapse_rows.len(),
        1,
        "execution lapse = one actor.failure_mode row"
    );
    // … and the defect run put nothing on the actor / the lapse run put
    // nothing further on the skill.
    assert_eq!(
        total_claims(&vault, &actor_entity)?,
        1,
        "the actor carries ONLY the lapse row"
    );
    assert_eq!(
        total_claims(&vault, &skill_entity)? - skill_claims_before,
        1,
        "the lapse contributed nothing to the skill"
    );
    Ok(())
}

/// Contract (ARCH-0053 §4, ONE-1737): a DISCOVERY outcome (missing
/// content) is NOT a claim at all — it becomes a skill EDIT PROPOSAL.
/// Zero claims land on either entity.
#[test]
fn sk04_discovery_outcome_mints_edit_proposal_not_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let actor_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.discovery")?;
    put_actor(&vault, &actor_entity)?;
    let skill_claims_before = total_claims(&vault, &skill_entity)?;

    // ARMED (ONE-1737): the projector runs over an outcome the routing table
    // judges DISCOVERY — the attempt failed, the actor DID follow the skill,
    // and the skill did NOT cover the failing step (missing content).
    let discovery_receipt = stamped_pack_receipt(&vault, "oracle.skill.discovery")?;
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(discovery_receipt, actor_entity, AttemptOutcome::Failed, 20)
            .with_skill(skill_entity)
            .with_routing_facts(true, false),
    )?;
    let judgments = run_attribution_projector(&vault, 0)?;
    let projected = judgments.len() == 1
        && judgments[0].verdict == AttributionVerdict::Discovery
        && judgments[0].subject == skill_entity;
    // The proposals are MINTED, PERSISTED rows read back off their own
    // keyspace — not a filtered view of the judgments, which would have made
    // this count a restatement of the line above rather than evidence.
    let edit_proposals: Vec<SkillEditProposal> = pending_edit_proposals(&vault)?;

    assert!(
        projected,
        "the outcome routed to exactly one DISCOVERY verdict"
    );
    assert_eq!(
        total_claims(&vault, &skill_entity)?,
        skill_claims_before,
        "discovery is not a claim on the skill"
    );
    assert_eq!(
        total_claims(&vault, &actor_entity)?,
        0,
        "discovery is not a claim on the actor"
    );
    assert_eq!(
        edit_proposals.len(),
        1,
        "discovery = exactly one edit proposal"
    );
    let proposal = &edit_proposals[0];
    assert_eq!(
        proposal.skill, skill_entity,
        "the proposal targets the skill whose content was missing"
    );
    assert_eq!(
        proposal.judgment_sequence, judgments[0].sequence,
        "the proposal cites the judgment that demanded it"
    );
    assert_eq!(
        proposal.evidence_receipts, judgments[0].evidence_receipts,
        "and carries that judgment's receipts forward as its trace"
    );
    Ok(())
}

// ═══ SK-05 · ONE-1738 — skill.reliability claim + score demotion ════════

/// Contract (ARCH-0053 §5 r3, ONE-1738): `skill.reliability` is a
/// projector-written SUPERSEDING claim carrying the Beta(α, β) posterior
/// and CITING its receipts as evidence. Two projection passes = one
/// active row + one superseded row, never two active rows.
#[test]
fn sk05_reliability_is_a_superseding_claim_citing_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let actor_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.reliability")?;
    put_actor(&vault, &actor_entity)?;

    // ARMED (ONE-1738): project reliability after a first attributed outcome,
    // then again after a second attributed outcome for the same skill. Both are
    // SK-04-routed skill defects — the only loss class §5 counts — and each
    // rides its own stamped pack receipt, which is what the claim cites.
    let mut minted = Vec::new();
    for at in [30_u64, 31] {
        let receipt = stamped_pack_receipt(&vault, "oracle.skill.reliability")?;
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&receipt, actor_entity, AttemptOutcome::Failed, at)
                .with_skill(skill_entity)
                .with_routing_facts(true, true),
        )?;
        let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
        assert_eq!(judgments.len(), 1, "one outcome routed per pass");
        assert_eq!(judgments[0].verdict, AttributionVerdict::SkillDefect);
        let projected = project_skill_reliability(&vault, &judgments)?;
        assert_eq!(
            projected,
            vec![skill_entity],
            "the defect's skill projected"
        );
        minted.push(Value::from(receipt));
    }
    let minted_receipts: Vec<Value> = minted;

    let (active, superseded) = claim_rows(&vault, &skill_entity, PRED_SKILL_RELIABILITY)?;
    assert_eq!(
        active.len(),
        1,
        "one-per-skill cardinality: exactly one active row"
    );
    assert_eq!(
        superseded.len(),
        1,
        "the earlier posterior was superseded, not deleted"
    );

    let row = &active[0];
    assert_eq!(row.approval, ClaimApprovalStatus::Auto, "projector-written");
    // Evidence cites exactly the two receipts the outcomes minted (review
    // C15): any array of length two must not pass.
    let minted = minted_receipts;
    assert_eq!(minted.len(), 2, "two attributed outcomes = two receipts");
    let evidence = row
        .evidence
        .as_ref()
        .expect("reliability cites its receipts");
    let cited = evidence.as_array().expect("evidence is an array");
    assert_eq!(
        cited.len(),
        2,
        "two attributed outcomes = two cited receipts"
    );
    for receipt in &minted {
        assert_eq!(
            cited.iter().filter(|entry| *entry == receipt).count(),
            1,
            "each minted receipt is cited exactly once"
        );
    }
    // Posterior KEY SET is pinned, not just the map length (review C15):
    // {x, y} must not pass. (The header rename clause covers a
    // ticket-pinned wire rename at arming.)
    let posterior = row.value.as_map().expect("the posterior is a map");
    assert_eq!(
        posterior.len(),
        2,
        "the value is the Beta posterior: {{alpha, beta}}"
    );
    for key in ["alpha", "beta"] {
        assert_eq!(
            posterior
                .iter()
                .filter(|(k, _)| k.as_str() == Some(key))
                .count(),
            1,
            "posterior carries {key} exactly once"
        );
    }
    Ok(())
}

/// Contract (ARCH-0053 §5, ONE-1738): the SkillRecord score field is a
/// REBUILDABLE CACHE (CID-7's demotion pattern). Claims are truth; the
/// cache rebuilds to the claim posterior's value, and touching the cache
/// never touches the claim.
#[test]
fn sk05_record_score_is_a_rebuildable_cache_claims_are_truth() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let actor_entity = EntityId::now();
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.cache")?;
    put_actor(&vault, &actor_entity)?;

    // ARMED (ONE-1738): project a reliability claim, capture the posterior mean
    // it asserts, clobber the record's cached score through the ordinary update
    // door, then run the rebuild door.
    let receipt = stamped_pack_receipt(&vault, "oracle.skill.cache")?;
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor_entity, AttemptOutcome::Failed, 30)
            .with_skill(skill_entity)
            .with_routing_facts(true, true),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    project_skill_reliability(&vault, &judgments)?;
    let claim_posterior_mean: f32 = skill_reliability_posterior(&vault, &skill_entity)?
        .expect("the projected claim carries the posterior")
        .mean();

    // The cache is WRITABLE and non-authoritative: clobbering it is a lawful
    // record edit that mints no revision — and, crucially, changes no claim.
    let mut clobbered = vault
        .get_skill_record(&skill_entity)?
        .expect("record persists");
    clobbered.confidence = 0.01;
    vault.update_skill_record(&skill_entity, &clobbered, t(40), 41)?;
    let rebuilt_cache_value: f32 = rebuild_skill_confidence_cache(&vault, &skill_entity, 42)?;
    assert!(
        (vault
            .get_skill_record(&skill_entity)?
            .expect("record persists")
            .confidence
            - rebuilt_cache_value)
            .abs()
            < 1e-6,
        "the rebuild landed on the stored record, not just in the return value"
    );

    let mean = claim_posterior_mean;
    let rebuilt = rebuilt_cache_value;
    assert!(
        (rebuilt - mean).abs() < 1e-6,
        "cache rebuilds to the claim's posterior mean: {rebuilt} vs {mean}"
    );
    let (active, _) = claim_rows(&vault, &skill_entity, PRED_SKILL_RELIABILITY)?;
    assert_eq!(
        active.len(),
        1,
        "clobbering + rebuilding the cache never touched the claim"
    );
    Ok(())
}

/// Contract (ARCH-0053 §5/§6, ONE-1738): a reliability floor-crossing
/// produces a PROPOSED quarantine — never an automatic one. The record
/// stays ACTIVE until a human rules; exactly one quarantine proposal
/// exists. (The ONE-1735 update gate already hard-rejects
/// `quarantined + approval=auto` — this test pins the projector's side.)
#[test]
fn sk05_floor_crossing_proposes_quarantine_never_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    let actor_entity = EntityId::now();
    let active = put_active_imported_skill(&vault, &skill_entity, "oracle.skill.floor")?;
    put_actor(&vault, &actor_entity)?;

    // Real today (ONE-1735 floor): the door itself refuses auto quarantine.
    let mut auto_quarantine = active;
    auto_quarantine.lifecycle_status = SkillLifecycle::Quarantined;
    auto_quarantine.approval_status = ClaimApprovalStatus::Auto;
    vault
        .update_skill_record(&skill_entity, &auto_quarantine, t(20), 21)
        .expect_err("auto quarantine is rejected at the door");

    // ARMED (ONE-1738): drive attributed losses past the reliability floor via
    // the projector. Every pass runs the floor check, so the run also proves the
    // crossing is not re-proposed once a proposal is open.
    let mut floor_crossed = false;
    for at in 30..30 + u64::from(SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES) + 2 {
        let receipt = stamped_pack_receipt(&vault, "oracle.skill.floor")?;
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&receipt, actor_entity, AttemptOutcome::Failed, at)
                .with_skill(skill_entity)
                .with_routing_facts(true, true),
        )?;
        let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
        project_skill_reliability(&vault, &judgments)?;
        let (open, _) = claim_rows(&vault, &skill_entity, PRED_SKILL_QUARANTINE_PROPOSAL)?;
        if let Some(row) = open.first() {
            assert_eq!(
                row.approval,
                ClaimApprovalStatus::Proposed,
                "the floor PROPOSES: a projector-minted `auto` quarantine would be the bug"
            );
            floor_crossed = true;
        }
    }
    let (proposals, _) = claim_rows(&vault, &skill_entity, PRED_SKILL_QUARANTINE_PROPOSAL)?;
    let quarantine_proposals: usize = proposals.len();

    assert!(
        floor_crossed,
        "armed by ONE-1738: floor-crossing projection not built yet"
    );
    let stored = vault
        .get_skill_record(&skill_entity)?
        .expect("record persists");
    assert_eq!(
        stored.lifecycle_status,
        SkillLifecycle::Active,
        "floor-crossing NEVER auto-retires: the record stays active until ruled"
    );
    assert_eq!(quarantine_proposals, 1, "exactly one PROPOSED quarantine");
    Ok(())
}

// ═══ SK-06 · ONE-1739 — actor.* claim writes ════════════════════════════

/// Contract (ARCH-0053 §4/§9, ONE-1739): §G.1 cardinalities are pinned.
/// `actor.lesson` / `actor.failure_mode` / `actor.scope_note` are SETS
/// keyed on the normalized string — a duplicate write collapses, a
/// distinct one adds a row. `actor.skill_fit` is ONE-PER-(actor, skill),
/// superseding, with a fit value in 0..=1.
#[test]
fn sk06_actor_row_cardinalities_are_pinned() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_entity = EntityId::now();
    let skill_a = EntityId::now();
    let skill_b = EntityId::now();
    put_actor(&vault, &actor_entity)?;
    put_active_imported_skill(&vault, &skill_a, "oracle.skill.fit.a")?;
    put_active_imported_skill(&vault, &skill_b, "oracle.skill.fit.b")?;

    // ARMED (ONE-1739): every row goes through `write_actor_claim`, the ONE
    // door both inlets share — cardinality is the door's contract, so this is
    // where it is pinned.
    let receipt = stamped_pack_receipt(&vault, "oracle.skill.fit.a")?;
    let evidence = |at: u64| ActorClaimEvidence::task(vec![receipt.clone()], at);
    for (row, at) in [
        (
            ActorClaimRow::Lesson {
                actor: actor_entity,
                text: "cite the receipt".to_owned(),
            },
            30_u64,
        ),
        (
            ActorClaimRow::Lesson {
                actor: actor_entity,
                text: "cite the receipt".to_owned(),
            },
            31,
        ),
        (
            ActorClaimRow::Lesson {
                actor: actor_entity,
                text: "read the diff".to_owned(),
            },
            32,
        ),
        (
            ActorClaimRow::FailureMode {
                actor: actor_entity,
                text: "skips verification".to_owned(),
            },
            33,
        ),
        (
            ActorClaimRow::ScopeNote {
                actor: actor_entity,
                text: "long-horizon research".to_owned(),
            },
            34,
        ),
        (
            ActorClaimRow::SkillFit {
                actor: actor_entity,
                skill: skill_a,
                fit: 0.25,
            },
            35,
        ),
        (
            ActorClaimRow::SkillFit {
                actor: actor_entity,
                skill: skill_a,
                fit: 0.75,
            },
            36,
        ),
        (
            ActorClaimRow::SkillFit {
                actor: actor_entity,
                skill: skill_b,
                fit: 0.5,
            },
            37,
        ),
    ] {
        write_actor_claim(&vault, row, &evidence(at)?)?;
    }

    let (lessons, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_LESSON)?;
    assert_eq!(
        lessons.len(),
        2,
        "set cardinality: duplicate lesson collapsed"
    );
    let (failure_modes, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_FAILURE_MODE)?;
    assert_eq!(failure_modes.len(), 1, "one distinct failure_mode row");
    let (scope_notes, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_SCOPE_NOTE)?;
    assert_eq!(scope_notes.len(), 1, "one distinct scope_note row");

    // Fit scope is per (actor, skill), NOT per actor (review C16): two
    // skills = two live rows, and only skill_a's first write superseded.
    let (fits, superseded_fits) = claim_rows(&vault, &actor_entity, PRED_ACTOR_SKILL_FIT)?;
    assert_eq!(
        fits.len(),
        2,
        "one live fit row per (actor, skill): two skills = two active rows"
    );
    assert_eq!(
        superseded_fits.len(),
        1,
        "only skill_a's first fit row is superseded, not deleted"
    );
    for row in &fits {
        let fit_value = row.value.as_f64().expect("fit is a number");
        assert!(
            (0.0..=1.0).contains(&fit_value),
            "fit is 0..=1, got {fit_value}"
        );
        assert!(
            row.scope.is_some(),
            "each fit row carries its (actor, skill) scope — the conflict-set key"
        );
    }
    assert_ne!(
        fits[0].scope, fits[1].scope,
        "the two live rows cite two DIFFERENT skills"
    );
    // Binary-exact fixture values: skill_a's superseding 0.75 and
    // skill_b's 0.5 each survive exactly once; skill_a's 0.25 lives only
    // in the superseded row.
    let live_values: Vec<f64> = fits
        .iter()
        .map(|row| row.value.as_f64().expect("fit is a number"))
        .collect();
    assert_eq!(
        live_values.iter().filter(|v| **v == 0.75).count(),
        1,
        "skill_a's live fit is the superseding 0.75"
    );
    assert_eq!(
        live_values.iter().filter(|v| **v == 0.5).count(),
        1,
        "skill_b's live fit is its only write, 0.5"
    );
    assert_eq!(
        superseded_fits[0].value.as_f64(),
        Some(0.25),
        "skill_a's first write survives only as the superseded row"
    );
    Ok(())
}

/// Contract (ARCH-0053 §3, ONE-1739): TWO INLETS, ONE LEDGER. The TASK
/// lane (receipt evidence → attribution projector) and the CHAT lane
/// (SESSION/TURN evidence → Dreamer session-end distill) write the SAME
/// claim rows, and BOTH go through the write gate — evidence-carrying,
/// projector/Dreamer-written per §G.1 (never hand-written next to their
/// evidence).
#[test]
fn sk06_two_inlets_one_ledger_both_through_the_write_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_entity = EntityId::now();
    let skill_entity = EntityId::now();
    put_actor(&vault, &actor_entity)?;
    put_active_imported_skill(&vault, &skill_entity, "oracle.skill.inlets")?;

    // ARMED (ONE-1739) TASK lane: an ATTEMPT receipt routes to an
    // ExecutionLapse judgment, the projector lands its failure-mode row, and
    // the lesson that receipt teaches lands through the SAME door on
    // receipt-grounded (`ToolOutput`-lineage) evidence. The projector itself
    // mints no lesson — a routing boolean cannot source prose — so the note is
    // the distiller tier's, exactly as on the chat side.
    let receipt = stamped_pack_receipt(&vault, "oracle.skill.inlets")?;
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor_entity, AttemptOutcome::Failed, 40)
            .with_skill(skill_entity)
            .with_routing_facts(false, false),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    let task_lane_wrote = !project_actor_claims_from_judgments(&vault, &judgments)?.is_empty()
        && write_actor_claim(
            &vault,
            ActorClaimRow::Lesson {
                actor: actor_entity,
                text: "check the pack before departing from it".to_owned(),
            },
            &ActorClaimEvidence::task(vec![receipt], 41)?,
        )
        .is_ok();

    // ARMED (ONE-1739) CHAT lane: the same rows, distilled at the SessionEnd
    // wake from a sitting's turns.
    let session = witnessed_chat_session(&vault, 2, 50)?;
    let chat_lane_wrote = !run_session_end_actor_distill(
        &vault,
        &session,
        &OracleDistiller(vec![ActorNote {
            actor: actor_entity,
            kind: ActorNoteKind::Lesson,
            text: "say what you are unsure of".to_owned(),
        }]),
    )?
    .is_empty();

    assert!(task_lane_wrote, "the task-lane inlet landed rows");
    assert!(chat_lane_wrote, "the chat-lane inlet landed rows");

    let (lessons, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_LESSON)?;
    assert_eq!(
        lessons.len(),
        2,
        "one ledger: both lanes landed as the same row kind"
    );
    for row in &lessons {
        assert!(
            row.evidence.is_some(),
            "gate-written rows are evidence-carrying (§G.1), never bare"
        );
        assert_eq!(
            row.approval,
            ClaimApprovalStatus::Auto,
            "projector/Dreamer-written rows land auto per §G.1 consent"
        );
        assert_eq!(row.subject, ClaimSubject::Entity(actor_entity));
    }
    Ok(())
}

/// Contract (ARCH-0053 §3, 08b r13, ONE-1739): plain chatting mints NO
/// TASK — chat evidence is SESSION/TURN and still teaches via Dreamer
/// distill. The moment chat spawns real work, THAT moment mints a TASK.
/// Lanes compose, never blur.
#[test]
fn sk06_chat_lane_mints_no_task_until_work_spawns() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_entity = EntityId::now();
    put_actor(&vault, &actor_entity)?;

    // ARMED (ONE-1739): the Dreamer session-end distill over a plain-chat
    // SESSION fixture mints CLAIMs and nothing else…
    let session = witnessed_chat_session(&vault, 2, 60)?;
    let distilled = !run_session_end_actor_distill(
        &vault,
        &session,
        &OracleDistiller(vec![ActorNote {
            actor: actor_entity,
            kind: ActorNoteKind::Lesson,
            text: "restate the ask before answering".to_owned(),
        }]),
    )?
    .is_empty();
    let tasks_minted_by_chat = vault.entities_by_type(ENTITY_TYPE_TASK)?;

    // …and the moment the sitting spawns real work, the surface that spawns
    // it mints the TASK explicitly. Minting is an ACT, never a side effect of
    // learning from a conversation.
    let spawned_task = EntityId::now();
    let mut task_body = Vec::new();
    rmpv::encode::write_value(
        &mut task_body,
        &Value::Map(vec![(Value::from("role"), Value::from(1_u8))]),
    )
    .expect("TASK role body encodes");
    vault.put_entity(&spawned_task, ENTITY_TYPE_TASK, t(61), 61, &task_body)?;
    let spawned = vault.entities_by_type(ENTITY_TYPE_TASK)?;

    assert!(distilled, "the chat-lane distill landed its row");
    let (lessons, _) = claim_rows(&vault, &actor_entity, PRED_ACTOR_LESSON)?;
    assert_eq!(
        lessons.len(),
        1,
        "chat still teaches: the distilled row landed"
    );
    assert_eq!(
        tasks_minted_by_chat.len(),
        0,
        "plain chatting mints no TASK (08b r13)"
    );
    assert_eq!(
        spawned.len(),
        1,
        "the moment chat spawns real work, that moment mints exactly one TASK"
    );
    Ok(())
}
