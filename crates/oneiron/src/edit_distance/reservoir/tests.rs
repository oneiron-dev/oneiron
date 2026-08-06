//! ONE-1765 (ED-09) unit tests: the pair projection and what it refuses to
//! project, the off-record exclusion (constructive) and its tripwire (loud,
//! zero-byte), the consent rail at the door, JSONL/hash determinism, the export
//! receipt, and the index rebuild identity.

use super::*;

use rmpv::Value as RmpValue;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::attribution::{AmendmentEvidence, record_amendment_evidence};
use crate::edit_distance::delta::{delta_from_reconstructed, put_amendment_delta_in_txn};
use crate::edit_distance::{
    FinalizedProposalText, LoroOpRef, ProposalArtifactRef, put_finalized_proposal_text,
};
use crate::off_record::OffRecordBackendClass;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A sink that only counts. The two-phase contract is a claim about BYTES, so
/// the test that checks it has to be able to see zero of them.
#[derive(Default)]
struct CountingSink {
    bytes: usize,
}

impl io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn put_actor(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"ed09 actor fixture")?;
    Ok(id)
}

fn put_skill(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    let tree_hash = canonical_skill_tree_hash([("SKILL.md", b"# ed09 fixture\n".as_slice())])
        .expect("fixture tree hashes");
    let candidate = SkillRecord::new(
        "ed09.fixture",
        "ed09 fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        RmpValue::Map(vec![(
            RmpValue::from("source"),
            RmpValue::from("ed09-fixture"),
        )]),
    )
    .with_content_hash(tree_hash);
    vault.put_skill_record(&id, &candidate, t(10), 11)?;
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, t(12), 13)?;
    Ok(id)
}

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = crate::test_util::entity(0x91);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            t(100),
            100,
            b"ed09 export owner",
        )
        .expect("put owner");
    vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner")
}

/// Mints the standing disclosure grant the export door demands, through the
/// real consent registry — the rail's own door, never a re-implementation.
fn grant_export(vault: &Vault) {
    let owner = owner(vault);
    vault
        .create_standing_grant(&owner, export_grant_bound().expect("bound"))
        .expect("grant the reservoir export audience");
}

/// Persists a finalized proposal artifact — ED-00's retention row, which is the
/// reservoir's whole candidate substrate.
fn put_artifact(
    vault: &Vault,
    proposed: &str,
    final_text: &str,
    source_turn_ref: Option<EntityId>,
) -> Result<ProposalArtifactRef> {
    let artifact_ref = ProposalArtifactRef::mint();
    put_finalized_proposal_text(
        vault,
        &FinalizedProposalText {
            artifact_ref,
            proposed_ref: LoroOpRef::from_bytes(vec![1]),
            final_ref: LoroOpRef::from_bytes(vec![2]),
            ops_by_actor: Vec::new(),
            proposed_text: proposed.to_owned(),
            final_text: final_text.to_owned(),
            source_turn_ref,
        },
    )?;
    Ok(artifact_ref)
}

/// Records the tag row an artifact's pair joins on: a real ED-01 Δ, then the
/// ED-03 evidence keyed by the artifact's own ref hex.
fn tag_artifact(
    vault: &Vault,
    artifact: ProposalArtifactRef,
    task_class: &str,
    at: u64,
    skill: Option<EntityId>,
) -> Result<()> {
    let receipt_id = artifact.entity_id().to_hex();
    let delta = delta_from_reconstructed("before", "after");
    vault.with_write_txn(|wtxn| {
        put_amendment_delta_in_txn(vault, wtxn, &receipt_id, &delta)?;
        Ok(())
    })?;
    let mut evidence = AmendmentEvidence::new(&receipt_id, put_actor(vault)?, task_class).at(at);
    if let Some(skill) = skill {
        evidence = evidence.with_skill(skill);
    }
    record_amendment_evidence(vault, &evidence)
}

fn export_to_vec(vault: &Vault, scope: ReservoirScope) -> Result<(ExportManifest, String)> {
    let mut out = Vec::new();
    let manifest = export_reservoir(vault, scope, &mut out)?;
    Ok((manifest, String::from_utf8(out).expect("JSONL is utf-8")))
}

// ─── the pair projection ────────────────────────────────────────────────

/// An amendment projects `rejected = proposed` / `chosen = final`. An untouched
/// approval and a rejection both leave the two ends EQUAL, and neither is a
/// preference — so neither projects a pair.
#[test]
fn an_amendment_projects_a_pair_and_an_unamended_outcome_projects_none() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let amended = put_artifact(&vault, "draft text", "decider's text", None)?;
    // approved_untouched / rejected: the window closed with nothing changed.
    put_artifact(&vault, "untouched", "untouched", None)?;

    let pairs = reservoir_candidates(&vault, ReservoirScope::default())?;
    assert_eq!(pairs.len(), 1, "only the amended artifact is a candidate");
    assert_eq!(pairs[0].rejected, "draft text");
    assert_eq!(pairs[0].chosen, "decider's text");
    assert_eq!(pairs[0].receipt_ref, amended.entity_id());
    Ok(())
}

/// Tags join from the evidence row. An artifact with no tag row still projects
/// its pair, with every tag explicitly absent — never a guess, never a drop.
#[test]
fn tags_join_from_the_evidence_row_and_absence_stays_explicit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill = put_skill(&vault)?;
    let tagged = put_artifact(&vault, "a", "b", None)?;
    tag_artifact(&vault, tagged, "outbound", 500, Some(skill))?;
    put_artifact(&vault, "c", "d", None)?;

    let pairs = reservoir_candidates(&vault, ReservoirScope::default())?;
    assert_eq!(pairs.len(), 2);
    let joined = pairs
        .iter()
        .find(|pair| pair.receipt_ref == tagged.entity_id())
        .expect("the tagged pair");
    assert_eq!(joined.task_class.as_deref(), Some("outbound"));
    assert_eq!(joined.skill, Some(skill));

    let untagged = pairs
        .iter()
        .find(|pair| pair.receipt_ref != tagged.entity_id())
        .expect("the untagged pair");
    assert_eq!(untagged.task_class, None, "absence is explicit");
    assert_eq!(untagged.skill, None);
    assert_eq!(untagged.model_id, None);
    Ok(())
}

/// A narrowed scope excludes untagged pairs, both on the class axis and the
/// time axis: a pair that cannot be SHOWN to be in the named set is not in it.
#[test]
fn a_narrowed_scope_excludes_pairs_it_cannot_place() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let prose = put_artifact(&vault, "p0", "p1", None)?;
    tag_artifact(&vault, prose, "prose", 100, None)?;
    let calendar = put_artifact(&vault, "c0", "c1", None)?;
    tag_artifact(&vault, calendar, "calendar", 900, None)?;
    put_artifact(&vault, "u0", "u1", None)?;

    let by_class = reservoir_candidates(
        &vault,
        ReservoirScope {
            task_classes: Some(vec!["prose".to_owned()]),
            since: None,
        },
    )?;
    assert_eq!(by_class.len(), 1);
    assert_eq!(by_class[0].receipt_ref, prose.entity_id());

    let by_time = reservoir_candidates(
        &vault,
        ReservoirScope {
            task_classes: None,
            since: Some(500),
        },
    )?;
    assert_eq!(
        by_time.len(),
        1,
        "the untagged pair has no instant to place"
    );
    assert_eq!(by_time[0].receipt_ref, calendar.entity_id());

    // An empty class list is not "everything" — `None` is how that is said.
    assert!(
        reservoir_candidates(
            &vault,
            ReservoirScope {
                task_classes: Some(Vec::new()),
                since: None,
            },
        )
        .is_err()
    );
    Ok(())
}

// ─── off-record: constructive exclusion, then the tripwire ──────────────

/// CONSTRUCTIVE exclusion (ONE-1570): a fenced turn is pipeline-inert, so no
/// derived row is produced from it and the scan has nothing to filter. The
/// candidate stream is empty because the work never became a row — not because
/// something removed it.
#[test]
fn a_fenced_session_contributes_no_candidates_at_all() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    vault.enter_off_record_session("session:ed09", OffRecordBackendClass::Local)?;
    let turn = crate::test_util::entity(0x41);
    vault.tag_turn_off_record("session:ed09", &turn)?;
    assert!(vault.is_turn_off_record_fenced(&turn)?, "the fence is up");

    // The room produced work, and none of it left a retention row.
    assert!(
        reservoir_candidates(&vault, ReservoirScope::default())?.is_empty(),
        "a fenced session's work never enters the candidate stream"
    );
    Ok(())
}

/// THE TRIPWIRE. A candidate whose persisted `source_turn_ref` is fenced means
/// an upstream inertness bug: the export ABORTS with a typed error, and the
/// two-phase contract means the sink has seen ZERO bytes when it does.
#[test]
fn a_fenced_source_turn_aborts_the_export_before_the_first_byte() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    // A healthy pair, so the abort is not merely an empty export.
    put_artifact(&vault, "healthy", "healthy amended", None)?;

    let turn = crate::test_util::entity(0x52);
    vault.put_entity(&turn, ENTITY_TYPE_TURN, t(3), 3, b"ed09 fenced turn")?;
    // The inertness bug: a retention row that carries a turn which is fenced.
    put_artifact(&vault, "leaked draft", "leaked final", Some(turn))?;
    vault.enter_off_record_session("session:ed09", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("session:ed09", &turn)?;

    let mut sink = CountingSink::default();
    let err = export_reservoir(&vault, ReservoirScope::default(), &mut sink)
        .expect_err("a fenced candidate refuses the export");
    assert!(
        matches!(err, Error::InvariantViolation(message) if message.contains("off-record fenced")),
        "the abort is typed and names the fence, got {err:?}"
    );
    assert_eq!(
        sink.bytes, 0,
        "validation completes before the first byte is written"
    );

    // Loud, never a silent skip: the healthy pair does not ship either.
    assert!(reservoir_candidates(&vault, ReservoirScope::default()).is_err());
    Ok(())
}

/// A candidate with no turn source passes the tripwire: absent is "not
/// turn-sourced", not "unknown", so there is no fence surface to violate.
#[test]
fn a_pair_with_no_source_turn_passes_the_tripwire() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    put_artifact(&vault, "no turn", "no turn amended", None)?;
    let (manifest, _) = export_to_vec(&vault, ReservoirScope::default())?;
    assert_eq!(manifest.pairs, 1);
    Ok(())
}

/// A turn-sourced pair whose turn is NOT fenced exports normally — the tripwire
/// discriminates on the fence, not on having a turn.
#[test]
fn an_unfenced_source_turn_exports_normally() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    let turn = crate::test_util::entity(0x43);
    vault.put_entity(&turn, ENTITY_TYPE_TURN, t(3), 3, b"ed09 open turn")?;
    put_artifact(&vault, "open draft", "open final", Some(turn))?;

    let (manifest, jsonl) = export_to_vec(&vault, ReservoirScope::default())?;
    assert_eq!(manifest.pairs, 1);
    assert!(jsonl.contains("open final"));
    Ok(())
}

/// NO OVERRIDE API. Two guards, because either alone is escapable: the scope
/// and pair shapes are destructured EXHAUSTIVELY (a new field is a compile
/// error right here), and the module source carries none of the identifiers an
/// override would have to be spelled with.
#[test]
fn no_override_api_on_the_export_surface() {
    // Compile-surface: adding an admit-fenced field to either type breaks this.
    let ReservoirScope {
        task_classes: _,
        since: _,
    } = ReservoirScope::default();
    let TrainingPair {
        rejected: _,
        chosen: _,
        task_class: _,
        skill: _,
        model_id: _,
        receipt_ref: _,
    } = TrainingPair {
        rejected: String::new(),
        chosen: String::new(),
        task_class: None,
        skill: None,
        model_id: None,
        receipt_ref: EntityId::now(),
    };

    let source = include_str!("../reservoir.rs");
    for needle in [
        concat!("allow_off", "_record"),
        concat!("include_", "fenced"),
        concat!("skip_", "fence"),
        concat!("off_record_", "override"),
        concat!("force_", "export"),
    ] {
        assert!(
            !source.contains(needle),
            "reservoir.rs must expose no `{needle}` override"
        );
    }
}

// ─── the consent rail ───────────────────────────────────────────────────

/// An export is content leaving the vault, so it rides the house disclosure
/// rail: fail-closed with no covering grant, and revocation is immediate.
#[test]
fn the_export_door_rides_the_disclosure_consent_rail() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_artifact(&vault, "x", "y", None)?;

    let mut sink = CountingSink::default();
    let err = export_reservoir(&vault, ReservoirScope::default(), &mut sink)
        .expect_err("no grant, no export");
    assert!(matches!(err, Error::ConsentGrantNotFound));
    assert_eq!(sink.bytes, 0, "a refused export writes nothing");

    let owner = owner(&vault);
    let receipt = vault.create_standing_grant(&owner, export_grant_bound()?)?;
    assert_eq!(export_to_vec(&vault, ReservoirScope::default())?.0.pairs, 1);

    let grant_ref = receipt.grant_ref().expect("the standing grant's row ref");
    vault.revoke_consent_grant(&owner, &grant_ref)?;
    assert!(
        matches!(
            export_reservoir(
                &vault,
                ReservoirScope::default(),
                &mut CountingSink::default()
            ),
            Err(Error::ConsentGrantNotFound)
        ),
        "revocation is immediate"
    );
    Ok(())
}

// ─── the artifact, the hash, the receipt ────────────────────────────────

/// The export is JSONL: one object per pair, every line parsing on its own.
#[test]
fn the_export_is_one_json_object_per_line() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    let first = put_artifact(&vault, "draft one", "final one", None)?;
    tag_artifact(&vault, first, "prose", 10, None)?;
    put_artifact(&vault, "draft two", "final two", None)?;

    let (manifest, jsonl) = export_to_vec(&vault, ReservoirScope::default())?;
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), manifest.pairs);
    assert_eq!(lines.len(), 2);

    let tagged = lines
        .iter()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("each line is JSON"))
        .find(|row| row["receipt_ref"] == first.entity_id().to_hex())
        .expect("the tagged row");
    assert_eq!(tagged["rejected"], "draft one");
    assert_eq!(tagged["chosen"], "final one");
    assert_eq!(tagged["task_class"], "prose");
    assert!(tagged["skill"].is_null(), "absence rides the wire as null");
    Ok(())
}

/// Re-exporting one scope over unchanged rows reproduces the hash exactly: the
/// walk is key-ordered and the encoding is field-ordered, so the digest is an
/// identity rather than a coincidence. A different scope is a different corpus
/// and says so.
#[test]
fn re_exporting_one_scope_reproduces_the_hash() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    let prose = put_artifact(&vault, "p0", "p1", None)?;
    tag_artifact(&vault, prose, "prose", 10, None)?;
    let calendar = put_artifact(&vault, "c0", "c1", None)?;
    tag_artifact(&vault, calendar, "calendar", 20, None)?;

    let (first, first_body) = export_to_vec(&vault, ReservoirScope::default())?;
    let (second, second_body) = export_to_vec(&vault, ReservoirScope::default())?;
    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(first_body, second_body);
    assert_ne!(
        first.receipt, second.receipt,
        "two exports are two acts, each receipted"
    );

    // Filter order and duplicates normalize away; a genuinely narrower scope
    // does not.
    let (a, _) = export_to_vec(
        &vault,
        ReservoirScope {
            task_classes: Some(vec!["prose".to_owned(), "calendar".to_owned()]),
            since: None,
        },
    )?;
    let (b, _) = export_to_vec(
        &vault,
        ReservoirScope {
            task_classes: Some(vec![
                "calendar".to_owned(),
                "prose".to_owned(),
                " prose ".to_owned(),
            ]),
            since: None,
        },
    )?;
    assert_eq!(a.content_hash, b.content_hash);
    let (narrow, _) = export_to_vec(
        &vault,
        ReservoirScope {
            task_classes: Some(vec!["prose".to_owned()]),
            since: None,
        },
    )?;
    assert_ne!(a.content_hash, narrow.content_hash);
    Ok(())
}

/// The export receipt records scope, count and hash — and projects through the
/// ordinary receipt query, in the `ScopedRead` family.
#[test]
fn the_export_receipt_records_scope_count_and_hash() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    grant_export(&vault);
    let prose = put_artifact(&vault, "p0", "p1", None)?;
    tag_artifact(&vault, prose, "prose", 10, None)?;

    let (manifest, _) = export_to_vec(
        &vault,
        ReservoirScope {
            task_classes: Some(vec!["prose".to_owned()]),
            since: Some(5),
        },
    )?;

    let receipt = vault
        .receipts(ReceiptQuery::default().with_kind(ReceiptKind::ScopedRead))?
        .into_iter()
        .find(|record| {
            record.receipt_id == format!("{EXPORT_RECEIPT_ID_PREFIX}{}", manifest.receipt.to_hex())
        })
        .expect("the export receipt projects into the ScopedRead family");
    assert_eq!(receipt.outcome, "exported");
    assert_eq!(
        receipt.fields.get(FIELD_EXPORT_PAIRS).map(String::as_str),
        Some("1")
    );
    assert_eq!(
        receipt
            .fields
            .get(FIELD_EXPORT_CONTENT_HASH)
            .map(String::as_str),
        Some(manifest.content_hash.as_str())
    );
    assert_eq!(
        receipt
            .fields
            .get(FIELD_EXPORT_TASK_CLASSES)
            .map(String::as_str),
        Some("prose")
    );
    assert_eq!(
        receipt.fields.get(FIELD_EXPORT_SINCE).map(String::as_str),
        Some("5")
    );
    Ok(())
}

// ─── the rebuildable index (CID-7) ──────────────────────────────────────

/// The index is derived state: rebuilding it twice is an identity, it carries
/// exactly the candidates the export carries, and a row that stopped being a
/// candidate is DELETED rather than remembered.
#[test]
fn rebuilding_the_index_is_an_identity_and_drops_stale_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let prose = put_artifact(&vault, "p0", "p1", None)?;
    tag_artifact(&vault, prose, "prose", 10, None)?;
    put_artifact(&vault, "same", "same", None)?;

    rebuild_reservoir_index(&vault)?;
    let first = index_rows(&vault)?;
    rebuild_reservoir_index(&vault)?;
    assert_eq!(first, index_rows(&vault)?, "the rebuild is an identity");

    let candidates = reservoir_candidates(&vault, ReservoirScope::default())?;
    assert_eq!(
        first.len(),
        candidates.len(),
        "the index holds exactly the candidates"
    );
    assert!(
        first.contains_key(&candidate_key(prose.entity_id())),
        "the amended artifact is indexed"
    );

    // A row the index remembers but the projection no longer produces is
    // deleted, not carried.
    let ghost = candidate_key(EntityId::now());
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &ghost, b"{}")?;
        Ok(())
    })?;
    rebuild_reservoir_index(&vault)?;
    assert!(!index_rows(&vault)?.contains_key(&ghost), "stale rows go");
    Ok(())
}

/// The index refuses to build over a fenced candidate for the same reason the
/// export does: the tripwire runs on the one shared enumeration path.
#[test]
fn the_index_rebuild_shares_the_export_tripwire() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turn = crate::test_util::entity(0x44);
    vault.put_entity(&turn, ENTITY_TYPE_TURN, t(3), 3, b"ed09 fenced turn")?;
    put_artifact(&vault, "leaked", "leaked amended", Some(turn))?;
    vault.enter_off_record_session("session:ed09", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("session:ed09", &turn)?;

    assert!(matches!(
        rebuild_reservoir_index(&vault),
        Err(Error::InvariantViolation(_))
    ));
    Ok(())
}

fn index_rows(vault: &Vault) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, CANDIDATE_KEY_PREFIX)?
        .map(|entry| {
            let (key, value) = entry?;
            Ok((key.to_vec(), value.to_vec()))
        })
        .collect()
}
