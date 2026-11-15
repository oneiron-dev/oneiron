//! Shared landing helper for the extraction binding commit tests (T1-T3).
//!
//! The green-tea landing copies `derive_candidate.rs`
//! `a_candidate_lands_as_native_prepares_it` exactly: owen chooses green tea,
//! `preference.food`, confidence `0.0` and no hints, with all same field
//! compares. The only intentional difference is run provenance:
//! a binding commit stamps the attempt's run (`EXTRACTION_RUN`), not the
//! stamp door's `"run"`.

use oneiron::claim::ClaimSubject;
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::test_doors::extraction_inputs::EXTRACTION_RUN;
use oneiron::test_doors::open_candidate::build_native_candidate;
use oneiron::{AttemptId, EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

use crate::verdict_support::{extraction_attempt_hex, extraction_candidate};

/// A fixture or assertion error, without hiding its source.
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The predicate the extraction fixture asserts.
pub(crate) const FOOD: &str = "preference.food";

/// The commit verb a binding lands through.
pub(crate) const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

/// One candidate operand over `subject` with `value` citing `turn`.
pub(crate) fn operand_for(subject: &str, value: Value, turn: &(String, Value)) -> Value {
    extraction_candidate(subject, FOOD, value, &turn.0, turn.1.clone())
}

/// One candidate member: `candidate` with `confidence` and `hints`.
pub(crate) fn member(candidate: Value, confidence: f64, hints: Vec<Value>) -> Value {
    json!({"candidate": candidate, "confidence": confidence, "prospective_queries": hints})
}

/// One Candidate wire item over `member`.
pub(crate) fn candidate_spec(local: &str, member: Value) -> Value {
    json!({"kind": "candidate", "spec": {"local": local, "member": member}})
}

/// The map entry `key` of `value`, when it is a map holding one.
pub(crate) fn map_at<'v>(value: &'v RmpValue, key: &str) -> Option<&'v RmpValue> {
    let RmpValue::Map(rows) = value else {
        return None;
    };
    rows.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, found)| found)
}

/// `value`'s encoded bytes as lowercase hex.
pub(crate) fn hex_of(value: &RmpValue) -> TestResult<String> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| "the value encodes")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// What a binding green-tea landing did.
pub(crate) struct BoundLanding {
    /// The landed claim.
    pub(crate) claim: EntityId,
    /// The recorded batch.
    pub(crate) batch: EntityId,
}

/// Lands one green-tea candidate via `binding` and checks every field the
/// stamp-door fixture checks, with run provenance `EXTRACTION_RUN`.
pub(crate) fn land_green_tea_via_binding(
    vault: &Vault,
    attempt: AttemptId,
    binding: &DreamerAttemptBinding,
    turns: &[(String, Value)],
    subject: &EntityId,
) -> TestResult<BoundLanding> {
    assert_eq!(turns.len(), 1);
    let operand = operand_for(&subject.to_hex(), json!("green tea"), &turns[0]);
    // The build-only door first, at the commit's own clock unit: the vault's
    // recorded seconds as milliseconds. No compared
    // field carries time (the id hashes identity axes only; the body, scope
    // and evidence are timeless), so the door's clock need not equal the
    // commit's second.
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let hex = extraction_attempt_hex(attempt);
    let door = build_native_candidate(vault, &hex, now_ms, &operand)?;
    let green = member(operand, 0.0, vec![]);
    let request = json!({"items": [candidate_spec("first", green)], "sources": []});
    let answer = binding.invoke(DERIVE_COMMIT_VERB, request, None)?;
    let item = &answer["items"][0];
    assert_eq!(item["landed"], true, "{answer}");
    assert_eq!(item["kind"], "candidate");
    assert_eq!(door["claim"], item["rows"][0]);
    assert_eq!(item["approval"], json!("auto"));
    let claim = EntityId::from_hex(item["rows"][0].as_str().ok_or("the row")?)?;
    let batch = EntityId::from_hex(answer["batch"].as_str().ok_or("the batch")?)?;
    let stored = vault.get_claim(&claim)?.ok_or("the stored claim")?;
    assert_eq!(door["predicate"].as_str().ok_or("p")?, stored.predicate);
    let ClaimSubject::Entity(stored_subject) = stored.subject else {
        return Err("the claim names an entity subject".into());
    };
    assert_eq!(
        door["subject"].as_str().ok_or("s")?,
        stored_subject.to_hex()
    );
    assert_eq!(
        door["value_hex"].as_str().ok_or("v")?,
        hex_of(&stored.value)?
    );
    let stored_scope = stored.scope.as_ref().ok_or("scope")?;
    assert_eq!(
        door["scope_hex"].as_str().ok_or("sc")?,
        hex_of(stored_scope)?
    );
    assert_eq!(
        door["source"].as_str().ok_or("src")?,
        stored.source.ok_or("source")?.as_str()
    );
    assert_eq!(
        door["confidence"].as_f64().ok_or("c")?,
        f64::from(stored.confidence)
    );
    assert_eq!(
        door["world"].as_str(),
        stored.world.map(|world| world.to_hex()).as_deref()
    );
    let stored_rel: Option<Vec<String>> = stored
        .rel
        .as_ref()
        .map(|rel| rel.iter().map(EntityId::to_hex).collect());
    assert_eq!(
        door["relationship"],
        stored_rel.map_or(json!(null), |rel| json!(rel))
    );
    assert_eq!(
        door["facet"].as_str().ok_or("f")?,
        stored.scope_facet.to_hex()
    );
    assert_eq!(
        door["project"].as_str().ok_or("pr")?,
        stored.scope_project.to_hex()
    );
    let stored_evidence = stored.evidence.as_ref().ok_or("e")?;
    let candidate_evidence = map_at(stored_evidence, "candidate_evidence").ok_or("ce")?;
    assert_eq!(
        door["candidate_evidence_hex"].as_str().ok_or("ee")?,
        hex_of(candidate_evidence)?
    );
    assert_eq!(
        door["approval"].as_str().ok_or("a")?,
        stored.approval.as_str()
    );
    let provenance = map_at(stored_evidence, "provenance").ok_or("p")?;
    let at = |key: &str| map_at(provenance, key).and_then(RmpValue::as_str);
    assert_eq!(at("surface"), Some("vault.derive"));
    assert_eq!(at("batch"), answer["batch"].as_str());
    assert_eq!(at("item"), Some("first"));
    assert_eq!(at("run"), Some(EXTRACTION_RUN));
    assert!(map_at(provenance, "job_id").is_none());
    assert!(map_at(provenance, "decisions").is_none());
    Ok(BoundLanding { claim, batch })
}
