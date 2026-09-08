//! ED-04 substitution-cluster mining pass.

use std::collections::BTreeMap;

use rmpv::Value;

use super::config::{
    MAX_ARTIFACT_SCAN, MAX_SUBSTITUTION_TOKENS, MINER_K_DEFAULT, MINER_K_ROW_LABEL,
    MINER_K_SETTINGS_KEY, PAYLOAD_KEY_SESSION, TONE_LEXICON, invalid,
};
use super::emission::emit_cluster;
use super::model::{
    AmendmentSource, ArtifactIndex, Bucket, ClusterKey, MinedOutcome, MinerRun, MinerWatermark,
    Region, Substitution, SubstitutionClass, SubstitutionCluster,
};
use super::store::{advance_watermark_in_txn, miner_watermark};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::edit_distance::attribution::{
    AmendmentJudgment, amendment_evidence, amendment_judgments,
};
use crate::edit_distance::delta::{DeltaSource, amendment_delta};
use crate::edit_distance::{
    FinalizedProposalText, PROPOSAL_ARTIFACT_KEY_PREFIX, decode_finalized_proposal_text,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// The K dial
// ---------------------------------------------------------------------------

/// Reads K, the distinct-receipt threshold (default [`MINER_K_DEFAULT`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] when the stored dial is not a
/// positive decimal count.
pub fn miner_k(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, MINER_K_SETTINGS_KEY)? else {
        return Ok(MINER_K_DEFAULT);
    };
    std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|k| *k > 0)
        .ok_or(Error::CorruptedIndex(MINER_K_ROW_LABEL))
}

/// Persists K.
///
/// Stored as decimal ASCII so the dial is readable in a `vault_meta` dump —
/// the `InboxReviewDial` token convention, applied to a count.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when `k` is zero: a threshold of zero emits on
/// the FIRST correction, which is the opposite of recurrence. Storage errors.
pub fn set_miner_k(vault: &Vault, k: u32) -> Result<()> {
    if k == 0 {
        return Err(invalid("the substitution miner's K must be at least 1"));
    }
    let encoded = k.to_string();
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, MINER_K_SETTINGS_KEY, encoded.as_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

/// Session-end pass: scan Δ receipts since the GLOBAL miner watermark, cluster,
/// emit at >=K.
///
/// The mint-mark and its DEDUP CHECK ride the same transaction as the proposal,
/// so a crash between emit and mark is unreachable and a racing caller cannot
/// double-propose. The pass-wide watermark advances once, at the END of the
/// pass, so a pass that dies partway leaves every unreached cluster still
/// reachable by the replay.
///
/// `run` names the sitting whose close triggered the pass and the actor its
/// proposals are written as (see [`MinerRun`]).
///
/// The returned vector holds one entry per cluster the pass RULED on. A cluster
/// the pass declined to rule on is ABSENT rather than reported as
/// below-threshold: an already-open proposal, a cooling rejection and a content
/// correction with no skill to edit are three different silences, and none of
/// them is "this did not recur".
///
/// # Errors
///
/// Storage errors; whatever the claim write gate rejects for a single cluster
/// rolls that cluster's transaction back and fails the pass.
pub fn run_substitution_miner(vault: &Vault, run: &MinerRun) -> Result<Vec<MinedOutcome>> {
    // Checked HERE, before any evidence is read, because the consequence is
    // invisible at the write: a mined preference under the wrong actor class or
    // with no run id lands Proposed in a tray that has no group, so no surface
    // can ever show it and no decider can ever answer it. Refusing the pass is
    // the only outcome a caller can notice.
    if run.agent.actor_class() != EdgeActorClass::Agent || run.run_id.trim().is_empty() {
        return Err(invalid(
            "a miner pass needs an Agent-class actor and a run id, or its proposals are unreviewable",
        ));
    }
    let judgments = amendment_judgments(vault)?;
    // The watermark is a WORK GATE: no evidence the last pass did not already
    // see means there is nothing a re-cluster could conclude that it did not.
    let Some(observed) = MinerWatermark::observed(&judgments) else {
        return Ok(Vec::new());
    };
    if !observed.advances(miner_watermark(vault)?) {
        return Ok(Vec::new());
    }

    let now = crate::unix_seconds_now();
    let k = miner_k(vault)?;
    let clusters = clusters_from(vault, &judgments)?;
    let mut outcomes = Vec::with_capacity(clusters.len());
    for cluster in &clusters {
        if cluster.count < k {
            outcomes.push(MinedOutcome::BelowThreshold);
            continue;
        }
        if let Some(outcome) = emit_cluster(vault, run, cluster, now)? {
            outcomes.push(outcome);
        }
    }
    // ONCE, and only now that every cluster has been ruled on. An error above
    // returns before this line, so the failed pass's unreached clusters are
    // still new evidence to its replay.
    vault.with_write_txn(|wtxn| advance_watermark_in_txn(vault, wtxn, observed))?;
    Ok(outcomes)
}

/// The `DreamerAttemptPayload.input` a substitution-mine attempt carries: the
/// sitting whose close registered it, and nothing else.
///
/// The shape is owned HERE rather than by the queue, so the module that defines
/// the job also defines its payload and `dreamer_consolidation` stays a
/// dispatcher. The entity ref rides as 16 MessagePack-binary bytes — the house
/// convention (`TURN_BODY_WORLD_REF_KEY`).
///
/// It carries no write actor on purpose. The registration runs inside the
/// session-close transaction, which knows a sitting ended and nothing about
/// which agent a deployment trusts to author claims; that is the executor's
/// configured actor, and a payload that pretended otherwise would be a policy
/// decision smuggled into a lifecycle door.
#[must_use]
pub fn miner_attempt_input(session: &EntityId) -> Value {
    Value::Map(vec![(
        Value::from(PAYLOAD_KEY_SESSION),
        Value::Binary(session.as_bytes().to_vec()),
    )])
}

/// Inverse of [`miner_attempt_input`].
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the payload does not name a sitting. Every
/// proposal a pass lands is stamped with it, and inventing one would put an
/// untraceable claim in front of the decider.
pub fn miner_session_from_input(input: &Value) -> Result<EntityId> {
    let Value::Map(entries) = input else {
        return Err(malformed_payload());
    };
    let Some((_, Value::Binary(bytes))) = entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(PAYLOAD_KEY_SESSION))
    else {
        return Err(malformed_payload());
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| malformed_payload())?;
    EntityId::from_bytes(bytes).map_err(|_| malformed_payload())
}

/// The inbox GROUP KEY a pass falls back to when its queue row carries no run
/// id — which is the ordinary case, because a session close enqueues without
/// one.
///
/// Per sitting, so one close's proposals arrive in the decider's tray as one
/// group. Any non-empty string would satisfy `gate.rs`; this one also says
/// which sitting earned the group, which is what a reader of a stale tray
/// needs.
#[must_use]
pub fn miner_run_id(session: &EntityId) -> String {
    format!("edit_distance.substitution_mine:{}", session.to_hex())
}

fn malformed_payload() -> Error {
    invalid("a substitution-mine payload must name a SESSION")
}

/// Every substitution cluster the judgment ledger currently supports, in
/// `(scope, actor, from, to)` order.
///
/// Recomputed from the ledger on every call — never a stored counter (doc-13
/// r1). ED-08's signature emission (ONE-1764) reads clusters through here.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable artifact row.
pub fn mine_substitution_clusters(vault: &Vault) -> Result<Vec<SubstitutionCluster>> {
    let judgments = amendment_judgments(vault)?;
    clusters_from(vault, &judgments)
}

/// Buckets every judged amendment's substitutions by `(scope, actor, from,
/// to)`.
fn clusters_from(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<SubstitutionCluster>> {
    let artifacts = artifact_index(vault)?;
    let mut buckets: BTreeMap<ClusterKey, Bucket> = BTreeMap::new();
    for judgment in judgments {
        let Some(source) = amendment_source(vault, judgment, &artifacts)? else {
            continue;
        };
        for substitution in substitutions(source.delta_source, source.artifact) {
            let key = ClusterKey {
                scope: judgment.scope.clone(),
                actor: source.actor,
                from: substitution.from,
                to: substitution.to,
            };
            buckets.entry(key).or_default().observe(
                &judgment.receipt_id,
                source.skill,
                judgment.at,
            );
        }
    }
    Ok(buckets
        .into_iter()
        .map(|(key, bucket)| bucket.into_cluster(key))
        .collect())
}

// ---------------------------------------------------------------------------
// Receipt -> artifact resolution
// ---------------------------------------------------------------------------

/// Resolves one judged amendment to its routing facts and its persisted
/// proposal artifact, or `None` when it carries no minable pair.
///
/// Three ways to carry none, all of them silent by design:
///
/// * no recorded routing facts — the amendment has no scope axis and no actor,
///   and inventing either is the failure ED-03 is instrumented against;
/// * no Δ — nothing measured this window, so there is nothing to read;
/// * a Δ whose refs name no persisted artifact — the field-diff lane hashes
///   two MessagePack BODIES, which are not retained, so it resolves to no text
///   pair at all. The recorded-ops and reconstructed lanes both do resolve,
///   which is exactly what their refs are for (ED-01 pins them as "directly
///   replayable" and "directly verifiable").
fn amendment_source<'a>(
    vault: &Vault,
    judgment: &AmendmentJudgment,
    artifacts: &'a ArtifactIndex,
) -> Result<Option<AmendmentSource<'a>>> {
    let Some(evidence) = amendment_evidence(vault, &judgment.receipt_id)? else {
        return Ok(None);
    };
    let Some(delta) = amendment_delta(vault, &judgment.receipt_id)? else {
        return Ok(None);
    };
    Ok(artifacts.resolve(&delta).map(|artifact| AmendmentSource {
        actor: evidence.actor,
        skill: evidence.skill,
        delta_source: delta.source,
        artifact,
    }))
}

/// Reads the artifact rows once per pass and indexes them under BOTH ref
/// families ED-01 can hand back.
///
/// The op-window pair addresses a [`DeltaSource::RecordedOps`] Δ (hex of the
/// encoded Loro frontiers, which is what that lane writes); the text-hash pair
/// addresses a [`DeltaSource::Reconstructed`] one (blake3 of each endpoint
/// text). One map holds both: the tokens are opaque hex, so the two families
/// cannot collide in any way a reader would have to reason about.
fn artifact_index(vault: &Vault) -> Result<ArtifactIndex> {
    let rtxn = vault.store.env.read_txn()?;
    let mut index = ArtifactIndex {
        records: Vec::new(),
        by_refs: BTreeMap::new(),
    };
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PROPOSAL_ARTIFACT_KEY_PREFIX)?
        .take(MAX_ARTIFACT_SCAN)
    {
        let (_, raw) = entry?;
        let record = decode_finalized_proposal_text(&raw)?;
        let position = index.records.len();
        index.by_refs.insert(
            (
                bytes_to_hex_lower(record.proposed_ref.as_bytes()),
                bytes_to_hex_lower(record.final_ref.as_bytes()),
            ),
            position,
        );
        index.by_refs.insert(
            (
                text_ref(&record.proposed_text),
                text_ref(&record.final_text),
            ),
            position,
        );
        index.records.push(record);
    }
    Ok(index)
}

/// The ref ED-01's reconstructed lane writes for one endpoint text.
fn text_ref(text: &str) -> String {
    bytes_to_hex_lower(blake3::hash(text.as_bytes()).as_bytes())
}

// ---------------------------------------------------------------------------
// Substitution extraction
// ---------------------------------------------------------------------------

/// Extracts every substitution one artifact shows, through the lane its Δ was
/// measured on.
///
/// * [`DeltaSource::RecordedOps`] — one pair per recorded CHANGE, from the
///   change's own before/after text. Op runs are what this lane retains and
///   they see churn: a word typed, replaced, and typed again yields the
///   substitution the decider actually performed.
/// * [`DeltaSource::Reconstructed`] — the stored text pair is re-diffed here
///   for line pairs. ED-02's `myers_line_diff` counts lines rather than naming
///   them, so the pairing is done locally instead of widening that lane's API
///   for one consumer.
/// * [`DeltaSource::FieldDiff`] — unreachable: that lane resolves to no
///   artifact (see [`amendment_source`]). Answered rather than asserted, so a
///   future body-retaining producer degrades to silence instead of a panic.
fn substitutions(source: DeltaSource, artifact: &FinalizedProposalText) -> Vec<Substitution> {
    match source {
        DeltaSource::RecordedOps => artifact
            .ops_by_actor
            .iter()
            .filter_map(|(_, span)| substitution_pair(&span.before_text, &span.after_text))
            .collect(),
        DeltaSource::Reconstructed => {
            line_substitutions(&artifact.proposed_text, &artifact.final_text)
        }
        DeltaSource::FieldDiff => Vec::new(),
    }
}

/// Pairs the lines a line-for-line rewrite replaced.
///
/// Deliberately narrow: after the common leading and trailing lines are
/// trimmed, the two middles must have the SAME length. A substitution IS a
/// one-for-one replacement, and when the counts differ there is no pairing that
/// is not a guess — pairing by position across a length change would cluster
/// two lines that have nothing to do with each other, and a wrong cluster is
/// worse than a missing one because it can reach K.
pub(super) fn line_substitutions(before: &str, after: &str) -> Vec<Substitution> {
    let before: Vec<&str> = before.lines().collect();
    let after: Vec<&str> = after.lines().collect();
    let (prefix, suffix) = common_affix(&before, &after);
    let left = &before[prefix..before.len() - suffix];
    let right = &after[prefix..after.len() - suffix];
    if left.len() != right.len() {
        return Vec::new();
    }
    left.iter()
        .zip(right)
        .filter_map(|(removed, added)| substitution_pair(removed, added))
        .collect()
}

/// The normalized substitution between two texts, or `None` when the change is
/// not one.
///
/// The pair is the CHANGED RUN — what sits between the common prefix and the
/// common suffix — widened to whole TOKENS, so the substitution recurs across
/// artifacts that share nothing but the correction. A run empty on either side
/// is a pure insertion or deletion, which is an edit but not a substitution, and
/// a run past [`MAX_SUBSTITUTION_TOKENS`] is a rewrite.
///
/// Emptiness is judged on the RAW region, before widening. Widening first would
/// dress an insertion up as a replacement: `hello` -> `hello there` has an
/// empty removed run, and pulling `hello` in on both sides would report the
/// substitution `hello` -> `hello there`, which nobody performed.
pub(super) fn substitution_pair(before: &str, after: &str) -> Option<Substitution> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (prefix, suffix) = common_affix(&before, &after);
    if prefix == before.len() - suffix || prefix == after.len() - suffix {
        return None;
    }
    let region = token_aligned(&before, &after, prefix, suffix);
    let from = normalize_run(&before[region.start..region.before_end]);
    let to = normalize_run(&after[region.start..region.after_end]);
    if from.is_empty() || to.is_empty() || from == to {
        return None;
    }
    if token_count(&from) > MAX_SUBSTITUTION_TOKENS || token_count(&to) > MAX_SUBSTITUTION_TOKENS {
        return None;
    }
    Some(Substitution { from, to })
}

/// Widens the changed region out to the whitespace on either side of it.
///
/// Without this the affix trim cuts INSIDE words: `regards` -> `cheers` shares a
/// trailing `s`, so the raw region is `regard` -> `cheer` and the chooser is
/// handed two words that are in no lexicon. §4 says the miner clusters TOKEN
/// pairs, and this is what makes the extracted pair one.
///
/// Both ends move in lockstep, which is exactly what the affixes guarantee:
/// `before[..prefix] == after[..prefix]`, so testing the left character on
/// either text gives the same answer, and the two suffixes are equal, so
/// advancing the right end by one advances both by the same character.
fn token_aligned(before: &[char], after: &[char], prefix: usize, suffix: usize) -> Region {
    let mut start = prefix;
    while start > 0 && !before[start - 1].is_whitespace() {
        start -= 1;
    }
    let mut before_end = before.len() - suffix;
    let mut after_end = after.len() - suffix;
    while before_end < before.len() && !before[before_end].is_whitespace() {
        before_end += 1;
        after_end += 1;
    }
    Region {
        start,
        before_end,
        after_end,
    }
}

/// Token normalization: lowercase, trim, collapse whitespace. Nothing else — no
/// stemming and no embeddings, because the signal is recurrence of the LITERAL
/// correction (blueprint note; §4's "mechanical distance, semantic recurrence").
fn normalize_run(run: &[char]) -> String {
    run.iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn token_count(normalized: &str) -> usize {
    normalized.split_whitespace().count()
}

/// The shared leading and trailing run of two slices, as `(prefix, suffix)`.
///
/// The two must not overlap on the shorter side, or a repeated run (`a a a` ->
/// `a a a a a`) would count the same element twice and report a negative
/// middle. ED-01's `CharAffix` and ED-02's line trim keep the same rule for the
/// same reason; those are counting helpers, this is a text extractor, so the
/// rule is restated rather than shared through a widened API.
fn common_affix<T: PartialEq>(before: &[T], after: &[T]) -> (usize, usize) {
    let prefix = before
        .iter()
        .zip(after)
        .take_while(|(left, right)| left == right)
        .count();
    let budget = before.len().min(after.len()) - prefix;
    let suffix = before
        .iter()
        .rev()
        .zip(after.iter().rev())
        .take(budget)
        .take_while(|(left, right)| left == right)
        .count();
    (prefix, suffix)
}

/// Routes one substitution: tone/stop lexicon on BOTH sides is a phrasing swap,
/// anything else is content.
///
/// A deterministic rule table over a closed lexicon, and the asymmetry is the
/// point: an unrecognized word makes the substitution CONTENT, which routes it
/// to a proposal a human reads, rather than to a preference claim that silently
/// shapes every later draft.
#[must_use]
pub fn classify_substitution(from: &str, to: &str) -> SubstitutionClass {
    let lexical = from
        .split_whitespace()
        .chain(to.split_whitespace())
        .all(|token| TONE_LEXICON.binary_search(&trim_token(token)).is_ok());
    if lexical {
        SubstitutionClass::Lexical
    } else {
        SubstitutionClass::Content
    }
}

/// A token stripped of the punctuation that rides on prose, so `"regards,"` is
/// the sign-off it plainly is. Normalization already lowercased it.
fn trim_token(token: &str) -> &str {
    token.trim_matches(|character: char| !character.is_alphanumeric())
}
