//! The world-scoped arm's partition: which records the agent's Grant leaves
//! out, and the grading view of the slice that keeps only the readable ones.

use std::collections::BTreeSet;

use oneiron_ruler::pack::PackSlice;
use sha2::Digest;

use crate::scorecard::ScorecardFailure;

/// The domain of the partition hash, so no other digest of the bench can
/// stand in for it.
const PARTITION_DOMAIN: &[u8] = b"oneiron-bench.scorecard.world-scoped.partition.v1\0";

/// The hidden share's denominator: the share is per mille.
const SHARE_SCALE: u64 = 1000;

/// Whether `record_id` sits in the second world: the first 8 bytes of
/// sha256(domain || `seed` as 4 little-endian bytes || record id), read
/// big-endian, modulo 1000, fall below `hidden_share` (per mille). The rule
/// reads the record id alone, so a record lands in the same world in every
/// corpus, every build and every pack order, and the qrels play no part.
pub(super) fn is_hidden(record_id: &str, seed: u32, hidden_share: u32) -> bool {
    let mut hasher = sha2::Sha256::new();
    hasher.update(PARTITION_DOMAIN);
    hasher.update(seed.to_le_bytes());
    hasher.update(record_id.as_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head) % SHARE_SCALE < u64::from(hidden_share)
}

/// The slice as the agent is graded on it.
pub(super) struct GradingView {
    /// The source slice less every hidden record, every query left with no
    /// readable relevant record, and every corpus no kept query reads. It
    /// pins no vectors: the arm reads none.
    pub(super) slice: PackSlice,
    /// The view's pack digest: the card's `pack_digest`.
    pub(super) pack_digest: String,
    /// The hidden record ids of the source slice.
    pub(super) hidden: BTreeSet<String>,
    /// The source records the partition leaves readable.
    pub(super) readable_count: usize,
    /// How many source queries were dropped: each graded hidden records only.
    pub(super) dropped_queries: usize,
    /// sha256 (hex) over the sorted hidden record ids as one JSON array: the
    /// pin of the partition. JSON quotes each id, so no id (one holding a
    /// newline included) can make two partitions hash alike.
    pub(super) partition_digest: String,
}

/// Build the grading view of `source` under the partition `seed` and
/// `hidden_share`. A hidden relevant record leaves its query's qrels; a
/// query left with none is dropped, not turned into an abstention (a hidden
/// answer does not make "no result" right); an abstention query stays. The
/// view keeps the corpora its queries read, less their hidden records, so a
/// served hidden record also fails grading as a hit outside its corpus.
pub(super) fn grading_view(
    source: &PackSlice,
    seed: u32,
    hidden_share: u32,
) -> Result<GradingView, ScorecardFailure> {
    let hidden: BTreeSet<String> = source
        .records
        .iter()
        .filter(|record| is_hidden(&record.record_id, seed, hidden_share))
        .map(|record| record.record_id.clone())
        .collect();
    let mut queries = Vec::with_capacity(source.queries.len());
    for query in &source.queries {
        let mut kept = query.clone();
        kept.qrels
            .retain(|record_id, _| !hidden.contains(record_id));
        if query.expect_empty || !kept.qrels.is_empty() {
            queries.push(kept);
        }
    }
    if queries.is_empty() {
        return Err(ScorecardFailure::Input(
            "no query keeps a readable relevant record under this partition".to_owned(),
        ));
    }
    let dropped_queries = source.queries.len() - queries.len();
    let read: BTreeSet<&str> = queries
        .iter()
        .map(|query| query.corpus_id.as_str())
        .collect();
    let mut corpora = Vec::with_capacity(read.len());
    for corpus in &source.corpora {
        if !read.contains(corpus.corpus_id.as_str()) {
            continue;
        }
        let mut kept = corpus.clone();
        for session in &mut kept.sessions {
            session
                .record_ids
                .retain(|record_id| !hidden.contains(record_id));
        }
        kept.sessions
            .retain(|session| !session.record_ids.is_empty());
        corpora.push(kept);
    }
    let named: BTreeSet<&str> = corpora
        .iter()
        .flat_map(|corpus| &corpus.sessions)
        .flat_map(|session| &session.record_ids)
        .map(String::as_str)
        .collect();
    let records = source
        .records
        .iter()
        .filter(|record| named.contains(record.record_id.as_str()))
        .cloned()
        .collect();
    let slice = PackSlice {
        contract: source.contract.clone(),
        pack_id: source.pack_id.clone(),
        revision: source.revision.clone(),
        slice: source.slice,
        source: source.source.clone(),
        embedding: None,
        records,
        corpora,
        queries,
    };
    slice.validate().map_err(|error| {
        ScorecardFailure::Run(format!(
            "the readable grading view does not validate: {error}"
        ))
    })?;
    let pack_digest = slice
        .pack_digest()
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let listing = serde_json::to_vec(&hidden)
        .map_err(|error| ScorecardFailure::Run(format!("hidden id listing: {error}")))?;
    let partition_digest = oneiron_hex::encode(&sha2::Sha256::digest(&listing));
    Ok(GradingView {
        slice,
        pack_digest,
        readable_count: source.records.len() - hidden.len(),
        hidden,
        dropped_queries,
        partition_digest,
    })
}
