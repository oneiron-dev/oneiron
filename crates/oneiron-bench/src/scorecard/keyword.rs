//! The keyword arm: one throwaway vault per corpus, scored with a rank profile.
//!
//! Each corpus is ingested once without vectors; every profile then scores
//! the same vaults, because profiles are scoring-only and never reindex.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use oneiron::config::Bm25RankProfile;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_ruler::pack::LoadedPack;
use oneiron_ruler::scorecard::{Hit, QueryRun, RepeatRun};

use super::ScorecardFailure;
use super::profile::ResolvedProfile;
use super::run::{MAP_SIZE, ingest};

/// The retriever id of a keyword run without dictionaries.
pub(crate) const RETRIEVER: &str = "bm25f";

/// The retriever id of a keyword run with a dictionary dir.
pub(crate) const RETRIEVER_DICTS: &str = "bm25f+dicts";

/// The retriever id for a keyword run: `bm25f`, or `bm25f+dicts` with `--dict-dir`.
pub(crate) fn retriever_id(dict_dir: Option<&Path>) -> &'static str {
    if dict_dir.is_some() {
        RETRIEVER_DICTS
    } else {
        RETRIEVER
    }
}

/// One throwaway vault per corpus of a loaded slice, filled once without vectors.
pub(crate) struct KeywordVaults {
    /// The open corpus vaults, by corpus id.
    vaults: BTreeMap<String, CorpusVault>,
}

/// One corpus vault: the vault, the id map, and the temp dir that outlives the vault.
///
/// Fields drop in declaration order, so the vault closes before its dir is removed.
struct CorpusVault {
    /// The vault holding the corpus.
    vault: Vault,
    /// The vault id of every staged record.
    ids: BTreeMap<EntityId, String>,
    /// The temp dir, kept alive while the vault is open; never read.
    #[allow(
        dead_code,
        reason = "the dir must outlive the vault, which only borrows its path"
    )]
    dir: tempfile::TempDir,
}

impl KeywordVaults {
    /// Open one throwaway vault per corpus and fill each once, without vectors.
    pub(crate) fn open(
        loaded: &LoadedPack,
        dict_dir: Option<&Path>,
    ) -> Result<Self, ScorecardFailure> {
        let mut ordinal_of: BTreeMap<&str, usize> = BTreeMap::new();
        for (ordinal, record) in loaded.slice.records.iter().enumerate() {
            ordinal_of.insert(record.record_id.as_str(), ordinal);
        }
        let mut vaults = BTreeMap::new();
        for corpus in &loaded.slice.corpora {
            let dir = tempfile::tempdir().map_err(|error| {
                ScorecardFailure::Run(format!("pack vault tempdir failed: {error}"))
            })?;
            let mut config = VaultConfig::device();
            config.map_size = MAP_SIZE;
            if let Some(dicts) = dict_dir {
                config.dict_search_paths = vec![dicts.to_path_buf()];
            }
            let vault = Vault::open(dir.path(), config).map_err(|error| {
                ScorecardFailure::Run(format!("pack vault open failed: {error}"))
            })?;
            let ids = ingest(&vault, loaded, corpus, &ordinal_of, false)?;
            vaults.insert(corpus.corpus_id.clone(), CorpusVault { vault, ids, dir });
        }
        Ok(Self { vaults })
    }

    /// Run every query `repeats` times under one profile; profiles are scoring-only.
    pub(crate) fn run(
        &self,
        loaded: &LoadedPack,
        profile: &ResolvedProfile,
        limit: usize,
        repeats: u32,
    ) -> Result<Vec<QueryRun>, ScorecardFailure> {
        let defaults = Bm25RankProfile::default();
        let store_profile = if profile.is_default {
            &defaults
        } else {
            &profile.profile
        };
        let mut runs = Vec::with_capacity(loaded.slice.queries.len());
        for query in &loaded.slice.queries {
            let Some(entry) = self.vaults.get(query.corpus_id.as_str()) else {
                let query_id = query.query_id.as_str();
                let corpus_id = query.corpus_id.as_str();
                return Err(ScorecardFailure::Run(format!(
                    "query {query_id} has no vault for corpus {corpus_id}"
                )));
            };
            let mut query_repeats = Vec::new();
            for _ in 0..repeats {
                let started = Instant::now();
                let scored = entry
                    .vault
                    .search_text_with_profile(&query.text, limit, store_profile)
                    .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
                let search_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let mut hits = Vec::with_capacity(scored.len());
                for row in scored {
                    let Some(record_id) = entry.ids.get(&row.id) else {
                        let found = row.id.to_hex();
                        return Err(ScorecardFailure::Run(format!(
                            "vault returned an id outside the pack: {found}"
                        )));
                    };
                    hits.push(Hit {
                        record_id: record_id.clone(),
                        score_bits: row.score.to_bits(),
                    });
                }
                query_repeats.push(RepeatRun { hits, search_us });
            }
            runs.push(QueryRun {
                query_id: query.query_id.clone(),
                repeats: query_repeats,
            });
        }
        Ok(runs)
    }
}
