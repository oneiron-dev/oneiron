//! Vector bench targets, settings, and CLI flag parsing.

// ─── ARCH-0019 contract literals ─────────────────────────────────────────
// "oneiron-db benchmark targets" table + "HNSW parameters" table.

/// "Vector search top-10 — < 5ms p50 — oneiron-db target; Flat NSW, ef=128".
pub(crate) const TARGET_SEARCH_TOP10_P50_MS: f64 = 5.0;

/// "Insert (entity + vector + edges) — < 1ms — Single write txn".
pub(crate) const TARGET_INSERT_P50_MS: f64 = 1.0;

/// "Recall@10 — > 90% — vs brute-force baseline".
pub(crate) const TARGET_RECALL_AT_10: f64 = 0.90;

/// "ef_search — 128 — Beam width during search".
pub(crate) const CONTRACT_EF_SEARCH: usize = 128;

/// "ef_construction — 200 — Beam width during insert".
pub(crate) const CONTRACT_EF_CONSTRUCTION: usize = 200;

/// "m_max_0 — 64 — Neighbours per node (layer 0)".
pub(crate) const CONTRACT_M_MAX_0: usize = 64;

/// Top-10: the contract's search and recall rows are both @10.
pub(crate) const SEARCH_LIMIT: usize = 10;

/// "mentions — 0.6" from the ARCH-0019 PPR edge-kind weight table; used for
/// the chain edge included in each new-node insert txn so the measured op is
/// the contract row's "entity + vector + edges" single write txn.
pub(crate) const MENTIONS_EDGE_WEIGHT: f32 = 0.6;

const DEFAULT_N: usize = 10_000;

const DEFAULT_DIM: usize = 1024;

const DEFAULT_SEED: u64 = 42;

const DEFAULT_QUERY_COUNT: usize = 100;

const DEFAULT_CHURN_PCT: u32 = 10;

pub(super) const BENCH_ENTITY_TYPE: u8 = 1;

pub(super) const BENCH_EMBEDDING_MODEL: &str = "bench/vector-harness@v1";

/// Query = corpus vector + perturbation × this scale (models a query
/// embedding landing near a stored document embedding).
pub(super) const QUERY_PERTURBATION_SCALE: f32 = 0.1;

// ─── CLI ─────────────────────────────────────────────────────────────────

/// Churn phases to run after the baseline measurement. `Both` runs refresh
/// first, then delete on the post-refresh vault (cumulative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChurnMode {
    None,
    Refresh,
    Delete,
    Both,
}

impl ChurnMode {
    pub(super) const fn runs_refresh(self) -> bool {
        matches!(self, Self::Refresh | Self::Both)
    }

    pub(super) const fn runs_delete(self) -> bool {
        matches!(self, Self::Delete | Self::Both)
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Refresh => "refresh",
            Self::Delete => "delete",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BenchSettings {
    pub(crate) n: usize,
    pub(crate) dim: usize,
    pub(crate) seed: u64,
    pub(crate) queries: usize,
    pub(crate) churn: ChurnMode,
    pub(crate) churn_pct: u32,
    /// Absolute cap on churn operations, overriding the `churn_pct`-derived
    /// count when set. Operational escape hatch: on the pre-ONE-324 engine a
    /// vector re-put (`hnsw_refresh`) triggers a full O(N) snapshot rebuild,
    /// so 10% of a 10K vault (1000 re-puts × ~45s each) cannot finish in one
    /// sitting. The X% mode stays the contract gate; `--churn-ops` makes the
    /// 10K refresh p50 measurable today.
    pub(crate) churn_ops: Option<usize>,
    pub(crate) assert_recall: bool,
}

impl Default for BenchSettings {
    fn default() -> Self {
        Self {
            n: DEFAULT_N,
            dim: DEFAULT_DIM,
            seed: DEFAULT_SEED,
            queries: DEFAULT_QUERY_COUNT,
            churn: ChurnMode::Both,
            churn_pct: DEFAULT_CHURN_PCT,
            churn_ops: None,
            assert_recall: true,
        }
    }
}

/// Parses `vector` subcommand flags. CLI surface pins the ticket's presets:
/// `--n` ∈ {1k, 10k}, `--dim` ∈ {1024, 4096} — anything else is rejected
/// (fail closed); tests drive arbitrary sizes through [`BenchSettings`]
/// directly.
pub(crate) fn parse_args(args: &[String]) -> Result<BenchSettings, String> {
    let mut settings = BenchSettings::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value_for = |name: &str| {
            iter.next()
                .map(String::as_str)
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag.as_str() {
            "--n" => {
                let value = value_for("--n")?;
                settings.n = if value.eq_ignore_ascii_case("1k") {
                    1_000
                } else if value.eq_ignore_ascii_case("10k") {
                    10_000
                } else {
                    return Err(format!("--n must be 1k or 10k, got `{value}`"));
                };
            }
            "--dim" => {
                let value = value_for("--dim")?;
                settings.dim = match value {
                    "1024" => 1024,
                    "4096" => 4096,
                    other => {
                        return Err(format!("--dim must be 1024 or 4096, got `{other}`"));
                    }
                };
            }
            "--seed" => {
                let value = value_for("--seed")?;
                settings.seed = value
                    .parse()
                    .map_err(|_| format!("--seed must be a u64, got `{value}`"))?;
            }
            "--queries" => {
                let value = value_for("--queries")?;
                settings.queries = value.parse().ok().filter(|q| *q > 0).ok_or_else(|| {
                    format!("--queries must be a positive integer, got `{value}`")
                })?;
            }
            "--churn" => {
                let value = value_for("--churn")?;
                settings.churn = match value {
                    "none" => ChurnMode::None,
                    "refresh" => ChurnMode::Refresh,
                    "delete" => ChurnMode::Delete,
                    "both" => ChurnMode::Both,
                    other => {
                        return Err(format!(
                            "--churn must be none|refresh|delete|both, got `{other}`"
                        ));
                    }
                };
            }
            "--churn-pct" => {
                let value = value_for("--churn-pct")?;
                settings.churn_pct = value
                    .parse()
                    .ok()
                    .filter(|p| (1..=99).contains(p))
                    .ok_or_else(|| format!("--churn-pct must be in 1..=99, got `{value}`"))?;
            }
            "--churn-ops" => {
                let value = value_for("--churn-ops")?;
                settings.churn_ops =
                    Some(value.parse().ok().filter(|o| *o > 0).ok_or_else(|| {
                        format!("--churn-ops must be a positive integer, got `{value}`")
                    })?);
            }
            "--no-recall-assert" => settings.assert_recall = false,
            other => return Err(format!("unknown vector flag: `{other}`")),
        }
    }
    Ok(settings)
}
