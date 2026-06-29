//! oneiron-bench — benchmark harness skeleton.
//!
//! Subcommands (plan ONE-317 §9, ONE-318, ONE-1120):
//!
//! * `analyzer throughput` — tokenization MiB/s microbench over a
//!   built-in mixed-script corpus.
//! * `analyzer smoke` — hand-crafted query sanity check that the
//!   analyzer + BM25F pipe isn't inverted (exact surface matches beat
//!   n-gram-only matches; mixed-script queries return their docs).
//! * `vector` — ARCH-0019 §perf vector harness: seeded deterministic
//!   corpus, insert p50 (new-node vs refresh), top-10 search p50 at
//!   ef_search=128, recall@10 vs float32 brute force, refresh/delete
//!   churn modes, RAM-at-index.
//! * `beam smoke` — EVAL-001 BEAM 128K fixture scaffold smoke: fixture +
//!   run-manifest parse, fixture ingest, deterministic context-pack arm,
//!   and explicit not-ready Agentic/Chat arms.
//!
//! The full MIRACL / Mr.TyDi / internal SEA judgment-set retrieval
//! matrix lives in ONE-318; this binary only ships the skeleton and
//! cheap in-workspace checks.

use std::process::ExitCode;
use std::time::Instant;

use oneiron::analyzer::{AnalyzerContext, MultilingualAnalyzer, Token};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

mod beam;
mod vector;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [cmd] if cmd == "analyzer" => run_analyzer_default(),
        [cmd, sub] if cmd == "analyzer" => match sub.as_str() {
            "throughput" => run_throughput(),
            "smoke" => run_smoke(),
            other => {
                eprintln!("unknown analyzer subcommand: {other}");
                print_help();
                ExitCode::FAILURE
            }
        },
        [cmd, sub] if cmd == "bm25" && sub == "hot-term-ingest" => run_hot_term_ingest(10_000),
        [cmd, sub, n] if cmd == "bm25" && sub == "hot-term-ingest" => match n.parse::<usize>() {
            Ok(n) if n > 0 => run_hot_term_ingest(n),
            _ => {
                eprintln!("hot-term-ingest expects a positive doc count, got: {n}");
                ExitCode::FAILURE
            }
        },
        [cmd, rest @ ..] if cmd == "beam" => beam::run(rest),
        [cmd, rest @ ..] if cmd == "vector" => vector::run(rest),
        _ => {
            eprintln!("unknown invocation: {args:?}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "usage: oneiron-bench <command> [<subcommand>] [flags]\n\
         \n\
         commands:\n\
           analyzer                    run all analyzer benches (throughput + smoke)\n\
           analyzer throughput         tokenization MiB/s microbench\n\
           analyzer smoke              hand-crafted BM25F retrieval smoke test\n\
           bm25 hot-term-ingest [N]    ingest N docs (default 10000) sharing one\n\
                                       hot term; reports per-chunk + total cost\n\
                                       (ONE-299 posting-append microbench)\n\
           beam smoke                  run the BEAM 128K fixture scaffold smoke\n\
                                       (deterministic context-pack arm +\n\
                                       explicit not-ready Agentic/Chat arms)\n\
           vector                      ARCH-0019 vector perf/recall harness\n\
                                       [--n 1k|10k] [--dim 1024|4096] [--seed N]\n\
                                       [--queries N] [--churn none|refresh|delete|both]\n\
                                       [--churn-pct 1..99] [--churn-ops N]\n\
                                       [--no-recall-assert]\n\
         \n\
         note: MIRACL / Mr.TyDi / internal SEA retrieval quality matrix\n\
         lives in ONE-318 (not yet implemented)."
    );
}

/// ONE-299 microbench: every doc carries the same hot term, so the cost of
/// one `text_postings` append under a hot term dominates. Per-chunk timings
/// expose the asymptotics: a read-modify-rewrite posting list grows each
/// chunk (O(N²) total bytes copied), while a DUP_SORT append stays flat.
fn run_hot_term_ingest(total_docs: usize) -> ExitCode {
    println!("== bm25 hot-term ingest ({total_docs} docs) ==");
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tempdir failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut cfg = smoke_config();
    cfg.map_size = 2 * 1024 * 1024 * 1024;
    let vault = match Vault::open(tmp.path(), cfg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vault open failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let chunk_size = 1000;
    let start = Instant::now();
    let mut indexed = 0_usize;
    while indexed < total_docs {
        let chunk = chunk_size.min(total_docs - indexed);
        let chunk_start = Instant::now();
        let mut batch = vault.batch();
        for _ in 0..chunk {
            let id = EntityId::now();
            batch = batch
                .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"doc")
                .text(&id, &[("body", "hotterm")]);
        }
        if let Err(e) = batch.commit() {
            eprintln!("batch commit failed after {indexed} docs: {e}");
            return ExitCode::FAILURE;
        }
        indexed += chunk;
        println!(
            "  docs {:>6}..{:>6}: {:>9.3}ms",
            indexed - chunk,
            indexed,
            chunk_start.elapsed().as_secs_f64() * 1e3
        );
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "  total: {elapsed:.3}s ({:.0} docs/s)",
        total_docs as f64 / elapsed
    );

    match vault.search_text("hotterm", 1) {
        Ok(hits) if !hits.is_empty() => ExitCode::SUCCESS,
        Ok(_) => {
            eprintln!("hot term not retrievable after ingest");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("post-ingest search failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_analyzer_default() -> ExitCode {
    let a = run_throughput();
    let b = run_smoke();
    if matches!((a, b), (ExitCode::SUCCESS, ExitCode::SUCCESS)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_throughput() -> ExitCode {
    println!("== analyzer throughput ==");
    let analyzer = match MultilingualAnalyzer::discover(&[]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("analyzer init failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = AnalyzerContext::for_index();
    let corpus = sample_corpus();
    let warmup_iters = 3;
    let bench_iters = 20;

    let mut buf: Vec<Token> = Vec::with_capacity(8192);
    for _ in 0..warmup_iters {
        for doc in &corpus {
            buf.clear();
            analyzer.analyze(doc, &ctx, &mut buf);
        }
    }

    let total_bytes: usize = corpus.iter().map(|s| s.len()).sum();
    let mut total_tokens: u64 = 0;
    let start = Instant::now();
    for _ in 0..bench_iters {
        for doc in &corpus {
            buf.clear();
            analyzer.analyze(doc, &ctx, &mut buf);
            total_tokens += buf.len() as u64;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let bytes = (total_bytes * bench_iters) as f64;
    let mib_per_s = (bytes / (1024.0 * 1024.0)) / elapsed;
    let tokens_per_s = total_tokens as f64 / elapsed;

    println!("  docs per iter: {}", corpus.len());
    println!("  iters: {bench_iters}");
    println!("  bytes analyzed: {bytes:.0}");
    println!("  elapsed: {elapsed:.3}s");
    println!("  throughput: {mib_per_s:.2} MiB/s");
    println!("  tokens/s:   {tokens_per_s:.0}");
    ExitCode::SUCCESS
}

fn run_smoke() -> ExitCode {
    println!("== analyzer retrieval smoke ==");
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tempdir failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let vault = match Vault::open(tmp.path(), smoke_config()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vault open failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let docs: &[(u8, &str)] = &[
        (1, "Tokyo University conducts advanced research"),
        (2, "東京大学で研究する学生"),
        (3, "The quick brown fox jumps over the lazy dog"),
        (4, "El gato duerme en la silla"),
        (5, "北京大学是中国的知名学府"),
        (6, "서울대학교에서 연구를 진행합니다"),
        (7, "emoji adjacent text launch pad"),
        (8, "ＡＢＣ fullwidth ASCII mixed with regular ABC"),
    ];
    let entity_ids: Vec<EntityId> = match docs
        .iter()
        .map(|(byte, _)| EntityId::from_bytes([*byte; 16]))
        .collect()
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("entity id failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut batch = vault.batch();
    for ((_, text), id) in docs.iter().zip(&entity_ids) {
        batch = batch
            .put(id, 1, TimeRange { start: 1, end: 1 }, 1, b"doc")
            .text(id, &[("body", *text)]);
    }
    if let Err(e) = batch.commit() {
        eprintln!("batch commit failed: {e}");
        return ExitCode::FAILURE;
    }

    // Each query carries the expected top-ranked doc so a regression that
    // lets a noisier doc outrank the intended surface match is caught
    // even when hits are non-empty.
    let queries: &[(&str, &EntityId)] = &[
        ("Tokyo", &entity_ids[0]),
        ("東京", &entity_ids[1]),
        ("京大", &entity_ids[1]),
        ("quick", &entity_ids[2]),
        ("gato", &entity_ids[3]),
        ("北京大学", &entity_ids[4]),
        ("서울", &entity_ids[5]),
    ];
    let mut all_passed = true;
    for &(q, expected) in queries {
        match vault.search_text(q, 10) {
            Ok(hits) if hits.is_empty() => {
                println!("  [fail] `{q}` -> 0 hits");
                all_passed = false;
            }
            Ok(hits) => {
                let top = &hits[0].id;
                if top == expected {
                    println!("  [pass] `{q}` -> {} ({} hits)", top.to_hex(), hits.len());
                } else {
                    println!(
                        "  [fail] `{q}` -> top {}, expected {} ({} hits)",
                        top.to_hex(),
                        expected.to_hex(),
                        hits.len()
                    );
                    all_passed = false;
                }
            }
            Err(e) => {
                println!("  [fail] `{q}` -> error: {e}");
                all_passed = false;
            }
        }
    }

    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn smoke_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 32 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("bench-smoke".to_owned());
    cfg.max_readers = 16;
    cfg
}

fn sample_corpus() -> Vec<String> {
    [
        "The quick brown fox jumps over the lazy dog near the riverbank.",
        "東京大学の研究チームは新しい言語モデルを発表しました。",
        "北京的清华大学是中国著名的高等学府之一。",
        "서울 대학교 연구소에서 자연어 처리 기술을 개발 중입니다。",
        "El rápido zorro marrón salta sobre el perro perezoso.",
        "Le renard brun rapide saute par-dessus le chien paresseux.",
        "Der schnelle braune Fuchs springt über den faulen Hund.",
        "Быстрая коричневая лиса перепрыгивает через ленивую собаку.",
        "emoji adjacent text rocket launch pad with unicode marks.",
        "ＡＢＣ fullwidth ASCII side by side with regular ABC ABC ABC.",
        "ไปโรงเรียนทุกวันเพื่อเรียนรู้สิ่งใหม่ๆ",
        "Chào bạn, hôm nay bạn có khỏe không?",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
