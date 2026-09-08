//! Vector bench text report rendering.

use super::{
    CONTRACT_EF_CONSTRUCTION, CONTRACT_EF_SEARCH, CONTRACT_M_MAX_0, LatencyStats, RamReport,
    SearchMeasure, TARGET_INSERT_P50_MS, TARGET_RECALL_AT_10, TARGET_SEARCH_TOP10_P50_MS,
    VectorBenchReport,
};

// ─── Reporting ───────────────────────────────────────────────────────────

pub(super) fn print_report(report: &VectorBenchReport) {
    let s = &report.settings;
    println!("== vector bench (ONE-1120) ==");
    println!(
        "contract: ARCH-0019 §perf — vector top-10 < {TARGET_SEARCH_TOP10_P50_MS}ms p50 \
         (Flat NSW, ef={CONTRACT_EF_SEARCH}); recall@10 > {TARGET_RECALL_AT_10} vs f32 brute \
         force; insert (entity+vector+edges) < {TARGET_INSERT_P50_MS}ms single txn"
    );
    let churn_scope = match s.churn_ops {
        Some(ops) => format!("churn-ops={ops} (absolute cap)"),
        None => format!("churn-pct={}%", s.churn_pct),
    };
    println!(
        "params: n={} dim={} seed={} queries={} churn={} {churn_scope}",
        s.n,
        s.dim,
        s.seed,
        s.queries,
        s.churn.as_str()
    );
    println!(
        "hnsw: m_max_0={CONTRACT_M_MAX_0} ef_construction={CONTRACT_EF_CONSTRUCTION} \
         ef_search={CONTRACT_EF_SEARCH}"
    );

    println!("\n[build: new-node inserts]");
    print_latency(
        "insert new-node",
        &report.insert_new,
        Some(TARGET_INSERT_P50_MS),
    );
    println!("  {}", format_ram(&report.ram, s.n, s.dim));

    println!("\n[baseline]");
    print_search_measure(&report.baseline);

    if let Some(refresh) = &report.refresh {
        println!(
            "\n[refresh-churn: re-put {} nodes, live={}]",
            refresh.churned, refresh.live_after
        );
        print_latency(
            "insert refresh ",
            &refresh.op_latency,
            Some(TARGET_INSERT_P50_MS),
        );
        print_search_measure(&refresh.search);
    }

    if let Some(delete) = &report.delete {
        println!(
            "\n[delete-churn: delete {} nodes, live={}]",
            delete.churned, delete.live_after
        );
        print_latency("delete         ", &delete.op_latency, None);
        print_search_measure(&delete.search);
    }
    println!();
}

fn print_latency(label: &str, stats: &LatencyStats, target_p50_ms: Option<f64>) {
    let target = match target_p50_ms {
        Some(t) => {
            let verdict = if stats.p50_ms < t { "ok" } else { "MISS" };
            format!(" — target < {t}ms p50: {verdict} (goal, not asserted)")
        }
        None => String::new(),
    };
    println!(
        "  {label}: p50={:.3}ms p90={:.3}ms p99={:.3}ms mean={:.3}ms ({} ops){target}",
        stats.p50_ms, stats.p90_ms, stats.p99_ms, stats.mean_ms, stats.count
    );
}

fn print_search_measure(measure: &SearchMeasure) {
    print_latency(
        "search top-10  ",
        &measure.latency,
        Some(TARGET_SEARCH_TOP10_P50_MS),
    );
    let verdict = if measure.recall > TARGET_RECALL_AT_10 {
        "ok"
    } else {
        "FAIL"
    };
    println!(
        "  recall@{}: {:.4} — target > {TARGET_RECALL_AT_10}: {verdict}",
        measure.recall_k, measure.recall
    );
    for violation in &measure.violations {
        println!("  [violation] {violation}");
    }
}

fn format_ram(ram: &RamReport, n: usize, dim: usize) -> String {
    let disk = ram
        .data_mdb_disk_bytes
        .map_or_else(|| "unavailable".to_owned(), format_mib);
    let rss = ram
        .process_rss_bytes
        .map_or_else(|| "unavailable".to_owned(), format_mib);
    format!(
        "ram-at-index: vectors-raw={} ({n} × {dim} × 4 B f32) data.mdb-disk={disk} \
         process-rss={rss}",
        format_mib(ram.vectors_raw_bytes)
    )
}

fn format_mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}
