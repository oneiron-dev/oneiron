//! yrs memory benchmark for Oneiron sync GO/NO-GO gate.
//!
//! Simulates the ARCH-023b window Doc schema:
//! - "entities" MapRef: 3,000 entities as Any::Buffer (header + JSON data)
//! - "edges" MapRef: ~6,000 edges (2 per entity) as Any::Buffer
//! - "tombstones" MapRef: empty (schema placeholder)
//! - 1,000 entities rewritten 3 times each (Dreamer consolidation sim)
//!
//! Run: cargo bench --bench sync_memory --features sync

use std::sync::Arc;

use yrs::{Any, Doc, Map, Transact};

// ─── Constants ───────────────────────────────────────────────────────────────

const NUM_ENTITIES: usize = 3_000;
const NUM_REWRITES: usize = 1_000;
const REWRITES_PER_ENTITY: usize = 3;
const EDGES_PER_ENTITY: usize = 2;

/// 25-byte header: entity_type(1) + occurred_start(8BE) + occurred_end(8BE) + learned_at(8BE)
const HEADER_SIZE: usize = 25;
/// ~325 bytes simulating realistic message entity JSON data
const JSON_DATA_SIZE: usize = 325;
const ENTITY_BLOB_SIZE: usize = HEADER_SIZE + JSON_DATA_SIZE;

/// 24 bytes: weight(4LE) + created_at(8LE) + valence(4LE) + arousal(4LE) + dominance(4LE)
const EDGE_VALUE_SIZE: usize = 24;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a 32-char hex string simulating a UUIDv7 hex encoding.
fn make_entity_id(index: usize) -> String {
    format!("{index:032x}")
}

/// Create a realistic entity blob: 25-byte header + ~325-byte JSON body.
fn make_entity_blob(index: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ENTITY_BLOB_SIZE);

    // Header: entity_type(1 byte)
    buf.push((index % 5) as u8); // 5 entity types

    // occurred_start: 8 bytes big-endian (unix ms)
    let ts_start: u64 = 1_700_000_000_000 + (index as u64 * 1_000);
    buf.extend_from_slice(&ts_start.to_be_bytes());

    // occurred_end: 8 bytes big-endian
    let ts_end: u64 = ts_start + 500;
    buf.extend_from_slice(&ts_end.to_be_bytes());

    // learned_at: 8 bytes big-endian
    let learned: u64 = ts_start + 100;
    buf.extend_from_slice(&learned.to_be_bytes());

    assert_eq!(buf.len(), HEADER_SIZE);

    // JSON data portion: simulate a realistic message entity
    // Something like: {"content":"user message text...","author":"user","type":"dialogue",...}
    let json_body = format!(
        r#"{{"content":"This is a simulated message entity number {} with enough text to be realistic and representative of actual chat messages that would be stored in the Oneiron graph memory system for retrieval and consolidation.","author":"user","type":"dialogue","conversationId":"conv-{:08x}","turnId":"turn-{:08x}","metadata":{{"sentiment":0.7,"topics":["work","planning"]}}}}"#,
        index,
        index / 50,
        index
    );

    // Pad or truncate to exactly JSON_DATA_SIZE bytes
    let json_bytes = json_body.as_bytes();
    if json_bytes.len() >= JSON_DATA_SIZE {
        buf.extend_from_slice(&json_bytes[..JSON_DATA_SIZE]);
    } else {
        buf.extend_from_slice(json_bytes);
        // Pad with spaces (valid JSON whitespace) to reach target size
        buf.resize(ENTITY_BLOB_SIZE, b' ');
    }

    assert_eq!(buf.len(), ENTITY_BLOB_SIZE);
    buf
}

/// Create a 24-byte edge value blob.
fn make_edge_value(index: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(EDGE_VALUE_SIZE);

    // weight: f32 as 4 bytes LE
    let weight: f32 = 0.5 + (index as f32 * 0.001);
    buf.extend_from_slice(&weight.to_le_bytes());

    // created_at: u64 as 8 bytes LE
    let created_at: u64 = 1_700_000_000_000 + (index as u64 * 500);
    buf.extend_from_slice(&created_at.to_le_bytes());

    // valence: f32 as 4 bytes LE
    let valence: f32 = 0.6;
    buf.extend_from_slice(&valence.to_le_bytes());

    // arousal: f32 as 4 bytes LE
    let arousal: f32 = 0.4;
    buf.extend_from_slice(&arousal.to_le_bytes());

    // dominance: f32 as 4 bytes LE
    let dominance: f32 = 0.5;
    buf.extend_from_slice(&dominance.to_le_bytes());

    assert_eq!(buf.len(), EDGE_VALUE_SIZE);
    buf
}

/// Build an edge key: `{src_hex}:{kind:02}:{tgt_hex}` (32+1+2+1+32 = 68 chars)
fn make_edge_key(src_index: usize, kind: u8, tgt_index: usize) -> String {
    format!(
        "{}:{:02}:{}",
        make_entity_id(src_index),
        kind,
        make_entity_id(tgt_index)
    )
}

/// Get current process RSS in bytes using mach_task_basic_info (macOS).
#[cfg(target_os = "macos")]
fn get_rss_bytes() -> u64 {
    use std::process::Command;
    // Use ps to read RSS (in KB) for the current process
    let pid = std::process::id();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("failed to run ps");
    let rss_kb: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("failed to parse RSS from ps");
    rss_kb * 1024 // convert KB to bytes
}

/// Get current process RSS in bytes using /proc/self/statm (Linux).
#[cfg(target_os = "linux")]
fn get_rss_bytes() -> u64 {
    let statm =
        std::fs::read_to_string("/proc/self/statm").expect("failed to read /proc/self/statm");
    let fields: Vec<&str> = statm.split_whitespace().collect();
    let rss_pages: u64 = fields[1].parse().expect("failed to parse RSS pages");
    // SAFETY: libc::sysconf is always safe to call with _SC_PAGESIZE.
    // POSIX permits returning -1 on error; guard explicitly so the cast to
    // u64 can't wrap into `u64::MAX` and poison the RSS calculation.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(raw > 0, "sysconf(_SC_PAGESIZE) returned {raw}");
    let page_size = raw as u64;
    rss_pages * page_size
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== yrs Memory Benchmark (Oneiron Sync GO/NO-GO) ===\n");

    // Measure baseline RSS before creating the Doc
    let rss_before = get_rss_bytes();
    println!(
        "Baseline RSS: {:.2} MB",
        rss_before as f64 / (1024.0 * 1024.0)
    );

    // ── Create the yrs Doc ──────────────────────────────────────────────────
    let doc = Doc::new();
    let entities = doc.get_or_insert_map("entities");
    let edges = doc.get_or_insert_map("edges");
    let _tombstones = doc.get_or_insert_map("tombstones");

    // ── Insert N entities ───────────────────────────────────────────────────
    println!("\nInserting {NUM_ENTITIES} entities (~{ENTITY_BLOB_SIZE} bytes each)...");
    {
        let mut txn = doc.transact_mut();
        for i in 0..NUM_ENTITIES {
            let id = make_entity_id(i);
            let blob = make_entity_blob(i);
            let value = Any::Buffer(Arc::from(blob.as_slice()));
            entities.insert(&mut txn, id.as_str(), value);
        }
    } // txn commits here

    let rss_after_entities = get_rss_bytes();
    println!(
        "RSS after {} entities: {:.2} MB (+{:.2} MB)",
        NUM_ENTITIES,
        rss_after_entities as f64 / (1024.0 * 1024.0),
        (rss_after_entities - rss_before) as f64 / (1024.0 * 1024.0)
    );

    // ── Rewrite M entities K times (Dreamer consolidation) ──────────────────
    let total_rewrites = NUM_REWRITES * REWRITES_PER_ENTITY;
    println!(
        "\nRewriting {NUM_REWRITES} entities x{REWRITES_PER_ENTITY} ({total_rewrites} total overwrites)..."
    );
    for round in 0..REWRITES_PER_ENTITY {
        let mut txn = doc.transact_mut();
        for i in 0..NUM_REWRITES {
            let id = make_entity_id(i);
            // Slightly different blob each rewrite to simulate consolidation
            let mut blob = make_entity_blob(i);
            // Mutate a few bytes to simulate updated content
            blob[HEADER_SIZE] = b'R'; // mark as rewritten
            blob[HEADER_SIZE + 1] = (round as u8) + b'0';
            let value = Any::Buffer(Arc::from(blob.as_slice()));
            entities.insert(&mut txn, id.as_str(), value);
        }
    }

    let rss_after_rewrites = get_rss_bytes();
    println!(
        "RSS after rewrites: {:.2} MB (+{:.2} MB from baseline)",
        rss_after_rewrites as f64 / (1024.0 * 1024.0),
        (rss_after_rewrites - rss_before) as f64 / (1024.0 * 1024.0)
    );

    // ── Insert edges (~2 per entity = 6,000 edges) ──────────────────────────
    let num_edges = NUM_ENTITIES * EDGES_PER_ENTITY;
    println!("\nInserting {num_edges} edges ({EDGE_VALUE_SIZE} bytes each)...");
    {
        let mut txn = doc.transact_mut();
        for i in 0..NUM_ENTITIES {
            for e in 0..EDGES_PER_ENTITY {
                let tgt = (i + e + 1) % NUM_ENTITIES;
                let kind = (e as u8) % 10;
                let key = make_edge_key(i, kind, tgt);
                let val = Any::Buffer(Arc::from(
                    make_edge_value(i * EDGES_PER_ENTITY + e).as_slice(),
                ));
                edges.insert(&mut txn, key.as_str(), val);
            }
        }
    }

    let rss_after_edges = get_rss_bytes();
    println!(
        "RSS after {} edges: {:.2} MB (+{:.2} MB from baseline)",
        num_edges,
        rss_after_edges as f64 / (1024.0 * 1024.0),
        (rss_after_edges - rss_before) as f64 / (1024.0 * 1024.0)
    );

    // ── Final measurement ────────────────────────────────────────────────────
    let rss_final = get_rss_bytes();
    let rss_delta = rss_final.saturating_sub(rss_before);
    let rss_delta_mb = rss_delta as f64 / (1024.0 * 1024.0);

    // Calculate raw data sizes for reference
    let raw_entity_data = NUM_ENTITIES * ENTITY_BLOB_SIZE;
    let raw_edge_data = num_edges * EDGE_VALUE_SIZE;
    let raw_edge_keys = num_edges * 68; // 68 chars per edge key
    let raw_entity_keys = NUM_ENTITIES * 32; // 32 chars per entity key
    let raw_total = raw_entity_data + raw_edge_data + raw_edge_keys + raw_entity_keys;
    let raw_total_mb = raw_total as f64 / (1024.0 * 1024.0);

    // Overhead = CRDT metadata
    let overhead_ratio = if raw_total > 0 {
        rss_delta as f64 / raw_total as f64
    } else {
        0.0
    };
    let per_entity_overhead = rss_delta as f64 / NUM_ENTITIES as f64;

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║            BENCHMARK RESULTS                        ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Entities:       {NUM_ENTITIES:>6}                              ║");
    println!(
        "║  Rewrites:       {total_rewrites:>6} ({NUM_REWRITES} entities x{REWRITES_PER_ENTITY})        ║"
    );
    println!("║  Edges:          {num_edges:>6}                              ║");
    println!("║  Tombstones map: empty                              ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Raw data size:  {raw_total_mb:>7.2} MB                         ║");
    println!("║  RSS delta:      {rss_delta_mb:>7.2} MB                         ║");
    println!("║  Overhead ratio: {overhead_ratio:>7.2}x                           ║");
    println!("║  Per-entity:     {per_entity_overhead:>7.0} bytes                      ║");
    println!("╠══════════════════════════════════════════════════════╣");

    let pass = rss_delta_mb < 15.0;
    if pass {
        println!("║  VERDICT:        PASS  (< 15 MB)                    ║");
    } else {
        println!("║  VERDICT:        FAIL  (>= 15 MB)                   ║");
    }
    println!("╚══════════════════════════════════════════════════════╝");

    // Also print absolute RSS for debugging
    println!(
        "\nAbsolute RSS: {:.2} MB (baseline: {:.2} MB)",
        rss_final as f64 / (1024.0 * 1024.0),
        rss_before as f64 / (1024.0 * 1024.0)
    );

    if !pass {
        std::process::exit(1);
    }
}
