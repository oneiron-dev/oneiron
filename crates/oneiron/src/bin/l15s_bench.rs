//! L15-S bench entry point (bench only, never merges): `l15s_bench <bm25|hydrate|temporal|secret>`.
fn main() {
    let stage = std::env::args().nth(1).unwrap_or_else(|| "bm25".to_string());
    println!("{}", oneiron::l15s_bench::run(&stage));
}
