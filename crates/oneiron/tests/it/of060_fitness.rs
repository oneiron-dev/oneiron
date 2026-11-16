use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::{
    code_run::SelfEffect, code_sandbox::SANDBOX_WIT_WORLD_NAME,
    code_sandbox::SandboxBoundaryContract, code_sandbox::SandboxGuestTier,
    code_sandbox::SandboxImportClass, code_sandbox::SandboxLinkedImportEffects,
    task_verb::sdk::RunVerb,
};

// Which FILES count as production is decided once, in the shared scanner
// (`src/test_util/source_scan.rs`, mounted here through `common`): test-only
// files by name, by a `tests/`/`benches/` directory, or transitively through
// `#[cfg(test)]` and `#[path]` mounts. This file keeps the needles, the pinned
// baselines and the in-file `#[cfg(test)]` masking it always had.
use crate::common::source_scan::{
    SourceTree, cfg_test_external_files, is_ident_byte, is_ident_start, normalized,
    production_source, test_only_by_path,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawHit {
    path: String,
    ident: String,
    line: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under crates/oneiron")
        .to_path_buf()
}

fn relative_path<'a>(repo: &Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(repo).unwrap_or(path)
}

fn line_number(source: &str, byte_idx: usize) -> usize {
    source.as_bytes()[..byte_idx]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn source_line(source: &str, line: usize) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn find_substring_hits(source: &str, needle: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut start = 0;
    while let Some(rel) = source[start..].find(needle) {
        let hit = start + rel;
        hits.push(hit);
        start = hit + needle.len();
    }
    hits
}

fn raw_escape_ident(ident: &str) -> bool {
    matches!(
        ident,
        "with_write_txn"
            | "try_with_write_txn"
            | "with_write_txn_grouped"
            | "try_with_write_txn_grouped"
            | "put_edge"
            | "put_vector"
            | "sync_state_put"
            | "sync_state_put_in_write_txn"
    )
}

fn raw_escape_hits(rel: &str, source: &str) -> Vec<RawHit> {
    let bytes = source.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            let ident = &source[start..i];
            if raw_escape_ident(ident) {
                let line = line_number(source, start);
                hits.push(RawHit {
                    path: rel.to_owned(),
                    ident: ident.to_owned(),
                    line: source_line(source, line),
                });
            }
        } else {
            i += 1;
        }
    }
    hits
}

/// Assembles the F2 hit map, counted per distinct hit.
///
/// The gate and the negative row below both go through this, so "an extra
/// `with_write_txn` on the surface fails F2" is proved by the assembly the
/// gate actually runs rather than by a copy of the pinned map incremented by
/// hand.
fn f2_actual_hits(sources: impl IntoIterator<Item = (String, String)>) -> BTreeMap<RawHit, usize> {
    let mut actual = BTreeMap::<RawHit, usize>::new();
    for (rel, source) in sources {
        if !f2_surface_path(&rel) {
            continue;
        }
        for hit in raw_escape_hits(&rel, &production_source(&source)) {
            *actual.entry(hit).or_default() += 1;
        }
    }
    actual
}

/// Every production file of `tree`, as the `(relative path, source)` pairs
/// [`f2_actual_hits`] reads.
fn f2_tree_pairs<'a>(
    repo: &'a Path,
    tree: &'a SourceTree,
) -> impl Iterator<Item = (String, String)> + 'a {
    tree.production_sources()
        .map(move |(path, source)| (normalized(relative_path(repo, path)), source.to_owned()))
}

/// FIX 5489 (#3316, #5684, #6736): the by-reference ASSET body lands through
/// the replicated door from two `pub(crate)`, `#[cfg(feature = "sync")]`
/// helpers that live beside the private state they touch
/// (`BatchBuilder::put_replicated_asset_file` and
/// `Vault::put_replicated_asset_body_in_txn`). Their only caller chain starts
/// in `src/sync/ingest/entity/asset_ref.rs`. Each call line is pinned once. A
/// new caller of either helper outside `src/sync/` still matches
/// `.put_replicated` and fails.
const F1_SYNC_HELPER_CALLS: [(&str, &str); 3] = [
    (
        "crates/oneiron/src/batch/builder/puts.rs",
        "self.put_replicated(",
    ),
    (
        "crates/oneiron/src/store/asset_body/stage.rs",
        "batch.put_replicated_asset_file(",
    ),
    (
        "crates/oneiron/src/store/asset_body/stage.rs",
        "batch.put_replicated(",
    ),
];

/// The test doors are not production code: lib.rs mounts them only under
/// `--cfg oneiron_test_support`, which only the integration test command sets.
/// The shared scanner knows only `#[cfg(test)]` mounts, so F1 skips this
/// directory itself, the way it skips `src/sync/`. The skip holds only while
/// that gate stays: `assert_test_doors_mount_is_cfg_gated` fails loud if lib.rs
/// mounts the doors without it.
const F1_TEST_DOORS_DIR: &str = "crates/oneiron/src/test_doors/";
const TEST_DOORS_GATE: &str = "#[cfg(oneiron_test_support)]";

fn assert_test_doors_mount_is_cfg_gated(repo: &Path) {
    let lib_rs = std::fs::read_to_string(repo.join("crates/oneiron/src/lib.rs"))
        .expect("read crates/oneiron/src/lib.rs");
    let lib_lines = lib_rs.lines().map(str::trim).collect::<Vec<_>>();
    let mounts = lib_lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !line.starts_with("//") && line.ends_with("mod test_doors;"))
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    assert_eq!(
        mounts.len(),
        1,
        "OF-060 F1 skips {F1_TEST_DOORS_DIR}: lib.rs must mount `pub mod test_doors;` exactly once"
    );
    let attributes = lib_lines[..mounts[0]]
        .iter()
        .rev()
        .copied()
        .take_while(|line| line.starts_with("#[") || line.starts_with("///"))
        .filter(|line| line.starts_with("#["))
        .collect::<Vec<_>>();
    assert!(
        attributes.contains(&TEST_DOORS_GATE),
        "OF-060 F1 skips {F1_TEST_DOORS_DIR} only while lib.rs mounts `pub mod test_doors;` \
         under `{TEST_DOORS_GATE}`; its attributes now: {attributes:?}"
    );
}

#[test]
fn of060_f1_put_replicated_stays_sync_only() {
    let repo = repo_root();
    assert_test_doors_mount_is_cfg_gated(&repo);
    let mut violations = Vec::new();
    let mut helper_calls = BTreeMap::<(String, String), usize>::new();
    let tree = SourceTree::read(&repo.join("crates"));

    for (path, source) in tree.production_sources() {
        let rel = normalized(relative_path(&repo, path));
        if rel.starts_with("crates/oneiron/src/sync/") || rel.starts_with(F1_TEST_DOORS_DIR) {
            continue;
        }
        let source = production_source(source);
        for pattern in [".put_replicated", "::put_replicated"] {
            for hit in find_substring_hits(&source, pattern) {
                let line = line_number(&source, hit);
                let text = source_line(&source, line);
                if F1_SYNC_HELPER_CALLS
                    .iter()
                    .any(|(path, pinned)| *path == rel && *pinned == text)
                {
                    *helper_calls.entry((rel.clone(), text)).or_default() += 1;
                } else {
                    violations.push(format!("{rel}:{line}: {pattern}"));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OF-060 F1: put_replicated must stay reachable only from oneiron sync production code:\n{}",
        violations.join("\n")
    );
    let pinned = F1_SYNC_HELPER_CALLS
        .iter()
        .map(|(path, line)| (((*path).to_owned(), (*line).to_owned()), 1))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        helper_calls, pinned,
        "OF-060 F1: the FIX 5489 sync helper calls changed; each pinned line occurs exactly once"
    );
}

#[test]
fn of060_f1_external_mount_keeps_production_controls_scanned() {
    let root = Path::new("");
    let parent = PathBuf::from("src/indexes.rs");
    // Named so only the transitive rule can exclude it: a `*_tests.rs` name
    // would be test-only by itself.
    let mounted = PathBuf::from("src/fixture_probe.rs");
    let test_mount = "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\nmod tests;";
    let production = "fn seed() { vault.put_replicated(); }";
    let rejected_calls = |sources: &[(PathBuf, String)]| {
        let test_only = cfg_test_external_files(root, sources);
        let mut violations = 0;
        for (path, source) in sources {
            let rel = normalized(relative_path(root, path));
            if test_only_by_path(&rel) || test_only.contains(path) {
                continue;
            }
            let source = production_source(source);
            for pattern in [".put_replicated", "::put_replicated"] {
                if !rel.starts_with("crates/oneiron/src/sync/") {
                    violations += find_substring_hits(&source, pattern).len();
                }
            }
        }
        violations
    };
    assert!(!test_only_by_path(&normalized(&mounted)));
    // A visibility does not change the mount; inline modules resolve their
    // targets under the parent's stem and module chain.
    for (source, target) in [
        (test_mount, "src/fixture_probe.rs"),
        (
            "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\npub(crate) mod tests;",
            "src/fixture_probe.rs",
        ),
        (
            "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\npub mod tests;",
            "src/fixture_probe.rs",
        ),
        (
            r#"#[cfg(test)] mod helpers { #[path = "fixture_probe.rs"] mod probe; }"#,
            "src/indexes/helpers/fixture_probe.rs",
        ),
        (
            r#"mod outer { #[cfg(test)] #[path = "fixture_probe.rs"] mod probe; }"#,
            "src/indexes/outer/fixture_probe.rs",
        ),
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), source.to_owned()),
                (PathBuf::from(target), production.to_owned()),
            ]),
            0,
            "test-only calls must be exempt: {source}",
        );
    }
    // The shared scanner's own mount in a mod-rs root.
    assert_eq!(
        rejected_calls(&[
            (
                PathBuf::from("src/lib.rs"),
                "#[cfg(test)]\npub(crate) mod test_util {\n    mod source_scan;\n}".to_owned(),
            ),
            (
                PathBuf::from("src/test_util/source_scan.rs"),
                production.to_owned(),
            ),
        ]),
        0,
    );
    for source in [
        "",
        r#"#[path = "fixture_probe.rs"] mod fixture;"#,
        "mod fixture_probe;",
        r#"#[cfg(not(test))] #[path = "fixture_probe.rs"] mod fixture;"#,
        r#"#[cfg(any(test, feature = "sync"))] #[path = "fixture_probe.rs"] mod fixture;"#,
        "// #[cfg(test)]\n#[path = \"fixture_probe.rs\"] mod fixture;",
        r#"/* #[cfg(test)] */ #[path = "fixture_probe.rs"] mod fixture;"#,
        r##"const DOC: &str = r#"#[cfg(test)] #[path = "fixture_probe.rs"] mod tests;"#;"##,
        r##"const DOC: &str = "#[cfg(test)]"; #[path = "fixture_probe.rs"] mod fixture;"##,
        r#"#[cfg(test)] const MARKER: () = (); #[path = "fixture_probe.rs"] mod fixture;"#,
        r#"macro_rules! quote { () => { #[cfg(test)] #[path = "fixture_probe.rs"] mod tests; }; }"#,
        r#"fn body() { #[cfg(test)] #[path = "fixture_probe.rs"] mod tests; }"#,
        r##"#[cfg(test)] #[path = r#"fixture_probe.rs"#] mod tests;"##,
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), source.to_owned()),
                (mounted.clone(), production.to_owned()),
            ]),
            1,
            "production calls must be rejected: {source}",
        );
    }
    for production_mount in [
        r#"#[path = "fixture_probe.rs"] mod live;"#,
        "mod fixture_probe;",
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), format!("{test_mount}\n{production_mount}")),
                (mounted.clone(), production.to_owned()),
            ]),
            1,
            "a shared mount must not exempt a production call",
        );
        let another_parent = [
            (parent.clone(), test_mount.to_owned()),
            (PathBuf::from("src/live.rs"), production_mount.to_owned()),
            (mounted.clone(), production.to_owned()),
        ];
        assert_eq!(
            rejected_calls(&another_parent),
            1,
            "a production mount in another parent must prevent exemption",
        );
    }
}

#[test]
fn of060_f2_surface_raw_escape_hatches_are_pinned() {
    let repo = repo_root();
    let tree = SourceTree::read(&repo.join("crates"));

    assert_eq!(
        f2_actual_hits(f2_tree_pairs(&repo, &tree)),
        f2_expected_raw_escape_hits(),
        "OF-060 F2: surface raw escape-hatch references changed. New foreign/guest writes must go through a stamper; remove or intentionally update this pinned baseline."
    );
}

fn f2_expected_raw_escape_hits() -> BTreeMap<RawHit, usize> {
    BTreeMap::from([
        // W7-C10: host-owned key metadata under fixed service-private prefixes, never
        // guest entity writes.
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 3),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, &key, &encode(&row)?)?;".to_owned() }, 3),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let result = self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, &new_key, &encode(&new)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, &old_key, &encode(&old)?)?;".to_owned() }, 1),
        // DOOR-104 (#3103): the window receipt and the thresholds manifest in one write.
        // The owner's verb reaches it through set_thresholds_as_owner.
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, MANIFEST, &encode(thresholds)?)".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(), ident: "with_write_txn".to_owned(), line: "let result = self.vault.with_write_txn(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(".to_owned() }, 1),
        // OF-520 (#1766), FIX 9531 (#3980): worker-owned wire-health check rows under
        // `wire:health:v1:`; the fold is one atomic host write.
        (RawHit { path: "crates/oneiron-server/src/wire_health.rs".to_owned(), ident: "sync_state_put".to_owned(), line: "vault.sync_state_put(&format!(           , check.subject), &encode(check)?)".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_health/evidence.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_health/evidence.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_health/evidence.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &earlier_key, &encode(&earlier)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_health/evidence.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &key, &encode(&check)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_health/evidence.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &cursor, read.as_bytes())?;".to_owned() }, 1),
        // OF-305: provider offer cooldowns, account parks and the owner's quota
        // question, this deployment's routing state under `models:offer-cooldown:v1:`
        // (split by #5763, #4160).
        (RawHit { path: "crates/oneiron-server/src/models/cooldown/account_park.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &row, &bytes)".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/cooldown/offer_core.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let kept = vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/cooldown/offer_core.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &key, &bytes)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/cooldown/quota_queue.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/cooldown/quota_queue.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &row, &bytes)?;".to_owned() }, 1),
        // OF-602 (#2492), FIX 2541 (#4509): the stored Responses chain cache, keyed by
        // a hash of the turn's item digests.
        (RawHit { path: "crates/oneiron-server/src/models/broker_responses.rs".to_owned(), ident: "sync_state_put".to_owned(), line: "if vault.sync_state_put(&key, &bytes).is_err() {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/responses_socket.rs".to_owned(), ident: "sync_state_put".to_owned(), line: "if vault.sync_state_put(&key, &bytes).is_err() {".to_owned() }, 1),
        // Media job rows: deletes of `models:media-job:v1:` only (#4059, #4458).
        (RawHit { path: "crates/oneiron-server/src/models/media/jobs.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| {".to_owned() }, 2),
        // FIX 12516 (#4489): model-call evidence side rows (digests and usage, no
        // text), written after an admitted call.
        (RawHit { path: "crates/oneiron-server/src/ai_host/step/response_capture.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| record_model_call_in_txn(vault, txn, &record))".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/api/llm.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| record_model_call_in_txn(vault, txn, &record))".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/models/native_call_capture.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: ".with_write_txn_grouped(|txn| record_model_call_in_txn(self.vault, txn, &record))".to_owned() }, 1),
        // OF-495 (#1767, #3586): the skill judge's decision journal and the owner's
        // person-time rows, append-only under `skill:judge:v1:`.
        (RawHit { path: "crates/oneiron-server/src/replay_judge.rs".to_owned(), ident: "sync_state_put".to_owned(), line: "vault.sync_state_put(&key, &bytes)".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/replay_judge.rs".to_owned(), ident: "sync_state_put".to_owned(), line: ".sync_state_put(&format!(             , EntityId::now().to_hex()), &bytes)".to_owned() }, 1),
        // The napi host handle: the unbound handle writes as the host process; a bound
        // handle goes through the caller-stamped raw door (OF-063 FIX 3387).
        (RawHit { path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(), ident: "put_edge".to_owned(), line: "pub fn put_edge(&self, src: Buffer, kind: u32, tgt: Buffer, weight: f64) -> napi::Result<()> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(), ident: "put_edge".to_owned(), line: ".put_edge(&src_id, edge_kind, &tgt_id, weight as f32)".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(), ident: "put_vector".to_owned(), line: "pub fn put_vector(&self, id: Buffer, vector: Array<'_>) -> napi::Result<()> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(), ident: "put_vector".to_owned(), line: "None => self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err),".to_owned() }, 1),
        // Server-plane auth metadata: one empty row per revoked bearer-token id
        // (ONE-1636, ONE-1939).
        (RawHit { path: "crates/oneiron-server/src/auth.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "Ok(vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/auth.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &key, &[])?;".to_owned() }, 1),
        // ONE-1595, W7-C09: trusted managed-vault metadata: the DEK MAC seal and the
        // lease scope id, both at fixed keys.
        (RawHit { path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(), ident: "sync_state_put".to_owned(), line: "vault.sync_state_put(DEK_MAC_KEY, mac.as_bytes())?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: ".with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, KEY, &id.to_be_bytes())?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/server/leases.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "if let Err(err) = self.vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        // BK/1815 (15c62bc2): resolve_booker_contact uses an approved atomic booking
        // transaction, not a stamper bypass. Pin exactly one call.
        (RawHit { path: "crates/oneiron-server/src/api/booking/subject.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: ".with_write_txn_grouped(|txn| {".to_owned() }, 1),
        // W7-C09 and its follow-ups (#3546, #3560, #4002, #4220, #4818): host-owned
        // money metadata: validated stamped usage events, meters, derived rollups,
        // staged settlements and the owner's repair door.
        (RawHit { path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let written = self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(txn, &key, &row)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {".to_owned() }, 2),
        (RawHit { path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/limit.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/limit.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(txn, &key, &raw)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/meters.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/meters.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/meters.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, key, &rmp_serde::to_vec_named(&stored)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/meters.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/meters.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, &rollup_key, &rmp_serde::to_vec_named(&rollup)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/pending.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| self.stage_settlement_in_write_txn(txn, raw))".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/pending.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: ".sync_state_put_in_write_txn(txn, &pending_key, &live)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/pending.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let (owner, vault_id, written) = self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/pending.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let written = self.vault.try_with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/repair.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/rollup.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, rollup_key, &encode_rollup(&marked)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/rollup.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "vault.sync_state_put_in_write_txn(txn, rollup_key, &encode_rollup(&CachedRollup::Stale)?)?;".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/rollup.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: ".try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/usage/rollup.rs".to_owned(), ident: "sync_state_put_in_write_txn".to_owned(), line: "self.vault.sync_state_put_in_write_txn(".to_owned() }, 1),
        // FIX 16029: the connector settler's own remote-task input ledger rows.
        (RawHit { path: "crates/oneiron-server/src/connector_call_host/remote_task_poll.rs".to_owned(), ident: "try_with_write_txn".to_owned(), line: "let turned = vault.try_with_write_txn(|txn| -> IntentLedgerResult<Turned> {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/connector_call_host/remote_task_poll.rs".to_owned(), ident: "try_with_write_txn".to_owned(), line: "Some(Posted::Accepted) => vault.try_with_write_txn(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron-server/src/connector_call_host/remote_task_poll.rs".to_owned(), ident: "try_with_write_txn".to_owned(), line: "None | Some(Posted::Uncertain) => vault.try_with_write_txn(|txn| {".to_owned() }, 1),
        // L14 PACK-STARTUP-2: the Dreamer seat's runner work binding, host settings only.
        (RawHit { path: "crates/oneiron-server/src/runtime/seat_login/runner_work.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "let bound = vault.try_with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        // FIX 5678: an empty write that carries the write door's piggyback work.
        (RawHit { path: "crates/oneiron-server/src/server/connector_events.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|_| Ok(()))".to_owned() }, 1),
        // DOOR-079, #4125, FIX 4606: code consent wait rows: mint, the owner's or
        // holder's answer, once-only admission, settlement, rebind and resume refusal.
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/browser.rs".to_owned(), ident: "with_write_txn".to_owned(), line: "let minted = vault.with_write_txn(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/browser.rs".to_owned(), ident: "with_write_txn".to_owned(), line: "vault.with_write_txn(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/browser.rs".to_owned(), ident: "with_write_txn".to_owned(), line: "self.with_write_txn(|txn| {".to_owned() }, 2),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/rebind.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "self.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/rebind.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "let result = self.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/resume.rs".to_owned(), ident: "with_write_txn".to_owned(), line: "self.with_write_txn(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/consent_wait/settle.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "let answered = self.with_write_txn_grouped(|txn| answer_in_txn(self, txn, owner, input))?;".to_owned() }, 1),
        // Code-run engine state outside storage/: the self-model binding (owner
        // revalidated), the Coach's owner-pair verdict and a leader's team start row.
        (RawHit { path: "crates/oneiron/src/code_run/compaction_home/self_model.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "self.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/contribution/owner.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "self.vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/dispatcher/team_verbs.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        // Code-run executor storage: the run's own engine rows under `code_run:*`
        // prefixes (folds, read worlds, reader jobs, replay capsules, wait delivery,
        // output progress, model seat, overlay erase marks). Keys derive from the run,
        // attempt or wait; no guest-chosen key, entity, edge or vector.
        (RawHit { path: "crates/oneiron/src/code_run/storage/folds.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "Self::Canonical(vault) => vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/folds.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/model_seat.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/overlay_erase.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "let segment = vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/read_worlds.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {".to_owned() }, 3),
        (RawHit { path: "crates/oneiron/src/code_run/storage/reader_jobs/txn.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/records/bodies/progress.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "self.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/replay_capsule.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/replay_capsule.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 2),
        (RawHit { path: "crates/oneiron/src/code_run/storage/replay_capsule/admit.rs".to_owned(), ident: "try_with_write_txn_grouped".to_owned(), line: "match vault.try_with_write_txn_grouped(|wtxn| write(wtxn, &spill)) {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/replay_capsule/owner_pair.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/routing/bodies.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|wtxn| {".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/wait_delivery.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| {".to_owned() }, 3),
        (RawHit { path: "crates/oneiron/src/code_run/storage/wait_delivery.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "Self::Canonical(vault) => vault.with_write_txn_grouped(|txn| {".to_owned() }, 2),
        (RawHit { path: "crates/oneiron/src/code_run/storage/wait_delivery.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "vault.with_write_txn_grouped(|txn| retire_wait_in_txn(vault, txn, key))".to_owned() }, 1),
        (RawHit { path: "crates/oneiron/src/code_run/storage/wait_delivery/settle_report.rs".to_owned(), ident: "with_write_txn_grouped".to_owned(), line: "ExecutorStorage::Canonical(vault) => vault.with_write_txn_grouped(|txn| {".to_owned() }, 1),
    ])
}

#[test]
fn of060_f2_extra_booking_write_txn_is_not_pinned() {
    let repo = repo_root();
    let tree = SourceTree::read(&repo.join("crates"));
    let expected = f2_expected_raw_escape_hits();
    let booking_path = "crates/oneiron-server/src/api/booking/subject.rs";
    let approved_line = ".with_write_txn_grouped(|txn| {";
    let approved_hits = raw_escape_hits(booking_path, &production_source(approved_line));
    assert_eq!(approved_hits.len(), 1);
    assert_eq!(expected.get(&approved_hits[0]), Some(&1));

    // Even an identical second call exceeds the pin. A different line in the
    // same file (here the hosts' door) or the same line in another booking
    // file must also fail F2.
    for (rel, extra_line) in [
        (booking_path, approved_line),
        (booking_path, ".with_write_txn(|extra_txn| {"),
        (
            "crates/oneiron-server/src/api/booking/extra.rs",
            approved_line,
        ),
    ] {
        assert!(!test_only_by_path(rel) && f2_surface_path(rel));
        let extra_hits = raw_escape_hits(rel, &production_source(extra_line));
        assert_eq!(extra_hits.len(), 1);
        let actual = f2_actual_hits(
            f2_tree_pairs(&repo, &tree).chain([(rel.to_owned(), extra_line.to_owned())]),
        );
        assert_ne!(
            actual, expected,
            "OF-060 F2: extra booking with_write_txn must fail: {rel}: {extra_line}"
        );
    }
}

fn f2_surface_path(rel: &str) -> bool {
    rel.starts_with("crates/oneiron-server/src/")
        || rel.starts_with("crates/oneiron-napi/src/")
        || rel.starts_with("crates/oneiron/src/code_run/")
        || rel.starts_with("crates/oneiron/src/code_sandbox/")
}

#[test]
fn of060_p3_code_mode_guest_surface_links_named_verbs_only() {
    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert_eq!(first_party.wit_world(), SANDBOX_WIT_WORLD_NAME);

    let mut write_imports = BTreeMap::new();
    for import in first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::WriteTrap)
    {
        assert!(
            write_imports
                .insert(
                    import.name().to_owned(),
                    import.write_trap_effect().expect("named write trap"),
                )
                .is_none(),
            "write-import names must be unique",
        );
    }
    // The memory writes reach the guest as verb-table rows the run answers
    // itself, each its own named, gated effect: the same closed set.
    for verb in RunVerb::ALL.iter().filter(|verb| verb.writes()) {
        assert!(
            write_imports
                .insert(format!("self.memory.{}", verb.as_str()), verb.effect())
                .is_none(),
            "write-import names must be unique",
        );
    }
    assert_eq!(
        write_imports,
        BTreeMap::from([
            ("self.report_blocked".to_owned(), SelfEffect::ReportBlocked),
            (
                "self.memory.connector.answer".to_owned(),
                SelfEffect::ConnectorAnswer
            ),
            (
                "self.memory.self.agents.spawn".to_owned(),
                SelfEffect::AgentsSpawn
            ),
            (
                "self.memory.self.code.checkout.bind".to_owned(),
                SelfEffect::RepoCheckoutBind
            ),
            (
                "self.memory.self.code.checks.finish".to_owned(),
                SelfEffect::RepoChecksFinish
            ),
            (
                "self.memory.self.code.checks.reuse".to_owned(),
                SelfEffect::RepoChecksReuse
            ),
            (
                "self.memory.self.code.checks.start".to_owned(),
                SelfEffect::RepoChecksStart
            ),
            (
                "self.memory.self.code.export".to_owned(),
                SelfEffect::RepoExport
            ),
            (
                "self.memory.self.code.merge_queue.enqueue".to_owned(),
                SelfEffect::RepoMergeQueueEnqueue
            ),
            (
                "self.memory.self.code.proposal_resolve".to_owned(),
                SelfEffect::RepoProposalResolve
            ),
            (
                "self.memory.self.code.proposal_submit".to_owned(),
                SelfEffect::RepoProposalSubmit
            ),
            (
                "self.memory.self.code.snapshots.ingest".to_owned(),
                SelfEffect::RepoSnapshotsIngest
            ),
            (
                "self.memory.self.code.symbols.declare".to_owned(),
                SelfEffect::RepoSymbolsDeclare
            ),
            (
                "self.memory.self.code.symbols.release".to_owned(),
                SelfEffect::RepoSymbolsRelease
            ),
            (
                "self.memory.self.code.symbols.renew".to_owned(),
                SelfEffect::RepoSymbolsRenew
            ),
            (
                "self.memory.self.code.work.open".to_owned(),
                SelfEffect::RepoWorkOpen
            ),
            ("self.memory.self.compact".to_owned(), SelfEffect::Fold),
            ("self.memory.self.fold".to_owned(), SelfEffect::Fold),
            (
                "self.memory.self.leader.split".to_owned(),
                SelfEffect::LeaderSplit
            ),
            (
                "self.memory.self.report_blocked".to_owned(),
                SelfEffect::ReportBlocked
            ),
            (
                "self.memory.self.skills.call".to_owned(),
                SelfEffect::SkillsCall
            ),
            ("self.memory.self.spawn".to_owned(), SelfEffect::ReaderSpawn),
            ("self.memory.self.team.record".to_owned(), SelfEffect::Team),
            ("self.memory.self.team.start".to_owned(), SelfEffect::Team),
            ("self.memory.self.team.submit".to_owned(), SelfEffect::Team),
            ("self.memory.self.team.vote".to_owned(), SelfEffect::Team),
            ("self.memory.self.unfold".to_owned(), SelfEffect::Fold),
            (
                "self.memory.self.workflows.dispatch_bound".to_owned(),
                SelfEffect::WorkflowDispatch
            ),
            ("self.memory.summarize".to_owned(), SelfEffect::Summarize),
            (
                "self.memory.tasks.consult.result".to_owned(),
                SelfEffect::ConsultResult
            ),
            (
                "self.memory.tasks.refuse".to_owned(),
                SelfEffect::TasksRefuse
            ),
            (
                "self.memory.vault.agents.put".to_owned(),
                SelfEffect::AgentsPut
            ),
            (
                "self.memory.vault.claims.put".to_owned(),
                SelfEffect::MemoryPutClaim
            ),
            (
                "self.memory.vault.claims.supersede".to_owned(),
                SelfEffect::MemorySupersedeClaim
            ),
            (
                "self.memory.vault.edges.put".to_owned(),
                SelfEffect::MemoryPutEdge
            ),
            (
                "self.memory.vault.worlds.privacy.set".to_owned(),
                SelfEffect::WorldPrivacySet
            ),
        ]),
        "OF-060 P3: write imports must map exactly to the run's named, gated write rows and the blocked-report receipt",
    );
    for verb in RunVerb::ALL {
        assert_ne!(
            verb.effect(),
            SelfEffect::MemoryWriteFixture,
            "OF-060 P3: a run row must not expose the fixture write effect",
        );
    }

    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        for import in contract.linked_imports() {
            assert!(
                !matches!(
                    import.write_trap_effect(),
                    Some(SelfEffect::MemoryWriteFixture),
                ),
                "OF-060 P3: {tier:?} must not expose the fixture write effect",
            );
            for forbidden in [
                "batch",
                "bulk",
                "raw",
                "delete",
                "put_entity",
                "put_replicated",
                "set_edge_weight",
                "write_fixture",
            ] {
                assert!(
                    !import.name().contains(forbidden),
                    "OF-060 P3: {tier:?} code-mode WIT import {} exposes raw escape hatch fragment {forbidden}",
                    import.name()
                );
            }
        }
    }
}

/// Module depth of a core source file below the crate root: 0 for
/// `src/lib.rs`, 1 for `src/a.rs` and `src/a/mod.rs`, 2 for `src/a/b.rs`. An
/// inline `mod` only adds depth, so this is a lower bound for every path
/// written in the file.
fn core_module_depth(rel: &str) -> usize {
    let below = rel.strip_prefix("crates/oneiron/src/").unwrap_or(rel);
    let dirs = below.matches('/').count();
    if below == "lib.rs" || below.ends_with("/mod.rs") {
        dirs
    } else {
        dirs + 1
    }
}

/// Whether the path segment at `hit` is reached through `self::` or a chain
/// of `super::` that stays below the crate root. Such a path names a sibling
/// or child module of core itself (`super::api::stream_error` in
/// `memory/witness/stream/refused.rs` is `memory::witness::stream::api`),
/// never gateway or server code. A chain that reaches the crate root spells
/// `crate::<segment>` another way and still counts.
fn names_core_submodule(source: &str, hit: usize, depth: usize) -> bool {
    let whole_ident = |head: &str| {
        !head
            .as_bytes()
            .last()
            .is_some_and(|byte| is_ident_byte(*byte))
    };
    let mut head = &source[..hit];
    let mut supers = 0usize;
    while let Some(rest) = head.strip_suffix("super::") {
        if !whole_ident(rest) {
            break;
        }
        supers += 1;
        head = rest;
    }
    let own = head.strip_suffix("self::").is_some_and(whole_ident);
    (supers > 0 || own) && supers < depth
}

#[test]
fn of060_f3_core_does_not_import_gateway_or_server_code() {
    let repo = repo_root();
    let mut violations = Vec::new();

    let tree = SourceTree::read(&repo.join("crates/oneiron/src"));
    for (path, source) in tree.production_sources() {
        let rel = normalized(relative_path(&repo, path));
        let depth = core_module_depth(&rel);
        let source = production_source(source);
        for pattern in [
            "oneiron_server::",
            "oneiron-server",
            "crate::mcp",
            "super::mcp",
            "mcp::",
            "crate::server",
            "server::",
            "crate::api",
            "api::",
            "crate::handler",
            "handler::",
            "gateway::",
        ] {
            // The bare segments. `crate::..`, `super::mcp` and the crate names
            // stay as written: they are whole paths already.
            let bare = matches!(
                pattern,
                "mcp::" | "server::" | "api::" | "handler::" | "gateway::"
            );
            for hit in find_substring_hits(&source, pattern) {
                // Match path segments, not suffixes such as `api::` in `agent_api::`.
                if hit > 0 && is_ident_byte(source.as_bytes()[hit - 1]) {
                    continue;
                }
                // `self::`/`super::` below the crate root is core's own module.
                if bare && names_core_submodule(&source, hit, depth) {
                    continue;
                }
                violations.push(format!("{rel}:{}: {pattern}", line_number(&source, hit)));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OF-060 F3: oneiron core must not import or path-reference gateway/MCP/server code:\n{}",
        violations.join("\n")
    );
}
