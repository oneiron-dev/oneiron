use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use oneiron::{
    SANDBOX_WIT_WORLD_NAME, SandboxBoundaryContract, SandboxGuestTier, SandboxImportClass,
    SelfEffect,
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

fn normalized(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(root, &mut out);
    out.sort();
    out
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), ".git" | "target") {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn production_file(rel: &str) -> bool {
    // `<module>/tests.rs` siblings are test mounts (`#[cfg(test)] mod tests;`),
    // never production code — same standing as an inline `mod tests` body.
    !rel.contains("/tests/")
        && !rel.contains("/benches/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("/src/tests_bug.rs")
}

fn production_source(source: &str) -> String {
    mask_cfg_test_modules(&strip_comments_and_literals(source))
}

fn strip_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i..].starts_with(b"//") {
            i = copy_until_newline(bytes, &mut out, i);
        } else if bytes[i..].starts_with(b"/*") {
            i = skip_block_comment(bytes, &mut out, i);
        } else if raw_string_hashes(bytes, i).is_some() {
            i = skip_raw_string(bytes, &mut out, i);
        } else if bytes[i] == b'"' {
            i = skip_quoted(bytes, &mut out, i, b'"');
        } else if bytes[i] == b'\'' && looks_like_char_literal(bytes, i) {
            i = skip_quoted(bytes, &mut out, i, b'\'');
        } else {
            out[i] = bytes[i];
            i += 1;
        }
    }
    String::from_utf8(out).expect("sanitized source is ASCII/newline")
}

fn copy_until_newline(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            return i + 1;
        }
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i..].starts_with(b"/*") {
            depth += 1;
            i += 2;
        } else if bytes[i..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn raw_string_hashes(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'r') {
        return None;
    }
    if start > 0 && is_ident_byte(bytes[start - 1]) {
        return None;
    }

    let mut i = start + 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    (bytes.get(i) == Some(&b'"')).then_some(i - start - 1)
}

fn skip_raw_string(bytes: &[u8], out: &mut [u8], start: usize) -> usize {
    let hashes = raw_string_hashes(bytes, start).expect("raw string start");
    let terminator = vec![b'#'; hashes];
    let mut i = start + hashes + 2;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
            continue;
        }
        if bytes[i] == b'"' && bytes.get(i + 1..i + 1 + hashes) == Some(&terminator[..]) {
            return i + hashes + 1;
        }
        i += 1;
    }
    i
}

fn looks_like_char_literal(bytes: &[u8], start: usize) -> bool {
    let mut i = start + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 2;
    } else {
        i += 1;
    }
    bytes.get(i) == Some(&b'\'')
}

fn skip_quoted(bytes: &[u8], out: &mut [u8], mut i: usize, quote: u8) -> usize {
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

fn mask_cfg_test_modules(source: &str) -> String {
    let mut out = source.as_bytes().to_vec();
    let mut search_start = 0;
    while let Some(rel_cfg) = source[search_start..].find("#[cfg(test)]") {
        let cfg_start = search_start + rel_cfg;
        let Some(rel_mod) = source[cfg_start..].find("mod tests") else {
            search_start = cfg_start + "#[cfg(test)]".len();
            continue;
        };
        let mod_start = cfg_start + rel_mod;
        if !source[cfg_start + "#[cfg(test)]".len()..mod_start]
            .chars()
            .all(char::is_whitespace)
        {
            search_start = cfg_start + "#[cfg(test)]".len();
            continue;
        }
        let Some(rel_open) = source[mod_start..].find('{') else {
            break;
        };
        let open = mod_start + rel_open;
        let Some(end) = matching_brace_end(source.as_bytes(), open) else {
            break;
        };
        mask_range_preserving_newlines(&mut out, cfg_start, end);
        search_start = end;
    }
    String::from_utf8(out).expect("masked source remains utf8")
}

fn matching_brace_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn mask_range_preserving_newlines(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
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

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_byte(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

#[test]
fn of060_f1_put_replicated_stays_sync_only() {
    let repo = repo_root();
    let mut violations = Vec::new();

    for path in rust_files_under(&repo.join("crates")) {
        let rel = normalized(relative_path(&repo, &path));
        if !production_file(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"));
        let source = production_source(&source);
        for pattern in [".put_replicated", "::put_replicated"] {
            for hit in find_substring_hits(&source, pattern) {
                if !rel.starts_with("crates/oneiron/src/sync/") {
                    violations.push(format!("{rel}:{}: {pattern}", line_number(&source, hit)));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OF-060 F1: put_replicated must stay reachable only from oneiron sync production code:\n{}",
        violations.join("\n")
    );
}

#[test]
fn of060_f2_surface_raw_escape_hatches_are_pinned() {
    let repo = repo_root();
    let mut actual = BTreeMap::<RawHit, usize>::new();

    for path in rust_files_under(&repo.join("crates")) {
        let rel = normalized(relative_path(&repo, &path));
        if !production_file(&rel) || !f2_surface_path(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"));
        for hit in raw_escape_hits(&rel, &production_source(&source)) {
            *actual.entry(hit).or_default() += 1;
        }
    }

    let expected = BTreeMap::from([
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib.rs".to_owned(),
                ident: "put_edge".to_owned(),
                line: "pub fn put_edge(&self, src: Buffer, kind: u32, tgt: Buffer, weight: f64) -> napi::Result<()> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib.rs".to_owned(),
                ident: "put_edge".to_owned(),
                line: ".put_edge(&src_id, edge_kind, &tgt_id, weight as f32)".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib.rs".to_owned(),
                ident: "put_vector".to_owned(),
                line: "pub fn put_vector(&self, id: Buffer, vector: Vec<f64>) -> napi::Result<()> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib.rs".to_owned(),
                ident: "put_vector".to_owned(),
                line: "self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err)".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/idempotency.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: ".sync_state_put(store_key, &raw)".to_owned(),
            },
            1,
        ),
        // Server-plane auth metadata: one empty row per revoked bearer-token
        // id (ONE-1636). Same class as the idempotency entry above — it writes
        // no entity, edge, or vector, so no stamper applies to it.
        (
            RawHit {
                path: "crates/oneiron-server/src/auth.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: "vault.sync_state_put(&key, &[])?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/server.rs".to_owned(),
                ident: "with_write_txn".to_owned(),
                line: "if let Err(err) = self.vault.with_write_txn(|wtxn| {".to_owned(),
            },
            1,
        ),
        // MCP proposed-control-record write (ONE-1936). This is NOT a raw
        // write bypassing a stamper: the transaction wraps the write-verb
        // target guard and a stamped `batch_in().claim_candidate(...)`, which
        // carries the same `WriteEnvelope` the unguarded `batch()` path did.
        // The explicit transaction is REQUIRED — guarding the target in one
        // transaction and writing the proposal in another recreates the
        // grounding-read race the ticket closes.
        (
            RawHit {
                path: "crates/oneiron-server/src/api/mcp_gateway.rs".to_owned(),
                ident: "with_write_txn".to_owned(),
                line: ".with_write_txn(|wtxn| {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "try_with_write_txn".to_owned(),
                line: ".try_with_write_txn(|wtxn| -> Result<LedgerWriteResult, UsageError> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &tenant_key, &tenant_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &vault_key, &vault_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &event_key, &entry_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "try_with_write_txn".to_owned(),
                line: ".try_with_write_txn(|wtxn| -> Result<TopUpWriteResult, UsageError> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "self.vault.sync_state_put_in_write_txn(".to_owned(),
            },
            2,
        ),
    ]);

    assert_eq!(
        actual, expected,
        "OF-060 F2: surface raw escape-hatch references changed. New foreign/guest writes must go through a stamper; remove or intentionally update this pinned baseline."
    );
}

fn f2_surface_path(rel: &str) -> bool {
    rel.starts_with("crates/oneiron-server/src/")
        || rel.starts_with("crates/oneiron-napi/src/")
        || matches!(
            rel,
            "crates/oneiron/src/code_run.rs" | "crates/oneiron/src/code_sandbox.rs"
        )
}

#[test]
fn of060_p3_code_mode_guest_surface_links_named_verbs_only() {
    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert_eq!(first_party.wit_world(), SANDBOX_WIT_WORLD_NAME);

    let write_imports = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::WriteTrap)
        .map(|import| import.name())
        .collect::<Vec<_>>();
    assert_eq!(
        write_imports,
        vec![
            "self.memory.put_claim",
            "self.memory.supersede_claim",
            "self.memory.put_edge",
        ],
        "OF-060 P3: code-mode WIT writes must stay on named memory verbs only"
    );

    let write_effects = first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::WriteTrap)
        .map(|import| import.write_trap_effect().expect("named write trap"))
        .collect::<Vec<_>>();
    assert_eq!(
        write_effects,
        vec![
            SelfEffect::MemoryPutClaim,
            SelfEffect::MemorySupersedeClaim,
            SelfEffect::MemoryPutEdge,
        ],
        "OF-060 P3: every linked code-mode write import must resolve to a named effect"
    );

    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        for import in contract.linked_imports() {
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

#[test]
fn of060_f3_core_does_not_import_gateway_or_server_code() {
    let repo = repo_root();
    let mut violations = Vec::new();

    for path in rust_files_under(&repo.join("crates/oneiron/src")) {
        let rel = normalized(relative_path(&repo, &path));
        if !production_file(&rel) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"));
        let source = production_source(&source);
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
            for hit in find_substring_hits(&source, pattern) {
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
