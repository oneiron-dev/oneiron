//! Freeze paired seeds, disjoint holdouts and rotated arm assignments.
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use super::{Result, digest, read, write_json};
pub(super) const CHECKER_VERSION: &str = "cua-checkers-1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cell {
    pub(crate) id: String, pub(crate) fixture: String, pub(crate) version: String, pub(crate) seed: u64,
    pub(crate) arm: String, pub(crate) repetition: u32, pub(crate) seconds: u64, pub(crate) actions: u64,
    pub(crate) public_task: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub(crate) schema: u32, pub(crate) campaign_seed: u64,
    pub(crate) fixture_public_bind: Option<std::net::SocketAddrV4>, pub(crate) manifest_digest: String,
    pub(crate) checker_digest: String, pub(crate) fixture_root: PathBuf, pub(crate) fixture_digest: String,
    pub(crate) checker_version: String, pub(crate) evaluation_seeds: BTreeMap<String, Vec<u64>>,
    pub(crate) holdout_seeds: BTreeMap<String, Vec<u64>>, pub(crate) cells: Vec<Cell>,
}
pub(super) fn checker_digest(root: &Path) -> Result<String> {
    let mut paths: Vec<_> = fs::read_dir(root.join("checkers")).map_err(|e| e.to_string())?
        .map(|p| p.map(|p| p.path())).collect::<std::result::Result<_, _>>().map_err(|e| e.to_string())?;
    paths.sort();
    let mut bytes = Vec::new();
    for p in paths.into_iter().filter(|p| p.extension().is_some_and(|x| x == "py")) {
        bytes.extend(p.file_name().ok_or("checker_name_missing")?.to_string_lossy().as_bytes());
        bytes.extend(fs::read(p).map_err(|e| e.to_string())?);
    }
    Ok(digest(&bytes))
}
pub(super) fn fixture_digest(root: &Path) -> Result<String> {
    let mut paths = vec![root.join("manifest.json"), root.join("state_server.py"), root.join("gen_data.py"),
        root.join("assets/app.js"), root.join("assets/style.css")];
    for fixture in ["F1", "F2", "F3", "F4", "F5"] {
        paths.extend(fs::read_dir(root.join(fixture).join("expected")).map_err(|e| e.to_string())?
            .map(|p| p.map(|p| p.path())).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| e.to_string())?);
    }
    paths.sort();
    let mut bytes = Vec::new();
    for path in paths { bytes.extend(fs::read(path).map_err(|e| e.to_string())?) }
    Ok(digest(&bytes))
}
pub(super) fn generate(manifest: &Path, seed: u64, fixture_public_bind: Option<std::net::SocketAddrV4>, out: &Path) -> Result<()> {
    if out.exists() { return Err("frozen_output_already_exists".into()) }
    if let Some(target) = fixture_public_bind {
        oneiron::code_sandbox::egress::FixtureForward::new(target).map_err(|e| e.to_string())?;
        if target.port() == 8766 { return Err("public_private_port_collision".into()) }
    }
    let source: Value = read(manifest)?;
    if source["schema"] != 1 || source["row"] != "S1" { return Err("s1_manifest_required".into()) }
    let fixture_root = manifest.canonicalize().map_err(|e| e.to_string())?
        .parent().ok_or("manifest_parent_missing")?.to_path_buf();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut cells = Vec::new();
    let mut holdout_seeds = BTreeMap::new();
    let mut evaluation_seeds = BTreeMap::new();
    for (index, (fixture, seconds, actions)) in [("F1",420,120), ("F2",60,20), ("F3",300,60), ("F4",120,20), ("F5",600,60)].into_iter().enumerate() {
        if source["fixtures"][fixture]["caps"]["seconds"] != seconds
            || source["fixtures"][fixture]["caps"]["actions"] != actions {
            return Err(format!("fixture_caps_mismatch:{fixture}"));
        }
        let mut seeds = Vec::new();
        while seeds.len() < 5 {
            let next = rng.gen_range(1..=i64::MAX as u64);
            if next != 20261021 && !seeds.contains(&next) { seeds.push(next) }
        }
        let (evaluation, holdout) = crate::interface_bench::freeze_tail(&seeds, 2);
        evaluation_seeds.insert(fixture.to_string(), evaluation);
        holdout_seeds.insert(fixture.to_string(), holdout);
        for repetition in 0..3 {
            let arms: &[&str] = if matches!(fixture, "F2" | "F4") { &["B", "C", "C+", "D"] } else { &["B", "C", "D"] };
            let rotation = (index + repetition) % arms.len();
            for offset in 0..arms.len() {
                let arm = arms[(rotation + offset) % arms.len()];
                cells.push(Cell { id: format!("{fixture}-{arm}-try{}", repetition+1), fixture: fixture.into(),
                    version: "v0".into(), seed: seeds[repetition], arm: arm.into(), repetition: repetition as u32+1,
                    seconds, actions, public_task: include_str!("../../cua-task-packet.txt").replace("{fixture}", fixture) });
            }
        }
    }
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let public: Vec<_> = cells.iter().map(|c| json!({"id":c.id,"fixture":c.fixture,"task":c.public_task})).collect();
    let plan = Plan { schema:1, campaign_seed: seed, fixture_public_bind, manifest_digest: digest(&fs::read(manifest).map_err(|e| e.to_string())?),
        checker_digest: checker_digest(&fixture_root)?, fixture_digest: fixture_digest(&fixture_root)?,
        fixture_root, checker_version: CHECKER_VERSION.into(), evaluation_seeds, holdout_seeds, cells };
    write_json(&out.join("public-packets.json"), &public)?;
    write_json(&out.join("holdout-freeze.json"), &json!({"evaluation":plan.evaluation_seeds,"reserved":plan.holdout_seeds}))?;
    write_json(&out.join("plan.json"), &plan)
}
