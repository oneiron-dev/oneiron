//! Durable terminal rows. Failures, timeouts and interruptions never rerun.
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use super::{Result, taskgen::Cell};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Row {
    pub(crate) key: String, pub(crate) cell: Cell, pub(crate) plan_digest: String, pub(crate) config_digest: String,
    pub(crate) engine: String, pub(crate) role: String, pub(crate) models: Value, pub(crate) diagnostic_approximation: bool,
    pub(crate) status: String, pub(crate) harness_stop: Option<Value>, pub(crate) engine_stop: Value,
    pub(crate) checker: Value, pub(crate) measures: Value, pub(crate) evidence: PathBuf,
}
pub(super) fn append(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, value).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
pub(super) fn load_values(path: &Path) -> Result<Vec<Value>> {
    if !path.exists() { return Ok(Vec::new()) }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') { return Err("truncated_evidence_jsonl".into()) }
    bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|e| format!("malformed_evidence_jsonl:{e}"))).collect()
}
pub(super) fn terminal(path: &Path, plan: &str, config: &str) -> Result<BTreeMap<String, Row>> {
    let mut rows = BTreeMap::new();
    for value in load_values(path)? {
        let row: Row = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if row.plan_digest != plan || row.config_digest != config { return Err("resume_identity_mismatch".into()) }
        if rows.insert(row.key.clone(), row).is_some() { return Err("duplicate_terminal_row".into()) }
    }
    Ok(rows)
}
pub(super) struct Lock(PathBuf);
impl Lock {
    pub(crate) fn acquire(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
        let path = directory.join("campaign.lock");
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|e| format!("campaign_locked_confirm_owned_cleanup_before_removing_lock:{e}"))?;
        writeln!(file, "{}", std::process::id()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for Lock { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
pub(super) fn blocked(row: &mut Row, cause: &str, detail: &str) {
    row.status = "blocked".into();
    row.harness_stop = Some(json!({"cause":cause,"detail":detail}));
}
