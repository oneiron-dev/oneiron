//! Credential-nulled, exact source files. No raw byte/base64 escape hatch.
use super::credential_nulling::{credential_key, null_credentials};
use crate::batch::export::{ExportFileTree, ExportSourceFile};
use crate::batch::secret_scan::scan_file_content;
use crate::error::{Error, Result};
use crate::skill::{SkillContentHash, canonical_skill_tree_hash};
use crate::skill_hub::HubFile;
use sha2::{Digest, Sha256};

fn source_file_is_safe(path: &str, content: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(content) else {
        return false;
    };
    if scan_file_content(path, content).is_some()
        || scan_file_content("", path.as_bytes()).is_some()
        || path.split('/').any(|part| {
            credential_key(part.split('.').next().unwrap_or(part))
                || [".pem", ".key", ".sig"]
                    .iter()
                    .any(|ext| part.to_ascii_lowercase().ends_with(ext))
        })
    {
        return false;
    }
    if let Ok(value @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) =
        serde_json::from_str(text)
    {
        return safe_json(&value, 0);
    }
    // Closed, conservative inspection of YAML/frontmatter, environment and code
    // assignments. An unfamiliar credential value is still secret by field name.
    !text.lines().any(|line| {
        line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(credential_key)
            && (line.contains(':') || line.contains('='))
    })
}

fn safe_json(value: &serde_json::Value, depth: usize) -> bool {
    if depth >= 24 || null_credentials("", value) != *value {
        return false;
    }
    match value {
        serde_json::Value::String(text) => {
            if let Ok(nested @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) =
                serde_json::from_str(text)
            {
                safe_json(&nested, depth + 1)
            } else {
                true
            }
        }
        serde_json::Value::Array(values) => values.iter().all(|v| safe_json(v, depth + 1)),
        serde_json::Value::Object(values) => values.values().all(|v| safe_json(v, depth + 1)),
        _ => true,
    }
}

fn source_digest(bytes: &[u8]) -> String {
    SkillContentHash::from_bytes(Sha256::digest(bytes).into()).to_hex()
}

pub(crate) fn export_source_tree(files: &[HubFile]) -> Result<ExportFileTree> {
    let original_hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    if files
        .iter()
        .any(|file| scan_file_content("", file.path.as_bytes()).is_some())
    {
        // Path names are source bytes too. Hide the whole tree's names rather
        // than leak a credential or mint aliases when replacing just one path.
        let tree = ExportFileTree {
            content_hash: None,
            files: (0..files.len())
                .map(|index| ExportSourceFile {
                    path: format!("_redacted_path/{index:08}"),
                    content: None,
                    sha256: None,
                })
                .collect(),
        };
        tree.validate()?;
        return Ok(tree);
    }
    let mut files: Vec<_> = files.iter().collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut complete = true;
    let files = files
        .into_iter()
        .map(|f| {
            let safe = source_file_is_safe(&f.path, &f.content);
            complete &= safe;
            ExportSourceFile {
                path: f.path.clone(),
                content: safe.then(|| String::from_utf8(f.content.clone()).expect("UTF-8 checked")),
                sha256: safe.then(|| source_digest(&f.content)),
            }
        })
        .collect();
    let tree = ExportFileTree {
        content_hash: complete.then(|| original_hash.to_hex()),
        files,
    };
    tree.validate()?;
    Ok(tree)
}

impl ExportFileTree {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.files.len() > crate::skill_hub::MAX_HUB_PACKAGE_FILES {
            return Err(invalid("too many source files"));
        }
        let mut total = 0usize;
        let mut prior: Option<&str> = None;
        let mut complete = true;
        let mut files = Vec::new();
        for file in &self.files {
            if scan_file_content("", file.path.as_bytes()).is_some() {
                return Err(invalid("source path contains credential material"));
            }
            if prior.is_some_and(|p| p >= file.path.as_str()) {
                return Err(invalid("source paths not sorted"));
            }
            prior = Some(&file.path);
            let content = match (&file.content, &file.sha256) {
                (Some(text), Some(hash))
                    if source_file_is_safe(&file.path, text.as_bytes())
                        && source_digest(text.as_bytes()) == *hash =>
                {
                    text.as_bytes()
                }
                (None, None) => {
                    complete = false;
                    &[]
                }
                _ => return Err(invalid("source file proof is invalid")),
            };
            total = total
                .checked_add(content.len())
                .ok_or_else(|| invalid("source size overflow"))?;
            if content.len() > crate::skill_hub::MAX_HUB_FILE_BYTES
                || total > crate::skill_hub::MAX_HUB_PACKAGE_TOTAL_BYTES
            {
                return Err(invalid("source files exceed package bounds"));
            }
            files.push((file.path.as_str(), content));
        }
        // Also rejects traversal, absolute paths and case-fold aliases for redacted trees.
        let hash = canonical_skill_tree_hash(files)?;
        if self.content_hash != complete.then(|| hash.to_hex()) {
            return Err(invalid("source tree proof is invalid"));
        }
        Ok(())
    }

    pub(crate) fn import_files(&self) -> Result<Vec<HubFile>> {
        self.validate()?;
        if self.content_hash.is_none() {
            return Err(invalid("redacted source tree is not importable"));
        }
        self.files
            .iter()
            .map(|file| {
                Ok(HubFile::new(
                    &file.path,
                    file.content
                        .as_ref()
                        .ok_or_else(|| invalid("nulled source file"))?
                        .as_bytes(),
                ))
            })
            .collect()
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault source bundle: {reason}"))
}
