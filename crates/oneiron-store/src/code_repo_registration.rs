//! The retained configuration of a registered repository (FIX 4299,
//! CODE-CUSTODY-01), nested in its CODE_ARTIFACT body.
//!
//! A registered repository is one stable CODE record. Its source says where
//! the importer reads it: an external local Git repository by its canonical
//! folder, or a Git store this vault serves by its served name. The source is
//! mutable config, never identity. The editable whitelist is an edit ceiling:
//! exact normalized repo-relative paths, no globs. An empty whitelist means
//! read-only. It filters no read: a capture still holds every file it reads.

use std::path::Path;

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;

use crate::code_snapshot::validation::validate_manifest_path;

/// The pinned keys of a registration map, in encode order.
pub const CODE_REPO_REGISTRATION_KEYS: [&str; 2] = ["source", "editable"];

const KEY_SOURCE: &str = CODE_REPO_REGISTRATION_KEYS[0];
const KEY_EDITABLE: &str = CODE_REPO_REGISTRATION_KEYS[1];

/// The spelling prefix of an external local source.
const LOCAL_SOURCE_PREFIX: &str = "local:";
/// The spelling prefix of a served source.
const SERVED_SOURCE_PREFIX: &str = "served:";
/// The longest source spelling: a path's bound and its prefix.
const SOURCE_MAX_BYTES: usize = crate::code_snapshot::snapshot::CODEBASE_FILE_PATH_MAX_BYTES + 16;

fn invalid(context: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(context))
}

/// Where the importer reads a registered repository (FIX 4299).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeRepoSource {
    /// An external local Git repository on this host, by its canonical
    /// absolute folder: the folder the importer opens.
    LocalFolder { path: String },
    /// A Git store this vault's origin serves, by its served name.
    Served { name: String },
}

impl CodeRepoSource {
    /// The one spelling: `local:<folder>` or `served:<name>`.
    #[must_use]
    pub fn spelling(&self) -> String {
        match self {
            Self::LocalFolder { path } => format!("{LOCAL_SOURCE_PREFIX}{path}"),
            Self::Served { name } => format!("{SERVED_SOURCE_PREFIX}{name}"),
        }
    }

    /// The source `text` spells.
    ///
    /// # Errors
    /// `InvalidCodeArtifactBody` for any other text.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > SOURCE_MAX_BYTES || text.chars().any(char::is_control) {
            return Err(invalid(
                "a registration source is bounded text with no control characters",
            ));
        }
        if let Some(path) = text.strip_prefix(LOCAL_SOURCE_PREFIX) {
            if path.is_empty() || path.trim() != path || !Path::new(path).is_absolute() {
                return Err(invalid(
                    "a local registration source names an absolute folder",
                ));
            }
            return Ok(Self::LocalFolder {
                path: path.to_owned(),
            });
        }
        if let Some(name) = text.strip_prefix(SERVED_SOURCE_PREFIX) {
            if name.is_empty() || name.trim() != name || name.contains(['/', '\\']) {
                return Err(invalid(
                    "a served registration source names one served repository",
                ));
            }
            return Ok(Self::Served {
                name: name.to_owned(),
            });
        }
        Err(invalid(
            "a registration source is local:<folder> or served:<name>",
        ))
    }
}

/// A registered repository's retained configuration (FIX 4299): its source
/// and its editable whitelist, kept sorted and unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRepoRegistration {
    source: CodeRepoSource,
    editable: Vec<String>,
}

impl CodeRepoRegistration {
    /// A registration of `source` whose edit ceiling is exactly the paths of
    /// `editable`, each a normalized repo-relative path; duplicates collapse.
    ///
    /// # Errors
    /// `InvalidCodeArtifactBody` for a path that is not normalized and
    /// repo-relative, or a source that does not parse.
    pub fn new(
        source: CodeRepoSource,
        editable: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        CodeRepoSource::parse(&source.spelling())?;
        let mut editable = editable
            .into_iter()
            .map(Into::into)
            .map(|path: String| {
                validate_manifest_path(&path)
                    .map_err(|_| invalid("an editable path is a normalized repo-relative path"))?;
                Ok(path)
            })
            .collect::<Result<Vec<_>>>()?;
        editable.sort();
        editable.dedup();
        Ok(Self { source, editable })
    }

    /// Where the importer reads the repository.
    #[must_use]
    pub const fn source(&self) -> &CodeRepoSource {
        &self.source
    }

    /// The editable whitelist, ascending: empty means read-only.
    #[must_use]
    pub fn editable(&self) -> &[String] {
        &self.editable
    }

    /// Whether the edit ceiling admits a change at `path`: an exact match,
    /// never a glob.
    #[must_use]
    pub fn admits_edit(&self, path: &str) -> bool {
        self.editable
            .binary_search_by(|held| held.as_str().cmp(path))
            .is_ok()
    }

    /// This registration with `source` as its source, the whitelist kept.
    #[must_use]
    pub fn with_source(mut self, source: CodeRepoSource) -> Self {
        self.source = source;
        self
    }

    /// The MessagePack map a CODE body nests.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::from(KEY_SOURCE), Value::from(self.source.spelling())),
            (
                Value::from(KEY_EDITABLE),
                Value::Array(
                    self.editable
                        .iter()
                        .map(|path| Value::from(path.as_str()))
                        .collect(),
                ),
            ),
        ])
    }

    /// The registration a CODE body's nested map spells, in its one
    /// spelling: both keys present, the whitelist sorted and unique.
    ///
    /// # Errors
    /// `InvalidCodeArtifactBody` for any other value.
    pub fn from_value(value: &Value) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(invalid("registration must be a MessagePack map"));
        };
        let mut source = None;
        let mut editable = None;
        for (key, value) in entries {
            match key.as_str() {
                Some(KEY_SOURCE) if source.is_none() => {
                    let text = value
                        .as_str()
                        .ok_or(invalid("registration source must be a UTF-8 string"))?;
                    source = Some(CodeRepoSource::parse(text)?);
                }
                Some(KEY_EDITABLE) if editable.is_none() => {
                    let Value::Array(paths) = value else {
                        return Err(invalid("registration editable must be an array"));
                    };
                    editable = Some(
                        paths
                            .iter()
                            .map(|path| {
                                path.as_str().map(str::to_owned).ok_or(invalid(
                                    "registration editable paths must be UTF-8 strings",
                                ))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    );
                }
                _ => {
                    return Err(invalid(
                        "registration keys are source and editable, each once",
                    ));
                }
            }
        }
        let (Some(source), Some(editable)) = (source, editable) else {
            return Err(invalid("registration requires source and editable"));
        };
        let registration = Self::new(source, editable.iter().map(String::as_str))?;
        if registration.editable != editable {
            return Err(invalid(
                "registration editable paths must be sorted and unique",
            ));
        }
        Ok(registration)
    }
}
