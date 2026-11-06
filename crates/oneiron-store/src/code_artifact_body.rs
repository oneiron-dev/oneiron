//! Code artifact body values and the pinned MessagePack codec.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;

pub const CODE_ARTIFACT_BODY_KEYS: [&str; 5] = [
    "summary_prompt",
    "summary_hash",
    "repo_ref",
    "class",
    "lens_tree",
];
pub const CODE_ARTIFACT_SUMMARY_HASH_LEN: usize = 32;
pub const CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES: usize = 16 * 1024;
pub const CODE_ARTIFACT_REPO_REF_MAX_BYTES: usize = 1024;

pub const KEY_SUMMARY_PROMPT: &str = CODE_ARTIFACT_BODY_KEYS[0];
pub const KEY_SUMMARY_HASH: &str = CODE_ARTIFACT_BODY_KEYS[1];
pub const KEY_REPO_REF: &str = CODE_ARTIFACT_BODY_KEYS[2];
pub const KEY_CLASS: &str = CODE_ARTIFACT_BODY_KEYS[3];
pub const KEY_LENS_TREE: &str = CODE_ARTIFACT_BODY_KEYS[4];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CodeArtifactClass {
    #[default]
    Codebase,
    Artifact,
    /// A saved lens (CODE kind=lens, FIX 9896): its body carries the frozen
    /// compiled tree in `lens_tree`, and its `repo_ref` names the pack slot
    /// it was compiled for, not a repository.
    Lens,
    /// A pack hook's script (FIX 11260): its `repo_ref` names the pack slot
    /// it was installed from (`pack:<pack>@<content hash>/hooks/<name>`),
    /// not a repository, and it carries no tree.
    Hook,
}

impl CodeArtifactClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codebase => "codebase",
            Self::Artifact => "artifact",
            Self::Lens => "lens",
            Self::Hook => "hook",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "codebase" => Ok(Self::Codebase),
            "artifact" => Ok(Self::Artifact),
            "lens" => Ok(Self::Lens),
            "hook" => Ok(Self::Hook),
            _ => Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "class must be codebase, artifact, lens or hook",
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeArtifactBody {
    pub summary_prompt: String,
    pub summary_hash: [u8; CODE_ARTIFACT_SUMMARY_HASH_LEN],
    pub repo_ref: String,
    pub class: CodeArtifactClass,
    /// A lens's frozen compiled tree, as canonical JSON; present exactly when
    /// `class` is [`CodeArtifactClass::Lens`].
    pub lens_tree: Option<String>,
}

impl CodeArtifactBody {
    #[must_use]
    pub fn new(
        summary_prompt: impl Into<String>,
        summary_hash: [u8; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        repo_ref: impl Into<String>,
    ) -> Self {
        Self {
            summary_prompt: summary_prompt.into(),
            summary_hash,
            repo_ref: repo_ref.into(),
            class: CodeArtifactClass::Codebase,
            lens_tree: None,
        }
    }

    /// A saved lens (FIX 9896): the authored prompt it was compiled from,
    /// the hash of its frozen tree, the pack slot it is bound to and the
    /// tree itself.
    #[must_use]
    pub fn lens(
        summary_prompt: impl Into<String>,
        summary_hash: [u8; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        slot_ref: impl Into<String>,
        lens_tree: impl Into<String>,
    ) -> Self {
        Self {
            summary_prompt: summary_prompt.into(),
            summary_hash,
            repo_ref: slot_ref.into(),
            class: CodeArtifactClass::Lens,
            lens_tree: Some(lens_tree.into()),
        }
    }

    #[must_use]
    pub fn with_class(mut self, class: CodeArtifactClass) -> Self {
        self.class = class;
        self
    }
}

pub fn encode_code_artifact_body(body: &CodeArtifactBody) -> Result<Vec<u8>> {
    validate_code_artifact_body(body)?;
    let mut entries = vec![
        (
            Value::from(KEY_SUMMARY_PROMPT),
            Value::from(body.summary_prompt.as_str()),
        ),
        (
            Value::from(KEY_SUMMARY_HASH),
            Value::Binary(body.summary_hash.to_vec()),
        ),
        (
            Value::from(KEY_REPO_REF),
            Value::from(body.repo_ref.as_str()),
        ),
        (Value::from(KEY_CLASS), Value::from(body.class.as_str())),
    ];
    if let Some(tree) = &body.lens_tree {
        entries.push((Value::from(KEY_LENS_TREE), Value::from(tree.as_str())));
    }
    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("CODE artifact body MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_code_artifact_body(bytes: &[u8]) -> Result<CodeArtifactBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "body is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after body map",
        )));
    }
    decode_code_artifact_body_value(&value)
}

pub fn validate_code_artifact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_code_artifact_body(bytes).map(|_| ())
}

fn decode_code_artifact_body_value(value: &Value) -> Result<CodeArtifactBody> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "body must be a MessagePack map",
        )));
    };

    let mut summary_prompt: Option<String> = None;
    let mut summary_hash: Option<[u8; CODE_ARTIFACT_SUMMARY_HASH_LEN]> = None;
    let mut repo_ref: Option<String> = None;
    let mut class: Option<CodeArtifactClass> = None;
    let mut lens_tree: Option<String> = None;
    let mut seen = [false; CODE_ARTIFACT_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = CODE_ARTIFACT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "body key is not in the pinned CODE_ARTIFACT_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;

        match CODE_ARTIFACT_BODY_KEYS[index] {
            KEY_SUMMARY_PROMPT => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidCodeArtifactBody("summary_prompt must be a UTF-8 string"),
                ))?;
                validate_text_field(
                    text,
                    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES,
                    "summary_prompt must be non-empty and at most 16384 bytes",
                )?;
                summary_prompt = Some(text.to_owned());
            }
            KEY_SUMMARY_HASH => {
                summary_hash = Some(hash_from_value(value)?);
            }
            KEY_REPO_REF => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidCodeArtifactBody("repo_ref must be a UTF-8 string"),
                ))?;
                validate_text_field(
                    text,
                    CODE_ARTIFACT_REPO_REF_MAX_BYTES,
                    "repo_ref must be non-empty and at most 1024 bytes",
                )?;
                repo_ref = Some(text.to_owned());
            }
            KEY_CLASS => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidCodeArtifactBody("class must be a UTF-8 string"),
                ))?;
                class = Some(CodeArtifactClass::parse(text)?);
            }
            KEY_LENS_TREE => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidCodeArtifactBody("lens_tree must be a UTF-8 string"),
                ))?;
                lens_tree = Some(text.to_owned());
            }
            _ => unreachable!("index resolved from CODE_ARTIFACT_BODY_KEYS"),
        }
    }

    let body = CodeArtifactBody {
        summary_prompt: summary_prompt.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing required replay key summary_prompt"),
        ))?,
        summary_hash: summary_hash.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing required replay key summary_hash"),
        ))?,
        repo_ref: repo_ref.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required replay key repo_ref",
        )))?,
        class: class.unwrap_or_default(),
        lens_tree,
    };
    validate_code_artifact_body(&body)?;
    Ok(body)
}

fn validate_code_artifact_body(body: &CodeArtifactBody) -> Result<()> {
    validate_text_field(
        &body.summary_prompt,
        CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES,
        "summary_prompt must be non-empty and at most 16384 bytes",
    )?;
    validate_text_field(
        &body.repo_ref,
        CODE_ARTIFACT_REPO_REF_MAX_BYTES,
        "repo_ref must be non-empty and at most 1024 bytes",
    )?;
    // A lens names its pack slot, not a repository, and carries its tree;
    // every other class carries no tree.
    if body.class == CodeArtifactClass::Lens {
        return match body.lens_tree.as_deref() {
            Some(tree) if !tree.is_empty() => Ok(()),
            _ => Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "a lens body must carry a non-empty lens_tree",
            ))),
        };
    }
    if body.lens_tree.is_some() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "only a lens body carries lens_tree",
        )));
    }
    // A pack hook, like a lens, names its pack slot, not a repository.
    if body.class == CodeArtifactClass::Hook {
        return Ok(());
    }
    crate::code_snapshot::repo_ref::RepoRef::parse(&body.repo_ref).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "repo_ref must be a valid v1 repo_ref",
        ))
    })?;
    Ok(())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            context,
        )));
    }
    Ok(())
}

fn hash_from_value(value: &Value) -> Result<[u8; CODE_ARTIFACT_SUMMARY_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "summary_hash must be MessagePack binary",
        )));
    };
    bytes.as_slice().try_into().map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "summary_hash must be 32-byte binary",
        ))
    })
}
