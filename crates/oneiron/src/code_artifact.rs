use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::temporal::TimeRange;

pub const CODE_ARTIFACT_BODY_KEYS: [&str; 4] =
    ["summary_prompt", "summary_hash", "repo_ref", "class"];
pub const CODE_ARTIFACT_SUMMARY_HASH_LEN: usize = 32;
pub const CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES: usize = 16 * 1024;
pub const CODE_ARTIFACT_REPO_REF_MAX_BYTES: usize = 1024;

const KEY_SUMMARY_PROMPT: &str = CODE_ARTIFACT_BODY_KEYS[0];
const KEY_SUMMARY_HASH: &str = CODE_ARTIFACT_BODY_KEYS[1];
const KEY_REPO_REF: &str = CODE_ARTIFACT_BODY_KEYS[2];
const KEY_CLASS: &str = CODE_ARTIFACT_BODY_KEYS[3];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeArtifactClass {
    #[default]
    Codebase,
    Artifact,
}

impl CodeArtifactClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codebase => "codebase",
            Self::Artifact => "artifact",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "codebase" => Ok(Self::Codebase),
            "artifact" => Ok(Self::Artifact),
            _ => Err(Error::InvalidCodeArtifactBody(
                "class must be codebase or artifact",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeArtifactBody {
    pub summary_prompt: String,
    pub summary_hash: [u8; CODE_ARTIFACT_SUMMARY_HASH_LEN],
    pub repo_ref: String,
    pub class: CodeArtifactClass,
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
    let value = Value::Map(vec![
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
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("CODE artifact body MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_code_artifact_body(bytes: &[u8]) -> Result<CodeArtifactBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidCodeArtifactBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after body map",
        ));
    }
    decode_code_artifact_body_value(&value)
}

pub(crate) fn validate_code_artifact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_code_artifact_body(bytes).map(|_| ())
}

fn decode_code_artifact_body_value(value: &Value) -> Result<CodeArtifactBody> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "body must be a MessagePack map",
        ));
    };

    let mut summary_prompt: Option<String> = None;
    let mut summary_hash: Option<[u8; CODE_ARTIFACT_SUMMARY_HASH_LEN]> = None;
    let mut repo_ref: Option<String> = None;
    let mut class: Option<CodeArtifactClass> = None;
    let mut seen = [false; CODE_ARTIFACT_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidCodeArtifactBody("body keys must be strings"));
        };
        let Some(index) = CODE_ARTIFACT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "body key is not in the pinned CODE_ARTIFACT_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody("duplicate body key"));
        }
        seen[index] = true;

        match CODE_ARTIFACT_BODY_KEYS[index] {
            KEY_SUMMARY_PROMPT => {
                let text = value.as_str().ok_or(Error::InvalidCodeArtifactBody(
                    "summary_prompt must be a UTF-8 string",
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
                let text = value.as_str().ok_or(Error::InvalidCodeArtifactBody(
                    "repo_ref must be a UTF-8 string",
                ))?;
                validate_text_field(
                    text,
                    CODE_ARTIFACT_REPO_REF_MAX_BYTES,
                    "repo_ref must be non-empty and at most 1024 bytes",
                )?;
                repo_ref = Some(text.to_owned());
            }
            KEY_CLASS => {
                let text = value.as_str().ok_or(Error::InvalidCodeArtifactBody(
                    "class must be a UTF-8 string",
                ))?;
                class = Some(CodeArtifactClass::parse(text)?);
            }
            _ => unreachable!("index resolved from CODE_ARTIFACT_BODY_KEYS"),
        }
    }

    let body = CodeArtifactBody {
        summary_prompt: summary_prompt.ok_or(Error::InvalidCodeArtifactBody(
            "missing required replay key summary_prompt",
        ))?,
        summary_hash: summary_hash.ok_or(Error::InvalidCodeArtifactBody(
            "missing required replay key summary_hash",
        ))?,
        repo_ref: repo_ref.ok_or(Error::InvalidCodeArtifactBody(
            "missing required replay key repo_ref",
        ))?,
        class: class.unwrap_or_default(),
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
    crate::codebase::RepoRef::parse(&body.repo_ref)
        .map_err(|_| Error::InvalidCodeArtifactBody("repo_ref must be a valid v1 repo_ref"))?;
    Ok(())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidCodeArtifactBody(context));
    }
    Ok(())
}

fn hash_from_value(value: &Value) -> Result<[u8; CODE_ARTIFACT_SUMMARY_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "summary_hash must be MessagePack binary",
        ));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodeArtifactBody("summary_hash must be 32-byte binary"))
}

impl Vault {
    pub fn put_code_artifact(
        &self,
        id: &EntityId,
        body: &CodeArtifactBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_code_artifact_body(body)?;
        self.put_entity(id, ENTITY_TYPE_CODE_ARTIFACT, occurred, learned_at, &data)
    }

    pub fn get_code_artifact(&self, id: &EntityId) -> Result<Option<CodeArtifactBody>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
            return Err(Error::InvalidCodeArtifactBody(
                "entity is not a type-83 CODE_ARTIFACT",
            ));
        }
        decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::registry::{
        EntityClassification, TypeByteZone, entity_type_registry_entry, short_id_prefix,
    };
    use crate::test_util::embedding_test_config;

    fn test_body() -> CodeArtifactBody {
        CodeArtifactBody::new(
            "Summarize the diff before applying the patch.",
            [0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
            "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277",
        )
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).expect("encode msgpack");
        out
    }

    fn code_artifact_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
        encode_value(&Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ))
    }

    #[test]
    fn code_artifact_codec_round_trips_required_replay_keys() -> Result<()> {
        let body = test_body();

        let encoded = encode_code_artifact_body(&body)?;
        let decoded = decode_code_artifact_body(&encoded)?;

        assert_eq!(decoded, body);
        Ok(())
    }

    #[test]
    fn code_artifact_registry_and_vault_helpers_round_trip() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
        let id = EntityId::now();
        let body = test_body();

        vault.put_code_artifact(&id, &body, TimeRange { start: 10, end: 10 }, 11)?;
        let decoded = vault.get_code_artifact(&id)?.ok_or(Error::EntityNotFound)?;

        assert_eq!(decoded, body);
        assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_CODE_ARTIFACT));
        assert_eq!(short_id_prefix(ENTITY_TYPE_CODE_ARTIFACT)?, "cd");
        let entry = entity_type_registry_entry(ENTITY_TYPE_CODE_ARTIFACT)
            .expect("CODE_ARTIFACT registry row");
        assert_eq!(entry.kind, "CODE_ARTIFACT");
        assert_eq!(entry.classification, EntityClassification::Pack);
        assert_eq!(entry.zone, TypeByteZone::CompiledProduct);
        Ok(())
    }

    #[test]
    fn code_artifact_repo_ref_stores_reference_not_inline_content() -> Result<()> {
        let body = CodeArtifactBody::new(
            "Summarize the local checkout.",
            [0xB6; CODE_ARTIFACT_SUMMARY_HASH_LEN],
            "local:/workspace/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277",
        );

        let encoded = encode_code_artifact_body(&body)?;
        let decoded = decode_code_artifact_body(&encoded)?;
        assert_eq!(decoded.repo_ref, body.repo_ref);

        let encoded_with_content = code_artifact_map(vec![
            (
                KEY_SUMMARY_PROMPT,
                Value::from(body.summary_prompt.as_str()),
            ),
            (KEY_SUMMARY_HASH, Value::Binary(body.summary_hash.to_vec())),
            (KEY_REPO_REF, Value::from(body.repo_ref.as_str())),
            (KEY_CLASS, Value::from(body.class.as_str())),
            ("content", Value::from("fn main() {}")),
        ]);
        let err = decode_code_artifact_body(&encoded_with_content)
            .expect_err("CODE artifact body must reject inline content slots");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        Ok(())
    }

    #[test]
    fn code_artifact_decode_rejects_missing_replay_keys() {
        for missing_key in [KEY_SUMMARY_PROMPT, KEY_SUMMARY_HASH, KEY_REPO_REF] {
            let entries: Vec<(&str, Value)> = CODE_ARTIFACT_BODY_KEYS
                .into_iter()
                .filter(|key| *key != missing_key)
                .map(|key| match key {
                    KEY_SUMMARY_PROMPT => (key, Value::from("prompt")),
                    KEY_SUMMARY_HASH => (
                        key,
                        Value::Binary(vec![0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN]),
                    ),
                    KEY_REPO_REF => (key, Value::from("repo")),
                    KEY_CLASS => (key, Value::from("codebase")),
                    _ => unreachable!("iterates pinned CODE artifact keys"),
                })
                .collect();
            let encoded = code_artifact_map(entries);
            let err = decode_code_artifact_body(&encoded)
                .expect_err("missing replay key must fail closed");
            assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        }
    }

    #[test]
    fn code_artifact_class_is_backward_compatible_and_validated() {
        let body = test_body().with_class(CodeArtifactClass::Artifact);
        let encoded = encode_code_artifact_body(&body).expect("encode artifact class");
        let decoded = decode_code_artifact_body(&encoded).expect("decode artifact class");
        assert_eq!(decoded.class, CodeArtifactClass::Artifact);

        let legacy = code_artifact_map(vec![
            (KEY_SUMMARY_PROMPT, Value::from("prompt")),
            (
                KEY_SUMMARY_HASH,
                Value::Binary(vec![0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN]),
            ),
            (
                KEY_REPO_REF,
                Value::from("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277"),
            ),
        ]);
        let decoded_legacy =
            decode_code_artifact_body(&legacy).expect("legacy classless body decodes");
        assert_eq!(decoded_legacy.class, CodeArtifactClass::Codebase);

        let invalid = code_artifact_map(vec![
            (KEY_SUMMARY_PROMPT, Value::from("prompt")),
            (
                KEY_SUMMARY_HASH,
                Value::Binary(vec![0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN]),
            ),
            (
                KEY_REPO_REF,
                Value::from("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277"),
            ),
            (KEY_CLASS, Value::from("website")),
        ]);
        let err = decode_code_artifact_body(&invalid)
            .expect_err("unknown CODE artifact class must fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    }

    #[test]
    fn code_artifact_repo_ref_must_follow_v1_grammar() {
        let mut body = test_body();
        body.repo_ref =
            "git:https://example.com/oneiron.git#9d561405a81ffbf29d1369cd848e0ef9fca4f277"
                .to_owned();

        let err = encode_code_artifact_body(&body)
            .expect_err("CODE artifact repo_ref must use the CODE-002 v1 grammar");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    }

    #[test]
    fn code_artifact_put_rejects_invalid_replay_key_without_writing() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
        let id = EntityId::now();
        let invalid = code_artifact_map(vec![
            (KEY_SUMMARY_PROMPT, Value::from("prompt")),
            (
                KEY_SUMMARY_HASH,
                Value::Binary(vec![0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN - 1]),
            ),
            (KEY_REPO_REF, Value::from("repo")),
        ]);

        let err = vault
            .put_entity(
                &id,
                ENTITY_TYPE_CODE_ARTIFACT,
                TimeRange { start: 10, end: 10 },
                11,
                &invalid,
            )
            .expect_err("invalid replay key must fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }
}
