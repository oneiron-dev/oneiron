#[cfg(test)]
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::temporal::TimeRange;

pub(crate) use crate::store::code_artifact_body::validate_code_artifact_body_bytes;
pub use crate::store::code_artifact_body::{
    CODE_ARTIFACT_BODY_KEYS, CODE_ARTIFACT_REPO_REF_MAX_BYTES, CODE_ARTIFACT_SUMMARY_HASH_LEN,
    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES, CodeArtifactBody, CodeArtifactClass,
    decode_code_artifact_body, encode_code_artifact_body,
};
#[cfg(test)]
use crate::store::code_artifact_body::{
    KEY_CLASS, KEY_REPO_REF, KEY_SUMMARY_HASH, KEY_SUMMARY_PROMPT,
};

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
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "entity is not a type-83 CODE_ARTIFACT",
            )));
        }
        decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
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
