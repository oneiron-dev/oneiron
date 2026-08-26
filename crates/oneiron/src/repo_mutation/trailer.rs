use std::path::Path;

use serde::Deserialize;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;

use rmpv::Value;

use super::git::{git_output_optional, run_git, validate_commit_message, validate_git_object_hash};
use super::support::utf8_trimmed;
use super::types::{RepoCommitProvenance, RepoMutationOperation, RepoMutationRequest};

pub const REPO_PROVENANCE_TRAILER_KEY: &str = "Oneiron-Claim";
pub const REPO_PROVENANCE_NOTES_REF: &str = "refs/notes/oneiron-provenance";

pub const REPO_PROVENANCE_PREDICATE: &str = "repo.provenance";
pub const REPO_PROVENANCE_VALUE_KEYS: [&str; 5] = [
    "actor",
    "model",
    "prompt_hash",
    "derivation_envelope",
    "diff_lineage_receipt",
];
pub const REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS: [&str; 4] =
    ["content_hash", "model_id", "version", "params_hash"];

pub(super) const REPO_PROVENANCE_TRAILER_PREFIX: &str = "Oneiron-Claim:";
const REPO_PROVENANCE_GIT_AUTHOR_NAME: &str = "Oneiron";
const REPO_PROVENANCE_GIT_AUTHOR_EMAIL: &str = "oneiron@example.invalid";
const REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR: u8 = 0x00;
const REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR: u8 = 0x1e;

pub(super) fn validate_repo_provenance_request(
    vault: &Vault,
    request: &RepoMutationRequest,
) -> Result<()> {
    let Some(claim_id) = request.provenance_claim_id else {
        return Ok(());
    };
    match &request.operation {
        RepoMutationOperation::CommitFile { .. }
        | RepoMutationOperation::ResolveConflictFile { .. } => {
            require_repo_provenance_claim(vault, &claim_id)
        }
        _ => Err(Error::InvalidRepoMutationRecord(
            "provenance claim id only applies to commit-producing repo mutations",
        )),
    }
}

fn require_repo_provenance_claim(vault: &Vault, claim_id: &EntityId) -> Result<()> {
    let raw = vault.get_raw(claim_id)?.ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidRepoMutationRecord(
            "provenance claim id must reference a CLAIM entity",
        ));
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    validate_repo_provenance_claim_body(&body)?;
    Ok(())
}

fn validate_repo_provenance_claim_body(body: &ClaimBody) -> Result<()> {
    if body.predicate != REPO_PROVENANCE_PREDICATE {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance claim must use the repo.provenance predicate",
        ));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance claim must be active",
        ));
    }
    let entries = msgpack_map_entries(
        &body.value,
        "repo provenance claim value must be a PROV-AGENT map",
    )?;
    require_nonblank_msgpack_string(entries, "actor")?;
    require_nonblank_msgpack_string(entries, "model")?;
    require_nonblank_msgpack_string(entries, "prompt_hash")?;
    let envelope = require_msgpack_map(entries, "derivation_envelope")?;
    for key in REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS {
        require_nonblank_msgpack_string(envelope, key)?;
    }
    let receipt = require_msgpack_map(entries, "diff_lineage_receipt")?;
    if receipt.is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance diff_lineage_receipt must be a non-empty map",
        ));
    }
    Ok(())
}

fn msgpack_map_entries<'a>(
    value: &'a Value,
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::InvalidRepoMutationRecord(context)),
    }
}

fn require_msgpack_map<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<&'a [(Value, Value)]> {
    let value = require_unique_msgpack_key(entries, key)?;
    msgpack_map_entries(value, "repo provenance nested field must be a map")
}

fn require_nonblank_msgpack_string(entries: &[(Value, Value)], key: &str) -> Result<()> {
    let value = require_unique_msgpack_key(entries, key)?;
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance field must be a string",
        ));
    };
    if value.trim().is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance field must be non-empty",
        ));
    }
    Ok(())
}

fn require_unique_msgpack_key<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut found = None;
    for (candidate, value) in entries {
        if candidate.as_str() == Some(key) && found.replace(value).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance claim value must not duplicate required keys",
            ));
        }
    }
    found.ok_or(Error::InvalidRepoMutationRecord(
        "repo provenance claim value is missing a required key",
    ))
}

fn final_trailer_block(message: &str) -> Option<Vec<&str>> {
    let trimmed = message.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return None;
    }
    let lines = trimmed.lines().collect::<Vec<_>>();
    let mut start = lines.len();
    while start > 0 && !lines[start - 1].trim().is_empty() {
        start -= 1;
    }
    if start == 0 {
        return None;
    }
    let block = lines[start..].to_vec();
    if block.is_empty() || !block.iter().all(|line| is_git_trailer_line(line)) {
        return None;
    }
    Some(block)
}

fn has_final_trailer_block(message: &str) -> bool {
    final_trailer_block(message).is_some()
}

fn is_git_trailer_line(line: &str) -> bool {
    let Some((key, value)) = line.split_once(':') else {
        return false;
    };
    !key.is_empty()
        && !value.trim().is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub fn parse_repo_provenance_trailer(message: &str) -> Result<Option<EntityId>> {
    let mut found = None;
    let Some(block) = final_trailer_block(message) else {
        return Ok(None);
    };
    for line in block {
        let Some(raw_claim_id) = line.strip_prefix(REPO_PROVENANCE_TRAILER_PREFIX) else {
            continue;
        };
        let claim_id = raw_claim_id.trim();
        if claim_id.is_empty() || claim_id.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be one token",
            ));
        }
        let claim_id = EntityId::from_hex(claim_id).map_err(|_| {
            Error::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be a 32-hex entity id",
            )
        })?;
        if found.replace(claim_id).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "commit message must not contain multiple repo provenance trailers",
            ));
        }
    }
    Ok(found)
}

pub fn repo_commit_provenance(
    repo_root: &Path,
    commit_sha: &str,
) -> Result<Option<RepoCommitProvenance>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let message_bytes = run_git(
        repo_root,
        &[
            "show".to_owned(),
            "-s".to_owned(),
            "--format=%B".to_owned(),
            commit_sha.clone(),
        ],
    )?;
    let message = String::from_utf8_lossy(&message_bytes);
    Ok(
        parse_repo_provenance_trailer(&message)?.map(|claim_id| RepoCommitProvenance {
            commit_sha,
            claim_id,
        }),
    )
}

pub fn repo_commit_for_provenance_claim(
    repo_root: &Path,
    claim_id: &EntityId,
) -> Result<Option<String>> {
    let trailer = format!("{REPO_PROVENANCE_TRAILER_KEY}: {}", claim_id.to_hex());
    let output = run_git(
        repo_root,
        &[
            "log".to_owned(),
            "--branches".to_owned(),
            "--tags".to_owned(),
            "--remotes".to_owned(),
            "--fixed-strings".to_owned(),
            "--grep".to_owned(),
            trailer,
            format!(
                "--format=%H%x{REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR:02x}%B%x{REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR:02x}"
            ),
        ],
    )?;
    let mut found = None;
    for record in output.split(|byte| *byte == REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR) {
        let record = trim_git_log_record_prefix(record);
        if record.is_empty() {
            continue;
        }
        let Some(commit_sha) = repo_commit_for_provenance_claim_record(record, claim_id)? else {
            continue;
        };
        if found.replace(commit_sha).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance claim id maps to multiple commits",
            ));
        }
    }
    Ok(found)
}

fn trim_git_log_record_prefix(mut record: &[u8]) -> &[u8] {
    while matches!(record.first(), Some(b'\r' | b'\n')) {
        record = &record[1..];
    }
    record
}

fn repo_commit_for_provenance_claim_record(
    record: &[u8],
    claim_id: &EntityId,
) -> Result<Option<String>> {
    let Some(separator) = record
        .iter()
        .position(|byte| *byte == REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR)
    else {
        return Err(Error::InvalidRepoMutationRecord(
            "git log provenance record missing commit separator",
        ));
    };
    let commit_sha = std::str::from_utf8(&record[..separator])
        .map_err(|_| Error::InvalidRepoMutationRecord("git log commit sha must be UTF-8"))?
        .trim();
    validate_git_object_hash(commit_sha, "git log commit sha must be a 40-hex commit")?;
    let message = String::from_utf8_lossy(&record[separator + 1..]);
    let Some(recorded_claim_id) = parse_repo_provenance_trailer(&message)? else {
        return Ok(None);
    };
    if recorded_claim_id == *claim_id {
        return Ok(Some(commit_sha.to_ascii_lowercase()));
    }
    Ok(None)
}

pub fn export_repo_provenance_git_note(
    repo_root: &Path,
    commit_sha: &str,
    claim_id: &EntityId,
) -> Result<()> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let note = repo_provenance_git_note_payload(&commit_sha, claim_id);
    run_git(
        repo_root,
        &[
            "-c".to_owned(),
            format!("user.name={REPO_PROVENANCE_GIT_AUTHOR_NAME}"),
            "-c".to_owned(),
            format!("user.email={REPO_PROVENANCE_GIT_AUTHOR_EMAIL}"),
            "notes".to_owned(),
            "--ref".to_owned(),
            REPO_PROVENANCE_NOTES_REF.to_owned(),
            "add".to_owned(),
            "-f".to_owned(),
            "-m".to_owned(),
            note,
            commit_sha,
        ],
    )?;
    Ok(())
}

pub fn repo_provenance_git_note(repo_root: &Path, commit_sha: &str) -> Result<Option<String>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let Some(note) = git_output_optional(
        repo_root,
        &[
            "notes".to_owned(),
            "--ref".to_owned(),
            REPO_PROVENANCE_NOTES_REF.to_owned(),
            "show".to_owned(),
            commit_sha,
        ],
    )?
    else {
        return Ok(None);
    };
    let note = String::from_utf8(note)
        .map_err(|_| Error::InvalidRepoMutationRecord("git notes payload must be UTF-8"))?;
    Ok(Some(note.trim_end_matches(['\r', '\n']).to_owned()))
}

pub fn repo_commit_provenance_from_git_note(
    repo_root: &Path,
    commit_sha: &str,
) -> Result<Option<RepoCommitProvenance>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let Some(note) = repo_provenance_git_note(repo_root, &commit_sha)? else {
        return Ok(None);
    };
    let payload: RepoProvenanceGitNotePayload = serde_json::from_str(&note)
        .map_err(|_| Error::InvalidRepoMutationRecord("git notes provenance payload invalid"))?;
    if payload.trailer != REPO_PROVENANCE_TRAILER_KEY {
        return Err(Error::InvalidRepoMutationRecord(
            "git notes provenance trailer key mismatch",
        ));
    }
    validate_git_object_hash(
        &payload.commit,
        "git notes provenance commit must be a 40-hex commit",
    )?;
    if payload.commit.to_ascii_lowercase() != commit_sha {
        return Err(Error::InvalidRepoMutationRecord(
            "git notes provenance commit mismatch",
        ));
    }
    let claim_id = EntityId::from_hex(&payload.claim_id).map_err(|_| {
        Error::InvalidRepoMutationRecord("git notes provenance claim id must be 32-hex")
    })?;
    Ok(Some(RepoCommitProvenance {
        commit_sha,
        claim_id,
    }))
}

pub(super) fn commit_message_with_provenance_trailer(
    message: &str,
    claim_id: Option<EntityId>,
) -> Result<String> {
    validate_commit_message(message)?;
    let Some(claim_id) = claim_id else {
        return Ok(message.to_owned());
    };
    if parse_repo_provenance_trailer(message)?.is_some() {
        return Err(Error::InvalidRepoMutationRecord(
            "commit message must not predefine the repo provenance trailer",
        ));
    }
    let message = message.trim_end_matches(['\r', '\n']);
    let separator = if has_final_trailer_block(message) {
        "\n"
    } else {
        "\n\n"
    };
    let message = format!(
        "{message}{separator}{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
        claim_id.to_hex()
    );
    validate_commit_message(&message)?;
    Ok(message)
}

#[derive(Deserialize)]
struct RepoProvenanceGitNotePayload {
    commit: String,
    claim_id: String,
    trailer: String,
}

fn repo_provenance_git_note_payload(commit_sha: &str, claim_id: &EntityId) -> String {
    format!(
        "{{\"commit\":\"{commit_sha}\",\"claim_id\":\"{}\",\"trailer\":\"{REPO_PROVENANCE_TRAILER_KEY}\"}}",
        claim_id.to_hex()
    )
}

fn canonical_commit_sha(repo_root: &Path, commit_sha: &str) -> Result<String> {
    validate_git_object_hash(commit_sha, "commit sha must be a 40-hex commit")?;
    let commit_sha = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                format!("{commit_sha}^{{commit}}"),
            ],
        )?,
        "git commit sha must be UTF-8",
    )?;
    validate_git_object_hash(&commit_sha, "resolved commit sha must be a 40-hex commit")?;
    Ok(commit_sha.to_ascii_lowercase())
}
