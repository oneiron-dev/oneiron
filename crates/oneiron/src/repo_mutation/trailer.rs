//! Repository commit provenance trailers and Git notes.
//! The parse entry is `parse_repo_provenance_trailer`.
//! `types` owns `RepoCommitProvenance`; this module owns the trailer and note helpers.

use std::path::Path;

use serde::Deserialize;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;

use rmpv::Value;

use super::git::{git_output_optional, run_git, validate_commit_message, validate_git_object_hash};
use super::support::utf8_trimmed;
use super::types::{RepoCommitProvenance, RepoMutationOperation, RepoMutationRequest};
use crate::error::CodeError;

pub use crate::store::repo_provenance_trailer::REPO_PROVENANCE_TRAILER_KEY;
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

/// The key that tells an owner's engine-attributed request from the model
/// form, which has none (NO-DOOR CODE-PROPOSAL-ATTRIBUTION).
pub(crate) const REPO_PROVENANCE_SOURCE_KIND_KEY: &str = "source_kind";
/// The `source_kind` of an owner's direct proposal: no model call is
/// witnessed, so none is named (Engine CODECUSTODY-ATTRIB Q2 = A).
pub(crate) const REPO_PROVENANCE_OWNER_REQUEST: &str = "owner_request";
/// The schema version of the `owner_request` form, not a model revision.
pub(crate) const OWNER_REQUEST_VERSION: &str = "vault.code.owner_request.v1";
/// The `owner_request` form's keys, its envelope's and its lineage's: each
/// map holds exactly these.
const OWNER_REQUEST_KEYS: [&str; 6] = [
    REPO_PROVENANCE_SOURCE_KIND_KEY,
    "actor",
    "session",
    "request_hash",
    "derivation_envelope",
    "diff_lineage_receipt",
];
const OWNER_REQUEST_ENVELOPE_KEYS: [&str; 2] = ["content_hash", "version"];
const OWNER_REQUEST_LINEAGE_KEYS: [&str; 3] = ["repo", "path", "base_commit"];

pub(super) use crate::store::repo_provenance_trailer::REPO_PROVENANCE_TRAILER_PREFIX;
const REPO_PROVENANCE_GIT_AUTHOR_NAME: &str = "Oneiron";
const REPO_PROVENANCE_GIT_AUTHOR_EMAIL: &str = "oneiron@example.invalid";
const REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR: u8 = 0x00;
const REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR: u8 = 0x1e;

pub(super) fn validate_repo_provenance_request(
    vault: &Vault,
    request: &RepoMutationRequest,
) -> Result<()> {
    // A received bundle proves its retained source, never an optional
    // model provenance map, and never falls through when it names none.
    if matches!(
        request.operation,
        RepoMutationOperation::ReceivedFiles { .. }
    ) {
        return super::received_file::require_received_files_source(vault, request);
    }
    let Some(claim_id) = request.provenance_claim_id else {
        return Ok(());
    };
    match &request.operation {
        RepoMutationOperation::CommitFile { .. }
        | RepoMutationOperation::ResolveConflictFile { .. }
        | RepoMutationOperation::CommitFiles { .. } => {
            require_repo_provenance_claim(vault, &claim_id)
        }
        _ => Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "provenance claim id only applies to commit-producing repo mutations",
        ))),
    }
}

pub(super) fn validate_repo_provenance_request_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &RepoMutationRequest,
) -> Result<()> {
    if matches!(
        request.operation,
        RepoMutationOperation::ReceivedFiles { .. }
    ) {
        return super::received_file::require_received_files_source_in_txn(vault, txn, request);
    }
    let Some(id) = request.provenance_claim_id else {
        return Ok(());
    };
    if !matches!(
        request.operation,
        RepoMutationOperation::CommitFile { .. }
            | RepoMutationOperation::ResolveConflictFile { .. }
            | RepoMutationOperation::CommitFiles { .. }
    ) {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "provenance claim id only applies to commit-producing repo mutations",
        )));
    }
    require_repo_provenance_claim_in_txn(vault, txn, &id)
}

fn require_repo_provenance_claim(vault: &Vault, claim_id: &EntityId) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    require_repo_provenance_claim_in_txn(vault, &txn, claim_id)
}

fn require_repo_provenance_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, claim_id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "provenance claim id must reference a CLAIM entity",
        )));
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    validate_repo_provenance_claim_body(&body)?;
    Ok(())
}

fn validate_repo_provenance_claim_body(body: &ClaimBody) -> Result<()> {
    if body.predicate != REPO_PROVENANCE_PREDICATE {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo provenance claim must use the repo.provenance predicate",
        )));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo provenance claim must be active",
        )));
    }
    let entries = msgpack_map_entries(
        &body.value,
        "repo provenance claim value must be a PROV-AGENT map",
    )?;
    if entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(REPO_PROVENANCE_SOURCE_KIND_KEY))
    {
        return validate_owner_request_value(body, entries);
    }
    require_nonblank_msgpack_string(entries, "actor")?;
    require_nonblank_msgpack_string(entries, "model")?;
    require_nonblank_msgpack_string(entries, "prompt_hash")?;
    let envelope = require_msgpack_map(entries, "derivation_envelope")?;
    for key in REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS {
        require_nonblank_msgpack_string(envelope, key)?;
    }
    let receipt = require_msgpack_map(entries, "diff_lineage_receipt")?;
    if receipt.is_empty() {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo provenance diff_lineage_receipt must be a non-empty map",
        )));
    }
    Ok(())
}

/// The closed `owner_request` form: exactly its keys, every value in its
/// grammar, on the sitting it names. A model field is not one of its keys,
/// so it is refused.
fn validate_owner_request_value(body: &ClaimBody, entries: &[(Value, Value)]) -> Result<()> {
    require_closed_keys(entries, &OWNER_REQUEST_KEYS)?;
    if require_unique_msgpack_key(entries, REPO_PROVENANCE_SOURCE_KIND_KEY)?.as_str()
        != Some(REPO_PROVENANCE_OWNER_REQUEST)
    {
        return Err(invalid_value(
            "repo provenance source_kind must be owner_request",
        ));
    }
    require_entity_hex(entries, "actor")?;
    let session = require_entity_hex(entries, "session")?;
    if body.subject != ClaimSubject::Entity(session) {
        return Err(invalid_value(
            "an owner request's provenance claim is on the sitting it names",
        ));
    }
    require_lower_hex(entries, "request_hash", 64)?;
    let envelope = require_msgpack_map(entries, "derivation_envelope")?;
    require_closed_keys(envelope, &OWNER_REQUEST_ENVELOPE_KEYS)?;
    require_lower_hex(envelope, "content_hash", 64)?;
    if require_unique_msgpack_key(envelope, "version")?.as_str() != Some(OWNER_REQUEST_VERSION) {
        return Err(invalid_value(
            "an owner request's derivation_envelope names its schema version",
        ));
    }
    let lineage = require_msgpack_map(entries, "diff_lineage_receipt")?;
    require_closed_keys(lineage, &OWNER_REQUEST_LINEAGE_KEYS)?;
    require_entity_hex(lineage, "repo")?;
    require_nonblank_msgpack_string(lineage, "path")?;
    require_lower_hex(lineage, "base_commit", 40)?;
    Ok(())
}

/// Every key of `entries` is one of `keys`, and there are as many: with the
/// unique-key reads that follow, exactly `keys`, once each.
fn require_closed_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    if entries.len() != keys.len()
        || entries
            .iter()
            .any(|(key, _)| !key.as_str().is_some_and(|key| keys.contains(&key)))
    {
        return Err(invalid_value(
            "an owner request's provenance holds exactly its own keys",
        ));
    }
    Ok(())
}

/// `key`'s value: `len` lower-hex characters.
fn require_lower_hex(entries: &[(Value, Value)], key: &str, len: usize) -> Result<()> {
    let value = require_unique_msgpack_key(entries, key)?;
    match value.as_str() {
        Some(text) if text.len() == len && is_lower_hex(text) => Ok(()),
        _ => Err(invalid_value(
            "an owner request's provenance hash is lower-hex of its length",
        )),
    }
}

/// `key`'s value: an entity id as 32 lower-hex characters.
fn require_entity_hex(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let value = require_unique_msgpack_key(entries, key)?;
    value
        .as_str()
        .filter(|text| text.len() == 32 && is_lower_hex(text))
        .and_then(|text| EntityId::from_hex(text).ok())
        .ok_or_else(|| invalid_value("an owner request's provenance id is 32 lower-hex characters"))
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_value(reason: &'static str) -> Error {
    Error::Code(CodeError::InvalidRepoMutationRecord(reason))
}

fn msgpack_map_entries<'a>(
    value: &'a Value,
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::Code(CodeError::InvalidRepoMutationRecord(context))),
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
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo provenance field must be a string",
        )));
    };
    if value.trim().is_empty() {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo provenance field must be non-empty",
        )));
    }
    Ok(())
}

fn require_unique_msgpack_key<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut found = None;
    for (candidate, value) in entries {
        if candidate.as_str() == Some(key) && found.replace(value).is_some() {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo provenance claim value must not duplicate required keys",
            )));
        }
    }
    found.ok_or(Error::Code(CodeError::InvalidRepoMutationRecord(
        "repo provenance claim value is missing a required key",
    )))
}

use crate::store::repo_provenance_trailer::has_final_trailer_block;
pub use crate::store::repo_provenance_trailer::parse_repo_provenance_trailer;

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
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo provenance claim id maps to multiple commits",
            )));
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
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "git log provenance record missing commit separator",
        )));
    };
    let commit_sha = std::str::from_utf8(&record[..separator])
        .map_err(|_| {
            Error::Code(CodeError::InvalidRepoMutationRecord(
                "git log commit sha must be UTF-8",
            ))
        })?
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
    let note = String::from_utf8(note).map_err(|_| {
        Error::Code(CodeError::InvalidRepoMutationRecord(
            "git notes payload must be UTF-8",
        ))
    })?;
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
    let payload: RepoProvenanceGitNotePayload = serde_json::from_str(&note).map_err(|_| {
        Error::Code(CodeError::InvalidRepoMutationRecord(
            "git notes provenance payload invalid",
        ))
    })?;
    if payload.trailer != REPO_PROVENANCE_TRAILER_KEY {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "git notes provenance trailer key mismatch",
        )));
    }
    validate_git_object_hash(
        &payload.commit,
        "git notes provenance commit must be a 40-hex commit",
    )?;
    if payload.commit.to_ascii_lowercase() != commit_sha {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "git notes provenance commit mismatch",
        )));
    }
    let claim_id = EntityId::from_hex(&payload.claim_id).map_err(|_| {
        Error::Code(CodeError::InvalidRepoMutationRecord(
            "git notes provenance claim id must be 32-hex",
        ))
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
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "commit message must not predefine the repo provenance trailer",
        )));
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
