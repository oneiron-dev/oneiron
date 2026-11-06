//! Repository provenance trailer grammar and exact entity-reference parsing.

use oneiron_base::error::{CodeError, Error, Result};
use oneiron_contracts::entity_id::EntityId;

pub const REPO_PROVENANCE_TRAILER_KEY: &str = "Oneiron-Claim";
pub const REPO_PROVENANCE_TRAILER_PREFIX: &str = "Oneiron-Claim:";

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

pub fn has_final_trailer_block(message: &str) -> bool {
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
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be one token",
            )));
        }
        let claim_id = EntityId::from_hex(claim_id).map_err(|_| {
            Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be a 32-hex entity id",
            ))
        })?;
        if found.replace(claim_id).is_some() {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "commit message must not contain multiple repo provenance trailers",
            )));
        }
    }
    Ok(found)
}
