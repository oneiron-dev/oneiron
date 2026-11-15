//! Moved from `crates/oneiron/src/browser_library/evidence.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_consent_state::runtime_hooks::verb::credential::VerbAskCredentialRef;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The domain a filing anchor's claim id is hashed in (FIX 10513): its
/// program and the digest of the group it covers, so one program's
/// anchor for one group is one claim however often it is refiled.
pub const WORKFLOW_FILING_DOMAIN: &[u8] = b"oneiron:browser-workflow-filing:v1";

/// The domain a solved run's evidence id is hashed in (CUA E8a, CALLS row
/// "evidence identity"): its scope, run, call, span and the durable body's
/// bytes; never its capture time. The same capture delivered again is the
/// same claim.
pub const SOLVED_RUN_DOMAIN: &[u8] = b"oneiron:browser-solved-run:v1";

/// The domain a scoped solved group's digest is hashed in (CUA E8a, CALLS
/// row "group identity").
pub const SOLVED_GROUP_DOMAIN: &[u8] = b"oneiron:browser-solved-group:v1";

/// The domain a caller's credential reference is hashed in for its scope.
pub const SOLVED_SCOPE_DOMAIN: &[u8] = b"oneiron:browser-solved-scope:v1";

/// The version of the evidence body this capture writes.
pub const SOLVED_CAPTURE_VERSION: u32 = 1;

/// Whose a solved run is, as its group's outer partition (CUA E8a): the
/// caller's actor and class, and the digest of the exact credential
/// reference it was admitted on, when it presented one a host verifies
/// again. No credential bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvedRunScope {
    pub actor: EntityId,
    pub actor_class: u8,
    pub authority: Option<[u8; 32]>,
}

impl SolvedRunScope {
    /// The scope of `actor` of `class`, admitted on `credential` when it
    /// presented one.
    ///
    /// # Errors
    ///
    /// A credential reference that does not encode.
    pub fn new(
        actor: EntityId,
        class: EdgeActorClass,
        credential: Option<&VerbAskCredentialRef>,
    ) -> Result<Self> {
        let authority = credential
            .map(|reference| {
                let bytes = serde_json::to_vec(reference)
                    .map_err(|_| Error::InvalidClaimBody("credential reference"))?;
                Ok::<_, Error>(digest(SOLVED_SCOPE_DOMAIN, &[&bytes]))
            })
            .transpose()?;
        Ok(Self {
            actor,
            actor_class: class as u8,
            authority,
        })
    }
}

/// The solved group a filing's caller files its program in (CUA E8a): the
/// caller's scope and the program's origin, read from its opening page as a
/// draft reads its span's. A filing with none covers no group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiledScope {
    pub scope: SolvedRunScope,
    pub origin: String,
}

/// BLAKE3 over `parts` in `domain`, each part length-delimited.
pub fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The claim id of `workflow`'s anchor for the group `group` digests
/// (FIX 10513), hashed in [`WORKFLOW_FILING_DOMAIN`].
///
/// # Errors
///
/// An id that does not encode (as the evidence ids').
pub fn workflow_filing_id(workflow: &EntityId, group: &[u8; 32]) -> Result<EntityId> {
    oneiron_store::code_snapshot::ids::entity_id_from_hash_material(
        WORKFLOW_FILING_DOMAIN,
        &[workflow.as_bytes(), group],
    )
}

/// Where a solved run's checks were named (CUA E8a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SolvedSource {
    /// A library run of the filed program `workflow` met its filled
    /// postcondition: its type and subgoal are the program record's.
    LibraryRun { workflow: EntityId },
    /// An agent's run of the TASK `task` ended with its done-means' browser
    /// checks met (CUA E8b): its type is the run's recorded stamp, its
    /// subgoal the done-means' question.
    TaskRun { task: EntityId },
    /// A `self.browser.library.draft` call drafted the span of an unfiled
    /// run (FIX 10508): its type is the one its caller recorded on the
    /// draft, its subgoal and checks the draft's.
    UnfiledDraft,
}
