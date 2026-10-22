//! Solved-run evidence (CUA E8a; DESIGN-2 "The Coach", row E8): a browser
//! run's span whose checks met on the page it reached, kept as ONE
//! caller-scoped `browser.solved_run` claim whose body is the
//! [`SolvedRunEvidence`]. Side rows hold only its refs, digests and
//! counters (the index); none holds the body again.
//!
//! The caller's own door writes it (`Memory::capture_browser_solved_run`):
//! the claim under the caller's envelope, its group ref, its group's dirty
//! generation and its source authority's reference, in one write. A source
//! with no recorded task type, or whose checks were not read on the page,
//! captures nothing: no group is made up for it.
//!
//! A group is exact ([`ScopedSolvedGroupKey`]): the caller's scope, then the
//! site, the origin, the recorded task type and the subgoal's exact bytes.
//! Its digest is length-delimited over each part, never a joined string.

use oneiron_browser::{DraftOutput, ExpectInput, SecretParam};
use serde::{Deserialize, Serialize};

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::VerbAskCredentialRef;

/// The predicate of a solved run's evidence claim (CUA E8a).
pub const SOLVED_RUN_PREDICATE: &str = "browser.solved_run";

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

/// The domain a candidate program's input fingerprint is hashed in (CUA E8,
/// CALLS row "candidate dedup"), for the Coach's seen marker.
pub const CANDIDATE_DOMAIN: &[u8] = b"oneiron:browser-program-induction:v1";

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

/// A solved group's semantic key (CUA E8a): exact site, origin, recorded
/// task type and subgoal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvedGroupKey {
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
}

/// A solved group within its caller's scope (CUA E8a): runs group only
/// with runs of the same scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedSolvedGroupKey {
    pub scope: SolvedRunScope,
    pub group: SolvedGroupKey,
}

impl ScopedSolvedGroupKey {
    /// The group's digest: every part length-delimited, in
    /// [`SOLVED_GROUP_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let scope = &self.scope;
        let group = &self.group;
        let authority = scope.authority.unwrap_or_default();
        let held = [u8::from(scope.authority.is_some())];
        digest(
            SOLVED_GROUP_DOMAIN,
            &[
                scope.actor.as_bytes(),
                &[scope.actor_class],
                &held,
                &authority,
                group.site.as_bytes(),
                group.origin.as_bytes(),
                group.type_ref.node_id.as_bytes(),
                &group.type_ref.tree_version.to_be_bytes(),
                group.subgoal.as_bytes(),
            ],
        )
    }
}

/// BLAKE3 over `parts` in `domain`, each part length-delimited.
pub(super) fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Where a solved run's checks were named (CUA E8a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SolvedSource {
    /// A library run of the filed program `workflow` met its filled
    /// postcondition: its type and subgoal are the program record's.
    LibraryRun { workflow: EntityId },
}

/// What a source door captured, before its caller's door scopes it.
#[derive(Debug, Clone)]
pub struct SolvedRunCapture {
    pub run_id: EntityId,
    /// The logical verb call it was captured at, when its door had one.
    pub call_id: Option<InvocationId>,
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
    /// The checks as a program keeps them, every one met on the page.
    pub checks: Vec<ExpectInput>,
    /// The span's durable draft: no secret slot's argument, no handle.
    pub draft: DraftOutput,
    /// The secret slots the draft names, by name and kind.
    pub secret_slots: Vec<SecretParam>,
    /// Whether the draft replays as it is; a solved page whose secrets need
    /// binding again is still solved, but not replay-ready.
    pub replay_ready: bool,
    pub source: SolvedSource,
    pub captured_at_ms: u64,
}

/// One solved run's evidence: the body of its `browser.solved_run` claim
/// (CUA E8a).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolvedRunEvidence {
    pub id: EntityId,
    pub run_id: EntityId,
    pub call_id: Option<InvocationId>,
    pub scope: SolvedRunScope,
    pub site: String,
    pub origin: String,
    pub type_ref: TypeRef,
    pub subgoal: String,
    pub checks: Vec<ExpectInput>,
    pub draft: DraftOutput,
    pub secret_slots: Vec<SecretParam>,
    pub replay_ready: bool,
    pub source: SolvedSource,
    pub version: u32,
    pub captured_at_ms: u64,
}

impl SolvedRunEvidence {
    /// `capture` within `scope`, its id hashed in [`SOLVED_RUN_DOMAIN`].
    ///
    /// # Errors
    ///
    /// A body that does not encode.
    pub fn new(scope: SolvedRunScope, capture: SolvedRunCapture) -> Result<Self> {
        let body = serde_json::to_vec(&(
            &capture.checks,
            &capture.draft,
            &capture.secret_slots,
            &capture.source,
        ))
        .map_err(|_| Error::InvalidClaimBody("solved run evidence"))?;
        let call = capture.call_id.map(|call| call.0).unwrap_or_default();
        let group = ScopedSolvedGroupKey {
            scope: scope.clone(),
            group: SolvedGroupKey {
                site: capture.site.clone(),
                origin: capture.origin.clone(),
                type_ref: capture.type_ref.clone(),
                subgoal: capture.subgoal.clone(),
            },
        }
        .digest();
        let id = crate::codebase::entity_id_from_hash_material(
            SOLVED_RUN_DOMAIN,
            &[
                &group,
                capture.run_id.as_bytes(),
                &[u8::from(capture.call_id.is_some())],
                &call,
                &capture.draft.after_seq.to_be_bytes(),
                &capture.draft.through_seq.to_be_bytes(),
                &body,
            ],
        )?;
        Ok(Self {
            id,
            run_id: capture.run_id,
            call_id: capture.call_id,
            scope,
            site: capture.site,
            origin: capture.origin,
            type_ref: capture.type_ref,
            subgoal: capture.subgoal,
            checks: capture.checks,
            draft: capture.draft,
            secret_slots: capture.secret_slots,
            replay_ready: capture.replay_ready,
            source: capture.source,
            version: SOLVED_CAPTURE_VERSION,
            captured_at_ms: capture.captured_at_ms,
        })
    }

    /// The scoped group this run is evidence in.
    #[must_use]
    pub fn group(&self) -> ScopedSolvedGroupKey {
        ScopedSolvedGroupKey {
            scope: self.scope.clone(),
            group: SolvedGroupKey {
                site: self.site.clone(),
                origin: self.origin.clone(),
                type_ref: self.type_ref.clone(),
                subgoal: self.subgoal.clone(),
            },
        }
    }
}

/// The source authority a solved run was captured under (CUA E8a), kept
/// beside its evidence and never in it: no credential, token or key bytes.
/// The credential reference names the exact instrument and door; the
/// witness digest is BLAKE3 of the signed binding the request was admitted
/// on. A later use resolves the live credential from them and revalidates
/// it then; this row is no authority of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedBrowserCaller {
    pub scope: SolvedRunScope,
    /// The digest of the evidence's scoped group.
    pub group: [u8; 32],
    pub run_id: EntityId,
    pub call_id: Option<InvocationId>,
    pub credential: Option<VerbAskCredentialRef>,
    pub witness_digest: Option<[u8; 32]>,
}

/// What a capture came to (CUA E8a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolvedCaptureReceipt {
    /// The evidence claim `id` stands in `group`; `fresh` is false when the
    /// same capture had landed before, which moves no generation.
    Captured {
        id: EntityId,
        group: [u8; 32],
        fresh: bool,
    },
    /// Nothing was captured, for this cause.
    Unavailable(SolvedCaptureGap),
}

/// Why a capture kept nothing (CUA E8a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolvedCaptureGap {
    /// The caller's call is off the record: its session's writer keeps its
    /// lifecycle, and the base vault keeps no evidence of it.
    OffRecord,
}
