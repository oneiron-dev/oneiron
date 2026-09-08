//! Receive-pack wire types and the admission/outcome evidence claims: producer
//! receipts plus the source/attribution validation `publication.rs` calls.

use std::path::{Path, PathBuf};

use super::door::{DoorAdmissionStamp, DoorSeam};
use super::door_window::DoorWindowReport;
use super::landing::ReceivePackAttribution;
use super::landing_lfs::{admit_landing_lfs_pointers, ref_required_lfs_oids};
use super::paths::{now_secs, serve_failed};
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
use crate::codebase::RepoRef;
use crate::credential_door::DOOR_RECEIVE_PACK_EFFECTOR;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire};
use crate::origin::lfs::{LfsOid, LfsPushedPointer, lfs_repo_id};
use crate::origin::publication::OriginPublicationRequest;
use crate::temporal::TimeRange;
use rmpv::Value;

/// A ref and the value the origin observed for it. The oid is the canonical
/// [`GitOid`]; this module mints no origin-local object identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRef {
    /// The full `refs/...` name.
    pub name: String,
    /// The observed value, absent when the ref does not exist.
    pub oid: Option<GitOid>,
}

/// One ref move a push proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The full `refs/...` name.
    pub name: String,
    /// The value the push was decided against; absent for a creation.
    pub old_oid: Option<GitOid>,
    /// The value the ref moves to; absent for a deletion.
    pub new_oid: Option<GitOid>,
}

impl RefUpdate {
    pub(super) fn publication(&self) -> Result<GitRefPublication> {
        let name = GitRefName::parse_full(self.name.clone())?;
        let expected = match &self.old_oid {
            Some(oid) => GitRefExpectation::Value(oid.clone()),
            None => GitRefExpectation::Absent,
        };
        Ok(match &self.new_oid {
            Some(next) => GitRefPublication::update(name, expected, next.clone()),
            None => GitRefPublication::delete(name, expected),
        })
    }
}

/// What one push moved, counted rather than buffered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PackStats {
    /// Request bytes streamed into the backend.
    pub request_bytes: u64,
    /// Response bytes streamed back out.
    pub response_bytes: u64,
    /// How many ref updates this outcome carries.
    pub ref_update_count: usize,
}

/// What the subprocess left behind for the single-writer landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivePackOutcome {
    /// The served repository directory.
    pub repo_root: PathBuf,
    /// The ref moves the push proposed, as the door window saw them.
    pub ref_updates: Vec<RefUpdate>,
    /// The Git-LFS pointers this push newly introduced, as the door window
    /// framed them. Empty for every push that introduced none, which is every
    /// push that does not use LFS.
    pub lfs_pointers: Vec<LfsPushedPointer>,
    /// Where the objects live after the quarantine migrated.
    pub staged_objects_dir: PathBuf,
    /// Byte and ref counters for the request.
    pub pack_stats: PackStats,
}

impl ReceivePackOutcome {
    /// The repo_ref this landing publishes against, pinned to a commit this
    /// object store carries.
    ///
    /// The pin cannot be chosen before the push: a repository receiving its
    /// first push holds no commit at all, and [`GitWire::open_repo`] proves the
    /// pin is present in the object store before it hands out a handle. Which
    /// commit is chosen is `landing_pin`'s rule, and a delete-only push has one
    /// because a deletion unlinks a name rather than removing an object.
    pub fn pinned_repo_ref(&self) -> Result<RepoRef> {
        let commit = landing_pin(&self.ref_updates)
            .ok_or_else(|| serve_failed("receive-pack outcome moved no ref"))?;
        local_repo_ref(&self.repo_root, commit)
    }
}

/// The commit a receive-pack landing pins its repo_ref to.
///
/// The pin's whole job is to name WHICH object store this landing publishes
/// into — [`GitWire::open_repo`] proves the pinned commit is present there
/// before it hands out a handle. It is never a statement about what the push
/// did; the publications carry that.
///
/// So the post-image comes first: an advancing push pins something it just made
/// durable. A push that only DELETES refs advances no post-image at all, and
/// reading the pin out of `new_oid` alone is what silently dropped delete-only
/// pushes on the floor — no pin, no handle, no landing, and a mutated
/// repository with no receipt. The pre-image the deletion was decided against
/// is still in that store (deleting a ref unlinks a name; it does not remove an
/// object, and the repository coordinator is held across this whole window), so
/// it names the same store just as well.
pub(super) fn landing_pin(updates: &[RefUpdate]) -> Option<&GitOid> {
    updates
        .iter()
        .find_map(|update| update.new_oid.as_ref())
        .or_else(|| updates.iter().find_map(|update| update.old_oid.as_ref()))
}

pub(super) fn local_repo_ref(repo_root: &Path, commit: &GitOid) -> Result<RepoRef> {
    let path = path_arg(repo_root)?;
    RepoRef::parse(&format!("local:{path}#{}", commit.as_str()))
}

// These claims describe transport admission and observation, NOT publication
// or a credential evaluation that Phase A never performed. The local receipt
// is atomic with the generic claim write and is not sync/export authority:
// copied or caller-written claim bodies alone cannot impersonate this observer.
pub(in crate::origin) const RECEIVE_PACK_ADMISSION_PREDICATE: &str = "repo.receive_pack_admission";

pub(in crate::origin) const RECEIVE_PACK_OUTCOME_PREDICATE: &str = "repo.receive_pack_outcome";

const RECEIVE_PACK_EVIDENCE_PREFIX: &[u8] = b"origin:receive_pack_evidence:v1:";

fn receive_pack_evidence_key(id: EntityId) -> Vec<u8> {
    let mut key = RECEIVE_PACK_EVIDENCE_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn receive_pack_fields(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

pub(super) fn receive_pack_field<'a>(body: &'a ClaimBody, key: &str) -> Result<&'a Value> {
    body.value
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .map(|(_, value)| value)
        })
        .ok_or_else(|| receive_pack_provenance_refused("missing evidence field"))
}

pub(super) fn receive_pack_provenance_refused(reason: &str) -> Error {
    Error::ReceivePackLandingRefused {
        reason: format!("receive-pack provenance: {reason}"),
    }
}

fn receive_pack_updates_value(updates: &[RefUpdate]) -> Value {
    Value::Array(
        updates
            .iter()
            .map(|update| {
                Value::Array(vec![
                    Value::from(update.name.clone()),
                    update
                        .old_oid
                        .as_ref()
                        .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
                    update
                        .new_oid
                        .as_ref()
                        .map_or(Value::Nil, |oid| Value::from(oid.as_str())),
                ])
            })
            .collect(),
    )
}

fn receive_pack_lfs_value(pointers: &[LfsPushedPointer]) -> Value {
    Value::Array(
        pointers
            .iter()
            .map(|pointer| {
                Value::Array(vec![
                    Value::from(pointer.path.clone()),
                    Value::from(pointer.oid.to_hex()),
                    Value::from(pointer.size_bytes),
                ])
            })
            .collect(),
    )
}

pub(super) fn receive_pack_stats_value(stats: PackStats) -> Value {
    Value::Array(vec![
        Value::from(stats.request_bytes),
        Value::from(stats.response_bytes),
        Value::from(stats.ref_update_count as u64),
    ])
}

fn receive_pack_claim(subject: ClaimSubject, predicate: &str, value: Value) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        subject,
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    // Only public repository operation metadata, as in repo.publication. No
    // bearer, credential bytes, blob contents, or scanner matches are retained.
    body.scope = Some(receive_pack_fields(vec![(
        "sensitivity",
        Value::from("public"),
    )]));
    body
}

impl Vault {
    fn put_receive_pack_evidence(&self, id: EntityId, body: &ClaimBody, at: u64) -> Result<()> {
        let encoded = encode_claim_body(body)?;
        let key = receive_pack_evidence_key(id);
        self.with_write_txn(|wtxn| {
            if self.store.entities.get(wtxn, id.as_bytes())?.is_some()
                || self.store.vault_meta.get(wtxn, &key)?.is_some()
            {
                return Err(receive_pack_provenance_refused(
                    "evidence id already exists",
                ));
            }
            self.put_claim_in_txn(wtxn, &id, body, TimeRange { start: at, end: at }, at)?;
            self.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })
    }

    pub(super) fn receive_pack_evidence_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: EntityId,
        predicate: &str,
    ) -> Result<ClaimBody> {
        let body = self
            .get_claim_in_txn(rtxn, &id)?
            .ok_or_else(|| receive_pack_provenance_refused("claim is absent"))?;
        let key = receive_pack_evidence_key(id);
        let receipt =
            self.store.vault_meta.get(rtxn, &key)?.ok_or_else(|| {
                receive_pack_provenance_refused("not a locally observed operation")
            })?;
        let receipt: &[u8] = receipt.as_ref();
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || receipt != encode_claim_body(&body)?.as_slice()
        {
            return Err(receive_pack_provenance_refused(
                "claim does not match its producer receipt",
            ));
        }
        Ok(body)
    }

    pub(super) fn record_receive_pack_admission(
        &self,
        repo_dir: &Path,
        stamp: &DoorAdmissionStamp,
        seam: DoorSeam,
    ) -> Result<()> {
        // Preserve the explicit no-op transport seam, but never describe it
        // as landed policy or scanning evidence. The authenticated server pins
        // Landed; the seam is not selected by any request field or claim id.
        let (door_seam, effector_check) = match seam {
            DoorSeam::Landed => ("landed", "admitted"),
            DoorSeam::Noop => ("noop", "not_performed"),
        };
        let actor = EntityId::from_hex(stamp.principal_ref())
            .map_err(|_| receive_pack_provenance_refused("principal is not an entity id"))?;
        let body = receive_pack_claim(
            ClaimSubject::Edge {
                source: stamp.operation_id,
                kind: EdgeKind::PartOf,
                target: actor,
            },
            RECEIVE_PACK_ADMISSION_PREDICATE,
            receive_pack_fields(vec![
                ("schema_version", Value::from(1)),
                ("operation_id", Value::from(stamp.operation_id.to_hex())),
                ("actor_id", Value::from(actor.to_hex())),
                (
                    "repo_root",
                    Value::from(path_arg(&repo_dir.canonicalize()?)?),
                ),
                ("operation", Value::from("git-receive-pack")),
                ("method", Value::from(stamp.method())),
                (
                    "credential_presented",
                    Value::from(stamp.credential_fingerprint().is_some()),
                ),
                ("door_seam", Value::from(door_seam)),
                ("effector", Value::from(DOOR_RECEIVE_PACK_EFFECTOR)),
                ("effector_check", Value::from(effector_check)),
                ("admitted_at", Value::from(stamp.admitted_at())),
            ]),
        );
        self.put_receive_pack_evidence(stamp.operation_id, &body, stamp.admitted_at())
    }

    // Only finish_serve calls this production producer, after the single
    // backend has exited, the door window admitted the intent and live refs
    // narrowed it to observed results under the repository lock. An explicit
    // Noop transport never claims the landed scanner ran.
    #[cfg(test)]
    pub(super) fn record_receive_pack_outcome(
        &self,
        stamp: &DoorAdmissionStamp,
        door: &DoorWindowReport,
        outcome: &ReceivePackOutcome,
        status: u16,
    ) -> Result<ReceivePackAttribution> {
        self.record_receive_pack_outcome_at(stamp, door, outcome, status, EntityId::now())
    }

    pub(super) fn record_receive_pack_outcome_at(
        &self,
        stamp: &DoorAdmissionStamp,
        door: &DoorWindowReport,
        outcome: &ReceivePackOutcome,
        status: u16,
        id: EntityId,
    ) -> Result<ReceivePackAttribution> {
        let attribution = ReceivePackAttribution {
            actor_id: EntityId::from_hex(stamp.principal_ref())
                .map_err(|_| receive_pack_provenance_refused("invalid actor"))?,
            provenance_claim_id: id,
        };
        if self.has_receive_pack_evidence(id)? {
            let wire = GitWire::new(self)?;
            let repo = wire.open_repo(outcome.pinned_repo_ref()?, &outcome.repo_root)?;
            self.validate_receive_pack_attribution(
                lfs_repo_id(&repo.identity().as_hex())?,
                outcome,
                &attribution,
            )?;
            return Ok(attribution);
        }
        if !door.admitted()
            || outcome.lfs_pointers != door.lfs_pointers
            || !outcome
                .ref_updates
                .iter()
                .all(|update| door.ref_updates.contains(update))
        {
            return Err(receive_pack_provenance_refused(
                "scan did not admit this intent",
            ));
        }
        let wire = GitWire::new(self)?;
        let repo = wire.open_repo(outcome.pinned_repo_ref()?, &outcome.repo_root)?;
        let repo_id = lfs_repo_id(&repo.identity().as_hex())?;
        let actor = EntityId::from_hex(stamp.principal_ref())
            .map_err(|_| receive_pack_provenance_refused("principal is not an entity id"))?;
        let admission = {
            let rtxn = self.store.env.read_txn()?;
            self.receive_pack_evidence_in_txn(
                &rtxn,
                stamp.operation_id,
                RECEIVE_PACK_ADMISSION_PREDICATE,
            )?
        };
        let scan = match receive_pack_field(&admission, "door_seam")?.as_str() {
            Some("landed") => "clean",
            Some("noop") => "not_performed",
            _ => {
                return Err(receive_pack_provenance_refused(
                    "unknown admitted door seam",
                ));
            }
        };
        let body = receive_pack_claim(
            ClaimSubject::Edge {
                source: actor,
                kind: EdgeKind::PartOf,
                target: repo_id,
            },
            RECEIVE_PACK_OUTCOME_PREDICATE,
            receive_pack_fields(vec![
                ("schema_version", Value::from(1)),
                ("operation_id", Value::from(stamp.operation_id.to_hex())),
                ("actor_id", Value::from(actor.to_hex())),
                ("repo_id", Value::from(repo_id.to_hex())),
                (
                    "repo_root",
                    Value::from(path_arg(&outcome.repo_root.canonicalize()?)?),
                ),
                ("operation", Value::from("git-receive-pack")),
                (
                    "intent_updates",
                    receive_pack_updates_value(&door.ref_updates),
                ),
                (
                    "realized_updates",
                    receive_pack_updates_value(&outcome.ref_updates),
                ),
                (
                    "lfs_pointers",
                    receive_pack_lfs_value(&outcome.lfs_pointers),
                ),
                ("pack_stats", receive_pack_stats_value(outcome.pack_stats)),
                (
                    "staged_objects_dir",
                    Value::from(path_arg(&outcome.staged_objects_dir)?),
                ),
                ("scan", Value::from(scan)),
                (
                    "backend_exited_successfully",
                    if status == 0 {
                        Value::Nil
                    } else {
                        Value::from(true)
                    },
                ),
                (
                    "http_status",
                    if status == 0 {
                        Value::Nil
                    } else {
                        Value::from(status)
                    },
                ),
                ("observed_at", Value::from(now_secs())),
            ]),
        );
        self.put_receive_pack_evidence(id, &body, now_secs())?;
        let attribution = ReceivePackAttribution {
            actor_id: actor,
            provenance_claim_id: id,
        };
        if scan == "clean" {
            self.validate_receive_pack_attribution(repo_id, outcome, &attribution)?;
        }
        Ok(attribution)
    }

    fn receive_pack_source(
        &self,
        repo_id: EntityId,
        repo_root: &Path,
        attribution: &ReceivePackAttribution,
    ) -> Result<ClaimBody> {
        let rtxn = self.store.env.read_txn()?;
        let body = self.receive_pack_evidence_in_txn(
            &rtxn,
            attribution.provenance_claim_id,
            RECEIVE_PACK_OUTCOME_PREDICATE,
        )?;
        let operation = receive_pack_field(&body, "operation_id")?
            .as_str()
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or_else(|| receive_pack_provenance_refused("invalid operation identity"))?;
        let admission =
            self.receive_pack_evidence_in_txn(&rtxn, operation, RECEIVE_PACK_ADMISSION_PREDICATE)?;
        let actor = attribution.actor_id;
        let root = Value::from(path_arg(&repo_root.canonicalize()?)?);
        let observation_matches_seam = matches!(
            (
                receive_pack_field(&admission, "door_seam")?.as_str(),
                receive_pack_field(&admission, "effector_check")?.as_str(),
                receive_pack_field(&body, "scan")?.as_str()
            ),
            (Some("landed"), Some("admitted"), Some("clean"))
        );
        if body.subject
            != (ClaimSubject::Edge {
                source: actor,
                kind: EdgeKind::PartOf,
                target: repo_id,
            })
            || admission.subject
                != (ClaimSubject::Edge {
                    source: operation,
                    kind: EdgeKind::PartOf,
                    target: actor,
                })
            || receive_pack_field(&body, "repo_id")? != &Value::from(repo_id.to_hex())
            || receive_pack_field(&body, "actor_id")? != &Value::from(actor.to_hex())
            || receive_pack_field(&admission, "actor_id")? != &Value::from(actor.to_hex())
            || receive_pack_field(&admission, "operation_id")? != &Value::from(operation.to_hex())
            || receive_pack_field(&body, "repo_root")? != &root
            || receive_pack_field(&admission, "repo_root")? != &root
            || receive_pack_field(&body, "operation")? != &Value::from("git-receive-pack")
            || receive_pack_field(&admission, "operation")? != &Value::from("git-receive-pack")
            || !observation_matches_seam
        {
            return Err(receive_pack_provenance_refused(
                "actor, repository or operation does not match",
            ));
        }
        Ok(body)
    }

    pub(super) fn validate_receive_pack_attribution(
        &self,
        repo_id: EntityId,
        outcome: &ReceivePackOutcome,
        attribution: &ReceivePackAttribution,
    ) -> Result<()> {
        let body = self.receive_pack_source(repo_id, &outcome.repo_root, attribution)?;
        if receive_pack_field(&body, "realized_updates")?
            != &receive_pack_updates_value(&outcome.ref_updates)
            || receive_pack_field(&body, "lfs_pointers")?
                != &receive_pack_lfs_value(&outcome.lfs_pointers)
            || receive_pack_field(&body, "pack_stats")?
                != &receive_pack_stats_value(outcome.pack_stats)
            || receive_pack_field(&body, "staged_objects_dir")?
                != &Value::from(path_arg(&outcome.staged_objects_dir)?)
        {
            return Err(receive_pack_provenance_refused(
                "outcome does not match the observed operation",
            ));
        }
        Ok(())
    }

    pub(in crate::origin) fn has_receive_pack_evidence(&self, id: EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .vault_meta
            .get(&rtxn, &receive_pack_evidence_key(id))?
            .is_some())
    }

    /// The publication door must not let a receive-pack source certify some
    /// other ref triple, actor or repository through a lower-level caller.
    pub(in crate::origin) fn validate_receive_pack_publication(
        &self,
        request: &OriginPublicationRequest,
    ) -> Result<()> {
        let attribution = ReceivePackAttribution {
            actor_id: request.actor_id,
            provenance_claim_id: request.provenance_claim_id,
        };
        let body =
            self.receive_pack_source(request.repo_id, request.repo.repo_root(), &attribution)?;
        let update = RefUpdate {
            name: request.ref_name.as_str().to_owned(),
            old_oid: request.expected_old_oid.clone(),
            new_oid: Some(request.new_oid.clone()),
        };
        let expected = receive_pack_updates_value(&[update]);
        if !receive_pack_field(&body, "realized_updates")?
            .as_array()
            .is_some_and(|updates| {
                expected
                    .as_array()
                    .is_some_and(|wanted| updates.contains(&wanted[0]))
            })
        {
            return Err(receive_pack_provenance_refused(
                "ref triple was not observed in this operation",
            ));
        }
        if request
            .required_objects
            .iter()
            .any(|oid| oid != &request.new_oid)
        {
            return Err(receive_pack_provenance_refused(
                "unobserved object dependency",
            ));
        }
        let pointers = receive_pack_field(&body, "lfs_pointers")?
            .as_array()
            .ok_or_else(|| receive_pack_provenance_refused("invalid LFS evidence"))?
            .iter()
            .map(|value| {
                let fields = value
                    .as_array()
                    .filter(|fields| fields.len() == 3)
                    .ok_or_else(|| receive_pack_provenance_refused("invalid LFS evidence"))?;
                Ok(LfsPushedPointer {
                    path: fields[0]
                        .as_str()
                        .ok_or_else(|| receive_pack_provenance_refused("invalid LFS path"))?
                        .to_owned(),
                    oid: LfsOid::parse_hex(
                        fields[1]
                            .as_str()
                            .ok_or_else(|| receive_pack_provenance_refused("invalid LFS oid"))?,
                    )?,
                    size_bytes: fields[2]
                        .as_u64()
                        .ok_or_else(|| receive_pack_provenance_refused("invalid LFS size"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let admitted = admit_landing_lfs_pointers(self, request.repo_id, &pointers)?;
        let wire = GitWire::new(self)?;
        if request.required_lfs_oids
            != ref_required_lfs_oids(&wire, &request.repo, &admitted, &request.new_oid)?
        {
            return Err(receive_pack_provenance_refused(
                "LFS dependencies differ from observed intent",
            ));
        }
        Ok(())
    }
}
