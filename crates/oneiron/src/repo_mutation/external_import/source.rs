//! The outside import's four reserved claim families (FIX 6871): the
//! immutable source, one immutable dispatch per send, immutable
//! observations of what a fetch or send did, and the source an imported
//! ref is bound to.
//!
//! - `repo.external_import_source`, about the served CODE anchor: the
//!   canonical store, source tuple, base, imported ref and the
//!   authenticated importer, whose `actor_id` the origin eraser rewrites in
//!   place. Its id is the import's identity: the same tuple resumes, a
//!   changed head is a new import, and an erased importer's source starts
//!   no new send.
//! - `repo.external_import_dispatch`, about the source claim: the intent to
//!   send the seed or the head, written before the send. Its id is the
//!   import and the step, so one send per step can ever be dispatched.
//! - `repo.external_import_observation`, about the source claim: one
//!   attempt's observed fact, with a safe reason code and the receive
//!   links it proved. Never a live status.
//! - `repo.external_import_ref`, about the served CODE anchor: the source
//!   tuple the first import onto one imported ref fixed. Its id is the
//!   anchor and the ref, so a later import reads it by key, never by a
//!   walk of the anchor's claims (FIX 7595).
//!
//! Every id is deterministic over a length-prefixed named encoding, and an
//! id that already holds a different body is refused, never overwritten.
//! No side table, index or mutable status row exists for an import.
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::entity_id_from_hash_material;
use crate::error::{ArtifactError, Error, Result};
use crate::{EntityId, TimeRange, Vault};

/// The import's immutable source claim.
pub(crate) const EXTERNAL_IMPORT_SOURCE_PREDICATE: &str = "repo.external_import_source";
/// One immutable send intent.
pub(crate) const EXTERNAL_IMPORT_DISPATCH_PREDICATE: &str = "repo.external_import_dispatch";
/// One immutable observed fact.
pub(crate) const EXTERNAL_IMPORT_OBSERVATION_PREDICATE: &str = "repo.external_import_observation";
/// The source one imported ref is bound to.
pub(crate) const EXTERNAL_IMPORT_REF_PREDICATE: &str = "repo.external_import_ref";

const SOURCE_DOMAIN: &[u8] = b"oneiron:external-import:v1";
const DISPATCH_DOMAIN: &[u8] = b"oneiron:external-import-dispatch:v1";
const OBSERVATION_DOMAIN: &[u8] = b"oneiron:external-import-observation:v1";
const REF_DOMAIN: &[u8] = b"oneiron:external-import-ref:v1";

/// The only schema these records are read at: no migration, no default.
const SCHEMA_VERSION: u32 = 1;

/// Which part of an import a fact is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportStep {
    Base,
    Fetch,
    Seed,
    Head,
}

impl ImportStep {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Fetch => "fetch",
            Self::Seed => "seed",
            Self::Head => "head",
        }
    }
}

/// What one attempt observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportOutcome {
    /// The base or the imported ref holds this import.
    Held,
    /// The outside ref names another commit.
    Moved,
    /// The fetch or its proof refused.
    Refused,
    /// The fetch and every proof of it passed.
    Fetched,
    /// The door took the send.
    Applied,
    /// The door refused the send.
    Rejected,
    /// The send's outcome is unknown.
    Unknown,
}

/// The source claim's record. `actor_id` is spelled as every origin claim
/// spells its actor (`OriginActor`), so the eraser reads and rewrites it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceRecord {
    pub(crate) schema_version: u32,
    pub(crate) actor_id: String,
    pub(crate) code_repo: String,
    pub(crate) repo: String,
    pub(crate) object_store: String,
    pub(crate) host: String,
    pub(crate) repository: String,
    pub(crate) source_ref: String,
    pub(crate) pull_request: Option<u64>,
    pub(crate) base_commit: String,
    pub(crate) head_commit: String,
    pub(crate) base_revision: String,
    pub(crate) imported_ref: String,
}

/// One send's intent: the import, the step, and the exact ref update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchRecord {
    pub(crate) schema_version: u32,
    pub(crate) import: String,
    pub(crate) step: ImportStep,
    pub(crate) imported_ref: String,
    pub(crate) expected_old: Option<String>,
    pub(crate) new_oid: String,
}

/// One attempt's observed fact: no actor, no diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservationRecord {
    pub(crate) schema_version: u32,
    pub(crate) import: String,
    pub(crate) attempt: String,
    pub(crate) step: ImportStep,
    pub(crate) outcome: ImportOutcome,
    pub(crate) observed_at: u64,
    pub(crate) observed_oid: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) receive_provenance: Option<String>,
    pub(crate) publication: Option<String>,
}

/// The source tuple one imported ref is bound to: no actor, no commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefBindingRecord {
    pub(crate) schema_version: u32,
    pub(crate) code_repo: String,
    pub(crate) imported_ref: String,
    pub(crate) host: String,
    pub(crate) repository: String,
    pub(crate) source_ref: String,
    pub(crate) pull_request: Option<u64>,
}

impl RefBindingRecord {
    /// The binding `record` fixes for its imported ref.
    fn of(record: &SourceRecord) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            code_repo: record.code_repo.clone(),
            imported_ref: record.imported_ref.clone(),
            host: record.host.clone(),
            repository: record.repository.clone(),
            source_ref: record.source_ref.clone(),
            pull_request: record.pull_request,
        }
    }

    /// Whether `record` imports from the source this ref is bound to.
    pub(crate) fn binds(&self, record: &SourceRecord) -> bool {
        self.host == record.host
            && self.repository == record.repository
            && self.source_ref == record.source_ref
            && self.pull_request == record.pull_request
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

/// The import id: the store, the anchor, the whole source tuple, the base,
/// the imported ref and the authenticated importer.
pub(crate) fn source_id(record: &SourceRecord) -> Result<EntityId> {
    let pull = record
        .pull_request
        .map(|number| number.to_string())
        .unwrap_or_default();
    entity_id_from_hash_material(
        SOURCE_DOMAIN,
        &[
            b"store",
            record.object_store.as_bytes(),
            b"code_repo",
            record.code_repo.as_bytes(),
            b"host",
            record.host.as_bytes(),
            b"repository",
            record.repository.as_bytes(),
            b"source_ref",
            record.source_ref.as_bytes(),
            b"pull_request",
            pull.as_bytes(),
            b"base_commit",
            record.base_commit.as_bytes(),
            b"head_commit",
            record.head_commit.as_bytes(),
            b"base_revision",
            record.base_revision.as_bytes(),
            b"imported_ref",
            record.imported_ref.as_bytes(),
            b"importer",
            record.actor_id.as_bytes(),
        ],
    )
}

/// The one dispatch id of `step` for `import`.
pub(crate) fn dispatch_id(import: EntityId, step: ImportStep) -> Result<EntityId> {
    entity_id_from_hash_material(
        DISPATCH_DOMAIN,
        &[
            b"import",
            import.as_bytes(),
            b"step",
            step.as_str().as_bytes(),
        ],
    )
}

/// The one binding id of `imported_ref` on the anchor `code_repo`.
fn ref_binding_id(code_repo: EntityId, imported_ref: &str) -> Result<EntityId> {
    entity_id_from_hash_material(
        REF_DOMAIN,
        &[
            b"code_repo",
            code_repo.as_bytes(),
            b"imported_ref",
            imported_ref.as_bytes(),
        ],
    )
}

fn observation_id(record: &ObservationRecord) -> Result<EntityId> {
    let fact = rmp_serde::to_vec_named(record).map_err(|_| invalid("import fact encode"))?;
    entity_id_from_hash_material(
        OBSERVATION_DOMAIN,
        &[
            b"attempt",
            record.attempt.as_bytes(),
            b"step",
            record.step.as_str().as_bytes(),
            b"fact",
            &fact,
        ],
    )
}

/// A record as a claim value: a named map, so each field reads by name.
fn encode<T: Serialize>(record: &T) -> Result<Value> {
    let bytes = rmp_serde::to_vec_named(record).map_err(|_| invalid("import record encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|_| invalid("import record encode"))
}

fn claim_body<T: Serialize>(predicate: &str, subject: EntityId, record: &T) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        encode(record)?,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    // Engine bookkeeping of one import, never a generic claim a caller
    // could write.
    body.source = Some(ClaimSource::Observed);
    Ok(body)
}

fn decode<T: for<'de> Deserialize<'de>>(
    body: &ClaimBody,
    predicate: &str,
    subject: EntityId,
) -> Result<T> {
    if body.predicate != predicate
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.subject != ClaimSubject::Entity(subject)
    {
        return Err(Error::CorruptedIndex(
            "an external import record's claim moved",
        ));
    }
    rmpv::ext::from_value(body.value.clone()).map_err(|_| invalid("import record decode"))
}

impl Vault {
    /// The import source claim `import`, read in `txn`: `None` when the id
    /// holds no claim.
    ///
    /// # Errors
    /// A claim of another shape at that id, or a store failure.
    pub(crate) fn external_import_source_in_txn(
        &self,
        txn: &RoTxn<'_>,
        import: EntityId,
        code_repo: EntityId,
    ) -> Result<Option<SourceRecord>> {
        let Some(body) = self.get_claim_in_txn(txn, &import)? else {
            return Ok(None);
        };
        let record: SourceRecord = decode(&body, EXTERNAL_IMPORT_SOURCE_PREDICATE, code_repo)?;
        if record.schema_version != SCHEMA_VERSION {
            return Err(Error::CorruptedIndex(
                "an external import source has another schema",
            ));
        }
        Ok(Some(record))
    }

    /// The source `imported_ref` on `code_repo` is bound to, read by key:
    /// `None` before the first import onto it.
    ///
    /// # Errors
    /// A claim of another shape at that id, or a store failure.
    pub(crate) fn external_import_ref_binding_in_txn(
        &self,
        txn: &RoTxn<'_>,
        code_repo: EntityId,
        imported_ref: &str,
    ) -> Result<Option<RefBindingRecord>> {
        let id = ref_binding_id(code_repo, imported_ref)?;
        let Some(body) = self.get_claim_in_txn(txn, &id)? else {
            return Ok(None);
        };
        let record: RefBindingRecord = decode(&body, EXTERNAL_IMPORT_REF_PREDICATE, code_repo)?;
        if record.schema_version != SCHEMA_VERSION || record.imported_ref != imported_ref {
            return Err(Error::CorruptedIndex(
                "an external import ref binding has another shape",
            ));
        }
        Ok(Some(record))
    }

    /// Binds `record`'s imported ref to its source in `txn`, once: an
    /// existing binding is never rewritten.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn put_external_import_ref_binding_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        record: &SourceRecord,
        now: u64,
    ) -> Result<()> {
        let subject = EntityId::from_hex(&record.code_repo)?;
        let id = ref_binding_id(subject, &record.imported_ref)?;
        if self.get_raw_in(txn, &id)?.is_some() {
            return Ok(());
        }
        let body = claim_body(
            EXTERNAL_IMPORT_REF_PREDICATE,
            subject,
            &RefBindingRecord::of(record),
        )?;
        self.put_reserved_claim_in_txn(txn, &id, &body, instant(now), now)
    }

    /// The dispatch of `step` for `import`, if one was written.
    pub(crate) fn external_import_dispatch_in_txn(
        &self,
        txn: &RoTxn<'_>,
        import: EntityId,
        step: ImportStep,
    ) -> Result<Option<DispatchRecord>> {
        let id = dispatch_id(import, step)?;
        let Some(body) = self.get_claim_in_txn(txn, &id)? else {
            return Ok(None);
        };
        let record: DispatchRecord = decode(&body, EXTERNAL_IMPORT_DISPATCH_PREDICATE, import)?;
        if record.schema_version != SCHEMA_VERSION || record.step != step {
            return Err(Error::CorruptedIndex(
                "an external import dispatch has another shape",
            ));
        }
        Ok(Some(record))
    }

    /// Every observation about `import`, oldest first.
    pub(crate) fn external_import_observations_in_txn(
        &self,
        txn: &RoTxn<'_>,
        import: EntityId,
    ) -> Result<Vec<ObservationRecord>> {
        let mut found = Vec::new();
        for id in self.claims_for_subject_in_txn(txn, &import)? {
            let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate != EXTERNAL_IMPORT_OBSERVATION_PREDICATE {
                continue;
            }
            let record: ObservationRecord =
                decode(&body, EXTERNAL_IMPORT_OBSERVATION_PREDICATE, import)?;
            if record.schema_version == SCHEMA_VERSION {
                found.push(record);
            }
        }
        found.sort_by(|left, right| {
            (left.observed_at, &left.attempt).cmp(&(right.observed_at, &right.attempt))
        });
        Ok(found)
    }

    /// Writes `record` once at its import id in `txn`. Answers the id; a
    /// repeat of the same body writes nothing, another body under the id is
    /// a refusal (an erased importer's source among them).
    pub(crate) fn put_external_import_source_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        record: &SourceRecord,
        now: u64,
    ) -> Result<std::result::Result<EntityId, &'static str>> {
        let id = source_id(record)?;
        let subject = EntityId::from_hex(&record.code_repo)?;
        match self.external_import_source_in_txn(txn, id, subject)? {
            Some(stored) if stored == *record => return Ok(Ok(id)),
            Some(stored) if stored.actor_id != record.actor_id => {
                return Ok(Err("external_import_importer_erased"));
            }
            Some(_) => return Ok(Err("external_import_source_differs")),
            None if self.get_raw_in(txn, &id)?.is_some() => {
                return Err(Error::CorruptedIndex(
                    "an external import id holds another record",
                ));
            }
            None => {}
        }
        let body = claim_body(EXTERNAL_IMPORT_SOURCE_PREDICATE, subject, record)?;
        self.put_reserved_claim_in_txn(txn, &id, &body, instant(now), now)?;
        Ok(Ok(id))
    }

    /// Writes the dispatch of `record.step` once in `txn`. Answers whether
    /// this call wrote it: an existing dispatch, equal or not, is never
    /// rewritten, so one send per step is ever dispatched.
    pub(crate) fn put_external_import_dispatch_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        import: EntityId,
        record: &DispatchRecord,
        now: u64,
    ) -> Result<bool> {
        let id = dispatch_id(import, record.step)?;
        if self.get_raw_in(txn, &id)?.is_some() {
            return Ok(false);
        }
        let body = claim_body(EXTERNAL_IMPORT_DISPATCH_PREDICATE, import, record)?;
        self.put_reserved_claim_in_txn(txn, &id, &body, instant(now), now)?;
        Ok(true)
    }

    /// Writes one observation in its own transaction; a repeat of the same
    /// fact writes nothing.
    pub(crate) fn put_external_import_observation(
        &self,
        import: EntityId,
        record: &ObservationRecord,
    ) -> Result<()> {
        let id = observation_id(record)?;
        let body = claim_body(EXTERNAL_IMPORT_OBSERVATION_PREDICATE, import, record)?;
        self.with_write_txn_grouped(|txn| {
            if self.get_raw_in(txn, &id)?.is_some() {
                return Ok(());
            }
            self.put_reserved_claim_in_txn(
                txn,
                &id,
                &body,
                instant(record.observed_at),
                record.observed_at,
            )
        })
    }
}

fn instant(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

impl ObservationRecord {
    /// A fresh fact of `step` in `attempt`.
    pub(crate) fn new(
        import: EntityId,
        attempt: EntityId,
        step: ImportStep,
        outcome: ImportOutcome,
        observed_at: u64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            import: import.to_hex(),
            attempt: attempt.to_hex(),
            step,
            outcome,
            observed_at,
            observed_oid: None,
            reason: None,
            receive_provenance: None,
            publication: None,
        }
    }

    pub(crate) fn because(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }
}

impl DispatchRecord {
    /// The intent to send `new` to `imported_ref` over `expected`.
    pub(crate) fn new(
        import: EntityId,
        step: ImportStep,
        imported_ref: &str,
        expected_old: Option<&str>,
        new_oid: &str,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            import: import.to_hex(),
            step,
            imported_ref: imported_ref.to_owned(),
            expected_old: expected_old.map(str::to_owned),
            new_oid: new_oid.to_owned(),
        }
    }
}

impl SourceRecord {
    /// The current-schema record of one normalized request.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        importer: EntityId,
        code_repo: EntityId,
        repo: &str,
        object_store: &str,
        source: &super::ExternalImportSource,
        base_revision: EntityId,
        imported_ref: &str,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            actor_id: crate::origin::publication::OriginActor::Actor(importer).to_hex(),
            code_repo: code_repo.to_hex(),
            repo: repo.to_owned(),
            object_store: object_store.to_owned(),
            host: source.host.clone(),
            repository: source.repository.clone(),
            source_ref: source.source_ref.clone(),
            pull_request: source.pull_request,
            base_commit: source.base_commit.clone(),
            head_commit: source.head_commit.clone(),
            base_revision: base_revision.to_hex(),
            imported_ref: imported_ref.to_owned(),
        }
    }

    /// The importer, unless erased.
    pub(crate) fn importer(&self) -> Option<EntityId> {
        crate::origin::publication::OriginActor::from_hex(&self.actor_id)
            .ok()
            .and_then(crate::origin::publication::OriginActor::id)
    }

    /// The frozen source as the wire carries it.
    pub(crate) fn source(&self) -> super::ExternalImportSource {
        super::ExternalImportSource {
            host: self.host.clone(),
            repository: self.repository.clone(),
            source_ref: self.source_ref.clone(),
            pull_request: self.pull_request,
            base_commit: self.base_commit.clone(),
            head_commit: self.head_commit.clone(),
        }
    }
}
