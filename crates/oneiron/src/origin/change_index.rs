//! Commit-hash keyed LEDGER change identities. Trailers are hints, never keys.
use super::publication::{OriginPublicationRecord, origin_published_commit_id};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::side_table::{self, Raw, SideTable};
use rmpv::Value;

/// Tamper-detection proof hash pinning one repo.change claim's exact byte content at publication
/// time. Key: change claim id.
const CHANGE_RECEIPTS: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::ORIGIN_CHANGE_RECEIPT);

pub const ORIGIN_CHANGE_PREDICATE: &str = "repo.change";
pub const ORIGIN_CHANGE_VALUE_KEYS: [&str; 7] = [
    "schema_version",
    "change_id",
    "commit_hash",
    "actor_id",
    "provenance_claim_id",
    "source",
    "ref_name",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginChange {
    pub change_id: EntityId,
    pub claim_id: EntityId,
    pub commit: GitOid,
    pub repo_id: EntityId,
    pub actor_id: EntityId,
    pub provenance_claim_id: EntityId,
    pub source: String,
    pub ref_name: String,
}
pub fn origin_change_id(repo: EntityId, commit: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:origin-change:v1",
        &[repo.as_bytes(), commit.as_str().as_bytes()],
    )
}
fn claim_id(repo: EntityId, commit: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:origin-change-claim:v1",
        &[repo.as_bytes(), commit.as_str().as_bytes()],
    )
}
impl Vault {
    pub fn origin_change_for_commit(
        &self,
        repo: EntityId,
        commit: &GitOid,
    ) -> Result<Option<OriginChange>> {
        let id = claim_id(repo, commit)?;
        let Some(body) = self.get_claim(&id)? else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let proof = CHANGE_RECEIPTS
            .get(&self.store, &txn, &id)?
            .ok_or(Error::CorruptedIndex(
                "origin change has no publication receipt",
            ))?;
        if proof != *blake3::hash(&encode_claim_body(&body)?).as_bytes() {
            return Err(Error::CorruptedIndex(
                "origin change claim was altered outside publication",
            ));
        }
        drop(txn);
        let subject = ClaimSubject::Edge {
            source: origin_published_commit_id(commit)?,
            kind: EdgeKind::PartOf,
            target: repo,
        };
        if body.predicate != ORIGIN_CHANGE_PREDICATE
            || body.subject != subject
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Err(Error::CorruptedIndex("origin change claim binding"));
        }
        let fields = body
            .value
            .as_map()
            .ok_or(Error::CorruptedIndex("origin change map"))?;
        let string = |name: &str| -> Result<&str> {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(name))
                .and_then(|(_, v)| v.as_str())
                .ok_or(Error::CorruptedIndex("origin change field"))
        };
        let change = OriginChange {
            change_id: EntityId::from_hex(string("change_id")?)?,
            claim_id: id,
            commit: GitOid::parse_hex(string("commit_hash")?)?,
            repo_id: repo,
            actor_id: EntityId::from_hex(string("actor_id")?)?,
            provenance_claim_id: EntityId::from_hex(string("provenance_claim_id")?)?,
            source: string("source")?.to_owned(),
            ref_name: string("ref_name")?.to_owned(),
        };
        if change.change_id != origin_change_id(repo, commit)? || change.commit != *commit {
            return Err(Error::CorruptedIndex("origin change hash identity"));
        }
        Ok(Some(change))
    }
    pub(in crate::origin) fn put_origin_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &OriginPublicationRecord,
        now: u64,
    ) -> Result<EntityId> {
        let id = claim_id(record.repo_id, &record.new_oid)?;
        let change = origin_change_id(record.repo_id, &record.new_oid)?;
        // The first import owns the stable attribution; a second ref or trailer-stripped
        // replay cannot rewrite commit-hash provenance.
        if let Some(raw) = self.store.entities.get(txn, id.as_bytes())? {
            let bytes = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("origin change entity header"))?;
            let proof =
                CHANGE_RECEIPTS
                    .get(&self.store, txn, &id)?
                    .ok_or(Error::CorruptedIndex(
                        "origin change has no publication receipt",
                    ))?;
            if proof != *blake3::hash(bytes).as_bytes() {
                return Err(Error::CorruptedIndex(
                    "origin change claim was altered outside publication",
                ));
            }
            return Ok(change);
        }
        let source = if record.ref_name.as_str().starts_with("refs/imported/") {
            "mirror_import"
        } else {
            "origin_publication"
        };
        let values = [
            Value::from(1_u64),
            Value::from(change.to_hex()),
            Value::from(record.new_oid.as_str()),
            Value::from(record.actor_id.to_hex()),
            Value::from(record.provenance_claim_id.to_hex()),
            Value::from(source),
            Value::from(record.ref_name.as_str()),
        ];
        let mut body = ClaimBody::new(
            ORIGIN_CHANGE_PREDICATE,
            ClaimSubject::Edge {
                source: origin_published_commit_id(&record.new_oid)?,
                kind: EdgeKind::PartOf,
                target: record.repo_id,
            },
            Value::Map(
                ORIGIN_CHANGE_VALUE_KEYS
                    .into_iter()
                    .zip(values)
                    .map(|(k, v)| (Value::from(k), v))
                    .collect(),
            ),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        self.put_claim_in_txn(txn, &id, &body, record.occurred, now)?;
        CHANGE_RECEIPTS.put(
            &self.store,
            txn,
            &id,
            blake3::hash(&encode_claim_body(&body)?).as_bytes(),
        )?;
        Ok(change)
    }
}
