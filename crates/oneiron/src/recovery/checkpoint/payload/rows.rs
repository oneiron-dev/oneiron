//! The payload registry (KS7-2b): one class for every declared side-table
//! family, for every manifest database and for every entity kind. A side
//! table's class is on its row (`[family: ..]`, core split slice 1); the
//! databases and kinds are classed here. Nothing has a class by default: a
//! table whose row says `unregistered` has none, and a capture keeps its rows
//! in the image, named ([`super::preflight`]).
//!
//! A family an owner getter reads is that getter's, and the getter places
//! each of its rows: in an owner's compartment, as structure, with another
//! client, or not compartmented. A structure family holds ids, counts,
//! digests, markers and pins and no payload of its own, and stays under the
//! image's seal. Another client's family goes to it as it stands, and
//! nothing seals those bytes a second time: KS-1's claim-bound gate
//! decisions are sealed under their claims' keys already, KS-2 carries
//! bodies and KS-2B responses under their instances, and KS-5 and KS-6 take
//! pads and credentials. A mixed sync carrier waits on KS7-3's port. An
//! unclassified family stays under the vault-wide seal, named on the capture
//! receipt ([`super::NOT_COMPARTMENTED`]). A not-imaged family's rows are
//! runtime or derived: tier filtering leaves them out of every image first.

use std::collections::BTreeMap;
use std::ops::Bound;

use super::{Carrier, Getter};
use crate::side_table::{self, SideDb, SideTableDecl};
use crate::store::checkpoint_payload::rows::OtherClient;
pub(super) use crate::store::checkpoint_payload::rows::{Class, Client};
use crate::store::{ResponseDb, ResponseFamily};

/// What a manifest database holds.
#[derive(Clone, Copy, Debug)]
pub(super) enum DbClass {
    /// Rows of one class.
    Rows(Class),
    /// Declared side-table families, each classed on its row.
    Families(SideDb),
}

/// Every manifest database, by name.
pub(super) static DATABASES: &[(&str, DbClass)] = &[
    ("entities", DbClass::Rows(Class::Owner(Getter::Entities))),
    ("type_index", DbClass::Rows(Class::NotImaged)),
    ("short_ids", DbClass::Rows(Class::Structure)),
    ("short_ids_reverse", DbClass::Rows(Class::Structure)),
    ("vault_meta", DbClass::Families(SideDb::VaultMeta)),
    ("vectors", DbClass::Rows(Class::NotImaged)),
    ("hnsw_neighbors", DbClass::Rows(Class::NotImaged)),
    ("hnsw_meta", DbClass::Rows(Class::Structure)),
    ("text_postings", DbClass::Rows(Class::NotImaged)),
    ("text_meta", DbClass::Rows(Class::NotImaged)),
    ("text_forward", DbClass::Rows(Class::NotImaged)),
    ("text_bm25_field_stats", DbClass::Rows(Class::NotImaged)),
    ("text_doc_field_lengths", DbClass::Rows(Class::NotImaged)),
    ("edges_out", DbClass::Rows(Class::Owner(Getter::Entities))),
    ("edges_in", DbClass::Rows(Class::Owner(Getter::Entities))),
    ("ppr_cache", DbClass::Rows(Class::NotImaged)),
    ("ppr_cache_deps", DbClass::Rows(Class::NotImaged)),
    ("temporal_occurred_start", DbClass::Rows(Class::NotImaged)),
    ("temporal_occurred_end", DbClass::Rows(Class::NotImaged)),
    ("temporal_learned", DbClass::Rows(Class::NotImaged)),
    ("temporal_long_intervals", DbClass::Rows(Class::NotImaged)),
    ("phonetic_index", DbClass::Rows(Class::NotImaged)),
    ("phonetic_forward", DbClass::Rows(Class::NotImaged)),
    ("sync_state", DbClass::Families(SideDb::SyncState)),
    (
        "sync_queue",
        DbClass::Rows(Class::Mixed(Carrier::SyncQueue)),
    ),
    ("job_records", DbClass::Rows(Class::Unclassified)),
    ("job_ready", DbClass::Rows(Class::NotImaged)),
    ("job_dedupe", DbClass::Rows(Class::NotImaged)),
];

/// Every entity kind's class, as the entity getter places its rows. A CLAIM
/// is its entity tree's, but for a dreamer step's (KS-2B) and an origin
/// claim's, which the getter places itself.
macro_rules! kinds {
    ($($class:expr => $($kind:ident)*;)+) => {
        static KINDS: &[(Class, &[&str])] = &[$(($class, &[$(stringify!($kind)),*])),+];
    };
}

kinds! {
    Class::Owner(Getter::Entities) => CLAIM TURN SESSION MESSAGE PERSON RELATIONSHIP EVENT SKILL
        SUMMARY PLACE ASSET_TEXT CONVERSATION ORG FACET WORLD NOTIFICATION AGENT_DEF WORKFLOW
        TASK_LIST TASK MACHINE CODE_ARTIFACT CODE_SYMBOL BLOB_ARTIFACT NOTE RECEIPT_RECORD
        REDACTION_AUDIT MODEL AUTHORITY_LOG POLICY_MANIFEST FEDERATION_GRANT ISSUE ACCESS_GRANT
        PSYCH_PROFILE CHANNEL_IDENTITY COUNTERPARTY_CONTACT OUTBOUND_GRANT PERSONA_SNAPSHOT_EXPORT
        CONNECTOR_KEY COMM_RECORD CLAIM_CLASS_DESCRIPTOR SKILL_HUB SKILL_CONTENT_ANCHOR
        EMBEDDING_SETUP;
    Class::Other(Client::Dispatch(OtherClient::Body)) => ASSET;
    Class::Other(Client::Dispatch(OtherClient::WorldPad)) => WORLD_KEY_PAD;
    Class::Other(Client::Dispatch(OtherClient::Credential)) => SECRET_CUSTODY;
    Class::Unclassified => IDENTITY_TOPOLOGY_EVENT;
    Class::NotImaged => DIAGNOSTIC;
}

/// The class the registry gives the entity kind `kind`, when it names it.
pub(super) fn kind_class(kind: &str) -> Option<Class> {
    KINDS
        .iter()
        .find(|(_, kinds)| kinds.contains(&kind))
        .map(|(class, _)| *class)
}

/// A family's identity: its database and prefix.
pub(super) fn identity(decl: &SideTableDecl) -> (bool, &'static [u8]) {
    (decl.db == SideDb::SyncState, decl.prefix)
}

pub(super) fn db_name(db: SideDb) -> &'static str {
    match db {
        SideDb::VaultMeta => "vault_meta",
        SideDb::SyncState => "sync_state",
    }
}

/// Every entity kind the registry names, by class, as written.
pub(super) fn kinds() -> &'static [(Class, &'static [&'static str])] {
    KINDS
}

/// The class of one image row of `database`: `declared`, its family's or
/// its database's, save in the two mixed families whose rows hold responses
/// one by one (FIX 9179): a queue row and a wait index row the response
/// client takes, by the same family and scan the census reads (a response,
/// the erased marker, a wait's erased reply), go to it; every other row of
/// theirs stays as declared, unclassified and named on the receipt.
pub(super) fn class_for_row(database: &str, key: &[u8], value: &[u8], declared: Class) -> Class {
    let mixed = match database {
        "job_records" => true,
        "vault_meta" => key.starts_with(side_table::CODE_RUN_WAIT_INDEX.prefix),
        _ => false,
    };
    let response = mixed
        && ResponseDb::of_name(database).is_some_and(|db| {
            ResponseFamily::mixed_response_placed_as_response(
                crate::engine_store_hooks::ENGINE_STORE_HOOKS.attempt_operations,
                db,
                key,
                value,
            )
        });
    if response {
        Class::Other(Client::Dispatch(OtherClient::Response))
    } else {
        declared
    }
}

/// The registry's families by database and prefix, to find a row's.
pub(super) struct Families([BTreeMap<&'static [u8], (&'static SideTableDecl, Class)>; 2]);

impl Families {
    /// Every declared table that names a family on its row.
    pub(super) fn new() -> Self {
        let mut by_db = [BTreeMap::new(), BTreeMap::new()];
        for decl in side_table::declared() {
            if let Some(class) = decl.family {
                let (sync, prefix) = identity(decl);
                by_db[usize::from(sync)].insert(prefix, (decl, class));
            }
        }
        Self(by_db)
    }

    /// The family the row `key` of `db` falls under, if one is declared:
    /// the last prefix at or before `key`, the only one it can start with
    /// since declared prefixes are disjoint.
    pub(super) fn of(&self, db: SideDb, key: &[u8]) -> Option<(&'static SideTableDecl, Class)> {
        self.0[usize::from(db == SideDb::SyncState)]
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .next_back()
            .filter(|(prefix, _)| key.starts_with(prefix))
            .map(|(_, family)| *family)
    }
}
