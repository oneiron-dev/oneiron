//! The eight existing WS read verbs call the engine facade, without write aliases.
use oneiron::EntityId;
use oneiron::memory::{ClaimListFilter, Memory, NeighborOpts};
use oneiron::task_verb::sdk::RecallRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AppError;

pub(super) fn read_method(method: &str) -> bool {
    matches!(
        method,
        "recall"
            | "queryBm25"
            | "neighbors"
            | "hydrate"
            | "pendingWrites"
            | "receipts"
            | "claimList"
            | "claimHistory"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    query: String,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hydrate {
    refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Neighbors {
    entity_ref: String,
    opts: NeighborOpts,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    claim_ref: String,
}

// This request shape and default are the released HTTP facade contract;
// `recall` decodes the facade's own `RecallRequest`.
#[derive(Deserialize)]
struct Receipts {
    #[serde(default)]
    limit: Option<usize>,
}

pub(super) enum Read {
    Hydrate(Vec<String>),
    Query(String, usize),
    Neighbors(String, NeighborOpts),
    PendingWrites(usize),
    Receipts(usize),
    ClaimList(ClaimListFilter),
    ClaimHistory(String),
    Recall(RecallRequest),
}

impl Read {
    pub(super) fn parse(method: &str, value: Value) -> Result<Self, AppError> {
        Ok(match method {
            "hydrate" => {
                let p: Hydrate = params(value)?;
                if p.refs.len() > crate::api::CORE_MAX_LIST_LIMIT {
                    return Err(AppError::bad_request(
                        "too many hydration references",
                        Some("refs"),
                    ));
                }
                Self::Hydrate(p.refs)
            }
            "queryBm25" => {
                let p: Query = params(value)?;
                Self::Query(p.query, facade_limit(Some(p.limit), p.limit)?)
            }
            "neighbors" => {
                let mut p: Neighbors = params(value)?;
                p.opts.limit = facade_limit(Some(p.opts.limit), p.opts.limit)?;
                Self::Neighbors(p.entity_ref, p.opts)
            }
            "pendingWrites" => {
                let p: Limit = params(value)?;
                Self::PendingWrites(facade_limit(Some(p.limit), p.limit)?)
            }
            "receipts" => {
                let p: Receipts = params(value)?;
                Self::Receipts(facade_limit(p.limit, 100)?)
            }
            "claimList" => {
                let mut filter: ClaimListFilter = params(value)?;
                filter.limit = facade_limit(Some(filter.limit), filter.limit)?;
                Self::ClaimList(filter)
            }
            "claimHistory" => {
                let p: History = params(value)?;
                Self::ClaimHistory(p.claim_ref)
            }
            "recall" => {
                let mut request: RecallRequest = params(value)?;
                request.limit = Some(facade_limit(request.limit, 10)?);
                oneiron::memory::caps::check_deadline_ms(request.deadline_ms)?;
                Self::Recall(request)
            }
            _ => return Err(AppError::bad_request("unknown read RPC", Some("method"))),
        })
    }

    /// The read's result, and the rows it carries: `None` when one of the
    /// refs it spells names no row.
    pub(super) fn run(
        self,
        server: &crate::server::SyncServer,
        auth: &crate::auth::CoreAuth,
        memory: &Memory<'_>,
    ) -> Result<(Value, Option<Vec<EntityId>>), AppError> {
        let mut rows = Carried::new(server.vault());
        let value = match self {
            Self::Hydrate(refs) => {
                let read = memory.hydrate(&refs)?;
                read.value.iter().for_each(|view| rows.name(&view.id_hex));
                result(read)
            }
            Self::Query(query, limit) => {
                let read = memory.query_bm25(&query, limit)?;
                read.value.iter().for_each(|hit| rows.name(&hit.short_id));
                result(read)
            }
            Self::Neighbors(entity_ref, opts) => {
                let read = memory.neighbors(&entity_ref, &opts)?;
                rows.name(&entity_ref);
                read.value.iter().for_each(|hit| rows.name(&hit.short_id));
                result(read)
            }
            Self::PendingWrites(limit) => {
                let read = memory.pending_writes(limit)?;
                read.iter().for_each(|write| rows.name(&write.claim_ref));
                result(read)
            }
            Self::Receipts(limit) => {
                let read = memory.receipts(limit)?;
                for receipt in &read {
                    receipt.claim_ref.iter().for_each(|id| rows.name(id));
                    receipt.actor_ref.iter().for_each(|id| rows.name(id));
                }
                result(read)
            }
            Self::ClaimList(filter) => {
                let read = memory.claim_list(&filter)?;
                read.value.iter().for_each(|claim| rows.claim(claim));
                result(read)
            }
            Self::ClaimHistory(claim_ref) => {
                let read = memory.claim_history(&claim_ref)?;
                read.value.iter().for_each(|claim| rows.claim(claim));
                result(read)
            }
            // Its own reader, so a deadline can leave the read behind.
            Self::Recall(request) => {
                let (actor, class) = super::bound_reader(auth)?;
                let proof = auth.verified_slip().cloned();
                let pack =
                    server.recall_at_sync_door(actor, class, proof, auth.locality(), request)?;
                rows.pack(&pack);
                result(pack)
            }
        }?;
        Ok((value, rows.rows))
    }
}

/// The rows a result carries, resolved from the refs it spells as it is
/// produced: a release judges them again (DEC-0005). A ref that names no
/// row leaves the result's rows unnamed, and it is refused off this device.
struct Carried<'a> {
    vault: &'a oneiron::Vault,
    rows: Option<Vec<EntityId>>,
}

impl<'a> Carried<'a> {
    const fn new(vault: &'a oneiron::Vault) -> Self {
        Self {
            vault,
            rows: Some(Vec::new()),
        }
    }

    fn name(&mut self, reference: &str) {
        let Some(rows) = &mut self.rows else {
            return;
        };
        match oneiron::memory::resolve_entity_ref(self.vault, reference) {
            Ok(id) => rows.push(id),
            Err(_) => self.rows = None,
        }
    }

    fn claim(&mut self, claim: &oneiron::memory::ClaimView) {
        self.name(&claim.claim_ref);
        // An edge subject is `edge:<source>:<kind>:<target>`.
        match claim.subject_ref.strip_prefix("edge:") {
            Some(edge) => {
                let mut parts = edge.split(':');
                for reference in [parts.next(), parts.nth(1)] {
                    self.name(reference.unwrap_or_default());
                }
            }
            None => self.name(&claim.subject_ref),
        }
        claim.world_ref.iter().for_each(|world| self.name(world));
    }

    fn pack(&mut self, pack: &oneiron::memory::MemoryPack) {
        for item in &pack.items {
            self.name(&item.short_id);
            for id in [&item.world, &item.facet, &item.conversation_id]
                .into_iter()
                .flatten()
            {
                self.name(id);
            }
            item.provenance
                .evidence_turn_ids
                .iter()
                .for_each(|turn| self.name(turn));
            item.cited_messages
                .iter()
                .for_each(|message| self.name(&message.short_id));
        }
        pack.scope_honesty
            .out_of_scope_worlds
            .iter()
            .for_each(|world| self.name(world));
    }
}

fn params<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, AppError> {
    serde_json::from_value(value).map_err(|_| AppError::invalid_params())
}

fn result<T: Serialize>(value: T) -> Result<Value, AppError> {
    serde_json::to_value(value)
        .map_err(|_| AppError::internal_server_error("facade serialization failed"))
}

pub(super) fn facade_limit(requested: Option<usize>, default: usize) -> Result<usize, AppError> {
    let limit = requested.unwrap_or(default);
    if limit == 0 || limit > crate::api::CORE_MAX_LIST_LIMIT {
        return Err(AppError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!(
                "limit must be between 1 and {}",
                crate::api::CORE_MAX_LIST_LIMIT
            ),
            ["Request a smaller page and paginate."],
        ));
    }
    Ok(limit)
}
