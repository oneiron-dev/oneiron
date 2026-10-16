//! The eight existing WS read verbs call the engine facade, without write aliases.
use oneiron::EntityId;
use oneiron::memory::{ClaimListFilter, Memory, NeighborOpts};
use oneiron::task_verb::sdk::RecallRequest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::AppError;

pub(super) fn read_method(method: &str) -> bool {
    matches!(
        method,
        "vault.recall"
            | "vault.search.bm25"
            | "vault.neighbors"
            | "vault.hydrate"
            | "vault.writes.pending"
            | "vault.receipts"
            | "vault.claims.list"
            | "vault.claims.history"
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
// `vault.recall` decodes the facade's own `RecallRequest`.
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
            "vault.hydrate" => {
                let p: Hydrate = params(value)?;
                if p.refs.len() > crate::api::CORE_MAX_LIST_LIMIT {
                    return Err(AppError::bad_request(
                        "too many hydration references",
                        Some("refs"),
                    ));
                }
                Self::Hydrate(p.refs)
            }
            "vault.search.bm25" => {
                let p: Query = params(value)?;
                Self::Query(p.query, facade_limit(Some(p.limit), p.limit)?)
            }
            "vault.neighbors" => {
                let mut p: Neighbors = params(value)?;
                p.opts.limit = facade_limit(Some(p.opts.limit), p.opts.limit)?;
                Self::Neighbors(p.entity_ref, p.opts)
            }
            "vault.writes.pending" => {
                let p: Limit = params(value)?;
                Self::PendingWrites(facade_limit(Some(p.limit), p.limit)?)
            }
            "vault.receipts" => {
                let p: Receipts = params(value)?;
                Self::Receipts(facade_limit(
                    p.limit,
                    oneiron::task_verb::sdk::VAULT_RECEIPTS_LIMIT_DEFAULT,
                )?)
            }
            "vault.claims.list" => {
                let mut filter: ClaimListFilter = params(value)?;
                filter.limit = facade_limit(Some(filter.limit), filter.limit)?;
                Self::ClaimList(filter)
            }
            "vault.claims.history" => {
                let p: History = params(value)?;
                Self::ClaimHistory(p.claim_ref)
            }
            "vault.recall" => {
                // Recall's door serves a limit past the ceiling at it.
                let request: RecallRequest = params(value)?;
                oneiron::memory::caps::check_deadline_ms(request.deadline_ms)?;
                Self::Recall(request)
            }
            _ => return Err(AppError::bad_request("unknown read RPC", Some("method"))),
        })
    }

    /// The row this read is, and its args in the row's own input shape: a
    /// verb hook reads one shape whichever door the row came through.
    fn row(&self) -> Result<(&'static str, Value), AppError> {
        Ok(match self {
            Self::Hydrate(refs) => ("vault.hydrate", json!({ "refs": refs })),
            Self::Query(query, limit) => (
                "vault.search.bm25",
                json!({ "query": query, "limit": limit }),
            ),
            Self::Neighbors(entity_ref, opts) => (
                "vault.neighbors",
                json!({ "entity_ref": entity_ref, "opts": opts }),
            ),
            Self::PendingWrites(limit) => ("vault.writes.pending", json!({ "limit": limit })),
            Self::Receipts(limit) => ("vault.receipts", json!({ "limit": limit })),
            Self::ClaimList(filter) => ("vault.claims.list", result(filter)?),
            Self::ClaimHistory(claim_ref) => {
                ("vault.claims.history", json!({ "claim_ref": claim_ref }))
            }
            Self::Recall(request) => ("vault.recall", result(request)?),
        })
    }

    /// The read a hook's rewrite of the row's args names, under the same caps
    /// [`Self::parse`] holds a request to.
    fn rewritten(verb: &str, mut args: Value) -> Result<Self, AppError> {
        if let Some(fields) = args.as_object_mut() {
            // The row's field names, where this socket spells them in
            // camelCase.
            for (row, socket) in [("entity_ref", "entityRef"), ("claim_ref", "claimRef")] {
                if let Some(value) = fields.remove(row) {
                    fields.insert(socket.to_owned(), value);
                }
            }
            if verb == "vault.writes.pending" && fields.get("limit").is_none_or(Value::is_null) {
                fields.insert(
                    "limit".to_owned(),
                    json!(oneiron::task_verb::sdk::VAULT_RECEIPTS_LIMIT_DEFAULT),
                );
            }
        }
        Self::parse(verb, args)
    }

    /// The read's result, and the rows it carries: `None` when one of the
    /// refs it spells names no row. The row's verb hooks run around it
    /// (ARCH-0080 §3), and the result is the caller's view of it.
    pub(super) fn run(
        self,
        server: &crate::server::SyncServer,
        auth: &crate::auth::CoreAuth,
        memory: &Memory<'_>,
    ) -> Result<(Value, Option<Vec<EntityId>>), AppError> {
        let (verb, args) = self.row()?;
        let hooks = oneiron::task_verb::verb_hook_boundary::row_pre(memory, verb, args.clone())?;
        let read = if hooks.args == args {
            self
        } else {
            Self::rewritten(verb, hooks.args.clone())?
        };
        let (value, rows) = read.run_read(server, auth, memory)?;
        let value = oneiron::task_verb::verb_hook_boundary::row_post(server.vault(), hooks, value)?;
        Ok((value, rows))
    }

    fn run_read(
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
                let (pack, listed) =
                    server.recall_at_sync_door(actor, class, proof, auth.locality(), request);
                // Derived from them too, though it names none.
                rows.list(listed);
                let pack = pack?;
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

    /// Rows the result was derived from without naming them.
    fn list(&mut self, listed: Vec<EntityId>) {
        if let Some(rows) = &mut self.rows {
            rows.extend(listed);
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
