//! One retrieval request's shape (F21(a)): its query against
//! `[limits].retrieval_query_bytes`, and the OF-520 question a crossing
//! raises.
//!
//! The row is a format bound on one request, not a rate (rule 5). A query
//! past it is refused with the typed 413 naming the field and the bound, and
//! the first crossing per caller, door, field and bound leaves one question
//! for the host. Questions live in memory for the server's lifetime; each
//! keeps its latest crossing's size and never the query.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;

/// Each door that reads a retrieval query, by the closed code its question
/// and log line name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum QueryDoor {
    ContextPack,
    ContextBoard,
    CoreQuery,
    MemoryReason,
    SearchText,
    SearchVector,
    SearchSemantic,
    McpMemoryQuery,
    McpMemoryContextPack,
}

impl QueryDoor {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ContextPack => "context_pack",
            Self::ContextBoard => "context_board",
            Self::CoreQuery => "core_query",
            Self::MemoryReason => "memory_reason",
            Self::SearchText => "search_text",
            Self::SearchVector => "search_vector",
            Self::SearchSemantic => "search_semantic",
            Self::McpMemoryQuery => "mcp_memory_query",
            Self::McpMemoryContextPack => "mcp_memory_context_pack",
        }
    }
}

/// OF-520 question one caller's query raised at one door: it carried more
/// bytes than `[limits].retrieval_query_bytes`, and the door refused it, or
/// served it whole where the door asks instead (FIX 6923).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalQueryCheck {
    /// The caller: its principal ref, else its principal.
    pub principal: String,
    /// The door, by its closed code.
    pub door: &'static str,
    /// The request field the query arrived in.
    pub field: &'static str,
    /// The row in force at the crossing.
    pub bound: usize,
    /// Bytes the latest crossing query carried.
    pub bytes: usize,
}

impl RetrievalQueryCheck {
    /// Machine-readable question discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "retrieval_query_bytes_exceeded";
}

type CheckKey = (String, QueryDoor, &'static str, usize);

/// The server's questions, at each key's latest crossing.
#[derive(Default)]
pub(crate) struct QueryChecks(Mutex<BTreeMap<CheckKey, RetrievalQueryCheck>>);

/// A query past its row: what the door's typed refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryOverRow {
    pub(crate) field: &'static str,
    pub(crate) bound: usize,
    pub(crate) bytes: usize,
}

impl From<QueryOverRow> for ApiError {
    fn from(over: QueryOverRow) -> Self {
        Self::payload_too_large(over.field, over.bound, over.bytes)
    }
}

/// The key a request's question is kept under: the caller's principal ref,
/// else its principal, as the MEMORIES cursor store keys a caller.
pub(crate) fn query_caller(auth: &CoreAuth) -> &str {
    auth.principal_ref().unwrap_or(auth.principal()).trim()
}

impl SyncServer {
    /// Checks `query`, as sent, against `[limits].retrieval_query_bytes`.
    /// Past the row the question is raised before the refusal returns; a
    /// query at the row is served.
    pub(crate) fn check_retrieval_query(
        &self,
        caller: &str,
        door: QueryDoor,
        field: &'static str,
        query: &str,
    ) -> Result<(), QueryOverRow> {
        let bound = self.config.limits.retrieval_query_bytes;
        let bytes = query.len();
        if bytes <= bound {
            return Ok(());
        }
        let check = RetrievalQueryCheck {
            principal: caller.to_owned(),
            door: door.code(),
            field,
            bound,
            bytes,
        };
        let first = self
            .query_checks
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((caller.to_owned(), door, field, bound), check)
            .is_none();
        if first {
            tracing::warn!(
                kind = RetrievalQueryCheck::KIND,
                door = door.code(),
                field,
                bound,
                bytes,
                "a retrieval query passed its row and was refused"
            );
        }
        Err(QueryOverRow {
            field,
            bound,
            bytes,
        })
    }

    /// [`Self::check_retrieval_query`] for a door that reads past the row
    /// (Rule 5, FIX 6923): the crossing raises the same question, and the
    /// query runs whole. Only the embedder's own input window cuts it.
    pub(crate) fn ask_retrieval_query(
        &self,
        caller: &str,
        door: QueryDoor,
        field: &'static str,
        query: &str,
    ) {
        let bound = self.config.limits.retrieval_query_bytes;
        let bytes = query.len();
        if bytes <= bound {
            return;
        }
        let check = RetrievalQueryCheck {
            principal: caller.to_owned(),
            door: door.code(),
            field,
            bound,
            bytes,
        };
        let first = self
            .query_checks
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((caller.to_owned(), door, field, bound), check)
            .is_none();
        if first {
            tracing::warn!(
                kind = RetrievalQueryCheck::KIND,
                door = door.code(),
                field,
                bound,
                bytes,
                "a retrieval query passed its row; it runs whole"
            );
        }
    }

    /// Every OF-520 question a retrieval query raised since this server
    /// started, at each one's latest crossing.
    #[must_use]
    pub fn retrieval_query_checks(&self) -> Vec<RetrievalQueryCheck> {
        self.query_checks
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}
