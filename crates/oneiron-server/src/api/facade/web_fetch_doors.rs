//! Distinct typed fetch and crawl doors, shared by HTTP, SDK and MCP.
use std::sync::Arc;

use oneiron::runtime_hooks::InvocationId;
use oneiron::web_fetch::{CrawlResult, FetchResult, WebCrawlRequest, WebFetchRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn fetch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WebFetchRequest,
) -> Listed<FetchResult> {
    credential_listing(server, auth, caller, "fetch", move |server, _, memory| {
        let fetcher = server.web_fetcher()?;
        memory.fetch_web_through(&fetcher, input)
    })
    .await
}

pub(crate) async fn crawl(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WebCrawlRequest,
) -> Listed<CrawlResult> {
    credential_listing(server, auth, caller, "crawl", move |server, _, memory| {
        let fetcher = server.web_fetcher()?;
        memory.crawl_web_through(&fetcher, input)
    })
    .await
}
