//! Grant-scoped home-node reads for opened-item devices.
//! App-tier bind provides the actor; request bytes never choose a principal.

#[cfg(test)]
pub(super) mod tests;

mod authority;
mod bundle_access;
mod bundle_commit;
mod bundles;
mod checkpoint_roots;
mod custody;
mod home_handoff;
mod index;
mod machine_history;
mod pad_custody;
mod pad_objects;
mod pad_refill;
mod pages;
mod search;

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::{Destination, PeerMachine};
use oneiron::sync::residence::{
    AuthorityAppendPart, AuthorityAppendProgress, AuthorityAppendStage, BundlePartRead, IndexPage,
    RESIDENCE_PAGE_REPLY_BYTES, ResidenceAdmission, SealedBundleEntry, SealedBundleObject,
    SealedBundleStage, WindowIndexEntry, ask_sealed_bundle_turn, authority_append_part_for,
    authority_append_progress_for, authority_checkpoint_part_for, authority_entry_part_for,
    authority_range_for, authority_tail_for, authority_wanted, home_search_candidates,
    index_selection_revision, promotion_snapshot_with, replace_sealed_bundle_pads,
    sealed_bundle_index, sealed_bundle_part, sealed_digest_from_hex, sealed_digest_hex,
    sealed_generation_from_hex, sealed_generation_hex, selected_item_blob_with,
    split_authority_page, stage_sealed_bundle_part, window_index_page, window_index_projection_with,
};
use oneiron::sync::residence_operation_budgets::ResidenceOperationBudgets;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{SyncSelector, WindowKey, decode_sync_selector};
use serde::Deserialize;
use serde_json::{Value, json};

use self::authority::*;
use self::bundles::*;
pub(super) use self::home_handoff::{machine_method, run_machine};
use self::index::*;
use self::search::*;
use super::{AppError, CoreAuth, CoreScope, RpcRequest};
use crate::wire_telemetry::LimitRow;

/// A result and the rows it carries (DEC-0005).
type Answer = (Value, Option<Vec<EntityId>>);
use crate::server::SyncServer;

/// One revision-bound metadata projection per authenticated socket. Replacing
/// it on the next window keeps memory bounded and never caches a grant decision
/// across sockets or principals.
pub(crate) struct ResidenceIndexCache {
    window: WindowKey,
    selector: SyncSelector,
    revision: String,
    window_vv: Vec<u8>,
    grant_raw: Vec<u8>,
    authority: oneiron::authority::AuthorityFold,
    /// The machine the projection was selected for: a proof that stops
    /// standing, or a new one, never reuses it.
    destination: Destination,
    selection_revision: ([u8; 32], u64, u64),
    items: Vec<WindowIndexEntry>,
    pages: usize,
    budgets: ResidenceOperationBudgets,
    /// The projection's charge on the server's retained-memory line.
    _held: crate::byte_line::HeldBytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexRequest {
    window: String,
    selector: String,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    revision: Option<String>,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TouchRequest {
    window: String,
    selector: String,
    entity_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PromotionRequest {
    window: String,
    selector: String,
    entity_id: String,
}

/// One window's version vector, asked before an opened machine demotes it
/// (OF-534).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowVvRequest {
    window: String,
    selector: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    query: String,
    limit: usize,
    selector: String,
    /// A caller's own holder proof its device forwards (FIX 2907), with
    /// `machine_proof`: the search is that caller's, not the device's.
    #[serde(default)]
    forwarded: Option<oneiron::authority::ForwardedCallerProof>,
    /// The device's install-key proof over the request and `forwarded`.
    #[serde(default)]
    machine_proof: Option<oneiron::authority::ForwardingMachineProof>,
    /// A recall's resolved scope (FIX 2905): the search is narrowed by it
    /// before the candidate cut. It narrows relevance only; every grant,
    /// selector and caller check below stands.
    #[serde(default)]
    scope: Option<oneiron::sync::residence::ResolvedRecallSelection>,
    /// A later page of a search served in pages (FIX 8865).
    #[serde(default)]
    page: Option<oneiron::sync::residence::ResidenceSearchCursor>,
}

impl SearchRequest {
    /// The forwarded caller, verified for this request (FIX 2907): `None`
    /// for the device's own search. Either proof alone, or a caller the
    /// verifier refuses, looks missing; the home never answers it as the
    /// device instead.
    fn forwarded_caller(
        &self,
        server: &SyncServer,
        peer: PeerMachine,
        selector: &SyncSelector,
    ) -> Result<Option<oneiron::authority::VerifiedForwardedCaller>, AppError> {
        let (caller, machine) = match (&self.forwarded, &self.machine_proof) {
            (None, None) => return Ok(None),
            (Some(caller), Some(machine)) => (caller, machine),
            _ => return Err(AppError::invalid_params()),
        };
        let selector_wire = base64::engine::general_purpose::STANDARD
            .decode(&self.selector)
            .map_err(|_| AppError::invalid_params())?;
        let member = selector.member_ref.to_hex();
        let device = oneiron::authority::ForwardingDevice {
            member_ref: &member,
            grant: selector.grant_id,
            connection: peer,
        };
        oneiron::sync::residence::with_forwarded_search_page(
            &self.query,
            self.limit,
            &selector_wire,
            self.scope.as_ref(),
            self.page.as_ref(),
            |request| {
                server
                    .vault
                    .verify_forwarded_caller(caller, machine, request, &device)
            },
        )
        .map(Some)
        .map_err(|_| AppError::not_found("item", None))
    }
}

/// One part of an upload of the vault's sealed bundle or its pad object
/// (FIX 922): `digest` is the blake3 of the whole object in hex, `offset` the
/// bytes staged before.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundlePutRequest {
    generation: String,
    object: String,
    total: u64,
    digest: String,
    offset: u64,
    part: String,
}

/// A list, naming the owner's bundle publication request when the machine is
/// the install he asked to publish here (WILL L04 row 03): entry hash in hex.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleListRequest {
    #[serde(default)]
    request: Option<String>,
}

/// A machine's ask for the publisher turn, or with `leave` its giving its
/// place up (FIX 3351).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleTurnRequest {
    #[serde(default)]
    leave: bool,
}

/// One slice of a kept generation's object; no generation names the newest.
/// `request` as a list names it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleGetRequest {
    #[serde(default)]
    generation: Option<String>,
    object: String,
    offset: u64,
    #[serde(default)]
    request: Option<String>,
}

/// Erase's rewrite of a kept generation's pad object, staged whole:
/// `replaces` is the digest of the object it was made from.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundlePadsReplaceRequest {
    generation: String,
    replaces: String,
}

/// The authority entries a machine holds, as concatenated 32-byte hashes in
/// base64, and how many missing entries it takes in one page (OF-469).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityTailRequest {
    held: String,
    limit: usize,
}

/// The authority entries a machine wants (`selection`), whether their
/// ancestors come too, down to the entries it holds or staged (`held`, as
/// concatenated 32-byte hashes in base64), and how many it takes from
/// `cursor` in one page (OF-469).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRangeRequest {
    #[serde(default)]
    vault_id: Option<String>,
    selection: AuthorityRangeSelection,
    #[serde(default)]
    parent_closure: bool,
    #[serde(default)]
    held: String,
    #[serde(default)]
    cursor: Option<String>,
    limit: usize,
}

/// Which authority entries a range fetch selects, tagged: `{"hashes":
/// "<packed hashes>"}` for exact entries, or `{"covered": {...}}` for the
/// entries one kept checkpoint image covers.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityRangeSelection {
    Hashes(String),
    Covered(AuthorityRangeCovered),
}

/// The entries the kept checkpoint image `checkpoint` covers, or that its
/// archive manifest `archive` lists, with hashes in `(lower_exclusive,
/// upper_inclusive]`; each a 32-byte value in base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRangeCovered {
    checkpoint: String,
    #[serde(default)]
    archive: Option<String>,
    #[serde(default)]
    lower_exclusive: Option<String>,
    #[serde(default)]
    upper_inclusive: Option<String>,
}

/// A part of the checkpoint image a machine adopts (OF-469): the image's id
/// in base64 and the byte offset the part starts at.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityCheckpointRequest {
    checkpoint: String,
    offset: u64,
}

/// The signed authority entries a machine appends, each canonical signed
/// body in base64, parents first (OF-469).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityAppendRequest {
    entries: Vec<String>,
}

/// A part of an authority entry a page named by reference (FIX 8246): the
/// entry's hash in base64 and the byte offset the part starts at.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntryRequest {
    hash: String,
    offset: u64,
}

/// A part of an authority entry a machine appends past one request frame
/// (FIX 8246): the entry's hash in base64 and its length, the part's offset,
/// and its bytes in base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityAppendPartRequest {
    hash: String,
    total: u64,
    offset: u64,
    part: String,
}

pub(super) fn run(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    request: RpcRequest,
    index_cache: &mut Option<ResidenceIndexCache>,
    append_stage: &mut Option<AuthorityAppendStage>,
) -> Result<super::RpcReply, crate::protocol::ProtocolError> {
    let call = super::RpcCall::of(&request);
    let result = (|| {
        auth.require(CoreScope::Read)?;
        if !auth.credential_is_live(server.vault.as_ref()) {
            return Err(AppError::unauthorized());
        }
        let budgets = operation_budgets(server)?;
        match request.method.as_str() {
            "residence.index" => index(server, auth, peer, request.params, index_cache, budgets),
            "residence.touch" => touch(server, auth, peer, request.params),
            "residence.promote" => promote(server, auth, peer, request.params),
            "residence.window.vv" => window_vv(server, auth, peer, request.params),
            "residence.search" => search(server, auth, peer, request.params, budgets),
            "residence.bundle.turn" => bundle_turn(server, auth, peer, request.params),
            "residence.bundle.put" => bundle_put(server, auth, peer, request.params),
            "residence.bundle.commit" => {
                bundle_commit::bundle_commit(server, auth, peer, request.params)
            }
            "residence.bundle.commit.status" => {
                bundle_commit::bundle_commit_status(server, peer, request.params)
            }
            "residence.bundle.list" => bundle_list(server, peer, request.params),
            "residence.bundle.get" => bundle_get(server, peer, request.params),
            "residence.bundle.pads.replace" => {
                bundle_pads_replace(server, auth, peer, request.params)
            }
            "residence.bundle.pads.refill" => {
                pad_refill::bundle_pads_refill(server, auth, peer, request.params)
            }
            "residence.pad.fetch" => pad_custody::pad_fetch(server, auth, peer, request.params),
            "residence.bundle.access" => {
                bundle_access::bundle_access(server, auth, peer, request.params)
            }
            "residence.authority.tail" => authority_tail(server, peer, request.params),
            "residence.authority.append" => authority_append(server, peer, request.params),
            "residence.authority.append.part" => {
                authority_append_part(server, peer, request.params, append_stage)
            }
            "residence.authority.entry" => authority_entry(server, peer, request.params),
            "residence.authority.range" => authority_range(server, peer, request.params),
            "residence.authority.checkpoint" => authority_checkpoint(server, peer, request.params),
            "residence.authority.checkpoint.roots" => {
                checkpoint_roots::roots(server, peer, request.params)
            }
            "residence.authority.checkpoint.attest" => {
                checkpoint_roots::attest(server, peer, request.params)
            }
            "residence.authority.checkpoint.countersign" => {
                checkpoint_roots::countersign(server, peer, request.params)
            }
            "residence.machine-history" => {
                machine_history::machine_history(server, auth, peer, request.params)
            }
            method if method.starts_with("residence.home_handoff.") => {
                home_handoff::run(server, auth, peer, method, request.params)
            }
            method => custody::run(server, auth, peer, method, request.params),
        }
    })();
    super::RpcReply::answer(server, auth, call, request.request_id, result)
}

fn operation_budgets(server: &SyncServer) -> Result<ResidenceOperationBudgets, AppError> {
    server
        .vault
        .residence_operation_budgets()
        .map_err(|_| AppError::internal_server_error("residence policy unavailable"))?
        .ok_or_else(|| AppError::internal_server_error("residence policy unavailable"))
}

fn bound_selector(
    server: &SyncServer,
    auth: &CoreAuth,
    encoded_selector: &str,
) -> Result<SyncSelector, AppError> {
    if encoded_selector.len() > 8192 {
        return Err(AppError::invalid_params());
    }
    let selector_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded_selector)
        .map_err(|_| AppError::invalid_params())?;
    if selector_bytes.len() > 4096 {
        return Err(AppError::invalid_params());
    }
    let selector = decode_sync_selector(&selector_bytes).map_err(|_| AppError::invalid_params())?;
    let principal = EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| AppError::unauthorized())?,
    )
    .map_err(|_| AppError::unauthorized())?;
    if selector.member_ref != principal {
        return Err(AppError::not_found("item", None));
    }
    oneiron::sync::authorize_sync_selector(
        &server.vault,
        crate::handler::selector_grant_scope(),
        &selector,
    )
    .map_err(|_| AppError::not_found("item", None))?;
    Ok(selector)
}

/// One request's residence admission for the machine this socket proved
/// (OF-534 G6). A refused credential, grant or member looks missing.
fn admitted<'v>(
    server: &'v SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    selector: &SyncSelector,
) -> Result<ResidenceAdmission<'v>, AppError> {
    let proof = auth.verified_slip().ok_or_else(AppError::unauthorized)?;
    ResidenceAdmission::load(
        &server.vault,
        proof,
        peer,
        crate::handler::selector_grant_scope(),
        selector,
    )
    .map_err(|_| AppError::not_found("item", None))
}

fn selected_window(
    server: &SyncServer,
    auth: &CoreAuth,
    key: &str,
    encoded_selector: &str,
) -> Result<(WindowKey, SyncSelector, loro::LoroDoc), AppError> {
    let window = WindowKey::try_new(key).ok_or_else(AppError::invalid_params)?;
    if !read_window_list(&server.root_doc).contains(&window) {
        return Err(AppError::not_found("item", None));
    }
    let selector = bound_selector(server, auth, encoded_selector)?;
    let doc = server
        .reassert_manager
        .open_window(&window)
        .map_err(|_| AppError::internal_server_error("window unavailable"))?;
    Ok((window, selector, doc.doc.clone()))
}
