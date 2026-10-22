//! `residence.pad.fetch` (KS-5, FIX 6706): one page of a world's current
//! pads, sealed for the machine this socket proved, which opens them with its
//! own machine key (`oneiron::sync::residence::world_pad_capsule`).
//!
//! Exact keys (`keys`, each a full id in hex) are a first open's or an exact
//! repair's: the world's pad recipients must name the machine, and no
//! residence selector is asked. Every pad of the window's world (`selector`
//! and `entityId`) is a promotion's or a retain's: admitted as
//! `residence.promote` admits the window, its snapshot aside. A selector or a
//! guest never gets more than its keys. A page names the last pad it covered
//! as `next` when more follow; the next request asks `after` it. A refused
//! machine, window or recipient looks missing.

use std::collections::BTreeSet;

use base64::Engine;
use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::sync::WindowKey;
use oneiron::sync::residence::{
    ResidenceAdmission, WorldPadFetch, WorldPadSelection, pad_wire_from_hex, pad_wire_hex,
    promotion_covers_full_window_for, selected_item_blob_with, world_pad_capsule,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, admitted, selected_window};
use crate::server::SyncServer;

/// One page a machine asks for: `keys`, or `selector` with `entityId`, the
/// item a promotion of the window is admitted through.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PadFetchRequest {
    window: String,
    #[serde(default)]
    keys: Option<Vec<String>>,
    #[serde(default)]
    selector: Option<String>,
    #[serde(default)]
    entity_id: Option<String>,
    /// The asking machine, hex: the one this socket proved.
    recipient: String,
    /// The custody position an earlier page was bound to, hex.
    #[serde(default)]
    known_position: Option<String>,
    /// The last pad an earlier page held, hex.
    #[serde(default)]
    after: Option<String>,
}

fn wire<const N: usize>(hex: &str) -> Result<[u8; N], AppError> {
    pad_wire_from_hex(hex).ok_or_else(AppError::invalid_params)
}

/// The admitted promotion of `window` through `entity_id` for the machine
/// `peer` proved, judged as `residence.promote` judges it before its
/// snapshot: the selector bound, the item read and selected, and the whole
/// window covered.
fn promoted<'v>(
    server: &'v SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    window: &str,
    selector: &str,
    entity_id: &str,
) -> Result<(WindowKey, ResidenceAdmission<'v>), AppError> {
    let id = EntityId::from_hex(entity_id).map_err(|_| AppError::invalid_params())?;
    let (window, selector, doc) = selected_window(server, auth, window, selector)?;
    let admission = admitted(server, auth, peer, &selector)?;
    let scope = crate::handler::selector_grant_scope();
    let unavailable = |_| AppError::internal_server_error("world pads unavailable");
    if !admission.allows_item(id).map_err(unavailable)?
        || selected_item_blob_with(
            &server.vault,
            &doc,
            &window,
            scope,
            &selector,
            admission.withhold(),
            id,
        )
        .map_err(|_| AppError::not_found("item", None))?
        .is_none()
        || !promotion_covers_full_window_for(
            &server.vault,
            &doc,
            &window,
            scope,
            &selector,
            admission.withhold(),
            |item| admission.allows_item(item),
        )
        .map_err(unavailable)?
    {
        return Err(AppError::not_found("window promotion", None));
    }
    Ok((window, admission))
}

/// One page of a world's current pads for the machine this socket proved.
pub(super) fn pad_fetch(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: PadFetchRequest =
        serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let recipient = EntityId::from_hex(&input.recipient).map_err(|_| AppError::invalid_params())?;
    let known_position = input.known_position.as_deref().map(wire).transpose()?;
    let after = input.after.as_deref().map(wire).transpose()?;
    let missing = |_| AppError::not_found("world pads", None);
    let page = match (input.keys, input.selector, input.entity_id) {
        (Some(keys), None, None) => {
            let window = WindowKey::try_new(&input.window).ok_or_else(AppError::invalid_params)?;
            let keys = keys
                .iter()
                .map(|key| wire(key))
                .collect::<Result<BTreeSet<_>, _>>()?;
            let fetch = WorldPadFetch {
                window,
                selection: WorldPadSelection::Keys(keys),
                recipient,
                known_position,
                after,
            };
            world_pad_capsule(&server.vault, peer, &fetch, None).map_err(missing)?
        }
        (None, Some(selector), Some(entity_id)) => {
            let (window, admission) =
                promoted(server, auth, peer, &input.window, &selector, &entity_id)?;
            let fetch = WorldPadFetch {
                window,
                selection: WorldPadSelection::PromotedWorld,
                recipient,
                known_position,
                after,
            };
            world_pad_capsule(&server.vault, peer, &fetch, Some(&admission)).map_err(missing)?
        }
        _ => return Err(AppError::invalid_params()),
    };
    let capsule = page.capsule.as_ref();
    let hexes = |keys: &[[u8; 40]]| keys.iter().map(|key| pad_wire_hex(key)).collect::<Vec<_>>();
    Ok((
        json!({
            "window": input.window,
            "world": page.world.to_hex(),
            "recipient": page.recipient.to_hex(),
            "position": capsule.map(|capsule| pad_wire_hex(&capsule.position)),
            "requiredKeys": capsule.map_or_else(Vec::new, |capsule| hexes(&capsule.required_keys)),
            "retired": capsule.map_or_else(Vec::new, |capsule| hexes(&capsule.retired)),
            "total": capsule.map_or(0, |capsule| capsule.bytes.len()),
            "digest": capsule.map(|capsule| pad_wire_hex(&capsule.digest)),
            "capsule": capsule
                .map(|capsule| base64::engine::general_purpose::STANDARD.encode(&capsule.bytes)),
            "positionMoved": capsule.is_some_and(|capsule| capsule.position_moved),
            "next": page.next.map(|next| pad_wire_hex(&next)),
        }),
        // A capsule carries pads, never a row.
        Some(Vec::new()),
    ))
}
