//! Owner-grade canonical read of a delivered proactivity digest.

use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::digest::{DigestReadRequest, ProactivityDigestView};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_proactivity_digest_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DigestReadRequest,
) -> MaybeListed<Option<ProactivityDigestView>> {
    const VERB: &str = "vault.proactivity.digest.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            let id = digest_id(&input.id).ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_BAD_REQUEST,
                    "id must be a 64-hex digest id",
                    &[],
                )
            })?;
            Ok(server.vault().proactivity_digest_view(&owner, id)?)
        },
        |_| None,
    )
    .await
}

fn digest_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut id = [0_u8; 32];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(id)
}
