//! The held socket's verb RPC (OF-489 socket-first): an `rpc.req` names any
//! facade row, and it runs through the facade's one generated dispatch under
//! the credential the connection bound, meeting the admission its HTTP route
//! applies. A Write row is a write here as there. Board, browser and run rows
//! stay off the socket: the dispatch refuses each by the context it needs.
use std::future::Future;
use std::sync::Arc;

use oneiron::EntityId;
use serde_json::Value;

use super::AppError;
use crate::auth::CoreAuth;
use crate::protocol::ProtocolError;
use crate::server::SyncServer;

/// Runs facade verb `method` over `params` as `auth`'s call. Beside the
/// result come the rows it carries, for the send door to judge again
/// (DEC-0005): those its reads listed, and those its input and its result
/// name by ref. `None` when one of them is unknown, so the result does not
/// leave this device.
pub(super) async fn run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    method: &str,
    params: Value,
) -> Result<(Value, Option<Vec<EntityId>>), AppError> {
    let mut input_rows = Vec::new();
    let input_named = named_rows(server.vault(), &params, &mut input_rows);
    let call = crate::api::FacadeCall::bound(auth, None);
    let output = crate::api::facade_call_verb(server, &call, method, Ok(params)).await?;
    let rows = output.rows.and_then(|mut rows| {
        input_named?;
        named_rows(server.vault(), &output.value, &mut rows)?;
        rows.append(&mut input_rows);
        Some(rows)
    });
    Ok((output.value, rows))
}

/// Lists in `rows` each row `value` names by ref: a whole id, or a short
/// ref, keys included. `None` when a short ref names no row.
fn named_rows(vault: &oneiron::Vault, value: &Value, rows: &mut Vec<EntityId>) -> Option<()> {
    rows.extend(crate::device_local::short_refs_named(vault, value)?);
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => rows.extend(EntityId::from_hex(text).ok()),
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => {
                for (key, item) in map {
                    rows.extend(EntityId::from_hex(key).ok());
                    pending.push(item);
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// Runs `call` to its answer from the app tier's synchronous RPC door, until
/// the owner loop completes calls off the loop (L03's seam):
/// [`crate::server::blocking`] leaves this socket's worker first, so every
/// other task keeps a worker while this socket waits, and the call runs on
/// the server's own runtime. Outside any runtime, a runtime of its own runs
/// it.
pub(super) fn blocking<T: Send>(
    call: impl Future<Output = Result<T, ProtocolError>> + Send,
) -> Result<T, ProtocolError> {
    let runtime = tokio::runtime::Handle::try_current().ok();
    crate::server::blocking(move || match runtime {
        Some(runtime) => runtime.block_on(call),
        None => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProtocolError::InvalidPayload("no runtime answers this RPC"))?
            .block_on(call),
    })
}
