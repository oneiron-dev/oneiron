//! One message each way per stream, in the organ protocol's codec: the
//! exchange organ calls ride (OF-575), shared with pass 33's job protocols
//! (`oneiron/job/1`, `oneiron/job-status/1`). The asking side opens a fresh
//! stream for each request and reads one answer back; the serving side reads
//! one request from each stream it accepts and sends one answer. A message
//! stays under the transport's 1 MiB bound; larger bytes are staged by the
//! protocol that carries them.

use oneiron_organ_protocol::{from_slice, to_vec};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{MeshConnection, MeshError};

/// `value` as one mesh message, in the organ protocol's codec, which neither
/// encodes nor decodes a value by recursing over its depth. `protocol` names
/// the protocol in the error, e.g. `organ mesh`.
pub fn encode_message<T: Serialize + ?Sized>(
    protocol: &str,
    value: &T,
) -> Result<Vec<u8>, MeshError> {
    to_vec(value).map_err(|err| MeshError::Io(format!("{protocol} encode: {err}")))
}

/// One mesh message read back as `T`, which must take every byte.
pub fn decode_message<T: DeserializeOwned>(protocol: &str, bytes: &[u8]) -> Result<T, MeshError> {
    from_slice(bytes).map_err(|err| MeshError::Io(format!("{protocol} decode: {err}")))
}

/// One message out on a fresh stream of `conn`, one back.
pub async fn exchange<Q, A>(
    protocol: &str,
    conn: &dyn MeshConnection,
    request: &Q,
) -> Result<A, MeshError>
where
    Q: Serialize + ?Sized,
    A: DeserializeOwned,
{
    let mut stream = conn.open_stream().await?;
    stream.send(&encode_message(protocol, request)?).await?;
    decode_message(protocol, &stream.recv().await?)
}
