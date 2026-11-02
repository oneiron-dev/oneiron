# A relay room's locker

`oneiron host relay --config <profile.json>` runs one relay room for a vault. The pinned
iroh-relay forwards the encrypted transport; this process keeps only a ciphertext locker for that
vault and the room's access token. It holds no engine, vault key or document, and relay admission
is never vault authority. TLS and public routing belong to the edge.

Every locker route takes the room's access token, from the profile's `access_token_file`, as
`Authorization: Bearer <token>`; without it the answer is 401. A path that names another vault,
or an object that is not `manifest` or a 64-hex id, is 404.

| Route | What it answers |
|---|---|
| `GET /v1/relay/{vault}/locker` | The stored objects, each `{"id", "bytes"}`, by id. |
| `GET`, `PUT`, `DELETE /v1/relay/{vault}/locker/{object}` | Reads, writes or deletes one object. A body is at most the profile's `max_object_bytes`. |
| `GET /v1/relay/{vault}/bytes` | `{"received", "sent"}`: the locker's bytes since the room started. |
| `GET /v1/relay/{vault}/pressure` | The locker's connection pressure check (FIX 7739). |

## Connection pressure

The locker serves on its own listener, with no descriptor floor and no clock on a request. The
room counts its open connections, and each request body the access token let in, from its first
byte to its last. While the open connections are as many as a vault's public listener holds at
its descriptor floor (`[limits] max_connections` as it defaults on this machine), the check is
raised and logged once; it clears below that.

`GET /v1/relay/{vault}/pressure` answers `{"state": "clear"}`, or `{"state": "active", "check":
{...}}` with the same fields a vault server's own pool check has. For the locker `reserve_bound`
and `parking_bound` are `0`, and the `remedy` says what to do: if the open uploads are not the
room's own devices, rotate the room's access token file and restart the room. The check only
observes: nothing waits, and no upload or connection is cut or refused.
