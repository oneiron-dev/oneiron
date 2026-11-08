# Name a predecessor device key

An owner can name an old device key as the predecessor of the current install.
The current install supplies its own successor identity. The request cannot
name a different successor or act as an agent.

Use `POST /v1/owner/device-successions/name` with the existing owner credential
and holder proof. The equivalent facade, MCP and SDK verb is
`vault.devices.predecessor.name`. MCP puts the input under `arguments.spec`.
Both surfaces take the same object:

```json
{
  "client": "0123456789abcdef",
  "device_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Copy `client` from the erase receipt's `att_client` and `device_key` from its
`att_pk`. They are exactly 16 and 64 lowercase hexadecimal digits. Keep the
client ID as a string; converting it to a JavaScript number can lose bits.
The key is the full public device key, not its fingerprint.

The response repeats these identifiers only after the naming act commits.
It does not say that every erase sweep has finished. The native authority door
revalidates the owner in its writer, names this install as successor, and
requeues the predecessor receipts whose sweeps still need work. Existing
native refusals, authority history requirements and receipt verification apply.

The REST route records the request's admitted machine or hosted-console
surface. Facade and MCP calls use the existing owner-bound call context. A
hosted operator root or an agent credential does not stand in for the owner.
No server configuration or rollout step is needed beyond the updated engine
and server.
