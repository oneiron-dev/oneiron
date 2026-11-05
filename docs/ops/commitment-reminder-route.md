# Set the owner's commitment reminder route

The SDK, MCP and HTTP facade use these owner-bound verbs:

- `vault.commitments.reminder_route.get` takes `{}` and returns `{"route": ...}`,
  with `null` when no route is stored.
- `vault.commitments.reminder_route.set` takes `{"route": ...}` and returns that
  route after the native write succeeds. `{"route": null}` clears it.

The existing CLI can call the same verbs with the owner's credential:

```sh
oneiron api call vault.commitments.reminder_route.get --data '{}'
oneiron api call vault.commitments.reminder_route.set \
  --data '{"route":{"channel":"native","verb":"send","target":"OWNER"}}'
oneiron api call vault.commitments.reminder_route.set --data '{"route":null}'
```

Use a channel, verb and target configured for this vault; the example is not a
new channel or delivery default. The route also carries the existing optional
`utc_offset_minutes`, `iana_timezone` and `voice` fields. `voice` may name its
`persona_ref`. The native route validation is unchanged.

These verbs match the existing owner GET/PUT route at
`/v1/owner/commitments/reminder-route`. They require the owner's proof; an agent's
write capability alone is not that proof. Setting a route neither approves a
reminder nor changes an already-approved reminder. Delivery still follows its
existing proposal and approval path. The stopped-vault CLI below runs the same verbs.

## Stopped-vault CLI

On a stopped vault the same verbs run shaped, reading the same config as
`serve`. The vault must be stopped: a running server answers instead at
`/v1/owner/commitments/reminder-route`.

```sh
oneiron reminder-route get
oneiron reminder-route set --channel native --verb send --target OWNER
oneiron reminder-route set --channel native --verb send --target OWNER \
  --utc-offset-minutes -300 --iana-timezone America/New_York
oneiron reminder-route set --channel native --verb send --target OWNER \
  --voice --persona-ref PERSONA_ID
oneiron reminder-route clear
```

`get` prints `{"route": ...}` with `null` when unset; `clear` writes `null`
through the same set verb. `--persona-ref` implies `--voice`. Clock fields
and voice labels follow native validation. Setting or clearing approves no
reminder and changes none already approved.
