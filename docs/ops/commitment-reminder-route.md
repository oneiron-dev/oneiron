# Set the owner's commitment reminder route

The route is the catalogue setting `commitments.reminder_route`. The SDK, MCP
and HTTP facade read and set it through the Setting primitive's verbs:

- `vault.settings.get` with `{"key":"commitments.reminder_route"}` returns the
  value in force (`null` when no route is set), the row that decided it and its
  revision.
- `vault.settings.set` with `{"key":"commitments.reminder_route","scope":{"kind":"vault"},"value":...}`
  stores the route; a `null` or absent `value` clears it. The answer is
  `applied` with the change's sequence, or `pending` with a check-in when an
  agent asks.

The existing CLI can call the same verbs with the owner's credential:

```sh
oneiron api call vault.settings.get --data '{"key":"commitments.reminder_route"}'
oneiron api call vault.settings.set \
  --data '{"key":"commitments.reminder_route","scope":{"kind":"vault"},"value":{"channel":"native","verb":"send","target":"OWNER"}}'
oneiron api call vault.settings.set \
  --data '{"key":"commitments.reminder_route","scope":{"kind":"vault"},"value":null}'
```

Use a channel, verb and target configured for this vault; the example is not a
new channel or delivery default. The route also carries the existing optional
`utc_offset_minutes`, `iana_timezone` and `voice` fields. `voice` may name its
`persona_ref`. The route's check is the one the owner's setter ran before.

The owner sets the key; an agent's change waits on a check-in the owner
approves, and only the owner reads it. Setting a route neither approves a
reminder nor changes an already-approved reminder. Delivery still follows its
existing proposal and approval path. Every change is one row in the settings
change stream. The stopped-vault CLI below runs the same verbs.

## Stopped-vault CLI

On a stopped vault the same verbs run shaped, reading the same config as
`serve`. The vault must be stopped: a running server answers the verbs above
instead.

```sh
oneiron reminder-route get
oneiron reminder-route set --channel native --verb send --target OWNER
oneiron reminder-route set --channel native --verb send --target OWNER \
  --utc-offset-minutes -300 --iana-timezone America/New_York
oneiron reminder-route set --channel native --verb send --target OWNER \
  --voice --persona-ref PERSONA_ID
oneiron reminder-route clear
```

`get` prints the `vault.settings.get` reply, whose `value` is `null` when unset;
`set` and `clear` print the `vault.settings.set` reply, and `clear` removes the
row. `--persona-ref` implies `--voice`. Clock fields and voice labels follow the
key's check. Setting or clearing approves no reminder and changes none already
approved.
