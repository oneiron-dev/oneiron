# Engine registry export

Run `oneiron registry` to print the engine-owned kind, family and zone tables as JSON.
The command needs no vault or configuration file. For a docs build, capture stdout:

```sh
oneiron registry > registry.json
```

The top-level fields are:

- `storage_abi_version`: the storage ABI of this engine revision.
- `kinds`: the live registered kind entries, including their byte, short-id prefixes,
  classification, family, zone and artifact kind. This does not allocate unnamed bytes.
- `families`: the live family ranges, including reserved overflow ranges.
- `zones`: each zone and its inclusive byte ranges, derived from the engine's `zone_of` rule.

Consumers should render this output instead of keeping a second allocation table.
Library callers can serialize `oneiron::registry::export::registry_snapshot()` directly;
it borrows the same kind and family tables.

WORKFLOW uses byte 43 in its declared AgentsAndSurfacing family and keeps the `wf` prefix.
This change raises the storage ABI from 24 to 25. There is no migration or old-format reader.
Use a fresh vault for the new ABI.
