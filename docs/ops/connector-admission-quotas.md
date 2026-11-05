# Connector admission quotas

Connector admission policy rows accept positive values representable as the
host's `usize` for `max_tools`, `max_permissions_per_tool` and
`max_triggers_per_tool`. Values above 4096 are valid; the decoder no longer
imposes that upper bound. Zero and non-integer values remain invalid.

These values are advisory asking points for connector admission, not the
independent codec safety bounds on persisted connector bodies. The existing
owner policy-edit authority and connector counters are unchanged.

Defaults remain 256 tools, 128 permissions per tool and 128 triggers per tool.
Repeated rows still narrow each value, and a holder's effective values remain
narrowed by the vault's row. This change adds no default, permission, refusal,
policy row or public verb.
