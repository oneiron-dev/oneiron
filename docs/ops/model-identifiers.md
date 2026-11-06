# Configured model identifiers

A configured `provider:wire-model` becomes the engine identifier
`provider/name@revision`. The provider key and configured provider revision stay
unchanged. The adapter still sends the original wire-model string to that provider.

The name preserves ASCII letters, digits, dots and hyphens. Every other UTF-8 byte,
including underscore, is encoded as an underscore followed by two lowercase hex
digits. Leading and trailing dots are retained. For example, `a/b`, `a.b` and
`a_2fb` have the distinct names `a_2fb`, `a.b` and `a_5f2fb`.

The same conversion builds catalog entries, configured role and media rungs, wire
model maps, and options rows. A declared embedding space uses that exact engine
identifier followed by `@provider`. Its selected model cannot collapse onto another
wire model's rung on the same provider. Locality, payer, admission, fallback order,
and the provider's wire request are unchanged.

Use the identifiers returned by the current model options/catalog when setting an
explicit engine-model alias target or declaring an embedding space. Spellings that
previously replaced punctuation with dots are not aliases for current identifiers.
No old-format model-id reader or migration is provided.
