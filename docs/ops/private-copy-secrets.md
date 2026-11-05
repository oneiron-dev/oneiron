# Private-copy secrets

`Vault::register_private_copy_as_owner` is the native supplier for a host that
has classified an owner-provided copy as private. It takes an authenticated
owner and the ordinary `OwnerSecretRegistration` request. It returns
`PrivateCopySecret`: registration metadata and the record's actual `scN`
handle. It returns no copy of the value. The handle is read in the same writer
that registers the secret, before commit.

The host supplies the name, custody class, device-only dial, rung, bindings and
optional manifest. The door reuses ordinary owner registration, including its
live-owner check, manifest and floor checks, name/generation handling, sealed
storage, counted owner act and portable custody. It does not invent a binding
or change the copy's class to prevent model access.

## Model access

A private-copy record stores `model_reveal_allowed: false`. Ordinary new
registrations explicitly store `true`. Both the full body decoder and the
value-less admission decoder require the field; there is no missing-field
fallback. Plaintext record DTOs use schema 3 and stored sealed bodies use
schema 4. Deploy matching engine versions together; there is no old-format
reader or migration.

The common model-reveal admission rule checks this policy before consent.
Handle descriptions, reveal asks, lease collection and rereads, and marked-file
model reads use that rule. A standing reveal grant cannot override a private
copy's policy. Ordinary owner reads and authorized native effector use still
follow their existing doors. Adding a use binding does not authorize model
plaintext reveal.

## Host integration still required

This supplier does not watch the clipboard or classify pasteboard markers. The
host must route a private copy here instead of the ordinary world-text capture
path, and must not send the value to text, recall or search indexing. Failed
private capture is not permission to fall back to ordinary plaintext capture.

The host must also implement the owner's Touch ID or Mac-password viewing
step and the setting that disables that step. The engine's authenticated owner
read is not proof that an OS viewing check happened. These host slices are
not implemented by this supplier.
