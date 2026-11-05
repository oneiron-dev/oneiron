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

## Mac owner-view backend

The Mac app registers three macOS-only owner commands:

- `private_copy_view(handle, reason)` returns the actual owner-read value as a
  JSON byte array and a receipt containing its reveal id, handle, Gate decision
  and delivery time. Binary values are not forced through UTF-8.
- `private_copy_view_settings()` reads the device-local viewing override.
- `set_private_copy_view_settings(skipAuthentication)` changes that override
  after taking the vault's writer lease and proving the live local owner.

The single `NSUserDefaults` key `PrivateCopySkipAuthentication` defaults to
false. Unless the owner explicitly skips it, each view requests macOS
`deviceOwnerAuthentication`: Touch ID **or** the Mac password. Failure or
cancellation returns no value. A fresh `LAContext` is used for that request;
there is no app-level authentication cache, grant or timeout. Changing the
setting does not require an additional OS confirmation.

No owner-act mutex, vault writer lease or transaction is held during the OS
dialog. The view then takes a fresh owner-act lease and proves the owner through
the existing native owner door. Its final preference check and reveal share
one mutex with setting writes, so re-enabling authentication cannot race an
unchecked view through that setter.

The native wiping value moves into the owner reply and is borrowed during
serialization. It is not logged, given a plaintext `Debug` implementation or
added to an agent verb. The serialized owner response necessarily contains the
value; this does not claim that renderer memory is wiped. These are backend
commands, not a new view panel or a capture watcher. Build and ship the matching
macOS app to use them; a Linux workspace compile does not exercise the native
authentication binding.

## Capture integration still required

This supplier does not watch the clipboard or classify pasteboard markers. The
host must route a private copy here instead of the ordinary world-text capture
path, and must not send the value to text, recall or search indexing. Failed
private capture is not permission to fall back to ordinary plaintext capture.

Other hosts must implement the owner's viewing step themselves. The engine's
authenticated owner read alone is not proof that an OS viewing check happened.
Private marker classification, the private capture adapter and its common
watcher integration remain separate from this Mac owner-view backend.
