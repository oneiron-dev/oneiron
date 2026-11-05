# Checkpoint host-order recipient delivery

Managed vaults seal a checkpoint's host-order hold family only to the public
recipient their supervisor pinned and delivered. This is not a data key,
owner credential, custody-anchor credential, or a new authority grant.

## Managed process

Pass `--checkpoint-host-holds-recipient-fd P` to `oneiron serve` in managed
mode. `P` is the read end of an anonymous pipe. Before starting the child,
write exactly one JSON object and close that same pipe's write end:

```json
{"bundle_b64":"<standard-base64 ONHB public bundle>","fingerprint":"<full-bundle SHA-256 as 64 hexadecimal digits>"}
```

The ONHB bundle contains the recipient's nonzero epoch. The engine takes the
epoch from that actual frame, calls the native `HostHoldsRecipient::new`
validator, and compares its full-bundle id with the delivered fingerprint.
The supervisor supplies the pinned binding; two matching public values from
an owner setting, environment variable, or untrusted request are not authority.

`P` must be distinct from the credentials, ready, custody-anchor, restore
input, restore result, and inherited listening descriptors. Resolution checks
these aliases before adoption. The host owns the adopted descriptor, sets
close-on-exec, consumes the object once before opening or restoring storage,
and closes it on decode or startup exit. Do not leave its writer open: EOF is
part of the delivery contract, not an independently forwarded background job.

Without a pipe, or when its public material is malformed, unusable, or does
not match its fingerprint, the vault still starts. Its configuration is
explicitly `RecipientMissing`, so checkpoint receipts report
`recipient_missing` rather than claiming a sealed member. Diagnostics never
print the delivered object. A negative or aliased descriptor remains an
existing descriptor-ownership error, not a missing-recipient fallback.

## Vault VM

Native host profiles require `checkpoint_host_holds_recipient`: either the
same public object or `null`. Before encoding the provision prelude, the
host validates that actual `VaultVmConfig` material through the same native
ONHB and fingerprint checks. Unusable material becomes `null` with a
content-free diagnostic, so even an oversized invalid string cannot veto
startup at the frame encoder. The guest must echo that exact normalized
prelude. It still precedes the unchanged 64-byte fscrypt key frame. Provision
revision 2 requires that field in both the prelude and the guest's exact echo.
No revision-1 reader is retained. Provision preludes, revision peeks and
replies use their own frame budget: the original 1 KiB binding/reply allowance
plus the fixed ONHB/base64, fingerprint and JSON-field geometry. Both readers
and codecs use that budget; ordinary boot/lifecycle frames keep their 1 KiB
bound. A valid recipient must not be rejected by that unrelated smaller bound.

For both open and cold-restore starts, the bootstrap validates the public
material, writes a private pipe without waiting for a child reader, closes
its writer, and explicitly maps the reader into the engine with the managed
flag. Its still-open reader has a distinct descriptor from the anchor and
restore pipes. The bootstrap drops its copy as soon as spawning finishes;
the engine owns and consumes its copy. Unusable public material or an
unavailable optional pipe keeps the same `RecipientMissing` behavior. An
inspection starts no engine and creates no recipient pipe. Snapshot restore
resumes the already-open engine configuration; it is not another cold
provision exchange or a recipient refresh.

## Rollout and scope

Deploy only a matching host, engine, bootstrap, and rebuilt image at this
change's actual merged build floor. Newly built image manifests advertise
`provision_revision = 2`. The shared supervisor contract stays 3. Outbox,
restore, and guest protocol revisions are unchanged. Existing pinned release
recipes still describe the images they actually built; changing this source
does not repin or rebuild them.

An external supervisor must publish and deliver its actual pinned public
recipient. This engine change does not create or select an operator key,
retrofit old checkpoints, implement a Hypnos publisher, or prove a restored
host-order family was consumed. Missing-recipient starts, existing host
orders, backup receipts, custody, and restore precedence are preserved.
