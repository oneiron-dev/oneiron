# Authenticator-app step-up

MFA is optional for a person. Passkeys are the first choice; an RFC 6238
TOTP authenticator app is the second choice (MFA-1 A). A weave Admin needs
a current step-up on the exact human credential that makes the request.

## Enroll and use

Use the person's own live, untransferred, undelegated slip on every request.
The core doors use read scope, like the passkey ceremonies. They do not grant
record access or owner authority.

1. `POST /v1/core/step-up/totp/enrollment` with no body starts enrollment.
   The response contains `enrollment_id`, `secret`, `algorithm`, `digits`,
   `period_secs` and `expires_at`. `secret` is unpadded base32. Construct the
   authenticator's `otpauth://totp/` URI with this secret and the desired account
   label and issuer. The response is `Cache-Control: no-store`. Do not log,
   cache or persist the provisioning secret in the client after enrollment.
2. `POST /v1/core/step-up/totp/confirm` with
   `{"enrollment_id":"...","code":"..."}` confirms the first six-digit code.
   It consumes that code's matched step and records step-up on this exact slip
   in the same writer. Until confirmation the seed is only pending; an existing
   authenticator remains enrolled. Pending enrollment has the same 300-second
   authority-clock lifetime as a passkey enrollment challenge.
3. `GET /v1/core/step-up/totp` lists enrolled metadata only. It never returns
   a seed or a sealed seed.
4. `POST /v1/core/step-up/totp` with the same code input steps up another
   admitted own slip using a later code. A code step already consumed during
   confirmation or on any other slip cannot be spent again.
5. `POST /v1/core/step-up/totp/remove` with `{"enrollment_id":"..."}` removes
   that enrolled or pending authenticator. It invalidates that factor's step-ups
   and stages retirement of its erasable seed key in the same writer.

The profile is HMAC-SHA1, six decimal digits, T0 = Unix epoch, 30-second steps,
and a one-step drift window on each side. The verifier reads the store's Unix
wall clock, not its authority observation floor. It returns the actual matched
step, and the enrollment's spent-step floor only advances. Authority timestamps
and pending expiry still use the existing authority clock.

A first factor can be enrolled on the person's own live slip. If a passkey or
confirmed authenticator is already enrolled, adding or removing a factor needs
a current step-up on that slip. Starting enrollment does not bypass this check
at confirmation. Multiple authenticators may be enrolled. No new factor count,
retry cap, periodic job, or successful-step-up timeout is introduced.

## Recovery and erasure

`vault.step_up.totp.reset` takes `{"person":"<32 hex>"}` under the vault owner's
real proof, revalidated in the same writer. It removes that person's pending and
confirmed authenticators and TOTP step-ups, but preserves their passkeys and
passkey-derived step-ups. `vault.step_up.passkeys.reset` remains passkey-only.
Neither reset silently resets the other factor.

Both factors use the original `StepUpRecord`, keyed by the admitted slip. A
TOTP record names the exact enrollment, never a second authority ledger. Its
Admin witness stands only while the slip and person remain live and that exact
enrollment and its custody leaf remain live. Removing or resetting a factor
cannot revive its records by later enrolling another factor.

The seed is random 32-byte material, held in wiping memory and returned only for
provisioning. Pending and confirmed rows keep only an authenticated sealed seed,
key reference, and metadata. The native envelope binds the actual person,
enrollment, key reference and TOTP domain. Its independent erasable custody leaf
uses `ErasablePurpose::TotpEnrollment`; the key is journaled before its row commits.
An actor erase deletes both table families and stages every enrollment leaf,
including an aborted writer's orphan. The existing custody finisher carries out
retirement after commit. No seed is stored in plaintext or restored by reminting
a retired key. Both side-table families are `LIVE` on checkpoint restore: image
rows cannot roll back enrollment, reset or spent steps.

No migration or old-format reader is provided.
