# LinkedIn Per-Seat Sandbox Harness

This is the throwaway-account harness for the first LinkedIn connector cut.
Do not develop against a member's real LinkedIn account.

## Host Shape

- One seat maps to one sandbox, one persistent browser profile, and one
  `stickerdaniel/linkedin-mcp-server` process.
- The sandbox runtime is a container by default; a microVM is an equivalent
  isolation target when the host supports it.
- Browser profile bytes stay inside the sandbox volume.
- The session cookie is referenced only as a vault-scoped secret handle such as
  `vault-secret:linkedin:<seat>:session-cookie`; never write cookie material to
  repo files, logs, comments, or shared namespaces.
- The default network route is one stable dedicated IP. Browserbase and Unipile
  remain escalation config only until flags/flakiness justify them.

## One-Time Login Handoff

1. Provision an empty sandbox for the throwaway LinkedIn account.
2. Start the MCP server with an empty persistent browser profile.
3. Open the remote browser handoff for the seat owner.
4. The owner signs in and completes 2FA. The operator never receives the
   password.
5. Close the handoff once the MCP server can read the inbox using the persistent
   profile.
6. Store only the vault-scoped cookie secret reference in connector config.

## Engine Walls

The host must pass `LinkedInSeatSandboxPolicy` into outbound dispatch. The engine
enforces these before the connector transport is called:

- default `15` DMs per day per seat
- default `25` profile reads per day per seat
- sends only when the seat session is active
- jittered cadence via `next_send_not_before`
- no sweep requests
- kill switch suppresses LinkedIn sends/connects after sandbox destruction and
  verb-catalog revocation

Profile-read tools are not yet part of the outbound verb catalog. Host code that
adds a LinkedIn profile-read MCP call must call
`LinkedInSeatSandboxPolicy::evaluate_profile_read()` before invoking the tool and
record the returned receipt fields beside the connector result.

The connector adapter must not be the only enforcement point for these walls.

## Consent Copy

Show the copy returned by `linkedin_connect_consent_screen_copy()` before the
handoff. It says in plain words that LinkedIn automation is a gray-zone account
risk, Oneiron uses the member's logged-in browser session rather than their
password, the default cap is 15 DMs/day, sweeps are blocked, and the member can
turn LinkedIn off at any time.

## Throwaway E2E Checklist

1. Create a throwaway LinkedIn account and a second recipient account.
2. Create a sandbox config with:
   - `seat_ref=linkedin:seat:throwaway`
   - `sandbox_ref=sandbox:tokyo:linkedin-throwaway`
   - `browser_profile_ref=browser-profile:linkedin:throwaway`
   - `session_cookie_secret_ref=vault-secret:linkedin:throwaway:session-cookie`
3. Complete the one-time remote-browser login handoff with the throwaway owner.
4. Run one `linkedin.send_dm` through outbound dispatch with an active
   `LinkedInSeatSandboxPolicy`; verify the receipt was delivered only after
   `get_conversation` observed the sent text.
5. Set `dm_sends_today=15`; dispatch another DM and verify the receipt is held
   with `linkedin_engine_policy_reason=linkedin.daily_dm_cap` and the MCP
   transport has zero `send_message` calls.
6. Set `profile_reads_today=25`; call the profile-read policy seam and verify it
   holds with `linkedin.daily_profile_read_cap` before any profile MCP call.
7. Set `next_send_not_before` in the future; verify dispatch holds with
   `linkedin.cadence_not_ready`.
8. Mark the request as a sweep; verify dispatch suppresses with
   `linkedin.no_sweeps`.
9. Run `run_linkedin_kill_switch`; verify the harness destroyed the sandbox,
   revoked the seat verb catalog, and later dispatch suppresses with
   `linkedin.kill_switch_engaged`.

The test harness in `crates/oneiron/tests/linkedin_connector_adapter.rs` covers
config, consent copy, secret custody, and kill-switch host calls. The outbound
unit tests in `crates/oneiron/src/outbound/tests.rs` cover engine-side cap, cadence,
no-sweep, and kill-switch enforcement before MCP transport.
