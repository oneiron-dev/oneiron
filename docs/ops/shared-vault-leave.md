# Shared-vault leave checks on observed sync runs

`SyncConnection::check_shared_leave(vault_id, member)` remains the manual
check. It asks the configured home with the connection's transport credential.
Leave requests carry credentials only over HTTPS or HTTP on a numeric loopback
address. A configured mesh dialer does not exempt this HTTP request, which uses
reqwest rather than that dialer. Redirects are not followed.
A failed request, a refused request or an unverified answer is never a leave.
Only an outcome verified against the environment's trusted home root and the
expected shared-vault id and member can end the lane.

## Automatic checks for a configured shared replica

A host can use `SyncConnection::run_observed_with_shared_leave` instead of
`run_observed` when it knows the shared vault and member that this environment
holds. It takes the same explicit target as the manual check. The target is
configuration data, not a new Owner credential or proof of membership.

The method keeps the original observed connection loop and event callback.
Each actual `Connecting` event schedules a leave check alongside that loop.
Only one request runs at a time. Attempts during a request coalesce into a
follow-up check. No periodic timer or new connection preflight is added.
An unavailable or refusing notice endpoint does not delay or refuse the dial.

The separate `on_leave` callback receives every completed check:

- `Ok(None)`: no verified leave notice was found.
- `Ok(Some(receipt))`: the native leave confirmation returned its receipt.
- `Err(error)`: the request, verification storage read or verified purge failed.

A verified notice stops the lane before the original native confirmation
counts discarded unsynced edits and purges the shared replica. A purge error
does not undo that verified leave or allow a reconnect. The existing purge,
receipt ownership and kept-entity rules are unchanged.

If the connection loop ends during an unverified request, the request is
cancelled. Once a notice is verified, its confirmation is kept alive beside
the same driver until both activities finish. Its receipt or error still
reaches `on_leave` if the driver has already ended. The method returns the
original connection-loop result. Dropping the whole future cancels both
activities; it does not create a detached completion task.

## Scope and remaining work

The existing `run`, `run_observed`, `ConnectionConfig` and manual check keep
their behavior. This API does not derive a member PERSON from a MACHINE,
server label, world list, unverified token or authority-vault byte array.
First-party device-sync adoption still needs a qualified shared-vault/member
target supplier and is not claimed here.

The existing ten-second leave-quiescence timeout is unchanged. If the lane
has not stopped when it expires, the native confirmation returns an error
before binding a receipt, counting or purging. The verified leave still stops
new connects. Leave deletion remains best effort. A personal vault is not the
shared replica to pass to this method, and removing a member does not erase
company-owned claims at the home.
