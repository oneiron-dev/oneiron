# VM outbox companion restarts

`oneiron-vm-init` owns the companion for the serving boot. If the initially
ready companion exits, the bootstrap reaps it and starts a replacement with
the same vault, UID and PATH. It never replaces the working engine to hide
a failed companion. A boot where the companion never became ready keeps the
existing engine-without-outboxes fallback. Only that successful initial ready
handshake makes the bootstrap emit the hidden `--vm-outbox-companion-admitted`
argument. The engine carries this immutable admission into its lifecycle task;
neither a failed startup probe, a later Down probe, nor matching configured
outbox paths decide whether this boot has a companion to park.

Both Open and Restore use the existing engine-supervision cadence, including
after the input and credential senders finish. The existing 100 ms constant
is unchanged. Replacement readiness uses a nonblocking pipe; a hung start
cannot block engine exit or a lost-input shutdown. Failed attempts remain
eligible at a later tick, without an attempt ceiling or a new cooldown.

Park and Resume use an owned async Unix socket and retry on the existing
carrier rescan cadence until the matching acknowledgement arrives. The engine
reports idle only after Park is acknowledged, and retries Resume after wake
rather than leaving a restarted companion parked. Both waits hear Stop;
cancelling them closes their pending socket I/O without a detached blocking
worker. Ordinary serving continues while these lifecycle requests wait. No
new retry duration or attempt cap is added. After Park is acknowledged, the
engine reads the current off-record snapshot predicate immediately before its
idle report. A late guest lifecycle request cannot overwrite a companion's
terminal Draining mode or acknowledge a transition it did not apply. This
guard does not change the host attachment's existing drain/resume behavior.

The lifecycle endpoint records its authenticated Park/Resume and validated
backup registration in `/run/oneiron-outbox/runtime.json`, root-owned 0600.
One endpoint thread writes complete records through a same-directory rename.
The initial companion resets the boot record before the engine starts. Only
a replacement receives `--resume-state`; it requires the current record to
name the same vault and UID. It reopens the registered backup directory with
the original containment, no-follow, UID and handoff-policy checks and restores
Parked before starting the endpoint, announcing readiness or carrying work.
A fast restart between status probes therefore does not depend on observing
a Down-to-Up transition. A missing or invalid replacement record does not
silently reopen a parked carrier or discard its registration.

At engine exit the bootstrap drains an observed-ready companion as before.
An unconfirmed replacement is killed and reaped without waiting for its ready
line or an unarmed stop handler. Every owned child is reaped before the
filesystem key is removed. A child already reaped by a poll is never signalled
through its old PID.

Roll out matching rebuilt `oneiron-vm-init`, `oneiron-vm-outbox` and
`oneiron-server` in the guest image. This source change performs no image build, deployment or VM boot.
It makes no runtime, snapshot, transfer-recovery or no-hang measurement claim.
Ping still reports the last completed companion probe, not instantaneous
liveness. No protocol revision, dependency, user policy, timing value or
configuration default changes. Existing tests are untouched; no tests are
written, compiled or run under the decree.
