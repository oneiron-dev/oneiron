# Wasabi Snapshot Credential Runbook

Vault snapshots must survive account or provider compromise. Upload and restore
run on a bucket-scoped, non-destructive Wasabi credential whose value lives only
in secret custody, so the snapshot path never carries the root credential and
restore drills stay provable.

This runbook is the operator procedure for that credential: preflight, mint,
custody registration, smoke, root retirement, and rotation.

**Nothing in this document has been executed by the change that introduced it.**
Every provider-side leg below is a live operator step. Fields marked
`NOT-EXECUTED-HERE` are placeholders an operator replaces with an observed
readback at the time they run the step. An unfilled placeholder means the step
has not been done — it never means the step passed.

No secret material belongs in this file, in the repository, or in any log,
receipt, or ticket comment. The repository references the credential by custody
name only.

## 1. Live Preflight Readback

Run this before minting anything. The point is a readback: read each fact back
from the provider and record what was observed, rather than restating what was
intended.

Target facts:

| Fact | Required value | Observed | Read back at |
| --- | --- | --- | --- |
| Bucket | `oneiron-snapshots-tokyo` | `NOT-EXECUTED-HERE` | `NOT-EXECUTED-HERE` |
| Region | `ap-northeast-1` | `NOT-EXECUTED-HERE` | `NOT-EXECUTED-HERE` |
| Versioning | enabled | `NOT-EXECUTED-HERE` | `NOT-EXECUTED-HERE` |
| Object Lock | enabled | `NOT-EXECUTED-HERE` | `NOT-EXECUTED-HERE` |

Checklist:

1. Read the bucket back by name and confirm it resolves in `ap-northeast-1`.
   A bucket in another region is a stop: do not proceed, do not "fix" it by
   widening the credential's region scope.
2. Read the versioning state back. Versioning must be enabled before any
   snapshot write, so an overwrite adds a version instead of replacing history.
3. Read the Object Lock state back. Object Lock must be enabled on the bucket.
   Record the mode and default retention actually observed.
4. Record each observation with the timestamp it was read, and replace the
   placeholders above in the operator's copy of this record.

If any fact reads back other than required, stop here. The credential is minted
against a bucket whose non-destructive posture has already been proven, never
against one that is expected to be fixed later.

## 2. Least-Privilege Sub-User Policy Shape

The snapshot path gets its own sub-user, not a shared or administrative
identity.

- Sub-user: `oneiron-snapshots-tokyo-serve-v1`.
- Exactly one access key exists on that sub-user at a time. A second live key
  on the same sub-user is an incident, not a convenience.
- The policy is a bucket allowlist naming `oneiron-snapshots-tokyo` and nothing
  else.

Forbidden in the policy, without exception:

- no `s3:Delete*` of any kind;
- no bucket administration (no bucket create/delete, no policy, ACL,
  versioning, lifecycle, or Object Lock configuration writes);
- no `iam:*`;
- no `s3:BypassGovernanceRetention`;
- no wildcard resource outside `arn:aws:s3:::oneiron-snapshots-tokyo/*`.

Bucket-level list actions name the bucket ARN itself
(`arn:aws:s3:::oneiron-snapshots-tokyo`), which is an exact resource, not a
wildcard. Object actions name `arn:aws:s3:::oneiron-snapshots-tokyo/*`. There is
no third resource.

Shape of the attached policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SnapshotObjectPutGet",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::oneiron-snapshots-tokyo/*"
    },
    {
      "Sid": "SnapshotBucketList",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": "arn:aws:s3:::oneiron-snapshots-tokyo"
    }
  ]
}
```

`s3:AbortMultipartUpload` is present because a resumable multipart upload must
be able to discard its own in-flight parts. It is not an `s3:Delete*` action and
cannot remove a completed object or a version. If a future need looks like it
requires a delete verb, it does not: it requires a lifecycle policy set by an
administrator out-of-band, which this credential must never be able to write.

## 3. Mint With Compensation

The mint is a two-phase step: the key only becomes real once custody holds it.

1. Mint exactly one access key on `oneiron-snapshots-tokyo-serve-v1`.
2. Receive the key material into zeroized buffers. Do not print it, do not echo
   it to a terminal, do not write it to a file, a clipboard manager, a shell
   history, a password prompt log, or a ticket. It exists in memory and in
   custody, nowhere else.
3. Register it into custody immediately (section 5), in the same operator
   session, without an intervening step.
4. **Compensation:** if custody registration fails for any reason — an error, a
   crash, an interrupted session, or an operator who is no longer certain the
   registration completed — deactivate the minted key immediately at the
   provider, then start over from step 1. A minted-but-unregistered key is an
   orphan credential with no custody home; deactivating it is the only correct
   outcome, and doing so is never "wasting" a key.
5. Scrub the buffers and confirm no copy of the value survives outside custody.

## 4. Snapshot Credential Smoke

The operator runs this live and by hand, using the key in memory (or a fresh
custody lease) — it is external to the test suite and is never asserted as
executed by the repository.

1. **Namespaced put/get with digest compare.** Write a tiny object under a
   dedicated smoke prefix (for example `smoke/<utc-timestamp>`), read it back,
   and compare digests of the written and read bytes. Equal digests prove the
   put and get legs of the credential end to end.
2. **Cross-bucket denial.** Issue the same request against a bucket other than
   `oneiron-snapshots-tokyo` and confirm it is denied. An allowed cross-bucket
   request means the allowlist is not what section 2 requires: stop, deactivate
   the key, and re-cut the policy.
3. **Policy readback.** Read the attached policy back from the provider and
   confirm no delete action appears anywhere in it — not `s3:DeleteObject`, not
   `s3:DeleteObjectVersion`, not a `s3:Delete*` wildcard, and not
   `s3:BypassGovernanceRetention`. The absence is the proof; do not infer it
   from the policy that was intended to be applied.
4. **The smoke object may remain.** Do not clean it up. Wasabi bills a 90-day
   minimum storage duration per object, so deleting a smoke object early saves
   nothing, and the credential has no delete permission anyway. A leftover
   smoke object under a known prefix is the expected end state.
5. **Never add a delete permission to make cleanup convenient.** That inverts
   the entire posture of this credential.

Record the run: what was put, what digest matched, which cross-bucket target was
denied, and that the policy readback showed no delete actions.

## 5. Custody Registration

Register the value through the merged custody API (ONE-1919), never into a
config file, environment variable, or deployment secret store of its own.

- Custody name: `oneiron-snapshots-tokyo-serve-v1` — the same name as the
  sub-user, so the provider identity and the custody record cannot drift apart.
- Class: `CustodyPortable` (wire `custody-portable`).
- Binding: effector `ops-serve:wasabi-snapshot`, tier ceiling `T1Leased`,
  scopes `put`, `get`, `multipart`.
- Status at registration: active, rotation generation 0.

The repository stores the custody name as a reference and nothing else. No key
component, no value byte, and no credential manifest enters the repository.

The custody contract is pinned by
`crates/oneiron/tests/it/wasabi_snapshot_custody_binding.rs`, which registers a
record built from fixed synthetic bytes and asserts the name resolves, the
binding grants exactly `put`/`get`/`multipart` at `T1Leased`, and the metadata
read carries no value field. That test touches no network and no provider.

## 6. Root Credential Retirement

Once the scoped credential is registered and smoked:

1. Remove the root credential from the active snapshot path entirely. No
   snapshot upload, restore, or drill may reference it.
2. Keep the root credential in owner-only cold custody. It is an account-
   recovery and administration credential, not an operational one.
3. Confirm the retirement by readback: the snapshot path resolves only
   `oneiron-snapshots-tokyo-serve-v1`, and a search of the deployment surface
   turns up no remaining root reference.

A compromise of the snapshot path after this point yields a bucket-scoped,
non-destructive credential — it cannot delete history, cannot reconfigure the
bucket, and cannot reach the account.

## 7. Rotation Facts

Two provider facts govern rotation economics, and neither is negotiable by
policy:

- **90-day minimum storage duration.** An object deleted before 90 days is still
  billed for the remainder of the 90 days. Early deletion buys nothing.
- **1 TB minimum monthly billing.** Storage below 1 TB is billed as 1 TB, so
  keeping an overlapping generation of snapshots during rotation is usually
  free in practice.

Rotation procedure:

1. Mint the next generation as its own sub-user (`...-serve-v2`) with the same
   policy shape from section 2, and register it under its own custody name
   following sections 3 and 5.
2. Overlap: both credentials are valid while the snapshot path cuts over. Run
   the section 4 smoke on the new credential before retiring the old one.
3. Verify a restore drill against the new credential.
4. Only then deactivate the previous generation's single access key at the
   provider.

Rotation never depends on deleting objects early, and never on a delete
permission being granted temporarily. If a rotation plan needs either, the plan
is wrong.

## Boundaries

- **Snapshots execute inside the vault process (ONE-1578).** The node supervisor
  never receives this credential and never needs to. Anything that would hand
  the value to a supervisor, a sidecar, or a build step is out of bounds.
- **SECRET-02 is not a mint gate.** Materializing the value at `T1Leased` for a
  running snapshot service is SECRET-02's door. The credential can be minted,
  registered, smoked, and rotated by this runbook without it.
- **Custody is the only home.** Every step above assumes the value exists in
  exactly one place. If that stops being true at any moment, deactivate the key
  and start over rather than tracking down copies.
