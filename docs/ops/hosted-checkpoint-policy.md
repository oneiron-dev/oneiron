# Hosted checkpoint signing

Normal hosted vaults use their eligible host root for checkpoint attestations.
Users do not configure checkpoint signing or perform a signing step.
This implements the QUORUM-HOST-ROOT=C owner ruling.

## Operator declaration

A managed supervisor declares cloud hosting with the existing
`--privacy-posture managed` argument. The engine applies it before opening the
vault and before bootstrapping authority. An omitted declaration retains
`self-host`, including existing managed-device starts. Supervision, delivered
key custody, a VM, and a device-sync connection do not declare cloud hosting.
A blind relay cannot accept supervisor-delivered data-key custody; the existing
native privacy validator still enforces that pairing.

The supervisor supplies its existing absolute, durable `--keystore-dir` outside
the vault. On Unix the native backend creates a private directory and stores
create-only slots keyed by the actual vault and install identities. A fresh,
unstarted vault draws an independent host-issuer seed once. Restarting an
existing authority loads its retained seed; it never draws a replacement root.
No supervisor or customer sends seed material through these arguments.

A fresh Hosted bootstrap records its root as `CloudCustodial` with `ROLE_CLOUD`.
An explicitly hosted start must have a usable issuer before workers start or
ready is signaled. This includes ordinary Hosted serving as well as managed
startup. Hosted issuer provisioning does not require a customer's auth secret. A missing issuer returns the existing typed error, rather
than serving rootless as normal hosted checkpoint service. A normal hosted
issuer must also be eligible under the effective checkpoint policy. This does
not relabel an existing Software root, change a pairing pin, or reseed authority.
Non-hosted supervision retains its existing rootless-warning behavior.

## Enterprise or advanced opt-out

The operator may explicitly grant a particular hosted vault the advanced
capability with `--managed-checkpoint-host-opt-out`. Its runtime setting is
`allow_host_checkpoint_opt_out`; it defaults to false. It is not part of the
owner's settings file, request body, headers, or credential claims.

With that capability, the existing authenticated owner checkpoint-policy door
can select roots and quorum, including a policy without the host. Enabling the
capability does not select a policy or remove a root by itself. Owner proof,
writer revalidation, root eligibility, quorum floors, hardware rules, revision
checks, and signing are unchanged. Clearing a choice remains available.

Without the capability, a hosted owner cannot select a custom signing policy.
The owner policy view reports `selection_available: false`, so settings surfaces
do not offer those controls. The effective hosted policy also ignores otherwise
valid owner choices received in authority history from another install. It uses
the normal host policy instead; the signed choices and conflict history remain
intact. The view does not label an ignored choice as the policy in force.
Self-host and relay owners retain their existing selection behavior.

Checkpoint image construction and countersign receipt checks use the same
native effective-policy resolver. Existing checkpoint and authority formats,
quorum constants, signatures, pairing pins, and history are not rewritten.

## Rollout boundary

Deploy matching engine and server binaries. The cloud supervisor must actually
supply the operator's cloud declaration and any per-vault advanced entitlement.
Its existing per-vault keystore-directory argument is sufficient and should be
retained. Adding the engine consumer alone does not prove that the cloud
producer was deployed, that a checkpoint ran, or that every managed vault is
Hosted. No guest, worker-Python, compatibility, or migration step is added here.
