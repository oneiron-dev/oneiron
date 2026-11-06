# Transfer a published host issuer seed to a synced install

A synced replica can have the vault's authority rows without a local custody head
or a `HostIssuerSeed` keystore slot. World-pad unlock alone does not transfer that
seed. Restoring a checkpoint already has its own custody recovery path; it is not
necessary to restore over a working replica just to import the seed.

Native owner callers can use `Vault::transfer_published_issuer_seed_as(owner,
lineage, recovery)`. `lineage` is the exact published custody vault and namespace,
not the replica's local binding. `CustodyRecovery` selects the existing folder or
fetched source, optional anchor and kit/machine openers. The local data-key custody
subkey is also used when available. A machine world-pad opener alone does not open
the head's control/host-readable compartments. No opener or recipient is invented.

The existing custody admission authenticates the selected complete head, source
lineage, configured anchor and intervening log, including retirements after the
head. With no configured anchor it retains the existing rollback-not-proven note.
The current local owner is checked before this read. Only live `HostIssuerSeed`
entries are retained as candidates; all other admitted custody stays uninstalled.

A candidate is escrowed into the replica's current local custody only when its
issuer matches this vault's live root in the current authority fold. That check
and owner-proof revalidation run in the SAME writer as the escrow, before binding
or entry publication. A stale or foreign root is not installed. Existing identical
seed bytes keep their generation; nothing is derived from a device key, vault ID
or configured secret. The source namespace, control secret, writer epoch and
retirement ledger are not copied over the replica's local custody.

The existing `prepare_host_issuer_custody_logged` pass then runs unchanged. It fills
only an empty this-install slot, with a seed of the current root; a filled slot is
not replaced and no successor is minted. A host without a keystore, or with no
matching candidate, keeps its existing rootless behavior and logs the condition.
The report contains candidate/publication/already-held/not-selected counts and the
custody note, never seed bytes, and does not claim signing readiness. A later error
does not undo earlier committed escrows; the ordinary idempotent escrow permits
retry. No CLI, HTTP, SDK, implicit sync transfer or restore behavior changes here.

Deploy the matching authorized engine/server revision for this native API. This
change does not run a transfer, read a native key, alter settings or deploy a host.
