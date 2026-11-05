# Staged foreign window imports

`stage_foreign_vault_import` grades an offered artifact as Imported evidence and keeps its
admitted bytes until its receipt is confirmed or fails. The existing confirmation and admission
checks still apply. A source label is not proof of a peer or authority.

When classification has an `exported_vault_id`, that manifest-claimed id selects the source's
foreign WORLD namespace. The manifest is unsigned. Its id grants no membership, source-trust
grade, pact standing or permission. Without an exported id, the existing unrouted import stays
available. No active pact is required by this offline path.

An admitted artifact can span several destination windows. Pending CONTENT retains every
actual window key and its update bytes, in admission order; STAMPS retains each window's own
held-facet record. The receipt binds both complete carriers by digest. These are current-format
ordered binary pairs, not a single Loro update. There is no old raw-update reader or migration.
The existing native byte maximum applies to each actual window update, not the combined
carrier or its framing overhead. Routing into several windows adds no aggregate byte ceiling.

Confirmation validates all retained part keys, bytes, policy and facet stamps before importing
any part. It then watches births, imports and lands supplied detached bodies, and releases each
window's own staged stamps under that actual key. The original receipt records one terminal
confirmation and deletes both retained carriers in the same final receipt transaction. A later
part's error leaves the receipt Pending; it does not make earlier window imports a new atomic
multi-window transaction. Stable admitted CRDT updates retain the existing retry behavior.

The public Rust `admit_federated_window_update` door takes an optional source namespace and
returns ordered `(WindowKey, Vec<u8>)` pairs. Import every pair into its named window. Dropping
all but the first part loses admitted data.

This does not add staged born-with text or delivered-row provenance that the peer receive
path keeps separately. That pre-existing gap is tracked as physical FIX 13246.
