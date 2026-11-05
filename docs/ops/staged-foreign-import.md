# Staged foreign window imports

`stage_foreign_vault_import` grades an offered artifact as Imported evidence and keeps its
admitted bytes until its receipt is confirmed or fails. The existing confirmation and admission
checks still apply. A source label is not proof of a peer or authority.

When classification has an `exported_vault_id`, that manifest-claimed id selects the source's
foreign WORLD namespace. The manifest is unsigned. Its id grants no membership, source-trust
grade, pact standing or permission. Without an exported id, the existing unrouted import stays
available. No active pact is required by this offline path.

An admitted artifact can span several destination windows. Pending CONTENT retains every
actual window key, its exact update bytes and the born-with text admission allowed beside
its rows, in admission order. CONTENT uses ordered three-field parts; STAMPS retains each
window's own held-facet record in ordered two-field parts. The receipt binds both complete
carriers by digest, including CONTENT's born-with text. Neither carrier is a single Loro update.
There is no old CONTENT or raw-update reader or migration; matching engine code is required.
The existing native byte maximum applies to each actual window update, not the combined
carrier or its framing overhead. Routing into several windows adds no aggregate byte ceiling.

Confirmation validates all retained part keys, bytes, policy and facet stamps before importing
any part. It records peer-origin rows recomputed from that same admitted part before the
import, watches births, imports and lands supplied detached bodies, then keeps the admitted
born-with text beside each landed row of the expected kind. It releases each window's own
staged stamps under that actual key. The original receipt records one terminal
confirmation and deletes both retained carriers in the same final receipt transaction. A later
part's error leaves the receipt Pending; it does not make earlier window imports a new atomic
multi-window transaction. Stable admitted CRDT updates retain the existing retry behavior.

The public Rust `admit_federated_window_update` door takes an optional source namespace and
returns ordered `(WindowKey, Vec<u8>)` pairs. Import every pair into its named window. Dropping
all but the first part loses admitted data.

The offline source label, manifest id and owner confirmation do not prove an authenticated
peer, grant, pact or epoch. This path therefore records no pact delivery intents or attribution.
That part of physical FIX 13246 remains separate from the retained born-with text and
peer-origin recording. Detached-body waiting and later delivery behavior are unchanged.
