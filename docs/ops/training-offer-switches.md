# Stock training-offer switches

An owner-approved stock switch keeps the previous model binding in its switch
receipt. The ordinary owner approval, offer digest, incumbent and registry-pin
checks remain the switch's admission path. Training candidates still need their
separate explicit training approval.

## Applied-switch inbox notice

A non-embedder switch records a `Finding` notification for each current vault
owner in the same write as its binding and switch receipt. An embedder switch
records the notification only when its staged space move applies the binding;
waiting, filling and not-applied moves do not announce an applied switch.
The staged move's raw-transaction owner explicitly signals notification readers
after its successful concluded commit; uncommitted or still-filling writes do
not send that signal.

The notification source is `coach.training_offer.switch`. Its `result` and sole
subject reference name the training offer. Its event identity combines the offer
and recipient, so a repeated record preserves seen and acknowledged state and
never recreates a deleted notice. The event time is the binding's application
time, not the time the original staged offer was approved.

The notification's `actions` list offers the existing
`vault.coach.training_offers.undo` verb with the offer id. It is computed when
this owner reads the notice, using a live owner proof and the current switch
receipt and manifest in one read transaction. An already-undone switch, a
non-applied switch, a changed binding, or a caller without owner authority offers
no tap. The notice itself grants no authority.

A client can render that registered action without inventing an undo endpoint.
The undo door still revalidates the owner, binding and staged space move when
called; listing an action does not reserve the binding against later changes.

## Remaining policy work

This notice does not enable automatic stock-switch approval or automatic model
downloads. The persisted off-by-default owner setting, native comparison and
availability join, and download-card-once behavior remain open. A sufficiency
card is not a download card. Later promise checks and the staged embedder's old
serving index remain unchanged.
