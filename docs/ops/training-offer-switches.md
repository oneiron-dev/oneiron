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

The notification source is `coach.training_offer.switch`. Its `result` and sole
subject reference name the training offer. Its event identity combines the offer
and recipient, so a repeated record preserves seen and acknowledged state and
never recreates a deleted notice. The event time is the binding's application
time, not the time the original staged offer was approved.

The existing `vault.coach.training_offers.undo` owner door takes the offer id.
Undo still requires a live owner proof and refuses to overwrite a binding that
changed since the switch. The notice does not itself grant that authority or
change a consumer's rendering.

## Remaining policy work

This notice does not enable automatic stock-switch approval or automatic model
downloads. The persisted off-by-default owner setting, native comparison and
availability join, and download-card-once behavior remain open. A sufficiency
card is not a download card. Later promise checks and the staged embedder's old
serving index remain unchanged.
