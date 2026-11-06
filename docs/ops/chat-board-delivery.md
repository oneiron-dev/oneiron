# Chat board rider delivery

A live chat turn hydrates its board before its user witness and final answer
opening. Its lifecycle rider is carried as an owned `ChangedLine` beside the
board, with the exact resolved read-set key. Chat acknowledges that rider only
when the board rides the admitted call and `begin_sourced_answer` succeeds.
A role refusal, omitted board, stopped witness or failed answer opening drops
the pending acknowledgement. It does not consume the rider's proposal outcomes
or connector baseline as if the call had carried them.

The commit looks up the captured key directly. It neither creates a read set nor
selects whichever session later became active. The existing delivery-generation
check still rejects a stale acknowledgement; another render can deliver those
changes again. No retrieval, embedding, rendering or lifecycle fold runs twice.
The admitted messages and their segment manifest do not change at commit.

Chat read-set keys are JSON pairs of principal and session. They live with the
server process. The current closer removes only four-part run keys, so it cannot
remove and recreate a chat entry while an acknowledgement is pending. Restarting
the process drops both the store and its pending acknowledgements. A new close
path for chat keys would need to preserve the entry identity across this interval
or bind delivery to the exact state instance.

The standalone context-board handler and the board used by turn actions keep
their immediate rider acknowledgement. A live turn keeps the split board order:
state before the user's message, query after it. Its deferred acknowledgement
travels with that same board; it does not join or render the parts again. There
is no new request field, stored format, configuration setting or delivery limit.

This is not full board rollback. MEMORIES cursor advancement, read observations,
pack inventory, once-disclosure consumption, hook deliveries and standing-use
receipts retain their existing hydration behavior. The user witness is never
withdrawn by this delivery step.
