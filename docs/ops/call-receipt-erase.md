# Call receipts after actor erasure

Call receipts keep their existence, reference, time, verb, outcome and digests
when an actor is erased. The native actor eraser replaces the actor reference and
class with `ERASED_CALL_IDENTITY`. It replaces a present credential reference with
the same value and drops the linked attempt. An absent credential stays absent.

The receipt may commit after the transport has answered. Its common native write
path now checks the same transaction for the named actor's permanent hard-delete
marker. A deferred receipt that lands after that marker applies the same identity
scrub before its existing storage wall. A receipt that lands before erasure is
covered by the existing actor-erasure scan. Neither path drops the receipt or
waits for the actor to return.

The check matches the native eraser's exact canonical actor reference and retains
its known-non-actor exception. It does not infer actor identity from a credential,
attempt or actor-class label. The agent witness still reads the actual stored
receipt after the wall, not the earlier transport input.

Storage and codec errors retain their existing error and rollback behavior. This
change does not add a second receipt, a queue, a timer, a restore format, a setting,
or a new permission. Deploy a matching engine/server to use the write-path fix.
It does not claim to repair all unknown historical receipt attribution.
