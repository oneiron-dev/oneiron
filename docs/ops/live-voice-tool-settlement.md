# Live voice tool settlement

`ai.voice.tool` calls the connector once under the caller's existing grant.
An immediate delivered result enters the live voice session through its native
tool-context command, as before. A held call, a pending delivery with a call ref,
or a call awaiting connector input also starts a session-local observer of that
same ref. The observer never sends the connector call or answers its questions.

The observer reads the existing caller-bound `connector.call_status` path. It
polls once immediately, then uses the connector settler's existing interval.
Each blocking read owns a fresh native write admission until that read completes:
the status reader may consume a settled input row. A frozen host defers the read;
a pending call never holds an admission through its wait or resets the session's
idle clock.

A delivered result keeps the original call's listed rows and the rows its actual
settled-status read lists. The existing tool-context command marks the result
foreign and accepts it only when the session is idle. A busy session retains the
result for another attempt. A successful attachment ends the observer. The
session follows each call ref at most once, including after its observer ends.
Terminal refusals and deliveries with no retained result attach nothing.
For a held or pending call, a receipt-only row may be visible before the settler
publishes its WaitDeliveries reply. That provisional receipt does not end the
observer. After an authorized status read, it checks publication and re-reads
through the native status door if publication raced the read, so both the body
and its listed source rows come from the actual publication. An unpublished
reply waits for the existing next poll. A published reply with no retained body
is terminal as before.

Before a generic connector call dispatches or reads a replayed call's row, the
credential-bound blocking caller registers interest in its exact native call ref.
An invocation it already carries keeps that identity; a call with none uses a fresh
native invocation. Web connector calls keep their existing path. For an input
call, the connector worker hands its cleared original result to active interests
before settling the receipt-only row. The status reader still authorizes the
caller before the voice observer uses that result. A concurrent answer that
settles a replay during the call can therefore still feed the same observer.

Only active interests retain a result, shared immutably between authorized
session observers. Each session keeps its own once-per-ref attachment gate.
The interest is owned before the observer is spawned; a rejected or unpolled
future drops it too. The last interest's drop releases the retained body. This
is not a permanent result cache: calls that already completed without a live
interest still have only their receipt, and a restart retains no result body.

The host owns these observers in its existing session-task collection. Stop
signals them and waits for them, including an in-flight blocking status read.
Session shutdown or a naturally closed command receiver ends a waiting observer.
A managed session released while idle still needs the native session admission
before its loop can consume a queued tool result; the observer does not renew it.

The session and observer are process-local, like the voice brain and event
journal. They do not survive a server restart. The connector's existing durable
call/status records remain the caller's recovery path. This adds no durable
voice record, public verb, DTO field, timeout, cap, or connector resend policy.
The immediate reply, device-local narrowing, and connector questions keep their
existing shapes.
