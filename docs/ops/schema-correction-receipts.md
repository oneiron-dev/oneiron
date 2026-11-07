# Schema-correction usage receipts

A structured generation may complete more than one paid call while correcting
an invalid reply. Its returned or failed-step usage sums the completed calls'
input, output and cache counters as before. The provider metadata retains each
call's inference receipts in call order, including identical physical calls.
The last call still supplies every non-receipt provider field.

Receipt lists use the existing direct or served-ladder location. The combined
list is written at the direct location. A null last provider becomes an object
when an earlier receipt list must be carried. A scalar provider or an unreadable
last receipt list stays as supplied; it is not evidence of complete usage.
Missing receipts and model identifiers remain unknown, never zero or free.

This preserves reported records. It does not establish complete physical-call
coverage, choose an answering model, or turn an input-token catalog rate into a
measured decision price. Answer validation, correction attempts, admission,
settlement, cancellation and token totals are unchanged.
