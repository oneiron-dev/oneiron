# Explicit team votes

A participant in a vote-pattern team can call
`self.team.vote({teamRef, choice})` from code mode. The host binds the voter
from the running attempt. The input has no voter or actor field.

The vote writer reads that attempt again in its write transaction. It must
carry the exact team's vote-pattern stamp, or be the current retry of the
leader whose recorded start opened that team. Off-record and unbound runs
cannot write a durable ballot. These checks apply only to the new verb.

Each attempt keeps its own choice for each team. Calling the verb again
replaces only that attempt's choice. The host does not choose a winner or
add a majority, quorum, tie-break, or voting deadline.

When `self.team.record` writes a new vote receipt, it reads the leader and
members on their newest tries in one snapshot. If every distinct current
participant has an explicit ballot, the host counts those choices instead
of the leader's supplied tally. A missing attempt or ballot leaves the tally
unknown, so the existing declared-tally behavior remains available. A
retry's ballot is not inherited from an earlier attempt. Seals, confessions,
replies, and role names are not ballots.

Recording again returns the existing receipt before reading ballots. A
later vote never changes a receipt already recorded. Roles, coverage, and
an unsigned referee rule remain declarations; the full team-meter work is
not complete. The ballot table is CONTENT for checkpoint restore. It adds
no entity-body copy, permission, automatic model call, or delivery claim.
