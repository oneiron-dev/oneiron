# First-entry disclosure offers

A native host can record an attendee with
`Memory::container_attendee_entered`. A PERSON's first non-project entry
records its first-entry fact and joins the room. The event's history choice
controls the membership window. A later call does not join the person again.

To also propose the newcomer's clearance, call
`Memory::container_attendee_entered_with_disclosure_offer(event, scope, owner_ref)`.
The host supplies the proposed Scope and the exact principal reference the
answering owner uses. The engine does not select a Scope or an owner. These
values are proposal data, not authority. The existing entry API and event
shape are unchanged.

The offer uses the entry's writer and its own savepoint. An offer error is
returned after the entry commits, so it does not undo the entry or its join.
The host can retry the same method. A retry reads the original first-entry
fact; it does not replace its time or revision. It can file only while the
original membership window is still open, before any leave and rejoin.
An old member with no entry fact gets no new entry or offer from this call.

The engine proposes only for the PERSON's active room-party contact. Project
rooms, speakers, decided entries, already-cleared contacts and always-ask mode
keep their existing behavior. A question already filed by the engine for that
contact and room is not filed again, even if its proposal expired or settled.
The explicit `Vault::file_person_entry_disclosure_offer` door remains available
for a host's deliberate replacement offer.

The owner reads the frozen proposal through `Vault::contact_disclosure_offers`
or the existing owner disclosure-offer HTTP list. Its channel identifies the
room. The owner confirms or denies through the existing attendee-entry doors.
Only that authenticated answer can change clearance or entry history. Filing
an offer alone grants no access.

This is a native API. Existing room-creation and membership callers do not
select a proposed Scope or owner recipient automatically.
