# Retained courtesy copies in disclosure reads

A recipient owner's non-delete answer to a cooperative deletion ask keeps
covered copies out of ordinary shared retrieval (BIZ-LEGAL-0004 B2, Docs Q09).
The owner's answer, not the requester's ask alone, creates the exclusion. A
later Delete answer removes that answer's exclusion; it does not lift a legal
hold or a separate restriction the earlier answer placed.

The shared predicate is `disclosure::retained_copy_admits`. It reads the current
filed answers in the caller's transaction. It admits every other entity kind,
then checks foreign-world CLAIM, TASK and SUMMARY copies against their pact,
the ask's named worlds and its delivery epoch cutoff. Existing unknown-world
and unknown-delivery coverage and sync/no-sync behavior are unchanged. Callers
pass the actual revision body, not an unrelated current revision.

`DisclosureContext` keeps its owner-alone bypass. Its row predicate now also
applies the exclusion after ordinary tier and scope checks, including the
sources an epoch summary discloses. Context-pack admission delegates to this
same predicate. Room P7 word-closure checks also apply it after the revision's
own scope check, before following the words' sources. A withheld copy is absent;
this adds no legal-order refusal and changes no legal-hold or use-limit rule.

Scoped reads also check the retained-copy choice after ordinary row admission,
including both cached CLAIM admission and the uncached path. The decision stays
outside the access-class cache, so it remains per copy. Named, collection and
selected-revision reads and their source checks use that same row admission.
Existing actual owner lanes remain exempt; an owner-exempt delegated key is not
itself an owner lane.

This is not a claim that every read or export path is covered. Selector egress
and standalone private-room renders that bypass P7 with no clearance still need
audience-aware integration. Same-owner replication is not assumed to
be ordinary shared retrieval. No storage format, migration, SDK, config, default,
or deployment change is required by this native disclosure slice.
