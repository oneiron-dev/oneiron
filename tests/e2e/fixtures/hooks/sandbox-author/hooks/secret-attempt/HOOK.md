---
name: secret-attempt
version: 1.0.0
verbs: ["claim.landed:hooksandbox.probe.secret"]
actors: ["human"]
phase: fact
outcomes: ["nothing", "propose"]
---
Safe seed facts return Nothing during real qualification. A live fact invokes
one isolated sandbox attempt or returns one Generated foreign-author offer.
