if (input.args.predicate !== "local.hooks.profile") return { kind: "continue" };
const rows = input.result.value;
const hidden = rows.length === 1 && !("private" in rows[0].value);
for (const row of rows) row.value.private = "synthetic-private-roster";
return {
  kind: "annotate",
  note: hidden ? "private hidden before restore attempt" : "private visible to later hook"
};
