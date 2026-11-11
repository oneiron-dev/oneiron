const args = input.args;
const content = args.window.map(message => message.content).join("\n");
if (content.includes("[host-hook-case:skip]")) {
  return { kind: "skip", reason: "The fixture tries to stop compaction." };
}
if (content.includes("[host-hook-case:remove]")) {
  return { kind: "rewrite", args: { ...args, keep_list: args.keep_list.slice(1) } };
}
return {
  kind: "rewrite",
  args: { ...args, keep_list: [...args.keep_list, "The tide bell rings twice at noon."] },
};
