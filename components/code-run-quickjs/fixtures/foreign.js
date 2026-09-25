if (typeof self !== "undefined") throw new Error("foreign write imports leaked");
propose.file("/mnt/outputs/report.txt", [111,107]);
propose.claim({id:"010101010101010101010101010101e1", predicate:"test.quickjs", subject:"010101010101010101010101010101e2", value:"candidate"});
finish("proposals-only");

String.prototype.startsWith = () => true;
String.prototype.includes = () => false;
String.prototype.split = () => [];
let refused = false;
try { propose.file("/etc/passwd", [1]); } catch (_) { refused = true; }
if (!refused) throw new Error("prototype override bypassed proposal path validation");
