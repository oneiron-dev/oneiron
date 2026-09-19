// Bring one explicitly identified, already-running Excel process forward.
// This never launches an application or reads, closes, or saves a workbook.
ObjC.import('AppKit');
function run(argv) {
    if (argv.length !== 1) throw new Error('One existing Excel PID is required');
    var pid = Number(argv[0]);
    if (!isFinite(pid) || Math.floor(pid) !== pid || pid <= 0 || pid > 2147483647)
        throw new Error('Invalid existing Excel PID');
    var app = $.NSRunningApplication.runningApplicationWithProcessIdentifier(pid);
    if (Number(app.processIdentifier) !== pid ||
        ObjC.unwrap(app.bundleIdentifier) !== 'com.microsoft.Excel')
        throw new Error('Existing Excel process identity mismatch; no launch permitted');
    return JSON.stringify({pid: pid, bundle: ObjC.unwrap(app.bundleIdentifier),
        activated: Boolean(app.activateWithOptions(2))});
}
